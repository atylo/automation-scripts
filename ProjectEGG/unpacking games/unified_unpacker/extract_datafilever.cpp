// DataFileVer (types 1-4): disk images stored as rotate/XOR-encrypted + LZSS blobs inside the EXE
// (port of egg_datafilever_ext.py v2).
#include <algorithm>

#include "compress.h"
#include "crypto.h"
#include "d88.h"
#include "extractors.h"
#include "pe.h"
#include "platform.h"

namespace {

using util::LoadU32;

struct Section {              // VA range uses *raw* size, like the Python tool
    std::string name;
    uint64_t start, end;
    size_t rawPtr;
};

struct Entry {
    uint32_t decomp;
    uint32_t va;
    size_t   blobOff;
    uint32_t comp;
    uint8_t  key;
};

std::optional<size_t> VaToOffset(uint64_t va, const std::vector<Section>& secs) {
    for (const auto& s : secs)
        if (s.start <= va && va < s.end) return s.rawPtr + static_cast<size_t>(va - s.start);
    return std::nullopt;
}

bool IsValidVa(uint64_t va, const std::vector<Section>& secs) {
    for (const auto& s : secs)
        if (s.start <= va && va < s.end) return true;
    return false;
}

// ---------------------------------------------------------------------------
// Type 1: metadata table located via 93 6F terminator
// ---------------------------------------------------------------------------
bool ValidEntry(uint32_t decomp, uint32_t va, uint32_t comp, size_t dataLen, uint64_t imageBase) {
    if (!(100000 < decomp && decomp < 5000000)) return false;
    if (!(imageBase < va && va < imageBase + 0x1000000)) return false;
    if (!(10000 < comp && comp < 5000000)) return false;
    uint64_t fileOff = va - imageBase;
    if (fileOff == 0 || fileOff >= dataLen) return false;
    if (fileOff + comp > dataLen) return false;
    return true;
}

std::vector<Entry> ParseType1Entries(ByteSpan d, size_t offset, uint64_t imageBase) {
    std::vector<Entry> entries;
    size_t entrySize = 0, vaOff = 0;

    uint32_t decomp = 0, va = 0, comp = 0;
    if (offset + 13 > d.size()) return {};
    decomp = LoadU32(&d[offset]);
    va = LoadU32(&d[offset + 4]);
    comp = LoadU32(&d[offset + 8]);
    if (ValidEntry(decomp, va, comp, d.size(), imageBase)) {
        entrySize = 13; vaOff = 4;                       // decomp, va, comp, key
    } else {
        if (offset + 17 > d.size()) return {};
        va = LoadU32(&d[offset + 8]);
        comp = LoadU32(&d[offset + 12]);
        if (!ValidEntry(decomp, va, comp, d.size(), imageBase)) return {};
        entrySize = 17; vaOff = 8;                       // decomp, unknown, va, comp, key
    }

    while (offset + entrySize <= d.size()) {
        Entry e;
        e.decomp = LoadU32(&d[offset]);
        e.va     = LoadU32(&d[offset + vaOff]);
        e.comp   = LoadU32(&d[offset + vaOff + 4]);
        e.key    = d[offset + entrySize - 1];

        uint64_t fileOff = static_cast<uint64_t>(e.va) - imageBase;
        if (e.va < imageBase || !(0 < fileOff && fileOff < d.size() && fileOff + e.comp <= d.size())) break;
        e.blobOff = static_cast<size_t>(fileOff);
        entries.push_back(e);

        offset += entrySize;
        while (offset < d.size() && d[offset] == 0x00) ++offset;

        if (offset + 1 < d.size() && d[offset] == 0x93 && d[offset + 1] == 0x6F) break;   // end marker

        if (offset + 4 <= d.size()) {
            uint32_t nextDecomp = LoadU32(&d[offset]);
            if (!(100000 < nextDecomp && nextDecomp < 5000000)) break;
        }
    }
    return entries;
}

std::vector<Entry> FindType1(ByteSpan d, uint64_t imageBase) {
    std::vector<Entry> entries;
    const uint8_t term[] = {0x93, 0x6F};
    const uint8_t ffff[] = {0xFF, 0xFF, 0xFF, 0xFF};

    size_t idx = d.size() / 2;
    while (true) {
        idx = util::FindBytes(d, ByteSpan(term, 2), idx);
        if (idx == util::npos) break;

        for (size_t back = 0x10; back < 0x200; ++back) {
            if (back > idx) break;
            size_t check = idx - back;
            if (check + 4 <= d.size() && std::memcmp(&d[check], ffff, 4) == 0) {
                size_t j = check + 4;
                while (j < idx && d[j] == 0x00) ++j;
                size_t zeros = j - (check + 4);
                if (zeros >= 4 && j < idx) {
                    auto test = ParseType1Entries(d, j, imageBase);
                    if (test.size() > entries.size()) { entries = std::move(test); break; }
                }
            }
        }
        if (!entries.empty()) break;
        ++idx;
    }

    if (entries.empty()) {                               // fallback: scan every FF FF FF FF
        for (size_t i = d.size() / 2; i + 24 < d.size(); ++i) {
            if (std::memcmp(&d[i], ffff, 4) != 0) continue;
            size_t j = i + 4;
            while (j < d.size() && d[j] == 0x00) ++j;
            size_t zeros = j - (i + 4);
            if (zeros >= 4 && j + 16 <= d.size()) {
                auto test = ParseType1Entries(d, j, imageBase);
                if (test.size() > entries.size()) entries = std::move(test);
            }
        }
    }
    return entries;
}

// ---------------------------------------------------------------------------
// Types 2/3/4: metadata scraped from the init function (E9 0B 00 00 00 marker)
// ---------------------------------------------------------------------------
struct BlobHeader { uint32_t decomp; uint8_t key; };

std::optional<BlobHeader> ParseBlobHeader(ByteSpan d, size_t blobOffset) {
    if (blobOffset == 0 || blobOffset > d.size()) return std::nullopt;
    size_t pos = blobOffset - 1;
    size_t minPos = std::max<size_t>(4, blobOffset >= 16 ? blobOffset - 16 : 0);

    while (pos > minPos && d[pos] == 0x00) --pos;
    if (d[pos] == 0x00 || pos < 4) return std::nullopt;

    size_t P = pos;
    uint8_t key;
    size_t decompPos;
    if (d[P - 1] != 0x00) {      // zero-key case: P landed on decomp[2]
        key = 0x00;
        decompPos = P - 2;
    } else {                     // non-zero key: P is the key, previous byte is decomp MSB
        key = d[P];
        decompPos = P - 4;
    }
    if (decompPos + 4 > d.size()) return std::nullopt;
    if (d[decompPos + 3] != 0x00) return std::nullopt;

    uint32_t decomp = LoadU32(&d[decompPos]);
    if (!(10000 < decomp && decomp < 5000000)) return std::nullopt;
    return BlobHeader{decomp, key};
}

std::vector<Entry> FindType234(ByteSpan d, const std::vector<Section>& secs) {
    const Section* dataSec = nullptr;
    for (const auto& s : secs)
        if (s.name.find(".data") != std::string::npos) { dataSec = &s; break; }
    if (!dataSec && secs.size() >= 2) dataSec = &secs[secs.size() - 2];
    if (!dataSec) return {};

    size_t ptrLoc = dataSec->rawPtr + 4;
    uint32_t initVa = 0;
    if (!util::ReadU32(d, ptrLoc, initVa)) return {};
    auto initOff = VaToOffset(initVa, secs);
    if (!initOff || *initOff == 0) return {};

    const uint8_t sig[] = {0xE9, 0x0B, 0x00, 0x00, 0x00};
    size_t winEnd = std::min(d.size(), *initOff + 5000);
    size_t sigIdx = util::FindBytes(d, ByteSpan(sig, 5), *initOff, winEnd);
    if (sigIdx == util::npos) return {};

    size_t cursor = sigIdx + sizeof(sig);
    size_t limit = cursor + 15000;
    std::vector<uint32_t> values;                         // immediates of MOV [mem], imm32
    while (cursor < limit && cursor + 10 <= d.size()) {
        if (d[cursor] == 0xC7 && d[cursor + 1] == 0x05) {
            values.push_back(LoadU32(&d[cursor + 6]));
            cursor += 10;
        } else {
            ++cursor;
        }
    }

    std::vector<Entry> entries;
    size_t i = 0;
    while (i + 1 < values.size()) {
        uint32_t blobVa = values[i], comp = values[i + 1];
        if (IsValidVa(blobVa, secs) && 10000 < comp && comp < 5000000) {
            auto off = VaToOffset(blobVa, secs);
            if (off) {
                auto h = ParseBlobHeader(d, *off);
                if (!h) {
                    util::Debug("Found possible blob at 0x" + util::Hex(*off) + " and comp 0x" + util::Hex(comp) +
                                ", but no actual blob header");
                    ++i;
                    continue;
                }
                entries.push_back({h->decomp, blobVa, *off, comp, h->key});
                i += 2;
                continue;
            }
        }
        ++i;
    }
    return entries;
}

}  // namespace

bool ExtractDataFileVer(const Context& ctx) {
    const Bytes& data = *ctx.data;
    PeInfo pe;
    if (!ParsePe(data, pe) || pe.imageBase == 0) { util::Error("could not parse the PE header"); return false; }

    std::vector<Section> secs;
    for (const auto& s : pe.sections)
        secs.push_back({s.name, pe.imageBase + s.virtualAddress, pe.imageBase + s.virtualAddress + s.rawSize, s.rawPtr});

    util::Info("Image base: 0x" + util::Hex(pe.imageBase));
    size_t nested = FindNestedPe(data);
    if (nested) util::Info("Nested PE at: 0x" + util::Hex(nested));

    // Types 2/3/4 first, then Type 1.
    std::vector<Entry> entries = FindType234(data, secs);
    std::string type = "2/3/4";
    if (entries.empty()) {
        entries = FindType1(data, pe.imageBase);
        type = "1";
    }
    if (entries.empty()) {
        util::Error("could not find the disk metadata (tried both the Type 1 and Type 2/3/4 layouts)");
        return false;
    }
    util::Info("Detected as Type " + type + ", " + std::to_string(entries.size()) + " disk entries");

    std::string base = util::PathToUtf8(ctx.input.stem());
    size_t extracted = 0;
    for (size_t idx = 0; idx < entries.size(); ++idx) {
        const Entry& e = entries[idx];
        util::Info("Disk " + std::to_string(idx + 1) + ":");
        util::Debug("  Decomp: " + std::to_string(e.decomp) + ", Comp: " + std::to_string(e.comp) + ", Key: 0x" + util::Hex(e.key, 2));

        size_t blobOff = e.blobOff;
        if (type == "1" && nested) {                      // Type 1 with nested PE: offsets are relative to it
            blobOff = nested + e.blobOff;
            util::Debug("  Blob offset: 0x" + util::Hex(e.blobOff) + " -> 0x" + util::Hex(blobOff) + " (nested PE adjusted)");
        } else {
            util::Debug("  Blob offset: 0x" + util::Hex(blobOff));
        }
        if (blobOff + e.comp > data.size()) {
            util::Warn("Blob extends beyond file!");
            continue;
        }

        Bytes decrypted = crypto::DataFileVerDecrypt(&data[blobOff], e.comp, e.key);
        Bytes disk = compress::LzssDecompress(decrypted.data(), decrypted.size(), e.decomp);
        util::Debug("  Result: " + std::to_string(disk.size()) + " bytes");

        auto info = d88::Validate(disk);
        if (info.valid) util::Debug("  Header name: \"" + info.name + "\" (valid D88)");
        else            util::Warn("Disk " + std::to_string(idx + 1) + ": invalid D88 header" +
                                   (info.name.empty() ? "" : " (name \"" + info.name + "\")"));

        fs::path out = util::UniquePath(ctx.outDir / d88::SuggestFileName(disk, base + "_disk_" + std::to_string(idx + 1)));
        if (util::WriteFile(out, disk)) ++extracted;
    }
    util::Info("Extraction complete: " + std::to_string(extracted) + "/" + std::to_string(entries.size()) + " disks extracted.");
    if (extracted == 0) util::Error("no disk image could be extracted");
    return extracted > 0;
}
