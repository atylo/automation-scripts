// "old Xor + LZSS": assets embedded in the EXE as bit-inverted LZSS streams whose header
// is "LZSS" inverted (B3 A5 AC AC) + inverted 16-bit size (port of lzss_extractor.py).
//
// Strategy per stream: 1) table of contents (name VA, data VA, size)  2) code references
// (PUSH imm / MOV reg,imm) to deduce the size  3) otherwise skipped as an orphan.
#include <algorithm>
#include <set>

#include "compress.h"
#include "d88.h"
#include "extractors.h"
#include "output.h"
#include "pe.h"
#include "platform.h"

namespace {

using util::LoadU32;

constexpr uint32_t kMaxSize = 50u * 1000u * 1000u;   // 50 MB sanity limit (as in the script)

struct AsmHint {
    enum Kind { None, Header, Hardcoded, RefFound } kind = None;
    uint32_t size = 0;
};

// Keeps valid UTF-8 sequences only (Python: decode('utf-8', 'ignore')).
std::string KeepValidUtf8(const std::string& in) {
    std::string out;
    size_t i = 0;
    while (i < in.size()) {
        unsigned char c = static_cast<unsigned char>(in[i]);
        size_t n = c < 0x80 ? 1 : (c >= 0xC2 && c < 0xE0) ? 2 : (c >= 0xE0 && c < 0xF0) ? 3 : (c >= 0xF0 && c < 0xF5) ? 4 : 0;
        bool ok = n != 0 && i + n <= in.size();
        for (size_t k = 1; ok && k < n; ++k) ok = (static_cast<unsigned char>(in[i + k]) & 0xC0) == 0x80;
        if (ok) { out.append(in, i, n); i += n; }
        else ++i;
    }
    return out;
}

Bytes DecompressStream(ByteSpan blob, size_t size) {
    if (blob.size() < 6) return {};
    return compress::LzssDecompress(blob.data() + 6, blob.size() - 6, size, /*invert=*/true);
}

void SaveAsset(const Bytes& data, const std::string& fileName, const fs::path& outDir, bool inventedName = false) {
    if (d88::LooksLikeBundle(data)) {
        util::Info("    [*] Detected D88 disk image bundle! Extracting disks...");
        if (d88::SplitBundle(data, outDir) > 0) return;
    }
    output::Options opt;
    opt.genericName = inventedName;
    output::Save(outDir, platform::PathToUtf8(platform::PathFromUtf8(fileName).filename()), data, opt);
}

AsmHint FindAsmHint(ByteSpan chunk, uint32_t dataVa) {
    uint8_t target[4];
    for (int i = 0; i < 4; ++i) target[i] = static_cast<uint8_t>(dataVa >> (8 * i));

    // PUSH imm32, MOV EAX/ECX/EDX/EBX/ESI/EDI, imm32
    const uint8_t opcodes[] = {0x68, 0xB8, 0xB9, 0xBA, 0xBB, 0xBE, 0xBF};
    bool foundAny = false;

    for (uint8_t op : opcodes) {
        uint8_t pattern[5] = {op, target[0], target[1], target[2], target[3]};
        size_t off = 0;
        while (true) {
            size_t local = util::FindBytes(chunk, ByteSpan(pattern, 5), off);
            if (local == util::npos) break;
            foundAny = true;

            // look back up to 50 bytes, but stop at a RET (we would be in another function)
            size_t checkStart = local >= 50 ? local - 50 : 0;
            ByteSpan check = chunk.subspan(checkStart, local - checkStart);
            ByteSpan valid = check;
            for (size_t k = check.size(); k-- > 0;)
                if (check[k] == 0xC3) { valid = check.subspan(k + 1); break; }

            const uint8_t push0[2] = {0x6A, 0x00};
            if (util::FindBytes(valid, ByteSpan(push0, 2)) != util::npos) return {AsmHint::Header, 0};

            for (size_t k = valid.size(); k-- > 0;) {
                if (valid[k] != 0x68) continue;
                if (k + 5 <= valid.size()) {
                    uint32_t sz = LoadU32(&valid[k + 1]);
                    if (sz > 0 && sz < kMaxSize) return {AsmHint::Hardcoded, sz};
                }
                break;      // only the last 0x68 is considered
            }
            off = local + 1;
        }
    }
    return {foundAny ? AsmHint::RefFound : AsmHint::None, 0};
}

bool ProcessPe(ByteSpan d, const PeLocation& pe, size_t endOffset, const fs::path& outDir) {
    const size_t peStart = pe.mzOffset;
    const uint8_t sig[4] = {0xB3, 0xA5, 0xAC, 0xAC};
    bool any = false;
    size_t startSearch = peStart;
    std::set<size_t> done;

    util::Info("\n=== Processing PE at 0x" + util::Hex(peStart) + " ===");

    while (true) {
        size_t dataOff = util::FindBytes(d, ByteSpan(sig, 4), startSearch);
        if (dataOff == util::npos || dataOff >= endOffset) break;
        startSearch = dataOff + 1;
        if (done.count(dataOff)) continue;

        uint32_t dataVa = static_cast<uint32_t>(pe.imageBase + (dataOff - peStart));
        util::Info("\n[+] Found signature at 0x" + util::Hex(dataOff) + " (VA 0x" + util::Hex(dataVa) + ")");

        // --- 1. TOC -----------------------------------------------------------
        bool foundToc = false;
        uint8_t packed[4];
        for (int i = 0; i < 4; ++i) packed[i] = static_cast<uint8_t>(dataVa >> (8 * i));
        size_t tocSearch = peStart;
        while (true) {
            size_t tocPtr = util::FindBytes(d, ByteSpan(packed, 4), tocSearch, endOffset);
            if (tocPtr == util::npos) break;
            tocSearch = tocPtr + 1;

            uint32_t nameVa = 0, size = 0;
            if (tocPtr < 4 || !util::ReadU32(d, tocPtr - 4, nameVa) || nameVa < pe.imageBase) continue;
            size_t nameOff = peStart + (nameVa - pe.imageBase);
            if (!(peStart <= nameOff && nameOff < endOffset)) continue;
            if (!util::ReadU32(d, tocPtr + 4, size) || !(size > 0 && size < kMaxSize)) continue;

            size_t avail = std::min<size_t>(64, d.size() - nameOff);
            std::string name(reinterpret_cast<const char*>(&d[nameOff]), avail);
            name = KeepValidUtf8(name.substr(0, name.find('\0')));
            name = name.substr(name.find_last_of('\\') == std::string::npos ? 0 : name.find_last_of('\\') + 1);
            if (name.empty()) continue;

            util::Info("    [Strategy: TOC] Found '" + name + "' (size: " + std::to_string(size) + ")");
            size_t blobLen = std::min<size_t>(static_cast<size_t>(size) + 8192, d.size() - dataOff);
            SaveAsset(DecompressStream(d.subspan(dataOff, blobLen), size), name, outDir);
            foundToc = true;
            any = true;
            break;
        }
        if (foundToc) { done.insert(dataOff); continue; }

        // --- 2. code references -----------------------------------------------------
        AsmHint hint = FindAsmHint(d.subspan(peStart, endOffset - peStart), dataVa);
        if (hint.kind != AsmHint::None) {
            if (hint.kind == AsmHint::Header || hint.kind == AsmHint::Hardcoded) {
                uint32_t finalSize = 0;
                if (hint.kind == AsmHint::Header) {
                    if (dataOff + 6 <= d.size())
                        finalSize = (static_cast<uint32_t>(static_cast<uint8_t>(~d[dataOff + 5])) << 8) |
                                    static_cast<uint8_t>(~d[dataOff + 4]);
                    util::Info("    [Strategy: ASM] PUSH 0 -> trusted header: " + std::to_string(finalSize));
                } else {
                    finalSize = hint.size;
                    util::Info("    [Strategy: ASM] hard-coded size: " + std::to_string(finalSize));
                }
                if (finalSize > 0) {
                    size_t blobLen = std::min<size_t>(static_cast<size_t>(finalSize) + 4096, d.size() - dataOff);
                    SaveAsset(DecompressStream(d.subspan(dataOff, blobLen), finalSize),
                              "asset_" + util::Hex(dataOff) + ".bin", outDir, true);
                    done.insert(dataOff);
                    any = true;
                    continue;
                }
                util::Info("    [!] ASM header size was 0. Downgrading to fallback extraction.");
                hint.kind = AsmHint::RefFound;
            }
            // fallback: referenced, size unknown -> decode until the end of the input
            util::Info("    [Strategy: Fallback] Referenced at 0x" + util::Hex(dataVa) + ", extracting until end-of-stream.");
            SaveAsset(DecompressStream(d.subspan(dataOff), 0), "asset_" + util::Hex(dataOff) + "_fallback.bin", outDir, true);
            done.insert(dataOff);
            any = true;
            continue;
        }

        // --- 3. orphan ----------------------------------------------------------------
        util::Info("    [!] Orphaned asset: no TOC and no code references. Skipping to avoid garbage.");
        done.insert(dataOff);
    }
    return any;
}

}  // namespace

bool ExtractOldXorLzss(const Context& ctx) {
    ByteSpan d(*ctx.data);
    auto pes = FindAllPeHeaders(d);
    if (pes.empty()) pes.push_back({0, 0x400000});

    bool any = false;
    for (size_t i = 0; i < pes.size(); ++i) {
        size_t next = (i + 1 < pes.size()) ? pes[i + 1].mzOffset : d.size();
        any |= ProcessPe(d, pes[i], next, ctx.outDir);
    }
    if (!any) util::Error("no extractable asset found (all LZSS streams were orphaned or undecodable)");
    return any;
}
