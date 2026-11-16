// EGGDATA: AES-ECB encrypted regions appended to the EXE (port of egg_EGGDATA_unpack.py).
//   region 0 = CONFIG (key = MD5(exe name) ^ 0xFF) -> contains "YekTpyrc=<32 hex>" = data key
//   region 1.. = DATA blobs, each a table of DATA/NEXT/END records pointing to files
#include <algorithm>
#include <set>

#include "compress.h"
#include "crypto.h"
#include "extractors.h"
#include "eggdisk.h"
#include "keyfinder.h"
#include "output.h"
#include "platform.h"

namespace {

constexpr size_t kChunk      = 0x100;
constexpr size_t kHeaderSkip = 0x20;      // "EGGDATA " (8) + 0x18 header bytes

struct Region { size_t start, end; };

std::vector<Region> FindRegions(ByteSpan exe) {
    std::vector<size_t> positions;
    size_t pos = 0;
    while (true) {
        size_t idx = util::FindString(exe, "EGGDATA ", pos);
        if (idx == util::npos) break;
        uint32_t word0 = 0;
        if (util::ReadU32(exe, idx + 8, word0) && word0 != 1) {      // real regions have word[0] == 1
            util::Debug("[dbg] Skipping false positive at 0x" + util::Hex(idx) + " (word[0]=0x" + util::Hex(word0) + ")");
            pos = idx + 8;
            continue;
        }
        positions.push_back(idx);
        pos = idx + 8;
    }

    util::Debug("[dbg] " + std::to_string(positions.size()) + " valid EGGDATA region(s)");
    std::vector<Region> regions;
    for (size_t i = 0; i < positions.size(); ++i) {
        size_t start = positions[i] + kHeaderSkip;
        size_t end   = (i + 1 < positions.size()) ? positions[i + 1] : exe.size();
        if (util::g_debug) {
            std::string words;
            for (int w = 0; w < 6; ++w) {
                uint32_t v = 0;
                util::ReadU32(exe, positions[i] + 8 + w * 4, v);
                words += (w ? ", 0x" : "0x") + util::Hex(v);
            }
            util::Debug("[dbg] Region " + std::to_string(i) + " @ 0x" + util::Hex(positions[i]) + ": " + words);
        }
        if (start < end) regions.push_back({start, end});
    }
    return regions;
}

std::string CleanName(const uint8_t* p, size_t n) {
    std::string s;
    for (size_t i = 0; i < n && p[i] != 0; ++i)
        if (p[i] < 0x80) s += static_cast<char>(p[i]);           // ASCII only (Python: decode "ignore")
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    s = s.substr(b, e - b);
    return s.empty() ? "NONAME" : s;
}

fs::path MakeOutputPath(const fs::path& dir, const std::string& name) {
    fs::path leaf = platform::PathFromUtf8(name).filename();     // drop any directory part
    if (leaf.empty()) leaf = "NONAME";
    if (!leaf.has_extension()) leaf += ".bin";
    return dir / leaf;
}

output::Options OptionsFor(const std::string& name) {
    output::Options o;
    o.genericName = (name == "NONAME");               // the record had no usable name
    return o;
}

size_t ExtractRecords(const Bytes& data, const fs::path& outDir) {
    std::error_code ec;
    fs::create_directories(outDir, ec);

    size_t written = 0;
    size_t off = 0;
    std::set<size_t> visitedNext;

    while (off + 4 <= data.size()) {
        const uint8_t* type = &data[off];
        off += 4;

        if (std::memcmp(type, "END\0", 4) == 0) break;

        if (std::memcmp(type, "NEXT", 4) == 0) {
            uint32_t next = 0;
            if (!util::ReadU32(data, off, next)) break;
            size_t target = static_cast<size_t>(next) * kChunk;
            if (!visitedNext.insert(target).second) { util::Warn("NEXT record loop detected, stopping"); break; }
            off = target;
            continue;
        }

        if (std::memcmp(type, "DATA", 4) != 0) break;            // unknown tag: stop to avoid desync

        if (off + 8 + 0x14 > data.size()) break;
        uint32_t entryOff = util::LoadU32(&data[off]);
        uint32_t entrySize = util::LoadU32(&data[off + 4]);
        off += 8;
        std::string name = CleanName(&data[off], 0x14);
        off += 0x14;

        size_t fileOff = static_cast<size_t>(entryOff) * kChunk;
        if (fileOff + std::min<size_t>(entrySize, 8) > data.size()) continue;
        size_t avail = data.size() - fileOff;
        size_t rawLen = std::min<size_t>(entrySize, avail);

        bool compzip = entrySize >= 0x10 && avail >= 8 && std::memcmp(&data[fileOff], "COMPZIP ", 8) == 0;
        if (compzip) {
            uint32_t xsize = 0;
            Bytes decomp;
            bool ok = util::ReadU32(data, fileOff + 8, xsize) && avail >= 0x10 &&
                      compress::ZlibDecompress(&data[fileOff + 0x10], rawLen - std::min<size_t>(rawLen, 0x10), decomp);
            if (ok) {
                if (decomp.size() != xsize)
                    util::Warn(name + " decompressed to " + std::to_string(decomp.size()) + " bytes, expected " + std::to_string(xsize));
                if (output::Save(outDir, platform::PathToUtf8(MakeOutputPath(outDir, name).filename()), decomp, OptionsFor(name))) ++written;
            } else {
                util::Warn("COMPZIP failed for " + name);
                fs::path leaf = platform::PathFromUtf8(name).filename();
                fs::path errName = leaf.has_extension()
                    ? fs::path(leaf.stem().native() + fs::path("_COMPZIP_error").native() + leaf.extension().native())
                    : fs::path(leaf.native() + fs::path("_COMPZIP_error.bin").native());
                if (util::WriteFile(outDir / errName, &data[fileOff], rawLen)) ++written;
            }
        } else {
            if (output::Save(outDir, platform::PathToUtf8(MakeOutputPath(outDir, name).filename()), ByteSpan(&data[fileOff], rawLen), OptionsFor(name))) ++written;
        }
    }
    return written;
}

bool FindDataKey(const Bytes& cfg, uint8_t key[16]) {
    static const std::string tag = "YekTpyrc=";
    size_t pos = 0;
    while ((pos = util::FindString(cfg, tag, pos)) != util::npos) {
        size_t s = pos + tag.size();
        if (s + 32 <= cfg.size()) {
            bool ok = true;
            for (size_t i = 0; i < 32; ++i)
                if (!std::isxdigit(cfg[s + i])) { ok = false; break; }
            if (ok) {
                for (size_t i = 0; i < 16; ++i) {
                    auto nib = [](uint8_t c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; };
                    key[i] = static_cast<uint8_t>((nib(cfg[s + i * 2]) << 4) | nib(cfg[s + i * 2 + 1]));
                }
                return true;
            }
        }
        pos += 1;
    }
    return false;
}

}  // namespace

bool ExtractEggData(const Context& ctx) {
    const Bytes& exe = *ctx.data;
    auto regions = FindRegions(exe);
    if (regions.empty()) {
        util::Error("no EGGDATA regions found in the executable");
        return false;
    }

    // region 0 -> CONFIG. The key comes from the EXE name; if that does not work (renamed file),
    // search the known name patterns instead.
    const uint8_t* cfgPtr = &exe[regions[0].start];
    const size_t   cfgLen = regions[0].end - regions[0].start;

    // The key comes from the EXE's original name. The file may have been renamed or its case changed
    // (e.g. "game01_1.EXE" whose key was made from "GAME01_1"), so try that name, its upper- and lower-case
    // forms, and finally the known name patterns.
    auto upper = [](std::string s) { for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c))); return s; };
    auto lower = [](std::string s) { for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c))); return s; };
    std::vector<std::string> names = {ctx.exeName, upper(ctx.exeName), lower(ctx.exeName)};
    names.erase(std::unique(names.begin(), names.end()), names.end());
    {   // remove duplicates that are not adjacent (e.g. ABC / abc / ABC)
        std::vector<std::string> uniq;
        for (const auto& n : names) if (std::find(uniq.begin(), uniq.end(), n) == uniq.end()) uniq.push_back(n);
        names = uniq;
    }

    uint8_t dataKey[16];
    Bytes cfg;
    bool haveKey = false;
    for (const std::string& n : names) {
        auto key = crypto::EggConfigKey(n);
        cfg = crypto::EggChunkedAesDecrypt(cfgPtr, cfgLen, key.data());
        if (FindDataKey(cfg, dataKey)) {
            util::Debug("CONFIG key name: " + n + (n == ctx.exeName ? "" : "  (file name in another letter case)"));
            haveKey = true;
            break;
        }
    }
    if (!haveKey) {
        util::Debug("CONFIG key from the file name \"" + ctx.exeName + "\" failed, searching known names...");
        std::string found;
        if (cfgLen >= 16 && keyfinder::FindConfigName(cfgPtr, found)) {
            util::Debug("CONFIG key name found: " + found);
            auto key = crypto::EggConfigKey(found);
            cfg = crypto::EggChunkedAesDecrypt(cfgPtr, cfgLen, key.data());
            haveKey = FindDataKey(cfg, dataKey);
        }
        if (!haveKey) {
            util::Error("could not decrypt CONFIG (the file name did not match and no known key name worked)");
            return false;
        }
    }
    util::WriteFile(ctx.outDir / "CONFIG.txt", cfg);
    util::Debug("AES data key: " + util::HexBytes(ByteSpan(dataKey, 16)));

    if (regions.size() == 1) {
        util::Error("only the CONFIG region was found, there is no DATA region");
        return false;
    }

    // region 1.. -> DATA
    bool any = false;
    for (size_t idx = 1; idx < regions.size(); ++idx) {
        Bytes dec = crypto::EggChunkedAesDecrypt(&exe[regions[idx].start], regions[idx].end - regions[idx].start, dataKey);
        if (util::g_debug) util::WriteFile(ctx.outDir / ("DATA_" + std::to_string(idx) + ".bin"), dec);
        fs::path dir = ctx.outDir / ("DATA_" + std::to_string(idx));
        size_t n = ExtractRecords(dec, dir);
        eggdisk::AssembleDisks(dir);                        // floppy / hard disk chunks -> disk images
        util::Info("DATA[" + std::to_string(idx) + "]: extracted " + std::to_string(n) + " files to " + util::PathToUtf8(dir));
        any = any || n > 0;
    }
    if (!any) util::Error("no files could be extracted from the DATA regions");
    return any;
}
