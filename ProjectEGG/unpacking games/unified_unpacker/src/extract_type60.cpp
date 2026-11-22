// TYPE60: the game is a launcher EXE that embeds the emulator as a second PE image. The embedded
// image holds "BIN" resources (CONFIG, ROM, STATE, ...), each:
//   [4 version][4 uncompressed size][4 CRC-32][1 seed] + payload
// payload = LCG-XOR encrypted arithmetic-coded data; the CRC (MSB-first poly 0x04C11DB7) covers the
// decompressed data. Port of extract_test_V2.py.
//
// The "ROM" resource is a concatenation of the machine's system ROMs. Its layout depends on the
// machine mode stored in CONFIG (u32 at 0x84); it is cut into the individual ROM files and each is
// named by its CRC-32 (port of ROM_cutter.py).
#include <algorithm>

#include "compress.h"
#include "crypto.h"
#include "extractors.h"
#include "output.h"
#include "pe.h"
#include "platform.h"
#include "romdb.h"

namespace {

constexpr size_t kHeader   = 13;
constexpr size_t kMaxSize  = 64u * 1024u * 1024u;    // sanity cap for the declared / produced size

bool IsBinLike(const PeResource& r) {
    std::string up = r.type;
    for (char& c : up) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return up.find("BIN") != std::string::npos || (r.typeIsId && r.type == "10");   // "BIN*" or RT_RCDATA
}

// Decodes one resource. Returns true (and fills `data`) when the CRC matched.
bool DecodeResource(ByteSpan res, const std::string& name, const fs::path& outDir, Bytes& data) {
    uint32_t version      = util::LoadU32(&res[0]);
    uint32_t uncompressed = util::LoadU32(&res[4]);
    uint32_t expectedCrc  = util::LoadU32(&res[8]);
    uint8_t  seed         = res[12];
    util::Debug("  header: version " + std::to_string(version) + ", size " + std::to_string(uncompressed) +
                ", crc 0x" + util::Hex(expectedCrc, 8) + ", seed 0x" + util::Hex(seed, 2));

    if (uncompressed > kMaxSize) {
        util::Error(name + ": implausible size in the resource header");
        return false;
    }

    Bytes payload(res.begin() + kHeader, res.end());
    crypto::LcgXorDecrypt(payload.data(), payload.size(), seed);

    // The decoder output is one byte longer than the header size on known files, so allow some slack.
    bool decoded = compress::ArithDecompress(payload.data(), payload.size(), uncompressed + 65536u, data);
    if (!decoded) {
        util::Warn(name + ": decompression error");
        data = payload;                      // same fallback as the Python tool (then the CRC fails)
    }

    uint32_t crc = crypto::Crc32Msb(data.data(), data.size());
    if (crc != expectedCrc) {
        util::Error(name + ": CRC mismatch (expected 0x" + util::Hex(expectedCrc, 8) + ", got 0x" + util::Hex(crc, 8) + ")");
        if (util::g_debug) util::WriteFile(util::UniquePath(outDir / platform::PathFromUtf8(name + "_FAIL.bin")), data);
        return false;
    }
    util::Debug("  CRC matched: 0x" + util::Hex(crc, 8));
    return true;
}

// ---------------------------------------------------------------------------------------------
// ROM cutter (port of ROM_cutter.py)
// ---------------------------------------------------------------------------------------------
struct Chunk { const char* desc; uint32_t size; };

// Layouts: the slices of the ROM resource, in order, per machine mode.
const std::vector<Chunk> kLayouts[5] = {
    /* 0  PC-6001           */ {{"MainRAM", 0x4000}, {"WorkRAM", 0x1000}},
    /* 1  PC-6001mkII       */ {{"MainRAM", 0x8000}, {"WorkRAM", 0x2000}, {"SubRAM", 0x2000}, {"VideoRAM", 0x8000}, {"SaveRAM", 0x4000}},
    /* 2  PC-6001mkII (ext) */ {{"MainRAM", 0x8000}, {"WorkRAM", 0x2000}, {"SubRAM", 0x2000}, {"VideoRAM", 0x8000}, {"SaveRAM", 0x4000}, {"ExtRAM", 0x2000}},
    /* 3  PC-6001mkII (alt) */ {{"MainRAM", 0x8000}, {"WorkRAM", 0x2000}, {"SubRAM", 0x2000}, {"VideoRAM", 0x8000}, {"SaveRAM", 0x4000}},
    /* 4  PC-6601 / SR      */ {{"MainRAM", 0x8000}, {"WorkRAM", 0x8000}, {"SubRAM", 0x2000}, {"SaveRAM", 0x2000}, {"VideoRAM", 0x4000}, {"ExtRAM", 0x2000}},
};

// The ROM database knows the file names; the machine mode decides which name a ROM gets when the same
// bytes are used on several machines (3CE48C33 is CGROM60m.62 on the mkII but CGROM66.66 on the PC-6601).
const std::vector<std::string_view>& SystemsFor(int mode) {
    static const std::vector<std::string_view> pc6001   = {"NEC PC-6001", "NEC PC-6001A"};
    static const std::vector<std::string_view> mk2      = {"NEC PC-6001mkII"};
    static const std::vector<std::string_view> pc6601   = {"NEC PC-6601", "NEC PC-6601SR / PC-6001mkII SR"};
    switch (mode) {
        case 0: return pc6001;
        case 1: case 2: case 3: return mk2;
        default: return pc6601;
    }
}

// Returns the number of ROM files written (0 = could not cut).
size_t CutRom(const Bytes& config, const Bytes& rom, const fs::path& outDir) {
    uint32_t mode = 0;
    if (!util::ReadU32(config, 0x84, mode)) {
        util::Warn("CONFIG is too short to contain the machine mode");
        return 0;
    }
    if (mode > 4) {
        util::Warn("unknown machine mode " + std::to_string(mode) + ", using the layout of mode 4");
        mode = 4;
    }
    util::Debug("TYPE60 machine mode " + std::to_string(mode));

    const auto& layout = kLayouts[mode];
    output::Options opt;
    opt.preferSystems = SystemsFor(static_cast<int>(mode));
    opt.splitContainers = false;

    size_t cursor = 0, written = 0, index = 0;
    for (const Chunk& c : layout) {
        if (cursor + c.size > rom.size()) {
            util::Warn("ROM too small for chunk " + std::to_string(index));
            break;
        }
        ByteSpan chunk(rom.data() + cursor, c.size);
        uint32_t crc = crypto::Crc32(chunk);

        // known ROM? (names from the database, preferring the machine of this mode)
        std::string fileName;
        if (const romdb::Entry* e = romdb::Identify(chunk, opt.preferSystems)) {
            fileName = e->name;
            util::Debug("  chunk " + std::to_string(index) + ": MATCH -> " + fileName + "  [" + e->system + "] (size 0x" + util::Hex(c.size) + ")");
        } else {
            fileName = "UNK_" + util::Hex(crc, 8) + "_" + c.desc + ".bin";
            util::Debug("  chunk " + std::to_string(index) + ": UNKNOWN (" + util::Hex(crc, 8) + ") (size 0x" + util::Hex(c.size) + ")");
        }
        opt.identifyRom = false;                       // the name is already decided
        if (output::Save(outDir, fileName, chunk, opt)) ++written;
        cursor += c.size;
        ++index;
    }
    if (written && cursor < rom.size())
        util::Debug("  " + std::to_string(rom.size() - cursor) + " trailing byte(s) after the last chunk ignored");
    return written;
}

bool EqNoCase(const std::string& a, const char* b) { return EqualsNoCase(a, b); }

}  // namespace

bool ExtractType60(const Context& ctx) {
    const Bytes& file = *ctx.data;
    auto images = FindPeImages(file);
    if (images.empty()) { util::Error("no PE image found"); return false; }

    bool any = false;
    size_t candidates = 0;
    for (size_t idx = 0; idx < images.size(); ++idx) {
        // each image is parsed on its own, so all offsets are relative to its start
        ByteSpan image = ByteSpan(file).subspan(images[idx].offset);
        const PeInfo& pe = images[idx].info;
        util::Debug("PE #" + std::to_string(idx) + " at 0x" + util::Hex(images[idx].offset));

        struct Decoded { std::string name; Bytes data; bool invented; };
        std::vector<Decoded> good;

        for (const PeResource& r : EnumResources(image, pe)) {
            if (!IsBinLike(r) || r.size < kHeader) continue;
            ByteSpan res = image.subspan(r.fileOffset, r.size);
            if (res[0] == 'M' && res[1] == 'Z') continue;           // an embedded executable, not packed data

            ++candidates;
            util::Info("Resource " + r.type + "/" + r.name + " (" + std::to_string(r.size) + " bytes)");
            std::string name = r.name.empty() ? ("resource_" + std::to_string(candidates)) : r.name;
            Bytes data;
            if (DecodeResource(res, name, ctx.outDir, data)) good.push_back({name, std::move(data), r.name.empty()});
        }

        const Bytes* config = nullptr;
        for (const auto& d : good)
            if (EqNoCase(d.name, "CONFIG")) config = &d.data;

        for (const auto& d : good) {
            if (config && EqNoCase(d.name, "ROM")) {
                size_t n = CutRom(*config, d.data, ctx.outDir);
                if (n > 0) {
                    any = true;
                    if (util::g_debug) util::WriteFile(util::UniquePath(ctx.outDir / "ROM.bin"), d.data);
                    continue;
                }
                util::Warn("could not cut the ROM resource, saving it whole");
            }
            output::Options opt;
            opt.genericName = d.invented;
            any |= output::Save(ctx.outDir, d.name + ".bin", d.data, opt);
        }
    }

    if (candidates == 0) { util::Error("no packed BIN resources found"); return false; }
    if (!any && util::LastError().empty()) util::Error("no resource could be decoded");
    return any;
}
