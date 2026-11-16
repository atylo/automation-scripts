// TYPE98 / TYPE98_old: "BIN" resources (CFG, FD, HD, ...) encrypted + LZSS (port of egg_type98_extractor_v2.cpp).
#include <algorithm>

#include "compress.h"
#include "crypto.h"
#include "d88.h"
#include "extractors.h"
#include "output.h"
#include "pe.h"

namespace {

struct Res {
    const uint8_t* ptr;
    size_t size;
};

std::optional<Res> Load(const Bytes& data, const std::vector<FoundResource>& all, const char* name) {
    const FoundResource* r = FindFoundResource(all, "BIN", name);
    if (!r || r->res.size == 0) return std::nullopt;
    return Res{data.data() + r->res.fileOffset, r->res.size};
}

std::string OutName(const std::string& n) {
    if (n == "HD") return n + ".hdi";
    if (n == "CFG") return n + ".txt";
    if (n == "HH" || n == "TOP" || n == "SD" || n == "BD" || n == "TOM" || n == "RIM") return n + ".wav";   // rhythm samples
    if (n == "FONT" || n == "SOUND" || n == "BIOS") return n + ".ROM";
    return n + ".bin";
}

// Decrypt + decompress one resource. Returns false on failure.
bool Unpack(const Res& res, const std::string& name, int version, ByteSpan password, Bytes& out) {
    if (res.size < 13) {
        util::Warn("Resource too small: " + name);
        return false;
    }
    util::Info("Processing: " + name);
    uint32_t magic = util::LoadU32(res.ptr);
    if (magic != 1) {
        util::Warn(name + ": invalid header magic");
        return false;
    }
    uint32_t uncompressed = util::LoadU32(res.ptr + 4);
    uint8_t  seed = res.ptr[12];

    Bytes payload(res.ptr + 13, res.ptr + res.size);
    crypto::Type98Decrypt(payload.data(), payload.size(), seed, password, version);
    out = compress::LzssDecompress(payload.data(), payload.size(), uncompressed);
    if (out.size() != uncompressed)
        util::Warn(name + ": output size mismatch (" + std::to_string(out.size()) + " of " + std::to_string(uncompressed) + ")");
    return true;
}

}  // namespace

bool ExtractType98(const Context& ctx) {
    const Bytes& data = *ctx.data;
    auto res = EnumAllResources(data);                       // resources of every PE image in the file
    if (FindPeImages(data).empty()) { util::Error("not a valid PE file"); return false; }

    int version = 1;
    Bytes productId;
    bool any = false;

    // --- Step 1: detect version from the CFG resource ---------------------
    if (auto cfgRaw = Load(data, res, "CFG"); cfgRaw && cfgRaw->size >= 8) {
        uint32_t v = util::LoadU32(cfgRaw->ptr + 4);        // the "uncompressed size" field
        if (v == 0x9E || v == 0x9F) version = 2;
        util::Info("Detected version: " + std::to_string(version));

        Bytes cfg;
        if (Unpack(*cfgRaw, "CFG", version, {}, cfg)) {
            any |= util::WriteFile(ctx.outDir / OutName("CFG"), cfg);

            size_t idOffset = (version == 2) ? 0x04 : 0x44;
            if (version == 1 && FindFoundResource(res, "BIN", "HD")) idOffset = 0x04;
            if (cfg.size() > idOffset + 64) {
                size_t len = 0;
                while (len < 64 && cfg[idOffset + len] != 0) ++len;
                productId.assign(cfg.begin() + idOffset, cfg.begin() + idOffset + len);
                util::Debug("Product ID (hex): " + util::HexBytes(productId));
            }
        }
    } else {
        util::Warn("CFG resource missing or invalid in the BIN resources.");
    }

    // --- Step 2: FD (floppy disks) ------------------------------------------
    if (auto fd = Load(data, res, "FD")) {
        Bytes fdData;
        if (Unpack(*fd, "FD", version, productId, fdData)) {
            util::Info("  -> Splitting FD archive...");
            size_t n = d88::SplitBundle(fdData, ctx.outDir);
            if (n == 0 || util::g_debug) util::WriteFile(ctx.outDir / OutName("FD"), fdData);
            any |= (n > 0);
        }
    }

    // --- Step 3: HD -----------------------------------------------------------
    if (auto hd = Load(data, res, "HD")) {
        Bytes out;
        if (Unpack(*hd, "HD", version, productId, out)) any |= util::WriteFile(ctx.outDir / OutName("HD"), out);
    }

    // --- Step 4: optional files (password = resource name) --------------------
    for (const char* name : {"FONT", "SOUND", "BIOS", "HH", "TOP", "SD", "BD", "TOM", "RIM"}) {
        auto r = Load(data, res, name);
        if (!r) continue;
        std::string s(name);
        Bytes pw(s.begin(), s.end());
        Bytes out;
        if (Unpack(*r, s, version, pw, out)) any |= output::Save(ctx.outDir, OutName(s), out);
    }
    if (!any) util::Error("no BIN resource could be decrypted and unpacked");
    return any;
}
