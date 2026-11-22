// old_pc98_aes / old_pc98_no_aes: "BINARY" resources, optional AES-128-ECB, XOR-obfuscated size
// header, then LZH (port of egg_old_pc98_decrypt.cpp).
#include <algorithm>
#include <string_view>

#include "compress.h"
#include "crypto.h"
#include "extractors.h"
#include "output.h"
#include "pds.h"
#include "pe.h"
#include "platform.h"

namespace {

const uint8_t kAesKey[16] = {0xEA, 0x40, 0x68, 0x99, 0xC6, 0x78, 0x4B, 0x71,
                             0x28, 0xA9, 0x96, 0x88, 0x64, 0x6B, 0x3D, 0x00};

// The AES variant keeps its 16-byte key inside .rdata.
bool AesKeyInRdata(ByteSpan data, const std::vector<PeImage>& images) {
    for (const PeImage& img : images) {
        for (const auto& s : img.info.sections) {
            if (s.name != ".rdata") continue;
            uint64_t start = static_cast<uint64_t>(img.offset) + s.rawPtr;
            if (s.rawSize == 0 || start + s.rawSize > data.size()) continue;
            ByteSpan sec(data.data() + start, s.rawSize);
            if (util::FindBytes(sec, ByteSpan(kAesKey, 16)) != util::npos) return true;
        }
    }
    return false;
}

std::string Extension(std::string_view name) {
    auto starts = [&](std::string_view p) { return name.substr(0, p.size()) == p; };
    if (starts("CONF")) return ".txt";
    if (starts("DISK")) return ".pds";
    if (starts("LOGO")) return ".bmp";
    if (starts("HH") || starts("TOP") || starts("SD") || starts("BD") || starts("TOM") || starts("RIM")) return ".wav";
    return ".rom";
}

bool ProcessPayload(Bytes raw, const fs::path& dir, const std::string& baseName, const std::string& ext, bool useAes, bool invented) {
    if (useAes) crypto::Aes128(kAesKey).DecryptEcbInPlace(raw.data(), raw.size());

    if (raw.size() < 4) { util::Warn("Data too small for header."); return false; }
    uint32_t header = util::LoadU32(raw.data()) ^ 0x18885963u;
    if (header % 0x4D != 0) { util::Warn("Header validation failed (header % 0x4D != 0)."); return false; }
    uint32_t zsize = header / 0x4D;

    Bytes out;
    if (!compress::LzhDecompress(raw.data() + 4, raw.size() - 4, zsize, out))
        util::Warn("Decompression ended abruptly.");
    output::Options opt;
    opt.genericName = invented;
    if (!output::Save(dir, baseName + ext, out, opt)) return false;
    util::Info("  Extracted " + std::to_string(out.size()) + " bytes.");

    // floppy images ("pds\n" signature): also convert to D88 automatically
    if (ext == ".pds") {
        size_t n = pds::ConvertToD88(out, dir, baseName);
        util::Info("  Converted to " + std::to_string(n) + " D88 image(s).");
    }
    return true;
}

}  // namespace

bool ExtractOldPc98(const Context& ctx) {
    const Bytes& data = *ctx.data;
    auto images = FindPeImages(data);
    if (images.empty()) { util::Error("not a valid PE file"); return false; }

    bool useAes = AesKeyInRdata(data, images);
    util::Info(useAes ? "AES key found in .rdata: payloads are AES-encrypted" : "No AES key in .rdata: payloads are not AES-encrypted");

    bool any = false;
    for (const FoundResource& found : EnumAllResources(data)) {
        const PeResource& r = found.res;
        if (!EqualsNoCase(r.type, "BINARY") || r.size == 0) continue;
        util::Info("Processing resource: " + r.name + " (" + std::to_string(r.size) + " bytes)");
        Bytes raw(data.begin() + r.fileOffset, data.begin() + r.fileOffset + r.size);
        any |= ProcessPayload(std::move(raw), ctx.outDir, r.name, Extension(r.name), useAes, r.nameIsId);
    }
    if (!any) util::Error("no BINARY resource could be decoded (header validation or decompression failed)");
    return any;
}
