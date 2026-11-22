// MSXPLAYer (old) and D4E MSX: encrypted ROMs / disk images stored as PE resources
// (MSXPLAYer: SYSTEM, DRIVE, SLOT; D4E: FLOPPY, ROM). Port of egg_msx_decrypt.py.
#include "crypto.h"
#include "extractors.h"
#include "output.h"
#include "pe.h"
#include "platform.h"

namespace {

Bytes Decrypt(ByteSpan raw, int type) {
    if (type == 1) return crypto::MsxPlayerOldDecrypt(raw, ByteSpan(crypto::kMsxKeyOld, 16));
    return crypto::MsxD4eDecrypt(raw, ByteSpan(crypto::kMsxKeyD4e, 16));
}

// Resource folders holding the encrypted ROMs / disks.
//   MSXPLAYer (old): SYSTEM, DRIVE, SLOT     D4E MSX: FLOPPY, ROM
bool IsRomOrDiskFolder(const std::string& type, int variant) {
    if (variant == 1)
        return EqualsNoCase(type, "SYSTEM") || EqualsNoCase(type, "DRIVE") || EqualsNoCase(type, "SLOT");
    return EqualsNoCase(type, "FLOPPY") || EqualsNoCase(type, "ROM");
}

// Same rule as the Python tool: > 500,000 bytes => .dsk, otherwise .ROM.
std::string Extension(size_t plainSize) { return plainSize > 500000 ? ".dsk" : ".ROM"; }

}  // namespace

bool ExtractMsxResources(const Context& ctx, int type) {
    const Bytes& data = *ctx.data;
    if (FindPeImages(data).empty()) { util::Error("not a valid PE file"); return false; }

    util::Info(type == 1 ? "MSX decryption: MSXPLAYer (old)" : "MSX decryption: D4E");
    bool any = false;
    for (const FoundResource& found : EnumAllResources(data)) {
        const PeResource& r = found.res;
        if (!IsRomOrDiskFolder(r.type, type) || r.size == 0) continue;

        util::Info("Processing resource " + r.type + "/" + r.name + " (" + std::to_string(r.size) + " bytes)");
        Bytes plain = Decrypt(ByteSpan(data.data() + r.fileOffset, r.size), type);

        // numeric names (DRIVE/1, DRIVE/2, ...) become "DRIVE_1"; named ones lose their extension
        fs::path base = platform::PathFromUtf8(r.name).filename();
        std::string stem = r.nameIsId ? (r.type + "_" + r.name) : platform::PathToUtf8(base.stem());
        if (stem.empty()) stem = r.type + "_unnamed";

        output::Options opt;
        opt.genericName = r.nameIsId || r.name.empty();
        any |= output::Save(ctx.outDir, stem + Extension(plain.size()), plain, opt);
    }
    if (!any) {
        util::Error("no ROMs or disks are embedded in this file (the player probably loads external ROM files)");
        util::MarkNothingToExtract();
    }
    return any;
}
