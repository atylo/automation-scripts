// old_X1: scrambled D88 disk images stored back to back in the EXE (ROL + XOR with a position
// counter, no compression). Port of old_x1_extractor.py.
#include "crypto.h"
#include "d88.h"
#include "extractors.h"
#include "platform.h"

bool ExtractOldX1(const Context& ctx) {
    const Bytes& data = *ctx.data;
    if (data.size() < 0x40) { util::Error("file too small"); return false; }

    const std::string base = util::PathToUtf8(ctx.input.stem());
    size_t physical = 0;
    int diskCount = 0;
    const size_t searchLimit = data.size() - 0x20;

    while (physical < searchLimit) {
        bool found = false;

        // The virtual start (0-7) tells how far the key counter was advanced; try them all.
        for (uint32_t v = 0; v < 8 && !found; ++v) {
            auto at = [&](size_t i) { return crypto::X1DescrambleByte(data[physical + i], v + static_cast<uint32_t>(i)); };

            uint8_t media = at(0x1B);                                   // cheap early reject
            if (media != 0x00 && media != 0x10 && media != 0x20) continue;
            uint32_t diskSize = static_cast<uint32_t>(at(0x1C)) | (static_cast<uint32_t>(at(0x1D)) << 8) |
                                (static_cast<uint32_t>(at(0x1E)) << 16) | (static_cast<uint32_t>(at(0x1F)) << 24);
            if (!(diskSize >= 0x400 && diskSize < 4000000)) continue;

            // label sanity: 17 bytes, NULs ignored, printable ASCII or high bytes
            Bytes label;
            for (size_t i = 0; i < 17; ++i) {
                uint8_t b = at(i);
                if (b != 0) label.push_back(b);
            }
            bool printable = true;
            for (uint8_t b : label)
                if (!((b >= 32 && b <= 126) || b > 128)) { printable = false; break; }
            if (!printable) continue;
            if (physical + diskSize > data.size()) continue;

            ++diskCount;
            std::string name = platform::PathToUtf8(fs::path(platform::SjisToWide(label.data(), label.size())));
            if (name.empty()) name = "Disk_" + std::to_string(diskCount);
            util::Info("\n[+] Disk " + std::to_string(diskCount) + " found!");
            util::Info("    Physical offset: 0x" + util::Hex(physical));
            util::Info("    Virtual start:   0x" + util::Hex(v));
            util::Info("    Size:            " + std::to_string(diskSize) + " bytes");
            util::Info("    Label:           " + name);

            Bytes disk = crypto::X1Descramble(&data[physical], diskSize, v);
            fs::path out = util::UniquePath(ctx.outDir / d88::SuggestFileName(disk, base + "_disk" + std::to_string(diskCount)));
            util::WriteFile(out, disk);

            physical += diskSize;
            found = true;
        }
        if (!found) physical += 4;      // keep 4-byte alignment while searching
    }

    if (diskCount == 0) {
        util::Error("no disk images found");
        return false;
    }
    util::Info("\nFinished. Extracted " + std::to_string(diskCount) + " disks.");
    return true;
}
