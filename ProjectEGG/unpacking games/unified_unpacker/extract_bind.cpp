// "BIND" archives (signature 42 49 4E 44). Port of bind_unpacker.cpp: header, file table and
// metadata are obfuscated with a session key derived from an 8-byte project id.
#include <algorithm>
#include <cctype>
#include <stdexcept>

#include "crypto.h"
#include "extractors.h"
#include "output.h"
#include "platform.h"

namespace {

using crypto::rol32;
using crypto::ror32;

class BindArchive {
public:
    explicit BindArchive(const Bytes& raw) : raw_(raw) {}

    void DeriveHeader() {
        if (raw_.size() < 40) throw std::runtime_error("File too small to contain a valid header.");

        // 1. project id & session key
        std::string projectId;
        for (int i = 0; i < 8; ++i) projectId += static_cast<char>(((raw_[8 + i] + 119) ^ (51 * i)) & 0xFF);

        uint32_t v2 = 0, v3 = 0;
        for (char c : projectId) {
            uint32_t val = static_cast<uint8_t>(c);
            v2 = val + 16 * v2;
            v3 += val;
        }
        sessionKey_ = ror32(v2 - 2083412177u, (v3 + 61) % 32);

        // 2. the table integers (raw_hdr[5] is reserved / checksum)
        uint32_t h[6];
        std::memcpy(h, &raw_[16], sizeof(h));
        hdr_.tableOff = rol32(h[0], 7)  - Factor(11) + 0x4CBD70AAu;
        hdr_.tableSz  = rol32(h[1], 15) - Factor(13) + 0x68CC8AEEu;
        hdr_.metaOff  = rol32(h[2], 9)  - Factor(15) - 0x7F61DB27u;
        hdr_.metaSz   = rol32(h[3], 19) - Factor(17) + 0x12BDD8CFu;
        hdr_.dataOff  = rol32(h[4], 27) - Factor(19) + 0x56E54C39u;

        util::Debug("Project ID:      " + projectId);
        util::Debug("Session key:     0x" + util::Hex(sessionKey_, 8));
        util::Debug("Table offset:    0x" + util::Hex(hdr_.tableOff) + "  size 0x" + util::Hex(hdr_.tableSz));
        util::Debug("Metadata offset: 0x" + util::Hex(hdr_.metaOff) + "  size 0x" + util::Hex(hdr_.metaSz));
        util::Debug("Data offset:     0x" + util::Hex(hdr_.dataOff));
        ready_ = true;
    }

    size_t Unpack(const fs::path& outDir) {
        if (!ready_) throw std::runtime_error("DeriveHeader() must be called before Unpack()");
        std::error_code ec;
        fs::create_directories(outDir, ec);

        size_t written = 0;
        uint32_t numFiles = hdr_.tableSz / 16;
        for (uint32_t i = 0; i < numFiles; ++i) {
            // 1. file table entry
            uint64_t tPos = static_cast<uint64_t>(hdr_.tableOff) + static_cast<uint64_t>(i) * 16;
            if (tPos + 16 > raw_.size()) continue;

            uint32_t d[4];                       // d[3] is reserved / unknown
            std::memcpy(d, &raw_[tPos], 16);
            uint32_t idx = i * 4;

            uint32_t mPtr = rol32(d[0], (idx + 73) % 32) + idx - Factor(idx) + 0x660BCDDBu;
            uint32_t fOff = rol32(d[1], (idx + 1 + 85) % 32) + (idx + 1) - Factor(idx + 1) + 0x48219C77u;
            uint32_t fSz  = rol32(d[2], (idx + 2 + 19) % 32) + (idx + 2) - Factor(idx + 2) + 0x357712D9u;

            // 2. metadata entry (12 bytes: obfuscated file name)
            uint64_t mPos = static_cast<uint64_t>(hdr_.metaOff) + mPtr;
            if (mPos + 12 > raw_.size()) continue;
            if (static_cast<uint64_t>(mPtr) + 12 > hdr_.metaSz) continue;

            std::string name = DecryptName(&raw_[mPos], 12);

            // keep at most 3 characters after the last dot (e.g. ".bmp")
            size_t dot = name.find_last_of('.');
            if (dot != std::string::npos && name.length() > dot + 4) name = name.substr(0, dot + 4);

            // 3. data
            uint64_t dPos = static_cast<uint64_t>(hdr_.dataOff) + fOff;
            Bytes clean;
            if (fSz > 0 && dPos + fSz <= raw_.size()) clean = Descramble(&raw_[dPos], fSz);

            util::Debug("FILE " + std::to_string(i) + ": " + name + "  table@0x" + util::Hex(tPos) + "  data@0x" +
                        util::Hex(dPos) + "  size " + std::to_string(fSz) + "  peek " +
                        (clean.empty() ? std::string("00 00 00 00") : util::HexBytes(clean, 4)));

            std::string safe;
            for (char c : name) {
                unsigned char u = static_cast<unsigned char>(c);
                if (std::isalnum(u) || c == '.' || c == '_' || c == '-' || c == ' ') safe += c;
            }
            bool invented = safe.empty();
            if (invented) safe = "file_" + std::to_string(i) + ".bin";

            if (clean.empty()) {
                util::Warn("Skipping empty or out-of-range file: " + name);
                continue;
            }
            output::Options opt;
            opt.genericName = invented;
            if (output::Save(outDir, safe, clean, opt)) ++written;
        }
        return written;
    }

private:
    const Bytes& raw_;
    uint32_t sessionKey_ = 0;
    bool ready_ = false;
    struct Header { uint32_t tableOff, tableSz, metaOff, metaSz, dataOff; } hdr_{};

    uint32_t Factor(uint32_t a2) const { return ror32(sessionKey_, (a2 + 17) % 32); }

    std::string DecryptName(const uint8_t* p, size_t n) const {
        std::string name;
        for (size_t i = 0; i < n; ++i) {
            uint8_t rotated = crypto::rol8(p[i], static_cast<unsigned>((i + 3) % 8));
            // NOTE: plain ror32 here, NOT Factor() (which adds 17)
            uint8_t subkey = static_cast<uint8_t>(ror32(sessionKey_, static_cast<uint32_t>((i + 34) % 32)) & 0xFF);
            uint8_t res = static_cast<uint8_t>(rotated - subkey);
            if (res != 0) name += static_cast<char>(res);
        }
        return name;
    }

    Bytes Descramble(const uint8_t* data, uint32_t fileSize) const {
        Bytes out(fileSize);
        uint32_t param2 = fileSize;
        uint32_t iVar5 = param2 + 0x61;
        for (size_t i = 0; i < fileSize; ++i) {
            uint8_t subkey = static_cast<uint8_t>(Factor(iVar5 - 0x4a) & 0xFF);
            uint8_t bSub = static_cast<uint8_t>(data[i] - subkey);
            uint8_t rotated = crypto::rol8(bSub, iVar5 % 8);
            out[i] = static_cast<uint8_t>(rotated + param2 - 0x23);
            --param2;
            --iVar5;      // intentional unsigned wrap-around
        }
        return out;
    }
};

}  // namespace

bool ExtractBind(const Context& ctx) {
    try {
        BindArchive archive(*ctx.data);
        archive.DeriveHeader();
        size_t n = archive.Unpack(ctx.outDir);
        util::Info("Extracted " + std::to_string(n) + " files.");
        if (n == 0) util::Error("the archive contains no extractable files (unknown or damaged BIND archive)");
        return n > 0;
    } catch (const std::exception& e) {
        util::Error(e.what());
        return false;
    }
}
