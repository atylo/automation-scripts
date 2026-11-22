#include "output.h"

#include <algorithm>

#include "crypto.h"
#include "platform.h"
#include "romdb.h"

namespace output {

namespace {

std::string Upper(std::string s) {
    for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

std::string StemOf(const std::string& name) {
    return platform::PathToUtf8(platform::PathFromUtf8(name).stem());
}

bool HasRomExtension(const std::string& name) {
    return Upper(platform::PathToUtf8(platform::PathFromUtf8(name).extension())) == ".ROM";
}

// "a, b, c" of the alternative names for debug output
std::string Alternatives(const std::vector<const romdb::Entry*>& all, const std::string& chosen) {
    std::string s;
    for (const romdb::Entry* e : all) {
        if (chosen == e->name) continue;
        if (!s.empty()) s += "; ";
        s += std::string(e->name) + " [" + e->system + "]";
        if (s.size() > 300) { s += " ..."; break; }
    }
    return s;
}

}  // namespace

bool IsBmp(ByteSpan d) {
    if (d.size() < 26 || d[0] != 'B' || d[1] != 'M') return false;
    uint32_t dibSize = util::LoadU32(&d[14]);
    bool knownDib = dibSize == 12 || dibSize == 40 || dibSize == 52 || dibSize == 56 || dibSize == 108 || dibSize == 124;
    uint32_t dataOffset = util::LoadU32(&d[10]);
    return knownDib && dataOffset >= 14 + dibSize && dataOffset < d.size();
}

std::string ResolveName(const std::string& desired, ByteSpan data, const Options& opt, std::string* reason) {
    auto note = [&](const std::string& s) { if (reason) *reason = s; };

    if (opt.bitmapRule && IsBmp(data)) {
        std::string out = (opt.genericName ? std::string("EGGLOGO") : StemOf(desired)) + ".bmp";
        if (out != desired) note(opt.genericName ? "bitmap signature, no proper name" : "bitmap signature");
        return out;
    }

    if (opt.identifyRom) {
        auto all = romdb::IdentifyAll(data);
        if (!all.empty()) {
            const romdb::Entry* e = romdb::Identify(data, opt.preferSystems);
            if (!e) {                                     // known ROM, but it has no conventional file name
                util::Debug("  " + desired + " is identified as: " + Alternatives(all, ""));
                return desired;
            }
            std::string alt = Alternatives(all, e->name);
            if (desired != e->name) note(std::string("known ROM: ") + e->system + (alt.empty() ? "" : "  | also: " + alt));
            else if (!alt.empty()) util::Debug("  " + desired + " is also known as: " + alt);
            return e->name;
        }
        if (util::g_debug && HasRomExtension(desired) && !data.empty()) {
            util::Debug("  ROM not in the database: " + desired + "  size " + std::to_string(data.size()) +
                        "  crc32 " + util::Hex(crypto::Crc32(data), 8) + "  md5 " + crypto::Md5Hex(data) +
                        "  sha1 " + crypto::Sha1Hex(data));
        }
    }
    return desired;
}

bool Save(const fs::path& dir, const std::string& desiredName, ByteSpan data, const Options& opt) {
    std::string reason;
    std::string finalName = ResolveName(desiredName, data, opt, &reason);
    if (!reason.empty()) util::Debug("  " + desiredName + " -> " + finalName + "  (" + reason + ")");
    fs::path out = util::UniquePath(dir / platform::PathFromUtf8(finalName).filename());
    bool ok = util::WriteFile(out, data.data(), data.size());

    // A ROM-like file that is not known as a whole: does it contain known ROMs?
    if (ok && opt.identifyRom && opt.splitContainers && finalName == desiredName && HasRomExtension(finalName) &&
        romdb::IdentifyAll(data).empty()) {
        auto parts = romdb::FindParts(data);
        size_t covered = 0;
        for (const auto& p : parts) covered += p.size;
        if (parts.size() >= 2 && covered * 2 >= data.size()) {
            fs::path partsDir = util::UniquePath(dir / platform::PathFromUtf8(StemOf(finalName) + "_parts"));
            std::error_code ec;
            fs::create_directories(partsDir, ec);
            util::Debug("  " + finalName + " contains " + std::to_string(parts.size()) + " known ROMs (" +
                        std::to_string(covered * 100 / data.size()) + "% of the file) -> " + util::PathToUtf8(partsDir));

            size_t cursor = 0;
            auto saveGap = [&](size_t end) {
                if (end > cursor) {
                    std::string n = "unknown_0x" + util::Hex(cursor) + ".bin";
                    util::WriteFile(util::UniquePath(partsDir / n), data.data() + cursor, end - cursor);
                }
            };
            for (const auto& p : parts) {
                saveGap(p.offset);
                util::Debug("    0x" + util::Hex(p.offset, 5) + "  " + std::to_string(p.size) + " bytes -> " + p.entry->name +
                            "  [" + p.entry->system + "]");
                util::WriteFile(util::UniquePath(partsDir / platform::PathFromUtf8(p.entry->name).filename()),
                                data.data() + p.offset, p.size);
                cursor = p.offset + p.size;
            }
            saveGap(data.size());
        }
    }
    return ok;
}

}  // namespace output
