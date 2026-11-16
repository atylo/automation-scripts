#include "detect.h"

#include <cctype>
#include <cstring>
#include <ctime>

#include "crypto.h"

const char* TypeTag(GameType t) {
    switch (t) {
        case GameType::EggData:      return "EGGDATA";
        case GameType::Type98:       return "TYPE98";
        case GameType::Type98Old:    return "TYPE98_old";
        case GameType::MsxPlayerOld: return "MSXPLAYer";
        case GameType::MsxD4e:       return "D4E MSX";
        case GameType::EggMsx:       return "EGGMSX";
        case GameType::DataFileVer:  return "DataFileVer";
        case GameType::OldPc98Aes:   return "old_pc98_aes";
        case GameType::OldPc98NoAes: return "old_pc98_no_aes";
        case GameType::Type60:       return "TYPE60";
        case GameType::OldXorLzss:   return "old Xor + LZSS";
        case GameType::OldX1:        return "old_X1";
        case GameType::Bind:         return "BIND";
        case GameType::Scn:          return "SCN";
    }
    return "?";
}

bool HasExtractor(GameType t) { return t != GameType::EggMsx; }

namespace {

// --- search configuration (identical to the checker) -------------------
const uint8_t kD4eSequence[]  = {0x33, 0x53, 0x93, 0x63, 0xA3, 0xC3, 0x35, 0x55, 0x95, 0x65, 0xA5, 0xC5, 0x36, 0x56, 0x96, 0x66};
const uint8_t kXorLzss[]      = {0xB3, 0xA5, 0xAC, 0xAC};
const uint8_t kOldX1[]        = {0x10, 0x88, 0x84, 0x62, 0x41, 0xA8, 0x58, 0x2E, 0x18, 0x8C};
const uint8_t kPc98AesUtf8[]  = {0xC3, 0x86, 0x78, 0x4B, 0x71, 0x28, 0xC2, 0xA9};   // "ÆxKq(©" as UTF-8
const uint8_t kPc98AesLatin[] = {0xC6, 0x78, 0x4B, 0x71, 0x28, 0xA9};               // "ÆxKq(©" as Latin-1

struct Term {
    const char* text;
    GameType    type;
};
// Order matters only for how tags are listed.
const Term kTerms[] = {
    {"EGGDATA", GameType::EggData},
    {"TYPE98", GameType::Type98},
    {"MSXPLAYer", GameType::MsxPlayerOld},
    {nullptr, GameType::OldPc98Aes},            // the "ÆxKq(©" entry
    {"DataFileVer", GameType::DataFileVer},
    {"EGGMSX", GameType::EggMsx},
};

template <size_t N>
ByteSpan Span(const uint8_t (&a)[N]) { return ByteSpan(a, N); }

bool Has(ByteSpan d, std::string_view s) { return util::FindString(d, s) != util::npos; }

}  // namespace

Detection Detect(const Bytes& bytes) {
    Detection det;
    ByteSpan d(bytes);
    det.md5  = crypto::Md5Hex(d);
    det.date = "No valid timestamp";

    if (d.size() >= 4 && std::memcmp(d.data(), "BIND", 4) == 0) {      // 42 49 4E 44
        det.isBind = true;
        det.tags.push_back("BIND");
        det.types.push_back(GameType::Bind);
        return det;
    }
    if (d.size() < 2 || d[0] != 'M' || d[1] != 'Z') {
        if (d.size() > 17 && std::memcmp(d.data(), "SCN\0", 4) == 0) {       // 53 43 4E 00
            det.tags.push_back("SCN");
            det.types.push_back(GameType::Scn);
        }
        return det;
    }
    det.isPe = true;

    // --- 1. timestamp & PE offset -------------------------------------
    size_t peOffset = 0;
    {
        uint32_t off = 0, ts = 0;
        if (util::ReadU32(d, 0x3C, off)) {
            peOffset = off;
            if (util::ReadU32(d, peOffset + 8, ts) && ts > 0 && ts < 4102444800u) {
                std::time_t t = static_cast<std::time_t>(ts);
                std::tm tmv{};
#ifdef _WIN32
                localtime_s(&tmv, &t);
#else
                localtime_r(&t, &tmv);
#endif
                char buf[16];
                std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tmv);
                det.date = buf;
            }
        }
    }

    // --- 2. text tags -------------------------------------------------
    for (const Term& term : kTerms) {
        size_t pos = util::npos, len = 0;
        if (term.text) {
            pos = util::FindString(d, term.text);
            len = std::strlen(term.text);
        } else {
            pos = util::FindBytes(d, Span(kPc98AesUtf8));
            len = sizeof(kPc98AesUtf8);
            if (pos == util::npos) {
                pos = util::FindBytes(d, Span(kPc98AesLatin));
                len = sizeof(kPc98AesLatin);
            }
        }
        if (pos == util::npos) continue;

        det.types.push_back(term.type);
        if (term.type == GameType::OldPc98Aes) {
            det.tags.push_back("old_pc98_aes");
        } else if (term.type == GameType::DataFileVer) {
            det.tags.push_back("DataFileVer");
            if (pos + len < d.size()) {
                unsigned char c = d[pos + len];
                std::string v = "Version ";
                v += std::isprint(c) ? std::string(1, static_cast<char>(c)) : "0x" + util::Hex(c, 2);
                det.tags.push_back(v);
            } else {
                det.tags.push_back("Version Unknown");
            }
        } else {
            det.tags.push_back(term.text);
        }
    }

    // --- 2b. D4E MSX hex signature --------------------------------------
    if (util::FindBytes(d, Span(kD4eSequence)) != util::npos) {
        det.tags.push_back("D4E MSX");
        det.types.push_back(GameType::MsxD4e);
    }

    // --- 3. fallbacks (only when nothing was found so far) ---------------
    auto none = [&] { return det.tags.empty(); };
    auto add  = [&](GameType t, const char* tag) { det.tags.push_back(tag); det.types.push_back(t); };

    if (none() && Has(d, "CFG") && Has(d, "BIN")) add(GameType::Type98Old, "TYPE98_old");
    if (none()) {
        if (Has(d, "CONFIG") && Has(d, "BIN") && Has(d, "STATE")) add(GameType::Type60, "TYPE60");
        if (none() && Has(d, "BINARY") && Has(d, "CONF")) add(GameType::OldPc98NoAes, "old_pc98_no_aes");
        if (none() && util::FindBytes(d, Span(kXorLzss)) != util::npos) add(GameType::OldXorLzss, "old Xor + LZSS");
        if (none() && util::FindBytes(d, Span(kOldX1)) != util::npos) add(GameType::OldX1, "old_X1");

        // 3f. section details, informational only
        if (none() && peOffset > 0) {
            uint16_t numSections = 0, optSize = 0;
            if (util::ReadU16(d, peOffset + 6, numSections) && util::ReadU16(d, peOffset + 20, optSize)) {
                size_t table = peOffset + 24 + optSize;
                std::string warn;
                auto addWarn = [&](const std::string& w) { warn += (warn.empty() ? "" : ", ") + w; };
                for (uint16_t i = 0; i < numSections; ++i) {
                    size_t so = table + static_cast<size_t>(i) * 40;
                    if (so > d.size() || d.size() - so < 40) break;
                    std::string name(reinterpret_cast<const char*>(&d[so]), 8);
                    while (!name.empty() && name.back() == '\0') name.pop_back();
                    uint32_t vSize = util::LoadU32(&d[so + 8]);
                    uint32_t rSize = util::LoadU32(&d[so + 16]);
                    if ((name == ".text" || name == ".data" || name == ".rdata") && vSize > rSize)
                        addWarn(name + " big virtual size");
                    if ((name == ".text" || name == ".rdata") && rSize > 400000) addWarn(name + " > 400KB");
                }
                if (!warn.empty()) det.noneSuffix = " (" + warn + ")";
            }
        }
    }
    return det;
}

std::string FormatLine(const std::string& fileName, const Detection& d) {
    std::string tags;
    if (d.tags.empty()) {
        tags = " | Type: None" + d.noneSuffix;
    } else {
        tags = " | Type: ";
        for (size_t i = 0; i < d.tags.size(); ++i) tags += (i ? ", " : "") + d.tags[i];
    }
    return fileName + " | " + d.md5 + " | " + d.date + tags;
}
