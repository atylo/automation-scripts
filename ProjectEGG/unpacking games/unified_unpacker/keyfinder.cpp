#include "keyfinder.h"

#include <cstring>

#include "crypto.h"

namespace keyfinder {

namespace {

// The order matters: arranged by frequency of usage.
const char* const kPrefixes[] = {
    "COM", "FAL", "TAE", "TEL", "BOT", "SYS", "MIC", "XTA", "NCS", "KSK",
    "SAC", "HAM", "RIV", "GMD", "ART", "SNT", "KNM", "COS", "DBS", "CAR",
    "GAR", "MLC", "STW", "KUR", "MIL", "SKP", "JLC", "ATN", "EBS", "HOT",
    "IMX", "THR", "WIN", "ETG", "CBR", "FAM", "NTB", "SQE", "MCN", "PPD",
    "GNX", "PHA", "NIC", "ARS", "CBE", "FAS", "FUG", "KNK", "TIT", "SPS",
    "WDP", "ZOM", "BNE", "POP", "USE", "BPS", "GDA", "HOK", "TEH", "CBC",
    "HRZ", "HUD", "ISE", "TEN", "QSR", "RDM", "ROM", "RTG", "SCS", "TZG",
    "AGL", "BGT", "BRM", "CPM", "DMB", "DTM", "IPM", "KDK", "MEW", "MVC",
    "ONS", "ANM", "IRI", "MCV", "PON", "PSK", "TTK", "WCT"};

bool TryName(const uint8_t block[16], const char* name, size_t len) {
    static const uint8_t magic[6] = {0x44, 0x41, 0x54, 0x41, 0x01, 0x00};   // "DATA" 01 00
    auto key = crypto::EggConfigKey(std::string_view(name, len));
    uint8_t out[16];
    crypto::Aes128(key.data()).DecryptBlock(block, out);
    return std::memcmp(out, magic, sizeof(magic)) == 0;
}

}  // namespace

bool FindConfigName(const uint8_t firstBlock[16], std::string& nameOut) {
    if (TryName(firstBlock, "GAME", 4)) { nameOut = "GAME"; return true; }

    // "E" + 3-letter prefix + every 4-digit number 0000-9999, prefixes in order of frequency
    char cand[9] = "EAAA0000";
    for (const char* prefix : kPrefixes) {
        std::memcpy(cand + 1, prefix, 3);
        for (int n = 0; n <= 9999; ++n) {
            cand[4] = static_cast<char>('0' + n / 1000);
            cand[5] = static_cast<char>('0' + n / 100 % 10);
            cand[6] = static_cast<char>('0' + n / 10 % 10);
            cand[7] = static_cast<char>('0' + n % 10);
            if (TryName(firstBlock, cand, 8)) { nameOut = cand; return true; }
        }
    }
    return false;
}

}  // namespace keyfinder
