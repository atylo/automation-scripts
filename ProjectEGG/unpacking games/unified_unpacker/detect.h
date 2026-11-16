// detect.h - game/packer type detection (port of check_exe_hash_time_gametype.py).
#pragma once

#include <string>
#include <vector>

#include "common.h"

enum class GameType {
    EggData,
    Type98,
    Type98Old,
    MsxPlayerOld,    // tag "MSXPLAYer"
    MsxD4e,          // tag "D4E MSX"
    EggMsx,          // detected only - no extractor yet
    DataFileVer,
    OldPc98Aes,
    OldPc98NoAes,
    Type60,          // detected only - no extractor yet
    OldXorLzss,
    OldX1,
    Bind,            // standalone archive, signature "BIND"
    Scn,             // .SCN file, signature "SCN\0"
};

const char* TypeTag(GameType t);          // same wording the checker prints
bool        HasExtractor(GameType t);

struct Detection {
    bool        isPe   = false;
    bool        isBind = false;
    std::string md5;                      // whole-file MD5, lower-case hex
    std::string date;                     // YYYY-MM-DD or "No valid timestamp"
    std::vector<std::string> tags;        // exactly as the checker lists them (incl. "Version N")
    std::vector<GameType>    types;       // one entry per detected type
    std::string noneSuffix;               // " (.text big virtual size, ...)" when nothing was found
};

Detection Detect(const Bytes& data);

// "name | md5 | date | Found: a, b"  (the checker's output line)
std::string FormatLine(const std::string& fileName, const Detection& d);
