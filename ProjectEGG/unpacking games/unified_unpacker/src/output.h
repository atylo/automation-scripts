// output.h - the single place where extracted (non-disk) files are saved.
//
// Rules applied to whatever the extractors produce:
//   1. Bitmaps (recognized by their "BM" header, never by file name) get the ".bmp" extension. If the
//      extractor had to invent the name (Options::genericName, e.g. "asset_5D0D0_fallback"), the file
//      becomes "EGGLOGO.bmp"; files that already have a proper name keep it.
//   2. Anything whose size + hash matches the known-ROM database (romdb) gets the name of that ROM.
//   3. A ROM-like file that is not known as a whole but consists mostly of known ROMs (several ROMs
//      concatenated) is kept as it is, and the known parts are also written to "<name>_parts/".
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "common.h"

namespace output {

struct Options {
    bool identifyRom     = true;    // look the data up in the known-ROM database
    bool splitContainers = true;    // look for known ROMs inside ROM-like files
    bool bitmapRule      = true;    // apply the bitmap rule
    bool genericName     = false;   // the extractor made up the file name (no real name exists)
    std::vector<std::string_view> preferSystems;   // database names for these machines win (e.g. by TYPE60 mode)
};

// True if `data` starts with a plausible BMP header.
bool IsBmp(ByteSpan data);

// Final file name for `data` that an extractor wanted to call `desiredName` (no directory part).
// `reason` (optional) receives a short note when the name changed.
std::string ResolveName(const std::string& desiredName, ByteSpan data, const Options& opt = {},
                        std::string* reason = nullptr);

// ResolveName + collision handling + write (+ container parts). Returns true on success.
bool Save(const fs::path& dir, const std::string& desiredName, ByteSpan data, const Options& opt = {});

}  // namespace output
