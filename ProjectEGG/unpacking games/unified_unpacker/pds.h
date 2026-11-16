// pds.h - PDS floppy image -> D88 conversion (port of pds2d88.py).
#pragma once

#include "common.h"

namespace pds {

// Converts every PDS disk found in `data` (a file may hold several, concatenated) and writes
// "<outDir>/<baseName>_<n>.d88". Returns the number of D88 files written (0 = no PDS signature).
size_t ConvertToD88(ByteSpan data, const fs::path& outDir, const std::string& baseName);

}  // namespace pds
