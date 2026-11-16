// d88.h - D88 floppy image helpers (merged from ExtractFD / save_extracted_asset / validate_d88).
#pragma once

#include "common.h"

namespace d88 {

constexpr size_t kHeaderSize = 0x2B0;   // 0x20 header + 164 track offsets * 4

// Heuristic used on unknown assets: first disk size is plausible and track 0 starts at 0x2B0.
bool LooksLikeBundle(ByteSpan data);

// Splits a buffer of concatenated D88 disks into <outDir>/<disk name>.d88.
// Names come from the Shift-JIS disk-name field (fallback "Disk_N"); existing files are
// never overwritten (_1, _2, ... suffix). Returns the number of disks written.
size_t SplitBundle(ByteSpan data, const fs::path& outDir);

// File name for a disk image taken from its header name (Shift-JIS, sanitized; letters, digits, kana, kanji
// and "._- " are kept). `fallback` (without extension) is used when the header has no usable name.
fs::path SuggestFileName(ByteSpan disk, const std::string& fallback);

// Validation of a single, exactly-sized disk image.
struct Info {
    bool        valid = false;
    std::string name;       // header name, UTF-8 (best effort)
};
Info Validate(ByteSpan disk);

}  // namespace d88
