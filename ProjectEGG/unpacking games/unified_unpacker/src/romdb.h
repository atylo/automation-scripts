// romdb.h - database of known system ROMs (names + hashes) for Japanese computers / MSX.
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "common.h"

namespace romdb {

struct Entry {
    const char* name;      // file name (or, for blueMSX entries, the ROM's title + ".rom")
    uint32_t    size;      // exact size in bytes; 0 = unknown / any
    uint32_t    crc32;     // 0 = not listed
    const char* md5;       // lower-case hex, nullptr = not listed
    const char* sha1;      // lower-case hex, nullptr = not listed
    const char* system;    // machine / source ("MAME: PC-8001", "blueMSX: ...", "NEC PC-6001", ...)
    bool        rename = true;  // false: only identifies the ROM (debug output); never used as a file name
};

// Every entry whose size and *all* listed hashes match `data`, in priority order (including entries that
// only identify the ROM and are never used as file names).
std::vector<const Entry*> IdentifyAll(ByteSpan data);

// The entry whose NAME to use for `data`: among the entries allowed to rename, the first whose `system` is one of
// `preferSystems` (exact match), otherwise the first in priority order. nullptr if there is none.
const Entry* Identify(ByteSpan data, const std::vector<std::string_view>& preferSystems = {});

// Known ROMs hiding inside a larger file (e.g. several ROMs concatenated into one resource).
struct Part {
    size_t       offset;
    size_t       size;
    const Entry* entry;                          // the name to use (see below)
    std::vector<const Entry*> alternatives;      // every database entry matching this slice
};
// Finds non-overlapping known ROMs at 1 KiB-aligned offsets. Intended for ROM-like files of 8-256 KiB.
// The same ROM is often listed under several machines; `entry` is taken from the one machine that explains
// the most parts, so the names of a set stay consistent.
std::vector<Part> FindParts(ByteSpan data);

size_t TableSize();

}  // namespace romdb
