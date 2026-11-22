// pe.h - minimal, bounds-checked PE parser: headers, sections, resources.
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "common.h"

struct PeSection {
    std::string name;            // trailing NULs stripped
    uint32_t virtualSize    = 0;
    uint32_t virtualAddress = 0;
    uint32_t rawSize        = 0;
    uint32_t rawPtr         = 0;
};

struct PeInfo {
    size_t   mzOffset   = 0;
    size_t   peOffset   = 0;
    bool     pe32plus   = false;
    uint32_t timestamp  = 0;
    uint64_t imageBase  = 0;
    uint32_t rsrcRva    = 0;
    uint32_t rsrcSize   = 0;
    std::vector<PeSection> sections;
};

// Parse the PE image that starts at `mzOffset`. Returns false if headers are invalid.
bool ParsePe(ByteSpan data, PeInfo& out, size_t mzOffset = 0);

// RVA -> file offset using the section table (raw data only).
std::optional<size_t> RvaToFileOffset(const PeInfo& pe, uint32_t rva, size_t fileSize);

// Every "MZ" that is followed by a valid "PE\0\0" header (as lzss_extractor.py did).
struct PeLocation {
    size_t   mzOffset;
    uint32_t imageBase;
};
std::vector<PeLocation> FindAllPeHeaders(ByteSpan data);

// --- resources ---------------------------------------------------------
struct PeResource {
    std::string type;        // string name, or decimal id
    std::string name;        // string name, or decimal id
    bool        typeIsId = false;
    bool        nameIsId = false;
    uint16_t    lang     = 0;
    size_t      fileOffset = 0;
    uint32_t    size       = 0;
};

std::vector<PeResource> EnumResources(ByteSpan data, const PeInfo& pe);

// Case-insensitive lookup by type and name (first language match).
const PeResource* FindPeResource(const std::vector<PeResource>& all,
                                 std::string_view type, std::string_view name);
bool EqualsNoCase(std::string_view a, std::string_view b);

// --- files with embedded executables -----------------------------------------------------------
// Launchers often carry the real program as a second PE image (e.g. the emulator stored as a resource). These
// helpers look at every image in a file, the outer one first.
struct PeImage {
    size_t offset = 0;      // where the image starts in the file
    PeInfo info;            // parsed on its own: all offsets inside `info` are relative to `offset`
};
std::vector<PeImage> FindPeImages(ByteSpan data);

struct FoundResource {
    PeResource res;         // res.fileOffset is ABSOLUTE (relative to the whole file)
    size_t     imageIndex;  // index into FindPeImages()
};
std::vector<FoundResource> EnumAllResources(ByteSpan data);
const FoundResource* FindFoundResource(const std::vector<FoundResource>& all, std::string_view type, std::string_view name);

// File offset of the first embedded image after the outer one (0 if none); only accepts an e_lfanew in [0x40, 0x400).
size_t FindNestedPe(ByteSpan data);
