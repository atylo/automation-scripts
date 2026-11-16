// common.h - shared helpers: logging, file I/O, byte searching, little-endian readers.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cctype>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
using Bytes    = std::vector<uint8_t>;
using ByteSpan = std::span<const uint8_t>;

namespace util {

inline constexpr size_t npos = static_cast<size_t>(-1);

// --- logging -----------------------------------------------------------
// Normal runs print only the final summary (Print / PrintErr). Everything else is verbose
// output that appears only with --debug.
extern bool g_debug;
void Print(std::string_view msg);     // always (stdout)
void PrintErr(std::string_view msg);  // always (stderr)
void Info(std::string_view msg);      // --debug only: progress
void Debug(std::string_view msg);     // --debug only: details
void Warn(std::string_view msg);      // --debug only: non-fatal problems
void Error(std::string_view msg);     // records the failure reason (see LastError); printed with --debug
const std::string& LastError();
// For recognized files that simply contain nothing to extract (not a failure): see main().
void MarkNothingToExtract();
bool NothingToExtract();
void ClearError();
void RemoveDirIfEmpty(const fs::path& dir);

std::string Hex(uint64_t value, int width = 0);          // upper-case, no prefix
std::string HexBytes(ByteSpan data, size_t limit = 0);   // "AA BB CC"
std::string PathToUtf8(const fs::path& p);

// --- files -------------------------------------------------------------
bool ReadFile(const fs::path& path, Bytes& out);
bool WriteFile(const fs::path& path, const uint8_t* data, size_t size);   // logs "-> Saved"
inline bool WriteFile(const fs::path& path, const Bytes& data) {
    return WriteFile(path, data.data(), data.size());
}
// Returns `desired` the first time it is requested in this run, then "stem_1.ext", "stem_2.ext", ...
// (so two outputs of one run never collide, but re-running simply overwrites the previous results).
fs::path UniquePath(const fs::path& desired);
// Output folder = "<input folder>/<input stem>" (created). If a *file* of that name
// already exists, "<stem>_extracted" is used instead.
bool PrepareOutputDir(const fs::path& input, fs::path& outDir);

// --- searching ---------------------------------------------------------
// Find `needle` in hay[from, to). Returns npos if absent.
size_t FindBytes(ByteSpan hay, ByteSpan needle, size_t from = 0, size_t to = npos);
size_t FindString(ByteSpan hay, std::string_view needle, size_t from = 0, size_t to = npos);

// --- little-endian access (bounds-checked variants return false) --------
inline uint16_t LoadU16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}
inline uint32_t LoadU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline bool ReadU16(ByteSpan d, size_t off, uint16_t& v) {
    if (off > d.size() || d.size() - off < 2) return false;
    v = LoadU16(d.data() + off);
    return true;
}
inline bool ReadU32(ByteSpan d, size_t off, uint32_t& v) {
    if (off > d.size() || d.size() - off < 4) return false;
    v = LoadU32(d.data() + off);
    return true;
}

}  // namespace util
