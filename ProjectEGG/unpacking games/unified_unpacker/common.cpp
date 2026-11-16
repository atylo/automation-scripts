#include "common.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <set>

#include "platform.h"

namespace util {

bool g_debug = false;

namespace { std::string g_lastError; bool g_nothingToExtract = false; }

void Print(std::string_view msg)    { std::cout << msg << '\n'; }
void PrintErr(std::string_view msg) { std::cerr << msg << '\n'; }
void Info(std::string_view msg)     { if (g_debug) std::cout << msg << '\n'; }
void Debug(std::string_view msg)    { if (g_debug) std::cout << msg << '\n'; }
void Warn(std::string_view msg)     { if (g_debug) std::cerr << "[!] " << msg << '\n'; }
void Error(std::string_view msg) {
    g_lastError = std::string(msg);
    if (g_debug) std::cerr << "[ERROR] " << msg << '\n';
}
const std::string& LastError() { return g_lastError; }
void ClearError() { g_lastError.clear(); g_nothingToExtract = false; }
void MarkNothingToExtract() { g_nothingToExtract = true; }
bool NothingToExtract() { return g_nothingToExtract; }

void RemoveDirIfEmpty(const fs::path& dir) {
    std::error_code ec;
    if (fs::is_directory(dir, ec) && fs::is_empty(dir, ec)) fs::remove(dir, ec);
}

std::string Hex(uint64_t value, int width) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%0*llX", width, static_cast<unsigned long long>(value));
    return buf;
}

std::string HexBytes(ByteSpan data, size_t limit) {
    std::string s;
    size_t n = (limit && limit < data.size()) ? limit : data.size();
    for (size_t i = 0; i < n; ++i) {
        if (i) s += ' ';
        s += Hex(data[i], 2);
    }
    return s;
}

std::string PathToUtf8(const fs::path& p) { return platform::PathToUtf8(p); }

bool ReadFile(const fs::path& path, Bytes& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize size = f.tellg();
    if (size < 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    if (size > 0 && !f.read(reinterpret_cast<char*>(out.data()), size)) return false;
    return true;
}

bool WriteFile(const fs::path& path, const uint8_t* data, size_t size) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        Warn("Could not create " + PathToUtf8(path));
        return false;
    }
    if (size) f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    if (!f) {
        Warn("Write failed for " + PathToUtf8(path));
        return false;
    }
    Info("  -> Saved " + PathToUtf8(path));
    return true;
}

namespace {
// Paths handed out by UniquePath() during this run (lower-cased: Windows file systems are case-insensitive).
std::set<std::string>& IssuedPaths() {
    static std::set<std::string> s;
    return s;
}
std::string Key(const fs::path& p) {
    std::string k = platform::PathToUtf8(p);
    for (char& c : k) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return k;
}
}  // namespace

fs::path UniquePath(const fs::path& desired) {
    auto& issued = IssuedPaths();
    if (issued.insert(Key(desired)).second) return desired;     // first use in this run (stale files get overwritten)
    fs::path stem = desired.stem();
    fs::path ext  = desired.extension();
    fs::path dir  = desired.parent_path();
    for (int i = 1; i < 100000; ++i) {
        fs::path candidate = dir / (stem.native() + fs::path("_" + std::to_string(i)).native() + ext.native());
        if (issued.insert(Key(candidate)).second) return candidate;
    }
    return desired;
}

bool PrepareOutputDir(const fs::path& input, fs::path& outDir) {
    std::error_code ec;
    fs::path abs = fs::absolute(input, ec);
    if (ec) abs = input;
    fs::path candidate = abs.parent_path() / abs.stem();
    if (fs::exists(candidate, ec) && !fs::is_directory(candidate, ec)) {
        candidate = abs.parent_path() / abs.stem();
        candidate += "_extracted";
    }
    fs::create_directories(candidate, ec);
    if (ec || !fs::is_directory(candidate, ec)) {
        Error("Could not create output folder " + PathToUtf8(candidate));
        return false;
    }
    outDir = candidate;
    return true;
}

size_t FindBytes(ByteSpan hay, ByteSpan needle, size_t from, size_t to) {
    if (to > hay.size()) to = hay.size();
    if (needle.empty() || from >= to || to - from < needle.size()) return npos;
    const uint8_t first = needle[0];
    const uint8_t* base = hay.data();
    const uint8_t* p    = base + from;
    const uint8_t* last = base + (to - needle.size());   // last valid start
    while (p <= last) {
        p = static_cast<const uint8_t*>(std::memchr(p, first, static_cast<size_t>(last - p) + 1));
        if (!p) return npos;
        if (std::memcmp(p, needle.data(), needle.size()) == 0) return static_cast<size_t>(p - base);
        ++p;
    }
    return npos;
}

size_t FindString(ByteSpan hay, std::string_view needle, size_t from, size_t to) {
    return FindBytes(hay, ByteSpan(reinterpret_cast<const uint8_t*>(needle.data()), needle.size()), from, to);
}

}  // namespace util
