// platform.h - the only place with OS-specific code (Windows target; stubs elsewhere so
// the portable parts can still be built and tested on other systems).
#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace platform {

void InitConsole();                                            // UTF-8 console output
std::vector<std::string> GetArgsUtf8(int argc, char** argv);   // full Unicode command line
std::filesystem::path PathFromUtf8(const std::string& s);
std::string PathToUtf8(const std::filesystem::path& p);

// Shift-JIS (CP932) -> UTF-16, invalid sequences are dropped.
std::wstring SjisToWide(const unsigned char* data, size_t len);
// True for letters/digits including kana and kanji (matches Python's str.isalnum()).
bool IsAlnumWide(wchar_t c);

}  // namespace platform
