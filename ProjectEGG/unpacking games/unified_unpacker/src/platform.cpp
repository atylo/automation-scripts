#include "platform.h"

#include <cwctype>
#ifndef _WIN32
#include <cerrno>
#include <iconv.h>
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "shell32.lib")
#endif
#endif

namespace platform {

namespace {
std::string FromU8(const std::u8string& s) { return std::string(s.begin(), s.end()); }
std::u8string ToU8(const std::string& s) { return std::u8string(s.begin(), s.end()); }
}  // namespace

std::string PathToUtf8(const std::filesystem::path& p) { return FromU8(p.u8string()); }
std::filesystem::path PathFromUtf8(const std::string& s) { return std::filesystem::path(ToU8(s)); }

#ifdef _WIN32

void InitConsole() { SetConsoleOutputCP(CP_UTF8); }

std::vector<std::string> GetArgsUtf8(int, char**) {
    std::vector<std::string> out;
    int n = 0;
    LPWSTR* w = CommandLineToArgvW(GetCommandLineW(), &n);
    if (!w) return out;
    for (int i = 0; i < n; ++i) {
        int len = WideCharToMultiByte(CP_UTF8, 0, w[i], -1, nullptr, 0, nullptr, nullptr);
        std::string s(len > 0 ? static_cast<size_t>(len - 1) : 0, '\0');
        if (len > 1) WideCharToMultiByte(CP_UTF8, 0, w[i], -1, s.data(), len, nullptr, nullptr);
        out.push_back(std::move(s));
    }
    LocalFree(w);
    return out;
}

std::wstring SjisToWide(const unsigned char* data, size_t len) {
    if (len == 0) return {};
    int n = MultiByteToWideChar(932, 0, reinterpret_cast<LPCCH>(data), static_cast<int>(len), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(932, 0, reinterpret_cast<LPCCH>(data), static_cast<int>(len), w.data(), n);
    return w;
}

bool IsAlnumWide(wchar_t c) {
    WORD type = 0;
    if (!GetStringTypeW(CT_CTYPE1, &c, 1, &type)) return false;
    return (type & (C1_ALPHA | C1_DIGIT)) != 0;
}

#else  // ---- non-Windows stubs (testing only) ----

void InitConsole() {}

std::vector<std::string> GetArgsUtf8(int argc, char** argv) {
    std::vector<std::string> out;
    for (int i = 0; i < argc; ++i) out.emplace_back(argv[i]);
    return out;
}

std::wstring SjisToWide(const unsigned char* data, size_t len) {
    std::wstring w;
    iconv_t cd = iconv_open("WCHAR_T", "CP932");
    if (cd == reinterpret_cast<iconv_t>(-1)) {                            // no converter: ASCII only
        for (size_t i = 0; i < len; ++i) if (data[i] < 0x80) w.push_back(static_cast<wchar_t>(data[i]));
        return w;
    }
    char* in = reinterpret_cast<char*>(const_cast<unsigned char*>(data));
    size_t inLeft = len;
    while (inLeft > 0) {
        wchar_t buf[64];
        char* out = reinterpret_cast<char*>(buf);
        size_t outLeft = sizeof(buf);
        size_t r = iconv(cd, &in, &inLeft, &out, &outLeft);
        w.append(buf, (sizeof(buf) - outLeft) / sizeof(wchar_t));
        if (r == static_cast<size_t>(-1) && errno != E2BIG) { ++in; --inLeft; }   // invalid byte: skip it
    }
    iconv_close(cd);
    return w;
}

bool IsAlnumWide(wchar_t c) { return c < 0x80 && std::iswalnum(static_cast<wint_t>(c)); }

#endif

}  // namespace platform
