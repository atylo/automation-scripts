#include "d88.h"

#include <cstring>
#include <cwctype>

#include "platform.h"

namespace d88 {

namespace {

// Disk name = first 25 bytes up to NUL (the standard field is 17 bytes, but longer names exist).
std::wstring HeaderNameWide(const uint8_t* disk) {
    size_t n = 0;
    while (n < 25 && disk[n] != 0) ++n;
    return platform::SjisToWide(disk, n);
}

std::wstring Trim(const std::wstring& s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == L' ' || s[b] == L'\t' || s[b] == 0x3000)) ++b;
    while (e > b && (s[e - 1] == L' ' || s[e - 1] == L'\t' || s[e - 1] == 0x3000)) --e;
    return s.substr(b, e - b);
}

// A valid Windows file name: everything is kept (brackets, kana, symbols...) except the characters Windows forbids
// (\\ / : * ? " < > | and control characters), which become '_'. Trailing dots/spaces are removed and reserved
// device names (CON, NUL, COM1...) get a '_' suffix.
std::wstring Sanitize(const std::wstring& s) {
    std::wstring out;
    for (wchar_t c : s) {
        bool invalid = c < 0x20 || c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?' || c == L'"' ||
                       c == L'<' || c == L'>' || c == L'|';
        out.push_back(invalid ? L'_' : c);
    }
    while (!out.empty() && (out.back() == L'.' || out.back() == L' ')) out.pop_back();
    std::wstring up = out;
    for (wchar_t& c : up) if (c < 0x80) c = static_cast<wchar_t>(std::towupper(c));
    static const wchar_t* reserved[] = {L"CON", L"PRN", L"AUX", L"NUL", L"COM1", L"COM2", L"COM3", L"COM4", L"COM5",
                                        L"COM6", L"COM7", L"COM8", L"COM9", L"LPT1", L"LPT2", L"LPT3", L"LPT4",
                                        L"LPT5", L"LPT6", L"LPT7", L"LPT8", L"LPT9"};
    for (const wchar_t* r : reserved) if (up == r) { out += L'_'; break; }
    return out;
}

std::string WideToUtf8(const std::wstring& w) {
    return platform::PathToUtf8(fs::path(w));
}

}  // namespace

fs::path SuggestFileName(ByteSpan disk, const std::string& fallback) {
    std::wstring name;
    if (disk.size() >= 25) name = Sanitize(Trim(HeaderNameWide(disk.data())));
    if (name.empty()) name = platform::PathFromUtf8(fallback).wstring();
    return fs::path(name + L".d88");
}

bool LooksLikeBundle(ByteSpan data) {
    if (data.size() < kHeaderSize) return false;
    uint32_t diskSize = util::LoadU32(&data[0x1C]);
    uint32_t track0   = util::LoadU32(&data[0x20]);
    return diskSize >= kHeaderSize && diskSize <= data.size() && track0 == kHeaderSize;
}

size_t SplitBundle(ByteSpan data, const fs::path& outDir) {
    size_t offset = 0;
    size_t count  = 0;
    while (offset + kHeaderSize <= data.size()) {
        uint32_t diskSize = util::LoadU32(&data[offset + 0x1C]);
        if (diskSize < kHeaderSize || offset + diskSize > data.size()) break;

        std::wstring name = Sanitize(Trim(HeaderNameWide(&data[offset])));
        if (name.empty()) name = L"Disk_" + std::to_wstring(count + 1);

        fs::path out = util::UniquePath(outDir / fs::path(name + L".d88"));
        if (util::WriteFile(out, &data[offset], diskSize)) ++count;
        offset += diskSize;
    }
    return count;
}

Info Validate(ByteSpan disk) {
    Info info;
    if (disk.size() < kHeaderSize) return info;
    info.name = WideToUtf8(Trim(HeaderNameWide(disk.data())));

    uint32_t diskSize   = util::LoadU32(&disk[0x1C]);
    uint32_t firstTrack = util::LoadU32(&disk[0x20]);
    if (diskSize != disk.size()) return info;
    if (firstTrack != 0 && firstTrack < kHeaderSize) return info;
    info.valid = true;
    return info;
}

}  // namespace d88
