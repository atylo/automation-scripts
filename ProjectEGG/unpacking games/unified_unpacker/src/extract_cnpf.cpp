// CNPF containers: game EXEs and other files packed into one archive (port of CNPF_archive_reader.py).
//
//   header (20): "CNPF", version (4 chars, e.g. VR02 / VR05 / VR06 / VR07 / VRB5), archive size, end of manifest, file count
//   manifest   : comma separated, Shift-JIS: file names only, or "name,attribute," pairs
//   entries    : [compression u8][type u8][payload size u32]            (VR06: [comp][type][3 bytes][size])
//                compression 1 = LZSS: payload starts with the decompressed size (u32), then the LZSS stream
//
// The version label is NOT reliable (archives labelled VR02 exist with and without attributes), so both
// the manifest layout and the entry-header size are decided from the data; the version is only a hint.
#include <algorithm>
#include <set>

#include "compress.h"
#include "extractors.h"
#include "output.h"
#include "platform.h"

namespace {

const char* TypeName(unsigned t) {
    static const char* names[] = {"MAINEXE", "README", "KYODAKU", "DATA", "MANUAL", "SUBEXE", "MATCHEXE", "MP3", "CHILDEXE",
                                  "LOCKBIN", "SETUPEXE", "STARTEXE", "EMDSOUND", "MSXROMIMG", "SCENARIO_SCN", "COMPILESTATION"};
    return t < sizeof(names) / sizeof(names[0]) ? names[t] : "unknown";
}

// Fields are split on ',' and empty fields are kept (an empty attribute must not shift the pairs); the empty
// field that a closing comma leaves at the end is dropped.
std::vector<std::wstring> SplitManifest(const std::wstring& text) {
    std::vector<std::wstring> items;
    std::wstring cur;
    for (wchar_t c : text) {
        if (c == L',') { items.push_back(cur); cur.clear(); }
        else if (c != L'\0') cur.push_back(c);
    }
    if (!cur.empty()) items.push_back(cur);          // text without a closing comma
    return items;
}

// Do `fileCount` entries with `headerSize`-byte headers, starting at `start`, end exactly at `end`?
bool EntriesFit(const Bytes& d, size_t start, uint32_t fileCount, size_t headerSize, size_t end) {
    size_t pos = start;
    for (uint32_t i = 0; i < fileCount; ++i) {
        if (pos + headerSize > d.size()) return false;
        uint32_t size = util::LoadU32(&d[pos + headerSize - 4]);
        pos += headerSize;
        if (size > d.size() - pos) return false;
        pos += size;
    }
    return pos == end;
}

// Manifest path ("DIR\NAME.EXE") -> relative path that cannot leave the output folder, or empty if unusable.
fs::path SafeRelativePath(const std::wstring& manifestName) {
    fs::path result;
    std::wstring part;
    auto flush = [&]() -> bool {
        if (part.empty() || part == L".") { part.clear(); return true; }
        if (part == L"..") return false;                                   // would escape the folder
        for (wchar_t& c : part)
            if (c < 0x20 || c == L':' || c == L'*' || c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|') c = L'_';
        while (!part.empty() && (part.back() == L'.' || part.back() == L' ')) part.pop_back();
        if (part.empty()) part = L"_";
        result /= fs::path(part);
        part.clear();
        return true;
    };
    for (wchar_t c : manifestName) {
        if (c == L'\\' || c == L'/') { if (!flush()) return {}; }
        else part.push_back(c);
    }
    if (!flush()) return {};
    return result;
}

}  // namespace

bool ExtractCnpf(const Context& ctx) {
    const Bytes& d = *ctx.data;
    if (d.size() < 20 || std::memcmp(d.data(), "CNPF", 4) != 0) { util::Error("not a CNPF archive"); return false; }

    std::string ver(reinterpret_cast<const char*>(&d[4]), 4);
    uint32_t archSize = util::LoadU32(&d[8]), manifEnd = util::LoadU32(&d[12]), fileCount = util::LoadU32(&d[16]);
    bool vr06 = ver.find("VR06") != std::string::npos;      // hints only
    bool vr02 = ver.find("VR02") != std::string::npos;
    util::Debug("CNPF version " + ver + ", archive size " + std::to_string(archSize) + ", " + std::to_string(fileCount) + " files");
    if (ver.compare(0, 2, "VR") != 0) util::Warn("unknown version label \"" + ver + "\"");
    if (archSize != d.size())
        util::Warn("the archive size field (" + std::to_string(archSize) + ") differs from the file size (" + std::to_string(d.size()) + ")");
    if (fileCount == 0) util::Warn("the header says the archive has no files");

    if (manifEnd < 20 || manifEnd > d.size()) { util::Error("invalid manifest size in the CNPF header"); return false; }
    std::wstring manifest = platform::SjisToWide(&d[20], manifEnd - 20);
    auto items = SplitManifest(manifest);

    // Manifest layout from the field count: 2 per file = "name,attribute" pairs, 1 per file = names only.
    bool pairs;
    if (items.size() == static_cast<size_t>(fileCount) * 2) pairs = true;
    else if (items.size() == fileCount) pairs = false;
    else {
        pairs = !vr02;                                                      // unclear: follow the version label
        util::Warn("the manifest has " + std::to_string(items.size()) + " fields for " + std::to_string(fileCount) +
                   " files (neither names only nor pairs), following the version label " + ver);
    }
    if ((pairs ? "pairs" : "names") != std::string(vr02 ? "names" : "pairs"))
        util::Debug("note: the manifest layout (" + std::string(pairs ? "name,attribute pairs" : "names only") +
                    ") differs from what the version label " + ver + " suggests");
    std::vector<std::wstring> names;
    for (size_t i = 0; i < items.size(); i += pairs ? 2 : 1) names.push_back(items[i]);
    util::Debug("files in the manifest: " + std::to_string(names.size()));
    if (names.size() < fileCount)
        util::Warn("the manifest names only " + std::to_string(names.size()) + " of the " + std::to_string(fileCount) +
                   " files, the others cannot be extracted");
    else if (names.size() > fileCount)
        util::Warn("the manifest names " + std::to_string(names.size()) + " files but the header says " + std::to_string(fileCount));

    // Entry header: 6 bytes, or 9 for VR06. Try the version's guess first, then the other; keep the one that
    // makes the entries end exactly at the end of the archive.
    size_t end = (archSize >= manifEnd && archSize <= d.size()) ? archSize : d.size();
    size_t entryHeader = vr06 ? 9 : 6;
    if (!EntriesFit(d, manifEnd, fileCount, entryHeader, end)) {
        size_t other = (entryHeader == 9) ? 6 : 9;
        if (EntriesFit(d, manifEnd, fileCount, other, end)) {
            util::Debug("note: entry headers are " + std::to_string(other) + " bytes, not " + std::to_string(entryHeader) +
                        " as the version label " + ver + " suggests");
            entryHeader = other;
        } else {
            util::Warn("the entries do not end exactly at the end of the archive, using " + std::to_string(entryHeader) + "-byte headers");
        }
    }

    size_t pos = manifEnd;
    size_t written = 0;
    std::set<std::string> usedNames;
    for (uint32_t i = 0; i < fileCount && i < names.size(); ++i) {
        if (pos + entryHeader > d.size()) {
            util::Warn("the archive ends before entry " + std::to_string(i) + " of " + std::to_string(fileCount));
            break;
        }
        uint8_t comp = d[pos], type = d[pos + 1];
        uint32_t payloadSize = util::LoadU32(&d[pos + entryHeader - 4]);
        pos += entryHeader;

        size_t avail = std::min<size_t>(payloadSize, d.size() - pos);
        if (avail < payloadSize) util::Warn("entry " + std::to_string(i) + ": archive is truncated");
        ByteSpan payload(&d[pos], avail);
        pos += avail;

        util::Debug("  > " + util::PathToUtf8(fs::path(names[i])) + "  type " + TypeName(type) + " (0x" + util::Hex(type, 2) +
                    "), compression " + std::to_string(comp) + ", size " + std::to_string(payloadSize));

        if (comp > 1) util::Warn("entry " + std::to_string(i) + ": compression type " + std::to_string(comp) +
                                 " is not supported, the data is saved as stored");
        if (type > 15) util::Warn("entry " + std::to_string(i) + ": unknown file type 0x" + util::Hex(type, 2));

        Bytes data;
        if (comp == 1) {                                                    // LZSS: 4-byte decompressed size, then the stream
            if (payload.size() < 4) { util::Warn("entry " + std::to_string(i) + ": compressed data too short"); continue; }
            uint32_t declared = util::LoadU32(payload.data());
            size_t limit = (declared > 0 && declared <= (512u << 20)) ? declared : 0;
            if (!limit) util::Warn("entry " + std::to_string(i) + ": no usable decompressed size in the header (" + std::to_string(declared) + ")");
            data = compress::LzssDecompress(payload.data() + 4, payload.size() - 4, limit);
            if (limit && data.size() != limit)
                util::Warn("entry " + std::to_string(i) + ": decompressed to " + std::to_string(data.size()) + " bytes, expected " + std::to_string(limit));
        } else {
            data.assign(payload.begin(), payload.end());
        }

        fs::path rel = SafeRelativePath(names[i]);
        if (rel.empty()) { util::Warn("entry " + std::to_string(i) + ": unusable file name, skipped"); continue; }
        {
            std::string key = platform::PathToUtf8(rel);
            for (char& c : key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (!usedNames.insert(key).second)
                util::Warn("entry " + std::to_string(i) + ": duplicate file name " + platform::PathToUtf8(rel) + ", saved with a suffix");
        }
        fs::path folder = ctx.outDir / rel.parent_path();
        std::error_code ec;
        fs::create_directories(folder, ec);
        if (output::Save(folder, platform::PathToUtf8(rel.filename()), data)) ++written;
    }

    if (written != fileCount)
        util::Warn(std::to_string(written) + " of " + std::to_string(fileCount) + " files were extracted");
    if (written == 0) util::Error("the archive contains no extractable files");
    return written > 0;
}
