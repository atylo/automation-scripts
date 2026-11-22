#include "pe.h"

#include <algorithm>
#include <cctype>
#include <cstring>

using util::LoadU16;
using util::LoadU32;

bool EqualsNoCase(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    return true;
}

bool ParsePe(ByteSpan d, PeInfo& pe, size_t mz) {
    if (mz > d.size() || d.size() - mz < 0x40) return false;
    if (d[mz] != 'M' || d[mz + 1] != 'Z') return false;

    size_t peOff = mz + LoadU32(&d[mz + 0x3C]);
    if (peOff > d.size() || d.size() - peOff < 0x18) return false;
    if (std::memcmp(&d[peOff], "PE\0\0", 4) != 0) return false;

    pe = PeInfo{};
    pe.mzOffset = mz;
    pe.peOffset = peOff;
    uint16_t numSections = LoadU16(&d[peOff + 6]);
    pe.timestamp         = LoadU32(&d[peOff + 8]);
    uint16_t optSize     = LoadU16(&d[peOff + 20]);

    size_t opt = peOff + 24;
    if (opt > d.size() || d.size() - opt < 2) return false;
    uint16_t magic = LoadU16(&d[opt]);
    pe.pe32plus = (magic == 0x20B);

    if (!pe.pe32plus) {
        if (d.size() - opt >= 32) pe.imageBase = LoadU32(&d[opt + 28]);
    } else {
        if (d.size() - opt >= 32)
            pe.imageBase = static_cast<uint64_t>(LoadU32(&d[opt + 24])) |
                           (static_cast<uint64_t>(LoadU32(&d[opt + 28])) << 32);
    }

    // data directory #2 = resource table
    size_t numDirsOff = opt + (pe.pe32plus ? 108 : 92);
    size_t dirOff     = opt + (pe.pe32plus ? 112 : 96) + 2 * 8;
    if (dirOff + 8 <= d.size() && dirOff + 8 <= opt + optSize && numDirsOff + 4 <= d.size() &&
        LoadU32(&d[numDirsOff]) > 2) {
        pe.rsrcRva  = LoadU32(&d[dirOff]);
        pe.rsrcSize = LoadU32(&d[dirOff + 4]);
    }

    size_t secTable = opt + optSize;
    for (uint16_t i = 0; i < numSections; ++i) {
        size_t so = secTable + static_cast<size_t>(i) * 40;
        if (so > d.size() || d.size() - so < 40) break;
        PeSection s;
        s.name = std::string(reinterpret_cast<const char*>(&d[so]), 8);
        while (!s.name.empty() && s.name.back() == '\0') s.name.pop_back();
        s.virtualSize    = LoadU32(&d[so + 8]);
        s.virtualAddress = LoadU32(&d[so + 12]);
        s.rawSize        = LoadU32(&d[so + 16]);
        s.rawPtr         = LoadU32(&d[so + 20]);
        pe.sections.push_back(std::move(s));
    }
    return true;
}

std::optional<size_t> RvaToFileOffset(const PeInfo& pe, uint32_t rva, size_t fileSize) {
    for (const auto& s : pe.sections) {
        if (rva >= s.virtualAddress && rva - s.virtualAddress < s.rawSize) {
            size_t off = static_cast<size_t>(s.rawPtr) + (rva - s.virtualAddress);
            if (off < fileSize) return off;
            return std::nullopt;
        }
    }
    return std::nullopt;
}

std::vector<PeLocation> FindAllPeHeaders(ByteSpan d) {
    std::vector<PeLocation> list;
    size_t offset = 0;
    while (true) {
        size_t mz = util::FindString(d, "MZ", offset);
        if (mz == util::npos) break;
        if (mz + 0x3C + 4 > d.size()) { offset = mz + 1; continue; }
        size_t peh = mz + LoadU32(&d[mz + 0x3C]);
        if (peh + 0x38 > d.size()) { offset = mz + 1; continue; }
        if (std::memcmp(&d[peh], "PE\0\0", 4) == 0)
            list.push_back({mz, LoadU32(&d[peh + 0x34])});
        offset = mz + 1;
    }
    return list;
}

// ---------------------------------------------------------------------------
// Resource tree
// ---------------------------------------------------------------------------
namespace {

std::string Utf16ToUtf8(const uint8_t* p, size_t chars) {
    std::string out;
    for (size_t i = 0; i < chars; ++i) {
        uint32_t c = LoadU16(p + i * 2);
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < chars) {
            uint32_t lo = LoadU16(p + (i + 1) * 2);
            if (lo >= 0xDC00 && lo < 0xE000) { c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00); ++i; }
        }
        if (c < 0x80) out += static_cast<char>(c);
        else if (c < 0x800) { out += static_cast<char>(0xC0 | (c >> 6)); out += static_cast<char>(0x80 | (c & 0x3F)); }
        else if (c < 0x10000) {
            out += static_cast<char>(0xE0 | (c >> 12)); out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (c >> 18)); out += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F)); out += static_cast<char>(0x80 | (c & 0x3F));
        }
    }
    return out;
}

struct Walker {
    ByteSpan d;
    const PeInfo& pe;
    size_t base;                 // file offset of the resource directory root
    size_t limit;                // end of readable resource area
    std::vector<PeResource>& out;
    int entriesSeen = 0;

    struct Key { std::string text; bool isId; };

    bool ReadName(uint32_t nameField, Key& k) const {
        if (nameField & 0x80000000u) {
            size_t o = base + (nameField & 0x7FFFFFFFu);
            if (o + 2 > d.size()) return false;
            uint16_t len = LoadU16(&d[o]);
            if (o + 2 + static_cast<size_t>(len) * 2 > d.size()) return false;
            k = {Utf16ToUtf8(&d[o + 2], len), false};
        } else {
            k = {std::to_string(nameField & 0xFFFF), true};
        }
        return true;
    }

    void Walk(uint32_t dirOffset, int level, std::vector<Key>& path) {
        if (level > 3) return;
        size_t o = base + dirOffset;
        if (o + 16 > d.size()) return;
        uint32_t count = static_cast<uint32_t>(LoadU16(&d[o + 12])) + LoadU16(&d[o + 14]);
        for (uint32_t i = 0; i < count; ++i) {
            if (++entriesSeen > 200000) return;                 // sanity limit
            size_t e = o + 16 + static_cast<size_t>(i) * 8;
            if (e + 8 > d.size()) return;
            uint32_t nameField = LoadU32(&d[e]);
            uint32_t target    = LoadU32(&d[e + 4]);
            Key k;
            if (!ReadName(nameField, k)) continue;
            path.push_back(k);
            if (target & 0x80000000u) {
                Walk(target & 0x7FFFFFFFu, level + 1, path);
            } else {
                size_t de = base + target;
                if (de + 16 <= d.size()) {
                    uint32_t rva  = LoadU32(&d[de]);
                    uint32_t size = LoadU32(&d[de + 4]);
                    auto off = RvaToFileOffset(pe, rva, d.size());
                    if (off && *off + size <= d.size()) {
                        PeResource r;
                        r.type     = path[0].text;
                        r.typeIsId = path[0].isId;
                        if (path.size() > 1) { r.name = path[1].text; r.nameIsId = path[1].isId; }
                        if (path.size() > 2 && path[2].isId) r.lang = static_cast<uint16_t>(std::stoul(path[2].text));
                        r.fileOffset = *off;
                        r.size       = size;
                        out.push_back(std::move(r));
                    }
                }
            }
            path.pop_back();
        }
    }
};

}  // namespace

std::vector<PeResource> EnumResources(ByteSpan data, const PeInfo& pe) {
    std::vector<PeResource> out;
    if (pe.rsrcRva == 0) return out;
    auto base = RvaToFileOffset(pe, pe.rsrcRva, data.size());
    if (!base) return out;
    Walker w{data, pe, *base, data.size(), out};
    std::vector<Walker::Key> path;
    w.Walk(0, 0, path);
    return out;
}

const PeResource* FindPeResource(const std::vector<PeResource>& all, std::string_view type, std::string_view name) {
    for (const auto& r : all)
        if (EqualsNoCase(r.type, type) && EqualsNoCase(r.name, name)) return &r;
    return nullptr;
}

// ---------------------------------------------------------------------------
// Files with embedded executables
// ---------------------------------------------------------------------------
std::vector<PeImage> FindPeImages(ByteSpan data) {
    std::vector<PeImage> images;
    for (const PeLocation& loc : FindAllPeHeaders(data)) {
        PeImage img;
        if (ParsePe(data.subspan(loc.mzOffset), img.info)) {
            img.offset = loc.mzOffset;
            images.push_back(std::move(img));
        }
    }
    return images;
}

std::vector<FoundResource> EnumAllResources(ByteSpan data) {
    std::vector<FoundResource> all;
    auto images = FindPeImages(data);
    for (size_t i = 0; i < images.size(); ++i) {
        for (PeResource& r : EnumResources(data.subspan(images[i].offset), images[i].info)) {
            r.fileOffset += images[i].offset;
            all.push_back({std::move(r), i});
        }
    }
    return all;
}

const FoundResource* FindFoundResource(const std::vector<FoundResource>& all, std::string_view type, std::string_view name) {
    for (const auto& f : all)
        if (EqualsNoCase(f.res.type, type) && EqualsNoCase(f.res.name, name)) return &f;
    return nullptr;
}

size_t FindNestedPe(ByteSpan d) {
    size_t idx = 1;
    while (idx + 0x100 < d.size()) {
        idx = util::FindString(d, "MZ", idx);
        if (idx == util::npos) return 0;
        if (idx + 0x40 < d.size()) {
            uint32_t lfanew = LoadU32(&d[idx + 0x3C]);
            if (lfanew >= 0x40 && lfanew < 0x400 && idx + lfanew + 4 < d.size() &&
                std::memcmp(&d[idx + lfanew], "PE\0\0", 4) == 0)
                return idx;
        }
        ++idx;
    }
    return 0;
}
