#include "eggdisk.h"

#include <algorithm>
#include <map>
#include <regex>

#include "crypto.h"
#include "d88.h"
#include "platform.h"

namespace eggdisk {

namespace {

std::string Lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

struct Dir {
    std::map<std::string, fs::path> byLower;       // lower-case file name -> path

    explicit Dir(const fs::path& dir) {
        std::error_code ec;
        for (const auto& e : fs::directory_iterator(dir, ec))
            if (e.is_regular_file(ec)) byLower[Lower(platform::PathToUtf8(e.path().filename()))] = e.path();
    }
    // A chunk is stored as "<base>.dat", "<base>.cl5", "<base>.bin" (our extractor) or without extension.
    const fs::path* Chunk(const std::string& base) const {
        for (const char* ext : {".dat", ".cl5", ".bin", ""}) {
            auto it = byLower.find(Lower(base + ext));
            if (it != byLower.end()) return &it->second;
        }
        return nullptr;
    }
};

void Put32(Bytes& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

void Remove(const std::vector<fs::path>& files) {
    std::error_code ec;
    for (const auto& f : files) fs::remove(f, ec);
}

// ---------------------------------------------------------------------------------------------
// Floppy: INF (md5 at 0x200, then u32 x3: ?, read-only, track count) + one file per track.
// Track file: [u32 sector count][u32 offset per sector]; each sector: 12-byte head (C H R N ..., size in the
// last 4 bytes) followed by its data.
// ---------------------------------------------------------------------------------------------
bool BuildFloppy(const Dir& dir, const std::string& disk, const fs::path& infPath, const fs::path& outDir) {
    Bytes inf;
    if (!util::ReadFile(infPath, inf) || inf.size() < 0x21C) {
        util::Warn(disk + ": INF file missing or too small");
        return false;
    }
    uint8_t md5[16];
    std::copy(inf.begin() + 0x200, inf.begin() + 0x210, md5);
    uint32_t readonly = util::LoadU32(&inf[0x214]);
    uint32_t numTracks = util::LoadU32(&inf[0x218]);
    if (numTracks == 0 || numTracks > 4096) {
        util::Warn(disk + ": implausible track count " + std::to_string(numTracks));
        return false;
    }
    uint8_t roFlag   = (readonly == 1) ? 0x10 : static_cast<uint8_t>(readonly);
    uint8_t diskType = numTracks > 84 ? 0x20 : 0x00;           // 2HD vs 2D

    Bytes data;
    std::vector<uint32_t> trackSizes;
    std::vector<fs::path> used;
    for (uint32_t t = 0; t < numTracks; ++t) {
        const fs::path* p = dir.Chunk(disk + "-" + std::to_string(t));
        Bytes tf;
        if (!p || !util::ReadFile(*p, tf) || tf.size() < 4) {
            util::Warn(disk + "-" + std::to_string(t) + " not found, adding an empty track");
            trackSizes.push_back(0);                           // keeps the track numbering intact
            continue;
        }
        used.push_back(*p);
        uint32_t numSectors = util::LoadU32(tf.data());
        if (numSectors > 4096 || 4 + static_cast<size_t>(numSectors) * 4 > tf.size()) {
            util::Warn("track " + std::to_string(t) + ": invalid sector table");
            trackSizes.push_back(0);
            continue;
        }
        uint32_t trackSize = 0;
        for (uint32_t s = 0; s < numSectors; ++s) {
            uint32_t off = util::LoadU32(&tf[4 + s * 4]);
            if (static_cast<size_t>(off) + 12 > tf.size()) {
                util::Warn("track " + std::to_string(t) + ": sector offset out of range, skipping");
                continue;
            }
            uint32_t size = util::LoadU32(&tf[off + 8]);
            if (size >= 0xFFFF) {
                util::Warn("Invalid sector length in track " + std::to_string(t) + ", skipping");
                continue;
            }
            // D88 sector header: C H R N | sector count | 9 x 0 | data size (u16)
            data.insert(data.end(), tf.begin() + off, tf.begin() + off + 4);
            data.push_back(static_cast<uint8_t>(std::min<uint32_t>(numSectors, 255)));
            data.insert(data.end(), 9, 0);
            data.push_back(static_cast<uint8_t>(size & 0xFF));
            data.push_back(static_cast<uint8_t>(size >> 8));
            size_t avail = std::min<size_t>(size, tf.size() - (static_cast<size_t>(off) + 12));
            data.insert(data.end(), tf.begin() + off + 12, tf.begin() + off + 12 + avail);
            if (avail < size) {
                util::Warn("track " + std::to_string(t) + ": sector data truncated");
                data.insert(data.end(), size - avail, 0);
            }
            trackSize += size + 0x10;
        }
        trackSizes.push_back(trackSize);
    }

    // D88 header
    size_t numEntries = std::max<size_t>(trackSizes.size(), 164);
    size_t startOff = 0x20 + numEntries * 4;
    if (startOff % 16) startOff += 16 - startOff % 16;

    Bytes header(0x1A, 0);
    header.push_back(roFlag);
    header.push_back(diskType);
    Put32(header, static_cast<uint32_t>(data.size() + startOff));      // total size
    Put32(header, static_cast<uint32_t>(startOff));                    // offset of the first track
    size_t offset = startOff + trackSizes[0];
    for (size_t i = 1; i < trackSizes.size(); ++i) {
        if (trackSizes[i] > 0) { Put32(header, static_cast<uint32_t>(offset)); offset += trackSizes[i]; }
        else Put32(header, 0);
    }
    header.insert(header.end(), (numEntries - trackSizes.size()) * 4, 0);
    header.resize(startOff, 0);

    Bytes image = header;
    image.insert(image.end(), data.begin(), data.end());

    fs::path out = util::UniquePath(outDir / d88::SuggestFileName(image, "fd_" + disk));
    if (!util::WriteFile(out, image)) return false;

    if (crypto::Md5(image) == std::array<uint8_t, 16>{md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7],
                                                       md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15]}) {
        util::Info("  MD5 check passed for " + util::PathToUtf8(out.filename()) + ", removing the chunks");
        used.push_back(infPath);
        Remove(used);
    } else {
        util::Warn("MD5 mismatch for " + util::PathToUtf8(out.filename()) + ", the chunk files are kept");
    }
    return true;
}

// ---------------------------------------------------------------------------------------------
// Hard disk: INF (geometry at 0x210: cylinders, segments per cylinder, sectors per segment, sector size)
// + one file per segment, concatenated behind an FDI header.
// ---------------------------------------------------------------------------------------------
bool BuildHardDisk(const Dir& dir, const fs::path& infPath, const fs::path& outDir) {
    Bytes inf;
    if (!util::ReadFile(infPath, inf) || inf.size() < 0x220) {
        util::Warn("EGGHDIMG: INF file missing or too small");
        return false;
    }
    uint32_t cyls = util::LoadU32(&inf[0x210]), segs = util::LoadU32(&inf[0x214]);
    uint32_t sectorsPerSeg = util::LoadU32(&inf[0x218]), sectorSize = util::LoadU32(&inf[0x21C]);
    uint64_t totalSegments = static_cast<uint64_t>(cyls) * segs;
    uint64_t segmentSize   = static_cast<uint64_t>(sectorsPerSeg) * sectorSize;
    util::Info("  HDD layout: " + std::to_string(cyls) + " cylinders x " + std::to_string(segs) + " segments, " +
               std::to_string(sectorsPerSeg) + " sectors x " + std::to_string(sectorSize) + " bytes");
    if (totalSegments == 0 || totalSegments > (1u << 20) || segmentSize == 0 || totalSegments * segmentSize > (4ull << 30)) {
        util::Warn("EGGHDIMG: implausible geometry, not assembled");
        return false;
    }

    std::vector<fs::path> used;
    Bytes data;
    for (uint64_t i = 0; i < totalSegments; ++i) {
        const fs::path* p = dir.Chunk("EGGHDIMG" + std::to_string(i));
        Bytes seg;
        if (!p || !util::ReadFile(*p, seg)) {
            util::Warn("Missing segment file EGGHDIMG" + std::to_string(i) + ", hard disk not assembled");
            return false;
        }
        if (seg.size() != segmentSize)
            util::Warn("EGGHDIMG" + std::to_string(i) + ": size mismatch (expected " + std::to_string(segmentSize) +
                       ", got " + std::to_string(seg.size()) + ")");
        used.push_back(*p);
        data.insert(data.end(), seg.begin(), seg.end());
    }

    Bytes image;
    for (uint32_t v : {0u, 0x90u, 0x1000u, static_cast<uint32_t>(data.size() + 0x1000), sectorSize, sectorsPerSeg, segs, cyls})
        Put32(image, v);
    image.resize(0x1000, 0);
    image.insert(image.end(), data.begin(), data.end());

    fs::path out = util::UniquePath(outDir / "hd_EGGHDIMG.fdi");
    if (!util::WriteFile(out, image)) return false;

    // The INF carries an MD5 at 0x200 on floppies; if the hard-disk INF has the same field, use it to verify.
    auto sameAs = [&](const Bytes& b) {
        auto d = crypto::Md5(b);
        return std::equal(d.begin(), d.end(), inf.begin() + 0x200);
    };
    if (sameAs(data) || sameAs(image)) {
        util::Info("  MD5 check passed for " + util::PathToUtf8(out.filename()) + ", removing the chunks");
        used.push_back(infPath);
        Remove(used);
    } else {
        util::Info("  no matching MD5 in the INF for the hard disk image, the chunk files are kept");
    }
    return true;
}

}  // namespace

size_t AssembleDisks(const fs::path& dirPath) {
    Dir dir(dirPath);
    size_t written = 0;

    static const std::regex floppyInf(R"(^(eggfdimg\d+)-inf(\..+)?$)", std::regex::icase);
    static const std::regex hardInf(R"(^egghdimg\d+-inf(\..+)?$)", std::regex::icase);

    std::vector<std::pair<std::string, fs::path>> floppies;       // (disk id, INF)
    fs::path hardInfPath;
    for (const auto& [lower, path] : dir.byLower) {
        std::smatch m;
        if (std::regex_match(lower, m, floppyInf)) {
            std::string id = m[1].str();
            for (size_t i = 0; i < 8; ++i) id[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(id[i])));   // "EGGFDIMG"
            floppies.push_back({id, path});
        } else if (hardInfPath.empty() && std::regex_match(lower, hardInf)) {
            hardInfPath = path;
        }
    }
    std::sort(floppies.begin(), floppies.end(), [](const auto& a, const auto& b) {
        if (a.first.size() != b.first.size()) return a.first.size() < b.first.size();      // numeric order
        return a.first < b.first;
    });

    for (const auto& [id, inf] : floppies) {
        util::Info("Assembling floppy " + id);
        if (BuildFloppy(dir, id, inf, dirPath)) ++written;
    }
    if (!hardInfPath.empty()) {
        util::Info("Assembling hard disk");
        if (BuildHardDisk(dir, hardInfPath, dirPath)) ++written;
    }
    return written;
}

}  // namespace eggdisk
