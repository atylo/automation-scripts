#include "pds.h"

#include <algorithm>

#include "d88.h"
#include "platform.h"

namespace pds {

namespace {

struct Track {
    uint8_t c, h;
    Bytes   blob;       // D88 sector headers + payloads
};

bool IsMagic(ByteSpan d, size_t p) {
    return p + 4 <= d.size() && std::tolower(d[p]) == 'p' && std::tolower(d[p + 1]) == 'd' &&
           std::tolower(d[p + 2]) == 's' && d[p + 3] == '\n';
}

// Parses one disk at `start`. Returns false if there is no "pds\n" signature.
bool ParseDisk(ByteSpan d, size_t start, std::vector<Track>& tracks, size_t& next) {
    size_t ptr = start;
    if (ptr + 5 > d.size() || !IsMagic(d, ptr)) return false;

    uint8_t version = d[ptr + 4];                       // 0 = 84 tracks, otherwise 164/168
    size_t maxTracks = (version == 0) ? 84 : 168;
    ptr += 5;

    size_t trackCount = 0;
    while (ptr < d.size() && trackCount < maxTracks) {
        if (IsMagic(d, ptr)) break;                     // next concatenated disk begins

        unsigned numSectors = d[ptr] & 0x7F;            // bit 7 is a flag
        ++ptr;
        ++trackCount;
        if (numSectors == 0) continue;

        Track t{0, 0, {}};
        for (unsigned s = 0; s < numSectors; ++s) {
            if (ptr + 6 > d.size()) break;              // EOF inside sector header
            uint8_t c = d[ptr], h = d[ptr + 1], r = d[ptr + 2], n = d[ptr + 3];
            uint8_t sizeFactor = d[ptr + 5];            // d[ptr+4] = status (not used)
            ptr += 6;
            t.c = c;
            t.h = h;

            size_t sectorSize = static_cast<size_t>(sizeFactor) << 7;
            if (ptr + sectorSize > d.size()) break;     // EOF inside payload

            // D88 sector header (16 bytes)
            uint8_t hdr[16] = {c, h, r, n,
                               static_cast<uint8_t>(numSectors & 0xFF), static_cast<uint8_t>(numSectors >> 8),
                               0x00,      // density: double
                               0x00,      // deleted flag
                               0x00,      // FDC status
                               0, 0, 0, 0, 0,   // reserved
                               static_cast<uint8_t>(sectorSize & 0xFF), static_cast<uint8_t>(sectorSize >> 8)};
            t.blob.insert(t.blob.end(), hdr, hdr + 16);
            t.blob.insert(t.blob.end(), d.begin() + ptr, d.begin() + ptr + sectorSize);
            ptr += sectorSize;
        }
        if (!t.blob.empty()) tracks.push_back(std::move(t));
    }
    next = ptr;
    return true;
}

void PutU32(Bytes& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

Bytes BuildD88(const std::vector<Track>& tracks) {
    // media type from the highest cylinder and the amount of data
    unsigned maxCyl = 0;
    size_t payload = 0;
    for (const Track& t : tracks) {
        maxCyl = std::max<unsigned>(maxCyl, t.c);
        payload += t.blob.size();
    }
    uint8_t media = 0x00;                               // 2D
    if (maxCyl > 45) media = (payload > 800000) ? 0x20 /*2HD*/ : 0x10 /*2DD*/;
    util::Debug("  - PDS media: " + std::string(media == 0 ? "2D" : media == 0x10 ? "2DD" : "2HD") +
                ", max cylinder " + std::to_string(maxCyl));

    // offset table: tracks beyond the 164 slots cannot be addressed and are dropped
    uint32_t offsets[164] = {0};
    size_t current = d88::kHeaderSize;
    std::vector<const Track*> written;
    for (const Track& t : tracks) {
        size_t idx = static_cast<size_t>(t.c) * 2 + t.h;
        if (idx < 164) {
            offsets[idx] = static_cast<uint32_t>(current);
            current += t.blob.size();
            written.push_back(&t);
        }
    }

    Bytes out;
    out.insert(out.end(), 16, 0);                       // disk name: blank
    out.insert(out.end(), 10, 0);                       // reserved
    out.push_back(0);                                   // write protect
    out.push_back(media);
    PutU32(out, static_cast<uint32_t>(current));        // total disk size
    for (uint32_t o : offsets) PutU32(out, o);
    for (const Track* t : written) out.insert(out.end(), t->blob.begin(), t->blob.end());
    return out;
}

}  // namespace

size_t ConvertToD88(ByteSpan data, const fs::path& outDir, const std::string& baseName) {
    size_t ptr = 0, images = 0;
    while (ptr < data.size()) {
        std::vector<Track> tracks;
        size_t next = ptr;
        if (ParseDisk(data, ptr, tracks, next)) {
            ++images;
            fs::path out = util::UniquePath(outDir / platform::PathFromUtf8(baseName + "_" + std::to_string(images) + ".d88"));
            util::WriteFile(out, BuildD88(tracks));
            ptr = next;
        } else {
            ++ptr;                                      // scan forward for the next signature
        }
    }
    return images;
}

}  // namespace pds
