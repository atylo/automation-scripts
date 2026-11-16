// .SCN files: ["SCN\0"][4 version][4 uncompressed size][4 crc][1 seed] + payload, where the payload is
// the TYPE98 cipher (key brute-forced, 8 bits) + LZSS and decompresses to a D88 disk image.
// Port of SCN_decrypt_brute.py.
#include <array>

#include "compress.h"
#include "crypto.h"
#include "extractors.h"
#include "platform.h"

namespace {

constexpr size_t kHeaderSize = 17;
constexpr size_t kPrefix     = 0x80;     // enough encrypted bytes to decode the first 0x20 output bytes

// The same D88 check as the script: the declared disk size (offset 0x1C) must equal the data size.
bool DeclaredSizeMatches(const uint8_t* d, size_t size) {
    return size >= 0x20 && util::LoadU32(d + 0x1C) == size;
}

}  // namespace

bool ExtractScn(const Context& ctx) {
    const Bytes& data = *ctx.data;
    if (data.size() <= kHeaderSize) { util::Error("file too small to be a SCN file"); return false; }

    uint32_t uncompressed = util::LoadU32(&data[8]);
    uint32_t crc          = util::LoadU32(&data[12]);
    uint8_t  seed         = data[16];
    const uint8_t* payload = &data[kHeaderSize];
    const size_t   payloadLen = data.size() - kHeaderSize;
    util::Debug("SCN header: version " + std::to_string(util::LoadU32(&data[4])) + ", size " +
                std::to_string(uncompressed) + ", crc 0x" + util::Hex(crc, 8) + ", seed 0x" + util::Hex(seed, 2));

    if (uncompressed < 0x20 || uncompressed > 256u * 1024u * 1024u) {
        util::Error("invalid uncompressed size in the SCN header");
        return false;
    }

    // Candidate order: 0xF8 first (the value left in the original script), then every other key.
    std::array<uint8_t, 256> order;
    order[0] = 0xF8;
    for (int k = 0, i = 1; k < 256; ++k)
        if (k != 0xF8) order[i++] = static_cast<uint8_t>(k);

    for (uint8_t keyGuess : order) {
        uint8_t combined = static_cast<uint8_t>(keyGuess ^ seed);

        // 1) cheap rejection: decode only the first 0x20 bytes and compare the D88 size field
        Bytes head(payload, payload + std::min(payloadLen, kPrefix));
        crypto::Type98DecryptRaw(head.data(), head.size(), combined, 1);
        Bytes first = compress::LzssDecompress(head.data(), head.size(), 0x20);
        if (first.size() < 0x20 || util::LoadU32(&first[0x1C]) != uncompressed) continue;

        // 2) full decryption + decompression + validation
        Bytes enc(payload, payload + payloadLen);
        crypto::Type98DecryptRaw(enc.data(), enc.size(), combined, 1);
        Bytes disk = compress::LzssDecompress(enc.data(), enc.size(), uncompressed);
        if (disk.size() != uncompressed || !DeclaredSizeMatches(disk.data(), disk.size())) continue;

        util::Debug("Key found: 0x" + util::Hex(keyGuess, 2));
        fs::path out = ctx.outDir / platform::PathFromUtf8(platform::PathToUtf8(ctx.input.stem()) + ".d88");
        return util::WriteFile(out, disk);
    }

    util::Error("no key produced a valid D88 disk image (damaged file, or not a disk SCN)");
    return false;
}
