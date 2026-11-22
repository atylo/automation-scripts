// crypto.h - hashing and decryption routines shared by all extractors.
//
//  * Generic primitives : rotates, MD5, AES-128 (ECB, decrypt only)
//  * Format ciphers     : one function per scheme found in the original tools
#pragma once

#include <array>
#include <span>

#include "common.h"

namespace crypto {

// --- bit helpers -------------------------------------------------------
inline uint8_t rol8(uint8_t v, unsigned n) {
    n &= 7;
    return n ? static_cast<uint8_t>((v << n) | (v >> (8 - n))) : v;
}
inline uint8_t ror8(uint8_t v, unsigned n) { return rol8(v, (8 - (n & 7)) & 7); }
inline uint32_t rol32(uint32_t v, uint32_t n) {
    n %= 32;
    return n ? (v << n) | (v >> (32 - n)) : v;
}
inline uint32_t ror32(uint32_t v, uint32_t n) {
    n %= 32;
    return n ? (v >> n) | (v << (32 - n)) : v;
}

// --- MD5 ---------------------------------------------------------------
using Md5Digest = std::array<uint8_t, 16>;
Md5Digest Md5(const uint8_t* data, size_t len);
inline Md5Digest Md5(ByteSpan s) { return Md5(s.data(), s.size()); }
std::string Md5Hex(ByteSpan data);                       // lower-case hex string

// --- SHA-1 / CRC-32 (used to identify known ROMs) -----------------------
std::string Sha1Hex(ByteSpan data);                      // lower-case hex string
uint32_t    Crc32(ByteSpan data);                        // standard CRC-32 (zlib / ZIP / ROM lists)

// --- AES-128 -----------------------------------------------------------
class Aes128 {
public:
    explicit Aes128(const uint8_t key[16]);
    void DecryptBlock(const uint8_t in[16], uint8_t out[16]) const;
    // ECB-decrypts floor(len/16) blocks in place; a trailing partial block is untouched.
    void DecryptEcbInPlace(uint8_t* data, size_t len) const;

private:
    uint8_t roundKeys_[176];
};

// --- format-specific ciphers ------------------------------------------

// ProjectEGG "EGGDATA": AES-ECB per 0x100-byte chunk, first 4 key bytes ^= chunk index (LE).
// A trailing partial chunk is copied unchanged.
Bytes EggChunkedAesDecrypt(const uint8_t* data, size_t len, const uint8_t baseKey[16]);
// Key for the CONFIG region: MD5(exe_name) ^ 0xFF
std::array<uint8_t, 16> EggConfigKey(std::string_view exeName);

// TYPE98 resources (version 1 or 2), in place.
void Type98Decrypt(uint8_t* data, size_t len, uint8_t seed, ByteSpan password, int version);
// Same cipher driven by the already-combined 8-bit key (= password hash ^ seed). Used directly
// by .SCN files, where the key is brute-forced.
void Type98DecryptRaw(uint8_t* data, size_t len, uint8_t combinedKey, int version);

// TYPE60 resources: only the LCG keystream XOR (the TYPE98 cipher without rotation / chaining),
// state seeded with a 1-byte value. In place.
void LcgXorDecrypt(uint8_t* data, size_t len, uint8_t seed);

// CRC-32 as used by the TYPE60 resources: forward (MSB-first) polynomial 0x04C11DB7,
// init 0xFFFFFFFF, final NOT, no bit reflection.
uint32_t Crc32Msb(const uint8_t* data, size_t len);

// DataFileVer disk blobs: rotate chain + XOR chain, seeded with a 1-byte key.
Bytes DataFileVerDecrypt(const uint8_t* blob, size_t len, uint8_t key);

// old_X1: ROL + XOR with a position counter. `startPos` is the virtual position of data[0].
Bytes X1Descramble(const uint8_t* data, size_t len, uint32_t startPos);
// Single byte at virtual position `pos` (used when probing headers).
inline uint8_t X1DescrambleByte(uint8_t b, uint32_t pos) {
    return static_cast<uint8_t>(pos ^ rol8(b, pos & 7));
}

// MSXPLAYer (old): swap(data) ^ key. A leading 0x8X byte selects "header mode".
Bytes MsxPlayerOldDecrypt(ByteSpan data, ByteSpan key16);
// MSX D4E: swap(data ^ key)
Bytes MsxD4eDecrypt(ByteSpan data, ByteSpan key16);

extern const uint8_t kMsxKeyOld[16];   // "MSX Association" key (MSXPLAYer old)
extern const uint8_t kMsxKeyD4e[16];   // D4E key

}  // namespace crypto
