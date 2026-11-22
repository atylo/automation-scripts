#include "crypto.h"

#include <cmath>
#include <cstring>

namespace crypto {

// ===========================================================================
// MD5
// ===========================================================================
Md5Digest Md5(const uint8_t* data, size_t len) {
    static uint32_t K[64];
    static bool init = false;
    if (!init) {
        for (int i = 0; i < 64; ++i)
            K[i] = static_cast<uint32_t>(std::fabs(std::sin(static_cast<double>(i + 1))) * 4294967296.0);
        init = true;
    }
    static const int S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                              5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                              4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                              6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;

    auto process = [&](const uint8_t* block) {
        uint32_t M[16];
        for (int i = 0; i < 16; ++i) M[i] = util::LoadU32(block + i * 4);
        uint32_t A = a0, B = b0, C = c0, D = d0;
        for (int i = 0; i < 64; ++i) {
            uint32_t F;
            int g;
            if (i < 16)      { F = (B & C) | (~B & D); g = i; }
            else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
            else if (i < 48) { F = B ^ C ^ D;          g = (3 * i + 5) % 16; }
            else             { F = C ^ (B | ~D);       g = (7 * i) % 16; }
            F = F + A + K[i] + M[g];
            A = D; D = C; C = B;
            B = B + rol32(F, static_cast<uint32_t>(S[i]));
        }
        a0 += A; b0 += B; c0 += C; d0 += D;
    };

    size_t full = len / 64;
    for (size_t i = 0; i < full; ++i) process(data + i * 64);

    uint8_t tail[128] = {0};
    size_t rem = len - full * 64;
    if (rem) std::memcpy(tail, data + full * 64, rem);
    tail[rem] = 0x80;
    size_t tailLen = (rem < 56) ? 64 : 128;
    uint64_t bits = static_cast<uint64_t>(len) * 8;
    for (int i = 0; i < 8; ++i) tail[tailLen - 8 + i] = static_cast<uint8_t>(bits >> (8 * i));
    process(tail);
    if (tailLen == 128) process(tail + 64);

    Md5Digest out;
    uint32_t v[4] = {a0, b0, c0, d0};
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j) out[i * 4 + j] = static_cast<uint8_t>(v[i] >> (8 * j));
    return out;
}

std::string Md5Hex(ByteSpan data) {
    auto d = Md5(data);
    static const char* hex = "0123456789abcdef";
    std::string s;
    for (uint8_t b : d) { s += hex[b >> 4]; s += hex[b & 15]; }
    return s;
}

// ===========================================================================
// SHA-1 and standard CRC-32
// ===========================================================================
std::string Sha1Hex(ByteSpan d) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    auto process = [&](const uint8_t* b) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = (static_cast<uint32_t>(b[i * 4]) << 24) | (static_cast<uint32_t>(b[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(b[i * 4 + 2]) << 8) | b[i * 4 + 3];
        for (int i = 16; i < 80; ++i) w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], bb = h[1], c = h[2], dd = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20)      { f = (bb & c) | (~bb & dd);            k = 0x5A827999; }
            else if (i < 40) { f = bb ^ c ^ dd;                      k = 0x6ED9EBA1; }
            else if (i < 60) { f = (bb & c) | (bb & dd) | (c & dd);  k = 0x8F1BBCDC; }
            else             { f = bb ^ c ^ dd;                      k = 0xCA62C1D6; }
            uint32_t t = rol32(a, 5) + f + e + k + w[i];
            e = dd; dd = c; c = rol32(bb, 30); bb = a; a = t;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += dd; h[4] += e;
    };
    size_t full = d.size() / 64;
    for (size_t i = 0; i < full; ++i) process(d.data() + i * 64);
    uint8_t tail[128] = {0};
    size_t rem = d.size() - full * 64;
    if (rem) std::memcpy(tail, d.data() + full * 64, rem);
    tail[rem] = 0x80;
    size_t tailLen = (rem < 56) ? 64 : 128;
    uint64_t bits = static_cast<uint64_t>(d.size()) * 8;
    for (int i = 0; i < 8; ++i) tail[tailLen - 1 - i] = static_cast<uint8_t>(bits >> (8 * i));
    process(tail);
    if (tailLen == 128) process(tail + 64);
    static const char* hex = "0123456789abcdef";
    std::string s;
    for (uint32_t v : h)
        for (int sh = 28; sh >= 0; sh -= 4) s += hex[(v >> sh) & 0xF];
    return s;
}

uint32_t Crc32(ByteSpan d) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : d) crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

// ===========================================================================
// AES-128 (decrypt only). S-boxes are generated at start-up (no big tables to mistype).
// ===========================================================================
namespace {

struct AesTables {
    uint8_t sbox[256], inv[256], m9[256], m11[256], m13[256], m14[256];
    AesTables() {
        uint8_t p = 1, q = 1;
        do {
            p = static_cast<uint8_t>(p ^ (p << 1) ^ ((p & 0x80) ? 0x1B : 0));       // p *= 3
            q ^= static_cast<uint8_t>(q << 1);                                        // q /= 3
            q ^= static_cast<uint8_t>(q << 2);
            q ^= static_cast<uint8_t>(q << 4);
            if (q & 0x80) q ^= 0x09;
            uint8_t x = static_cast<uint8_t>(q ^ rol8(q, 1) ^ rol8(q, 2) ^ rol8(q, 3) ^ rol8(q, 4));
            sbox[p] = static_cast<uint8_t>(x ^ 0x63);
        } while (p != 1);
        sbox[0] = 0x63;
        for (int i = 0; i < 256; ++i) inv[sbox[i]] = static_cast<uint8_t>(i);
        for (int i = 0; i < 256; ++i) {
            uint8_t x  = static_cast<uint8_t>(i);
            uint8_t x2 = xtime(x), x4 = xtime(x2), x8 = xtime(x4);
            m9[i]  = x8 ^ x;
            m11[i] = x8 ^ x2 ^ x;
            m13[i] = x8 ^ x4 ^ x;
            m14[i] = x8 ^ x4 ^ x2;
        }
    }
    static uint8_t xtime(uint8_t x) { return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1B : 0)); }
};

const AesTables& T() {
    static const AesTables t;
    return t;
}

}  // namespace

Aes128::Aes128(const uint8_t key[16]) {
    const auto& t = T();
    std::memcpy(roundKeys_, key, 16);
    uint8_t rcon = 1;
    for (int i = 16; i < 176; i += 4) {
        uint8_t tmp[4] = {roundKeys_[i - 4], roundKeys_[i - 3], roundKeys_[i - 2], roundKeys_[i - 1]};
        if (i % 16 == 0) {
            uint8_t first = tmp[0];
            tmp[0] = static_cast<uint8_t>(t.sbox[tmp[1]] ^ rcon);
            tmp[1] = t.sbox[tmp[2]];
            tmp[2] = t.sbox[tmp[3]];
            tmp[3] = t.sbox[first];
            rcon   = static_cast<uint8_t>((rcon << 1) ^ ((rcon & 0x80) ? 0x1B : 0));
        }
        for (int j = 0; j < 4; ++j) roundKeys_[i + j] = static_cast<uint8_t>(roundKeys_[i - 16 + j] ^ tmp[j]);
    }
}

void Aes128::DecryptBlock(const uint8_t in[16], uint8_t out[16]) const {
    const auto& t = T();
    uint8_t s[16], tmp[16];
    for (int i = 0; i < 16; ++i) s[i] = static_cast<uint8_t>(in[i] ^ roundKeys_[160 + i]);

    for (int round = 9; round >= 0; --round) {
        // InvShiftRows + InvSubBytes (state byte index = 4*column + row)
        for (int c = 0; c < 4; ++c)
            for (int r = 0; r < 4; ++r) tmp[((c + r) & 3) * 4 + r] = t.inv[s[c * 4 + r]];
        // AddRoundKey
        for (int i = 0; i < 16; ++i) tmp[i] ^= roundKeys_[round * 16 + i];
        if (round == 0) break;
        // InvMixColumns
        for (int c = 0; c < 4; ++c) {
            uint8_t a = tmp[c * 4], b = tmp[c * 4 + 1], cc = tmp[c * 4 + 2], d = tmp[c * 4 + 3];
            s[c * 4 + 0] = t.m14[a] ^ t.m11[b] ^ t.m13[cc] ^ t.m9[d];
            s[c * 4 + 1] = t.m9[a] ^ t.m14[b] ^ t.m11[cc] ^ t.m13[d];
            s[c * 4 + 2] = t.m13[a] ^ t.m9[b] ^ t.m14[cc] ^ t.m11[d];
            s[c * 4 + 3] = t.m11[a] ^ t.m13[b] ^ t.m9[cc] ^ t.m14[d];
        }
    }
    std::memcpy(out, tmp, 16);
}

void Aes128::DecryptEcbInPlace(uint8_t* data, size_t len) const {
    for (size_t off = 0; off + 16 <= len; off += 16) DecryptBlock(data + off, data + off);
}

// ===========================================================================
// ProjectEGG "EGGDATA"
// ===========================================================================
std::array<uint8_t, 16> EggConfigKey(std::string_view exeName) {
    auto d = Md5(reinterpret_cast<const uint8_t*>(exeName.data()), exeName.size());
    std::array<uint8_t, 16> key;
    for (int i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(d[i] ^ 0xFF);
    return key;
}

Bytes EggChunkedAesDecrypt(const uint8_t* data, size_t len, const uint8_t baseKey[16]) {
    constexpr size_t kChunk = 0x100;
    Bytes out(data, data + len);
    uint32_t keyInc = util::LoadU32(baseKey);
    size_t nFull = len / kChunk;
    for (size_t i = 0; i < nFull; ++i) {
        uint8_t key[16];
        std::memcpy(key, baseKey, 16);
        uint32_t v = keyInc ^ static_cast<uint32_t>(i);
        for (int b = 0; b < 4; ++b) key[b] = static_cast<uint8_t>(v >> (8 * b));
        Aes128(key).DecryptEcbInPlace(out.data() + i * kChunk, kChunk);
    }
    return out;
}

// ===========================================================================
// TYPE98  (from egg_type98_extractor_v2.cpp)
// ===========================================================================
void Type98DecryptRaw(uint8_t* ptr, size_t len, uint8_t combinedKey, int version) {
    uint8_t shiftInit, mask, shiftR;
    if (version == 1) {
        shiftInit = (combinedKey >> 3) & 7;
        mask      = 0x38;
        shiftR    = 3;
    } else {
        shiftInit = (combinedKey >> 2) & 7;
        mask      = 0x1C;
        shiftR    = 2;
    }

    uint32_t prng  = combinedKey;
    uint8_t  shift = shiftInit;
    uint8_t  chain = combinedKey;

    for (size_t i = 0; i < len; ++i) {
        prng = (prng * 0x1000u + 0x24d69u) % 0xae529u;
        uint8_t xorMask = static_cast<uint8_t>((prng * 0x100u) / 0xae529u);
        uint8_t val = ptr[i] ^ xorMask;

        uint8_t nextShift = static_cast<uint8_t>((val & mask) >> shiftR);
        val = rol8(val, shift);

        uint8_t layer2 = val;
        ptr[i] = static_cast<uint8_t>(val ^ chain);
        shift = nextShift;
        chain = layer2;
    }
}

void Type98Decrypt(uint8_t* ptr, size_t len, uint8_t seed, ByteSpan password, int version) {
    uint8_t keyHash = 0;
    if (!password.empty()) {
        keyHash = 0xFF;
        for (uint8_t b : password) keyHash ^= b;
    }
    uint8_t combined = (version == 1) ? static_cast<uint8_t>(keyHash ^ seed)
                                      : static_cast<uint8_t>(~(keyHash ^ seed));
    Type98DecryptRaw(ptr, len, combined, version);
}

// ===========================================================================
// TYPE60  (from extract_test_V2.py : decrypt_aw4 / alicesoft_crc32)
// ===========================================================================
void LcgXorDecrypt(uint8_t* ptr, size_t len, uint8_t seed) {
    uint32_t state = seed;
    for (size_t i = 0; i < len; ++i) {
        state = (state * 0x1000u + 0x24d69u) % 0xae529u;
        ptr[i] ^= static_cast<uint8_t>((state * 0x100u) / 0xae529u);
    }
}

uint32_t Crc32Msb(const uint8_t* data, size_t len) {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t crc = i << 24;
            for (int k = 0; k < 8; ++k) crc = (crc & 0x80000000u) ? (crc << 1) ^ 0x04C11DB7u : (crc << 1);
            table[i] = crc;
        }
        init = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) crc = table[(data[i] ^ (crc >> 24)) & 0xFF] ^ (crc << 8);
    return ~crc;
}

// ===========================================================================
// DataFileVer  (from egg_datafilever_ext.py : decrypt_blob)
// ===========================================================================
Bytes DataFileVerDecrypt(const uint8_t* blob, size_t len, uint8_t key) {
    Bytes rot(len), out(len);
    uint8_t curr = key;
    for (size_t i = 0; i < len; ++i) {           // pass 1: rotation driven by previous cipher byte
        rot[i] = rol8(blob[i], (curr >> 3) & 7);
        curr = blob[i];
    }
    uint8_t xorK = key;
    for (size_t i = 0; i < len; ++i) {           // pass 2: XOR chain
        out[i] = static_cast<uint8_t>(rot[i] ^ xorK);
        xorK = rot[i];
    }
    return out;
}

// ===========================================================================
// old_X1  (from old_x1_extractor.py : descramble)
// ===========================================================================
Bytes X1Descramble(const uint8_t* data, size_t len, uint32_t startPos) {
    Bytes out(len);
    for (size_t i = 0; i < len; ++i) out[i] = X1DescrambleByte(data[i], startPos + static_cast<uint32_t>(i));
    return out;
}

// ===========================================================================
// MSX  (from egg_msx_decrypt.py)
// ===========================================================================
const uint8_t kMsxKeyOld[16] = {0xB4, 0xD1, 0xB4, 0xBD, 0xB4, 0xAF, 0xB8, 0xBD,
                                0xB1, 0xBF, 0xBC, 0xB4, 0xB0, 0xBC, 0xAE, 0xDD};
const uint8_t kMsxKeyD4e[16] = {0x33, 0x53, 0x93, 0x63, 0xA3, 0xC3, 0x35, 0x55,
                                0x95, 0x65, 0xA5, 0xC5, 0x36, 0x56, 0x96, 0x66};

Bytes MsxPlayerOldDecrypt(ByteSpan data, ByteSpan key) {
    if (data.empty()) return {};
    size_t start;
    unsigned shift;
    unsigned keyBase;
    if ((data[0] & 0xF0) == 0x80) {          // header mode (e.g. DISK.ROM, disk images)
        start   = 1;
        shift   = 4 - (data[0] & 3);
        keyBase = data[0] & 0xFC;
    } else {                                 // raw mode (e.g. MSX.ROM)
        start   = 0;
        shift   = 4;
        keyBase = 0;
    }
    Bytes out(data.size() - start);
    for (size_t i = 0; i < out.size(); ++i) {
        uint8_t t = ror8(data[start + i], shift);
        out[i] = static_cast<uint8_t>(t ^ key[(keyBase + i) & 0x0F]);
    }
    return out;
}

Bytes MsxD4eDecrypt(ByteSpan data, ByteSpan key) {
    Bytes out(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t x = static_cast<uint8_t>(data[i] ^ key[i & 0x0F]);
        out[i] = static_cast<uint8_t>((x << 4) | (x >> 4));
    }
    return out;
}

}  // namespace crypto
