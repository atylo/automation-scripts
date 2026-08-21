#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <iomanip>
#include <filesystem>
#include <windows.h> 
#include <string_view>
#include <memory>

namespace fs = std::filesystem;

// =============================================================
// Data Structures
// =============================================================

struct ExtractedResource {
    std::string name;
    std::vector<uint8_t> data;
};

// =============================================================
// 1. Tiny AES-128-ECB Implementation
// =============================================================

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

class AES128 {
public:
    AES128(const uint8_t* key) {
        ExpandKey(key);
    }
    void DecryptBlock(const uint8_t* in, uint8_t* out) {
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) state[i][j] = in[i + 4 * j];
        AddRoundKey(10);
        for (int round = 9; round > 0; round--) {
            InvShiftRows(); InvSubBytes(); AddRoundKey(round); InvMixColumns();
        }
        InvShiftRows(); InvSubBytes(); AddRoundKey(0);
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) out[i + 4 * j] = state[i][j];
    }
private:
    uint8_t roundKeys[176];
    uint8_t state[4][4];
    void ExpandKey(const uint8_t* key) {
        for (int i = 0; i < 16; i++) roundKeys[i] = key[i];
        uint8_t temp[4], k = 0;
        for (int i = 16; i < 176; i += 4) {
            for (int j = 0; j < 4; j++) temp[j] = roundKeys[i - 4 + j];
            if (i % 16 == 0) {
                uint8_t t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
                for (int j = 0; j < 4; j++) temp[j] = sbox[temp[j]];
                temp[0] ^= Rcon[++k];
            }
            for (int j = 0; j < 4; j++) roundKeys[i + j] = roundKeys[i - 16 + j] ^ temp[j];
        }
    }
    void AddRoundKey(int round) {
        for (int c = 0; c < 4; c++) for (int r = 0; r < 4; r++) state[r][c] ^= roundKeys[round * 16 + c * 4 + r];
    }
    void InvSubBytes() {
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) state[i][j] = rsbox[state[i][j]];
    }
    void InvShiftRows() {
        uint8_t t;
        t = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = t;
        t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t; t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;
        t = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = t;
    }
    uint8_t xtime(uint8_t x) { return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)); }
    uint8_t Multiply(uint8_t x, uint8_t y) {
        return (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ ((y >> 2 & 1) * xtime(xtime(x))) ^
                ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^ ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
    }
    void InvMixColumns() {
        uint8_t a, b, c, d;
        for (int i = 0; i < 4; i++) {
            a = state[0][i]; b = state[1][i]; c = state[2][i]; d = state[3][i];
            state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
            state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
            state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
            state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
        }
    }
};

// =============================================================
// 2. LZH Decompression (Ported from QuickBMS lzhxlib.c)
//    Implements standard Okumura LH5/LH4 algorithm
// =============================================================

namespace LZH {

using BitBufType = uint16_t;
constexpr size_t CHAR_BIT_LZH = 8;
constexpr size_t UCHAR_MAX_LZH = 255;
constexpr size_t BITBUFSIZ = (CHAR_BIT_LZH * sizeof(BitBufType));
constexpr size_t DICBIT = 13; // LH5=13, LH4=12
constexpr size_t DICSIZ = (1U << DICBIT);
constexpr size_t MAXMATCH = 256;
constexpr size_t THRESHOLD = 3;
constexpr size_t NC = (UCHAR_MAX_LZH + MAXMATCH + 2 - THRESHOLD);
constexpr size_t CBIT = 9;
constexpr size_t CODE_BIT = 16;
constexpr size_t NP = (DICBIT + 1);
constexpr size_t NT = (CODE_BIT + 3);
constexpr size_t PBIT = 4;
constexpr size_t TBIT = 5;
constexpr size_t NPT = (NT > NP) ? NT : NP;

class Decoder {
public:
    Decoder(const uint8_t* in, size_t insz, std::vector<uint8_t>& out)
        : src(in), src_end(in + insz), dst(out) {
        dst.clear();
    }

    void Decode(size_t out_size) {
        init_getbits();

        std::vector<uint8_t> buffer(DICSIZ, 0);
        uint32_t count = 0;
        uint32_t loc = 0;
        uint16_t blocksize = 0;

        while (count < out_size) {
            if (blocksize == 0) {
                blocksize = getbits(16);
                read_pt_len(NT, TBIT, 3);
                read_c_len();
                read_pt_len(NP, PBIT, -1);
            }
            blocksize--;

            uint16_t c = decode_c();
            if (c <= 255) {
                buffer[loc++] = (uint8_t)c;
                loc &= (DICSIZ - 1);
                dst.push_back((uint8_t)c);
                count++;
            } else {
                uint32_t j = c - 256 + THRESHOLD;
                uint32_t i = (loc - decode_p() - 1) & (DICSIZ - 1);
                while (j > 0 && count < out_size) {
                    uint8_t val = buffer[i];
                    buffer[loc++] = val;
                    loc &= (DICSIZ - 1);
                    i = (i + 1) & (DICSIZ - 1);
                    dst.push_back(val);
                    count++;
                    j--;
                }
            }
        }
    }

private:
    const uint8_t* src;
    const uint8_t* src_end;
    std::vector<uint8_t>& dst;

    uint16_t bitbuf = 0;
    uint32_t subbitbuf = 0;
    int bitcount = 0;

    uint16_t left[2 * NC - 1];
    uint16_t right[2 * NC - 1];
    uint8_t c_len[NC];
    uint8_t pt_len[NPT];
    uint16_t c_table[4096];
    uint16_t pt_table[256];

    void fillbuf(int n) {
        bitbuf = (bitbuf << n) & 0xffff;
        while (n > bitcount) {
            bitbuf |= subbitbuf << (n -= bitcount);
            if (src < src_end) {
                subbitbuf = *src++;
            } else {
                subbitbuf = 0;
            }
            bitcount = CHAR_BIT_LZH;
        }
        bitbuf |= subbitbuf >> (bitcount -= n);
    }

    uint16_t getbits(int n) {
        uint16_t x;
        x = bitbuf >> (BITBUFSIZ - n);
        fillbuf(n);
        return x;
    }

    void init_getbits() {
        bitbuf = 0;
        subbitbuf = 0;
        bitcount = 0;
        fillbuf(BITBUFSIZ);
    }

    void make_table(int nchar, uint8_t* bitlen, int tablebits, uint16_t* table) {
        uint16_t count[17], weight[17], start[18];
        uint32_t i, k, len, ch, jutbits, avail, nextcode, mask;
        uint16_t *p;

        for (i = 1; i <= 16; i++) count[i] = 0;
        for (i = 0; i < (uint32_t)nchar; i++) count[bitlen[i]]++;

        start[1] = 0;
        for (i = 1; i <= 16; i++) start[i + 1] = start[i] + (count[i] << (16 - i));

        jutbits = 16 - tablebits;
        for (i = 1; i <= (uint32_t)tablebits; i++) {
            start[i] >>= jutbits;
            weight[i] = 1U << (tablebits - i);
        }
        while (i <= 16) {
            weight[i] = 1U << (16 - i);
            i++;
        }

        i = start[tablebits + 1] >> jutbits;
        if (i != (uint16_t)(1U << 16)) {
            k = 1U << tablebits;
            while (i != k) table[i++] = 0;
        }

        avail = nchar;
        mask = 1U << (15 - tablebits);
        for (ch = 0; ch < (uint32_t)nchar; ch++) {
            if ((len = bitlen[ch]) == 0) continue;
            nextcode = start[len] + weight[len];
            if (len <= (uint32_t)tablebits) {
                for (i = start[len]; i < nextcode; i++) table[i] = ch;
            } else {
                k = start[len];
                p = &table[k >> jutbits];
                i = len - tablebits;
                while (i != 0) {
                    if (*p == 0) {
                        right[avail] = left[avail] = 0;
                        *p = avail++;
                    }
                    if (k & mask) p = &right[*p];
                    else          p = &left[*p];
                    k <<= 1;
                    i--;
                }
                *p = ch;
            }
            start[len] = nextcode;
        }
    }

    void read_pt_len(int nn, int nbit, int i_special) {
        int i, n;
        int c;
        uint32_t mask;

        n = getbits(nbit);
        if (n == 0) {
            c = getbits(nbit);
            for (i = 0; i < nn; i++) pt_len[i] = 0;
            for (i = 0; i < 256; i++) pt_table[i] = c;
        } else {
            i = 0;
            while (i < n) {
                c = bitbuf >> (BITBUFSIZ - 3);
                if (c == 7) {
                    mask = 1U << (BITBUFSIZ - 1 - 3);
                    while (mask & bitbuf) {
                        mask >>= 1;
                        c++;
                    }
                }
                fillbuf((c < 7) ? 3 : c - 3);
                pt_len[i++] = c;
                if (i == i_special) {
                    c = getbits(2);
                    while (--c >= 0) pt_len[i++] = 0;
                }
            }
            while (i < nn) pt_len[i++] = 0;
            make_table(nn, pt_len, 8, pt_table);
        }
    }

    void read_c_len() {
        int i, n;
        int c;
        uint32_t mask;

        n = getbits(CBIT);
        if (n == 0) {
            c = getbits(CBIT);
            for (i = 0; i < NC; i++) c_len[i] = 0;
            for (i = 0; i < 4096; i++) c_table[i] = c;
        } else {
            i = 0;
            while (i < n) {
                c = pt_table[bitbuf >> (BITBUFSIZ - 8)];
                if (c >= NT) {
                    mask = 1U << (BITBUFSIZ - 1 - 8);
                    do {
                        if (bitbuf & mask) c = right[c];
                        else               c = left[c];
                        mask >>= 1;
                    } while (c >= NT);
                }
                fillbuf(pt_len[c]);
                if (c <= 2) {
                    if (c == 0) c = 1;
                    else if (c == 1) c = getbits(4) + 3;
                    else             c = getbits(CBIT) + 20;
                    while (--c >= 0) c_len[i++] = 0;
                } else {
                    c_len[i++] = c - 2;
                }
            }
            while (i < NC) c_len[i++] = 0;
            make_table(NC, c_len, 12, c_table);
        }
    }

    uint16_t decode_c() {
        uint16_t j, mask;
        j = c_table[bitbuf >> (BITBUFSIZ - 12)];
        if (j >= NC) {
            mask = 1U << (BITBUFSIZ - 1 - 12);
            do {
                if (bitbuf & mask) j = right[j];
                else               j = left[j];
                mask >>= 1;
            } while (j >= NC);
        }
        fillbuf(c_len[j]);
        return j;
    }

    uint16_t decode_p() {
        uint16_t j, mask;
        j = pt_table[bitbuf >> (BITBUFSIZ - 8)];
        if (j >= NP) {
            mask = 1U << (BITBUFSIZ - 1 - 8);
            do {
                if (bitbuf & mask) j = right[j];
                else               j = left[j];
                mask >>= 1;
            } while (j >= NP);
        }
        fillbuf(pt_len[j]);
        if (j != 0) j = (1U << (j - 1)) + getbits(j - 1);
        return j;
    }
};

} // namespace LZH

// =============================================================
// 3. Automation and Extraction Logic
// =============================================================

// Hardcoded AES key we are looking for in .rdata
static const uint8_t TARGET_AES_KEY[16] = {
    0xEA, 0x40, 0x68, 0x99, 0xC6, 0x78, 0x4B, 0x71, 
    0x28, 0xA9, 0x96, 0x88, 0x64, 0x6B, 0x3D, 0x00
};

// Parses the PE headers, finds .rdata, and scans it for the AES key
bool CheckIfAesKeyExistsInRData(const fs::path& exePath) {
    // Open at the end with std::ios::ate to get the total file size
    std::ifstream file(exePath, std::ios::binary | std::ios::ate);
    if (!file) return false;

    // 1. Get exact file size to prevent out-of-bounds reads
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Ensure it's big enough to even hold a DOS header
    if (fileSize < sizeof(IMAGE_DOS_HEADER)) return false;

    IMAGE_DOS_HEADER dosHeader;
    if (!file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER))) return false;
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return false;

    // 2. Validate e_lfanew (NT Header offset)
    // It must be a positive offset and leave enough room for the NT signature
    if (dosHeader.e_lfanew <= 0 || dosHeader.e_lfanew >= (fileSize - sizeof(DWORD))) return false;

    file.seekg(dosHeader.e_lfanew, std::ios::beg);

    DWORD peSignature;
    if (!file.read(reinterpret_cast<char*>(&peSignature), sizeof(DWORD))) return false;
    if (peSignature != IMAGE_NT_SIGNATURE) return false;

    IMAGE_FILE_HEADER fileHeader;
    if (!file.read(reinterpret_cast<char*>(&fileHeader), sizeof(IMAGE_FILE_HEADER))) return false;

    // 3. Prevent skipping past the end of the file 
    // Calculate where the section headers begin
    std::streampos currentPos = file.tellg();
    if (currentPos + static_cast<std::streamoff>(fileHeader.SizeOfOptionalHeader) > fileSize) {
        return false;
    }

    // Skip the Optional Header
    file.seekg(fileHeader.SizeOfOptionalHeader, std::ios::cur);

    // Iterate through sections to find .rdata
    for (int i = 0; i < fileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sectionHeader;
        
        // 4. Validate we can actually read the section header
        if (!file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(IMAGE_SECTION_HEADER))) break;

        if (std::strncmp(reinterpret_cast<const char*>(sectionHeader.Name), ".rdata", 8) == 0) {
            
            DWORD offset = sectionHeader.PointerToRawData;
            DWORD size = sectionHeader.SizeOfRawData;

            // 5. Validate the section's raw data actually exists within the file boundaries
            if (size == 0 || (static_cast<std::streamoff>(offset) + size > fileSize)) {
                continue; 
            }

            std::vector<uint8_t> rdata(size);
            std::streampos savedPos = file.tellg(); 
            
            file.seekg(offset, std::ios::beg);
            if (file.read(reinterpret_cast<char*>(rdata.data()), size)) {
                auto it = std::search(rdata.begin(), rdata.end(), std::begin(TARGET_AES_KEY), std::end(TARGET_AES_KEY));
                if (it != rdata.end()) {
                    return true; // Key found
                }
            }
            
            // Restore stream position to read the next section header
            file.seekg(savedPos, std::ios::beg); 
        }
    }
    return false;
}

void ProcessPayload(std::vector<uint8_t>& fileData, const std::string& outputPath, bool useAES) {
    size_t fileSize = fileData.size();
    
    // --- Step 1: Decrypt AES-128-ECB ---
    if (useAES) {
        AES128 aes(TARGET_AES_KEY);
        size_t numBlocks = fileSize / 16;
        for (size_t i = 0; i < numBlocks; ++i) {
            size_t offset = i * 16;
            aes.DecryptBlock(&fileData[offset], &fileData[offset]);
        }
    }

    // --- Step 2: Parse Header Safely ---
    if (fileSize < 4) {
        std::cerr << "  -> Error: Data too small for header." << std::endl;
        return;
    }

    uint32_t header = 0;
    std::memcpy(&header, fileData.data(), sizeof(header));
    header ^= 0x18885963;

    if ((header % 0x4D) == 0) {
        uint32_t zsize = header / 0x4D;
        
        size_t compressedPayloadSize = fileSize - 4;
        const uint8_t* compressedPtr = fileData.data() + 4;
        
        // --- Step 3: Decompress LZH ---
        std::vector<uint8_t> decompressedData;
        decompressedData.reserve(zsize);

        try {
            LZH::Decoder decoder(compressedPtr, compressedPayloadSize, decompressedData);
            decoder.Decode(zsize);
        } catch (...) {
            std::cerr << "  -> Warning: Decompression ended abruptly." << std::endl;
        }

        std::ofstream outFile(outputPath, std::ios::binary);
        if (outFile) {
            outFile.write(reinterpret_cast<const char*>(decompressedData.data()), decompressedData.size());
            outFile.close();
            std::cout << "  -> Success! Extracted " << decompressedData.size() << " bytes.\n" << std::endl;
        } else {
            std::cerr << "  -> Error: Could not write output file." << std::endl;
        }

    } else {
        std::cerr << "  -> Error: Header validation failed (header % 0x4D != 0)." << std::endl;
    }
}


std::string GetExtension(std::string_view name) {
    if (name.starts_with("CONF")) return ".txt";
    if (name.starts_with("DISK")) return ".pds";
    if (name.starts_with("LOGO")) return ".bmp";
    
    if (name.starts_with("HH")  || name.starts_with("TOP") || name.starts_with("SD") ||
        name.starts_with("BD")  || name.starts_with("TOM") || name.starts_with("RIM")) {
        return ".wav";
    }
    
    return ".rom";
}

// Memory Cleanup Helper for HMODULE
struct HModuleDeleter {
    void operator()(HMODULE h) const { if (h) FreeLibrary(h); }
};
using UniqueHModule = std::unique_ptr<std::remove_pointer_t<HMODULE>, HModuleDeleter>;

// -------------------------------------------------------------
// Callback to just collect raw resource bytes into memory
// -------------------------------------------------------------
BOOL CALLBACK EnumResNameProc(HMODULE hModule, LPCSTR lpszType, LPSTR lpszName, LONG_PTR lParam) {
    auto* resourceList = reinterpret_cast<std::vector<ExtractedResource>*>(lParam);
    
    HRSRC hResInfo = FindResourceA(hModule, lpszName, lpszType);
    if (!hResInfo) return TRUE;
    
    HGLOBAL hResData = LoadResource(hModule, hResInfo);
    if (!hResData) return TRUE;
    
    DWORD resSize = SizeofResource(hModule, hResInfo);
    void* pResData = LockResource(hResData);
    
    if (resSize == 0 || !pResData) return TRUE;

    std::string resNameStr;
    if (IS_INTRESOURCE(lpszName)) {
        resNameStr = std::to_string(reinterpret_cast<uintptr_t>(lpszName));
    } else {
        resNameStr = lpszName;
    }

    // Copy raw bytes to vector and add to our list
    const uint8_t* byteData = static_cast<const uint8_t*>(pResData);
    std::vector<uint8_t> fileData(byteData, byteData + resSize);
    
    resourceList->push_back({ resNameStr, std::move(fileData) });

    return TRUE;
}

int main(int argc, char* argv[]) {
    std::cout << "===ProjectEGG old_PC98 Extraction Utility===\n";
    
    if (argc < 2) {
        std::cout << "   Extracts and decompresses from EXE BINARY resources.\n";
        std::cout << "   Automatically detects AES encryption via .rdata scan.\n\n";
        fs::path exeName = argv[0];
        std::cerr << "Usage: " << exeName.filename().string() << " <input.exe>" << std::endl;
        return 1;
    }

    fs::path inputPath = argv[1];

    if (!fs::exists(inputPath) || !fs::is_regular_file(inputPath)) {
        std::cerr << "Error: Could not find executable: " << inputPath << std::endl;
        return 1;
    }

    // 1. Scan for AES Key
    bool useAES = CheckIfAesKeyExistsInRData(inputPath);
    
    fs::path outputDir = inputPath.parent_path() / inputPath.stem();
    if (!fs::exists(outputDir)) {
        fs::create_directory(outputDir);
    }
    std::cout << "Output directory: " << outputDir.string() << "\n" << std::endl;

    // 2. Load the executable safely with RAII
    UniqueHModule hExe(LoadLibraryExA(inputPath.string().c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE));
    if (!hExe) {
        std::cerr << "Error: Could not load the executable to parse resources. Error Code: " << GetLastError() << std::endl;
        return 1;
    }

    // 3. Setup our vector and enumerate resources
    std::vector<ExtractedResource> resources;
    EnumResourceNamesA(hExe.get(), "BINARY", EnumResNameProc, reinterpret_cast<LONG_PTR>(&resources));

    // 4. Process all collected files
    for (auto& item : resources) {
        std::cout << "Processing Resource: " << item.name << " (" << item.data.size() << " bytes)\n";
        
        std::string extension = GetExtension(item.name);
        fs::path outPath = outputDir / (item.name + extension);
        
        ProcessPayload(item.data, outPath.string(), useAES);
    }

    std::cout << "Extraction complete." << std::endl;
    return 0;
}