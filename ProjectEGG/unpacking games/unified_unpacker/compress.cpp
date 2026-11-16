#include "compress.h"

#include <array>
#include <cstring>
#include <stdexcept>

namespace compress {

// ===========================================================================
// LZSS
// ===========================================================================
Bytes LzssDecompress(const uint8_t* src, size_t srcLen, size_t outSize, bool invert) {
    constexpr size_t kSafetyLimit = 64u * 1024u * 1024u;
    const size_t limit = outSize ? outSize : kSafetyLimit;
    const uint8_t x = invert ? 0xFF : 0x00;

    Bytes out;
    if (outSize) out.reserve(outSize);

    std::array<uint8_t, 4096> hist{};
    uint32_t pos = 0xFEE;
    size_t si = 0;
    unsigned flags = 0;
    int bits = 0;

    while (out.size() < limit) {
        if (bits == 0) {
            if (si >= srcLen) break;
            flags = src[si++] ^ x;
            bits = 8;
        }
        bool literal = (flags & 1) != 0;
        flags >>= 1;
        --bits;

        if (literal) {
            if (si >= srcLen) break;
            uint8_t v = src[si++] ^ x;
            out.push_back(v);
            hist[pos] = v;
            pos = (pos + 1) & 0xFFF;
        } else {
            if (si + 1 >= srcLen) break;
            uint8_t b1 = src[si++] ^ x;
            uint8_t b2 = src[si++] ^ x;
            uint32_t offset = b1 | ((b2 & 0xF0u) << 4);
            uint32_t length = (b2 & 0x0Fu) + 3;
            for (uint32_t k = 0; k < length && out.size() < limit; ++k) {
                uint8_t v = hist[(offset + k) & 0xFFF];
                out.push_back(v);
                hist[pos] = v;
                pos = (pos + 1) & 0xFFF;
            }
        }
    }
    return out;
}

// ===========================================================================
// LZH (LH5) - ported from QuickBMS lzhxlib.c via egg_old_pc98_decrypt.cpp,
// with bounds guards so that corrupt data cannot overrun the tables.
// ===========================================================================
namespace {

using BitBufType = uint16_t;
constexpr size_t CHAR_BIT_LZH = 8;
constexpr size_t BITBUFSIZ    = CHAR_BIT_LZH * sizeof(BitBufType);
constexpr size_t DICBIT       = 13;
constexpr size_t DICSIZ       = 1u << DICBIT;
constexpr size_t MAXMATCH     = 256;
constexpr size_t THRESHOLD    = 3;
constexpr size_t NC           = 255 + MAXMATCH + 2 - THRESHOLD;
constexpr size_t CBIT         = 9;
constexpr size_t CODE_BIT     = 16;
constexpr size_t NP           = DICBIT + 1;
constexpr size_t NT           = CODE_BIT + 3;
constexpr size_t PBIT         = 4;
constexpr size_t TBIT         = 5;
constexpr size_t NPT          = (NT > NP) ? NT : NP;

[[noreturn]] void Corrupt() { throw std::runtime_error("corrupt LZH stream"); }

class LzhDecoder {
public:
    LzhDecoder(const uint8_t* in, size_t insz, Bytes& out) : src_(in), srcEnd_(in + insz), dst_(out) { dst_.clear(); }

    void Decode(size_t outSize) {
        InitGetBits();
        std::vector<uint8_t> buffer(DICSIZ, 0);
        size_t   count = 0;
        uint32_t loc = 0;
        uint16_t blocksize = 0;

        while (count < outSize) {
            if (blocksize == 0) {
                blocksize = GetBits(16);
                ReadPtLen(NT, TBIT, 3);
                ReadCLen();
                ReadPtLen(NP, PBIT, -1);
            }
            --blocksize;

            uint16_t c = DecodeC();
            if (c <= 255) {
                buffer[loc++] = static_cast<uint8_t>(c);
                loc &= (DICSIZ - 1);
                dst_.push_back(static_cast<uint8_t>(c));
                ++count;
            } else {
                uint32_t j = c - 256 + THRESHOLD;
                uint32_t i = (loc - DecodeP() - 1) & (DICSIZ - 1);
                while (j > 0 && count < outSize) {
                    uint8_t v = buffer[i];
                    buffer[loc++] = v;
                    loc &= (DICSIZ - 1);
                    i = (i + 1) & (DICSIZ - 1);
                    dst_.push_back(v);
                    ++count;
                    --j;
                }
            }
        }
    }

private:
    const uint8_t* src_;
    const uint8_t* srcEnd_;
    Bytes& dst_;

    uint16_t bitbuf_ = 0;
    uint32_t subbitbuf_ = 0;
    int bitcount_ = 0;

    uint16_t left_[2 * NC - 1]{};
    uint16_t right_[2 * NC - 1]{};
    uint8_t  cLen_[NC]{};
    uint8_t  ptLen_[NPT]{};
    uint16_t cTable_[4096]{};
    uint16_t ptTable_[256]{};

    void FillBuf(int n) {
        bitbuf_ = static_cast<uint16_t>((bitbuf_ << n) & 0xffff);
        while (n > bitcount_) {
            bitbuf_ |= static_cast<uint16_t>(subbitbuf_ << (n -= bitcount_));
            subbitbuf_ = (src_ < srcEnd_) ? *src_++ : 0;
            bitcount_ = CHAR_BIT_LZH;
        }
        bitbuf_ |= static_cast<uint16_t>(subbitbuf_ >> (bitcount_ -= n));
    }

    uint16_t GetBits(int n) {
        uint16_t x = static_cast<uint16_t>(bitbuf_ >> (BITBUFSIZ - n));
        FillBuf(n);
        return x;
    }

    void InitGetBits() {
        bitbuf_ = 0; subbitbuf_ = 0; bitcount_ = 0;
        FillBuf(BITBUFSIZ);
    }

    void MakeTable(int nchar, const uint8_t* bitlen, int tablebits, uint16_t* table) {
        uint16_t count[17], weight[17], start[18];
        uint32_t i, k, len, ch, jutbits, avail, nextcode, mask;
        uint16_t* p;

        for (i = 1; i <= 16; ++i) count[i] = 0;
        for (i = 0; i < static_cast<uint32_t>(nchar); ++i) {
            if (bitlen[i] > 16) Corrupt();
            count[bitlen[i]]++;
        }

        start[1] = 0;
        for (i = 1; i <= 16; ++i) start[i + 1] = static_cast<uint16_t>(start[i] + (count[i] << (16 - i)));

        jutbits = 16 - tablebits;
        for (i = 1; i <= static_cast<uint32_t>(tablebits); ++i) {
            start[i] >>= jutbits;
            weight[i] = static_cast<uint16_t>(1u << (tablebits - i));
        }
        while (i <= 16) {
            weight[i] = static_cast<uint16_t>(1u << (16 - i));
            ++i;
        }

        i = start[tablebits + 1] >> jutbits;
        if (i != static_cast<uint16_t>(1u << 16)) {
            k = 1u << tablebits;
            while (i < k) table[i++] = 0;
        }

        avail = static_cast<uint32_t>(nchar);
        mask  = 1u << (15 - tablebits);
        for (ch = 0; ch < static_cast<uint32_t>(nchar); ++ch) {
            if ((len = bitlen[ch]) == 0) continue;
            nextcode = start[len] + weight[len];
            if (len <= static_cast<uint32_t>(tablebits)) {
                if (nextcode > (1u << tablebits)) Corrupt();
                for (i = start[len]; i < nextcode; ++i) table[i] = static_cast<uint16_t>(ch);
            } else {
                k = start[len];
                p = &table[k >> jutbits];
                i = len - tablebits;
                while (i != 0) {
                    if (*p == 0) {
                        if (avail >= 2 * NC - 1) Corrupt();
                        right_[avail] = left_[avail] = 0;
                        *p = static_cast<uint16_t>(avail++);
                    }
                    if (*p >= 2 * NC - 1) Corrupt();
                    p = (k & mask) ? &right_[*p] : &left_[*p];
                    k <<= 1;
                    --i;
                }
                *p = static_cast<uint16_t>(ch);
            }
            start[len] = static_cast<uint16_t>(nextcode);
        }
    }

    void ReadPtLen(int nn, int nbit, int iSpecial) {
        int i, n, c;
        uint32_t mask;

        n = GetBits(nbit);
        if (n == 0) {
            c = GetBits(nbit);
            for (i = 0; i < nn; ++i) ptLen_[i] = 0;
            for (i = 0; i < 256; ++i) ptTable_[i] = static_cast<uint16_t>(c);
        } else {
            if (n > nn) Corrupt();
            i = 0;
            while (i < n) {
                c = bitbuf_ >> (BITBUFSIZ - 3);
                if (c == 7) {
                    mask = 1u << (BITBUFSIZ - 1 - 3);
                    while (mask & bitbuf_) { mask >>= 1; ++c; }
                }
                if (c > 16) Corrupt();
                FillBuf((c < 7) ? 3 : c - 3);
                ptLen_[i++] = static_cast<uint8_t>(c);
                if (i == iSpecial) {
                    c = GetBits(2);
                    while (--c >= 0) {
                        if (i >= nn) Corrupt();
                        ptLen_[i++] = 0;
                    }
                }
            }
            while (i < nn) ptLen_[i++] = 0;
            MakeTable(nn, ptLen_, 8, ptTable_);
        }
    }

    void ReadCLen() {
        int i, n, c;
        uint32_t mask;

        n = GetBits(CBIT);
        if (n == 0) {
            c = GetBits(CBIT);
            for (i = 0; i < static_cast<int>(NC); ++i) cLen_[i] = 0;
            for (i = 0; i < 4096; ++i) cTable_[i] = static_cast<uint16_t>(c);
        } else {
            if (n > static_cast<int>(NC)) Corrupt();
            i = 0;
            while (i < n) {
                c = ptTable_[bitbuf_ >> (BITBUFSIZ - 8)];
                if (c >= static_cast<int>(NT)) {
                    mask = 1u << (BITBUFSIZ - 1 - 8);
                    do {
                        if (mask == 0) Corrupt();
                        c = (bitbuf_ & mask) ? right_[c] : left_[c];
                        mask >>= 1;
                    } while (c >= static_cast<int>(NT));
                }
                FillBuf(ptLen_[c]);
                if (c <= 2) {
                    if (c == 0)      c = 1;
                    else if (c == 1) c = GetBits(4) + 3;
                    else             c = GetBits(CBIT) + 20;
                    while (--c >= 0) {
                        if (i >= static_cast<int>(NC)) Corrupt();
                        cLen_[i++] = 0;
                    }
                } else {
                    if (i >= static_cast<int>(NC)) Corrupt();
                    cLen_[i++] = static_cast<uint8_t>(c - 2);
                }
            }
            while (i < static_cast<int>(NC)) cLen_[i++] = 0;
            MakeTable(NC, cLen_, 12, cTable_);
        }
    }

    uint16_t DecodeC() {
        uint16_t j = cTable_[bitbuf_ >> (BITBUFSIZ - 12)];
        if (j >= NC) {
            uint32_t mask = 1u << (BITBUFSIZ - 1 - 12);
            do {
                if (mask == 0) Corrupt();
                j = (bitbuf_ & mask) ? right_[j] : left_[j];
                mask >>= 1;
            } while (j >= NC);
        }
        FillBuf(cLen_[j]);
        return j;
    }

    uint16_t DecodeP() {
        uint16_t j = ptTable_[bitbuf_ >> (BITBUFSIZ - 8)];
        if (j >= NP) {
            uint32_t mask = 1u << (BITBUFSIZ - 1 - 8);
            do {
                if (mask == 0) Corrupt();
                j = (bitbuf_ & mask) ? right_[j] : left_[j];
                mask >>= 1;
            } while (j >= NP);
        }
        FillBuf(ptLen_[j]);
        if (j != 0) j = static_cast<uint16_t>((1u << (j - 1)) + GetBits(j - 1));
        return j;
    }
};

}  // namespace

bool LzhDecompress(const uint8_t* src, size_t srcLen, size_t outSize, Bytes& out) {
    out.clear();
    out.reserve(outSize);
    try {
        LzhDecoder dec(src, srcLen, out);
        dec.Decode(outSize);
        return true;
    } catch (...) {
        return false;
    }
}

// ===========================================================================
// Adaptive arithmetic decoder (TYPE60)
// ===========================================================================
bool ArithDecompress(const uint8_t* src, size_t srcLen, size_t maxOut, Bytes& out) {
    constexpr int kSymbols = 257;
    out.clear();

    int64_t freq[kSymbols];
    int64_t cum[kSymbols + 1];
    for (int i = 0; i < kSymbols; ++i) freq[i] = 1;
    for (int i = 0; i <= kSymbols; ++i) cum[i] = i;

    size_t ptr = 0;
    auto readByte = [&]() -> int64_t { return ptr < srcLen ? src[ptr++] : 0; };   // zeros past the end

    constexpr int64_t kMask = 0xFFFFFFFF;
    int64_t code = 0, low = 0, range = 0xFFFFFFFF;
    for (int i = 0; i < 4; ++i) code = (code << 8) | readByte();

    while (out.size() < maxOut) {
        int64_t total = cum[kSymbols];
        if (total == 0) break;

        int64_t step = range / total;
        if (step == 0) return false;                               // Python: ZeroDivisionError

        int64_t diff  = code - low;                                // floor division (may be negative)
        int64_t value = diff / step;
        if (diff % step != 0 && diff < 0) --value;

        int symbol = 0;
        for (int i = 0; i < kSymbols; ++i) {
            if (cum[i] <= value && value < cum[i + 1]) { symbol = i; break; }
        }
        if (symbol == 256) break;                                  // end of data
        out.push_back(static_cast<uint8_t>(symbol));

        range = step * freq[symbol];
        low  += step * cum[symbol];

        // model update (+ rescale when the total reaches 0x10000)
        freq[symbol] += 1;
        for (int i = symbol + 1; i <= kSymbols; ++i) cum[i] += 1;
        if (cum[kSymbols] >= 0x10000) {
            cum[0] = 0;
            int64_t current = 0;
            for (int i = 0; i < kSymbols; ++i) {
                int64_t nf = (freq[i] | 2) >> 1;
                freq[i] = nf;
                current += nf;
                cum[i + 1] = current;
            }
        }

        // renormalization (iteration guards: the original would hang on a corrupt state)
        int guard = 0;
        while (((low ^ (low + range)) & 0xFF000000) == 0) {
            if (++guard > 8) return false;
            code  = ((code << 8) | readByte()) & kMask;
            range = (range << 8) & kMask;
            low   = (low << 8) & kMask;
        }
        guard = 0;
        while (range < 0x10000) {
            if (++guard > 8) return false;
            range = ((-low) & 0xFFFF) << 8;
            code  = ((code << 8) | readByte()) & kMask;
            low   = (low << 8) & kMask;
        }
    }
    return true;
}

// ===========================================================================
// zlib / inflate (RFC 1950 / 1951)
// ===========================================================================
namespace {

constexpr int kMaxBits = 15;

struct Huffman {
    uint16_t count[kMaxBits + 1];
    uint16_t symbol[288];
};

struct InflateState {
    const uint8_t* in;
    size_t inLen;
    size_t pos = 0;
    uint32_t bitBuf = 0;
    int bitCnt = 0;
    Bytes& out;

    int Bits(int need) {                       // returns -1 at end of input
        uint32_t val = bitBuf;
        while (bitCnt < need) {
            if (pos >= inLen) return -1;
            val |= static_cast<uint32_t>(in[pos++]) << bitCnt;
            bitCnt += 8;
        }
        bitBuf = val >> need;
        bitCnt -= need;
        return static_cast<int>(val & ((1u << need) - 1));
    }
};

int Construct(Huffman& h, const uint16_t* length, int n) {
    for (int l = 0; l <= kMaxBits; ++l) h.count[l] = 0;
    for (int s = 0; s < n; ++s) h.count[length[s]]++;
    if (h.count[0] == n) return 0;
    int left = 1;
    for (int l = 1; l <= kMaxBits; ++l) {
        left <<= 1;
        left -= h.count[l];
        if (left < 0) return left;
    }
    uint16_t offs[kMaxBits + 1];
    offs[1] = 0;
    for (int l = 1; l < kMaxBits; ++l) offs[l + 1] = static_cast<uint16_t>(offs[l] + h.count[l]);
    for (int s = 0; s < n; ++s)
        if (length[s] != 0) h.symbol[offs[length[s]]++] = static_cast<uint16_t>(s);
    return left;
}

int Decode(InflateState& s, const Huffman& h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= kMaxBits; ++len) {
        int b = s.Bits(1);
        if (b < 0) return -1;
        code |= b;
        int count = h.count[len];
        if (code - count < first) return h.symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -2;
}

const uint16_t kLenBase[29]  = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
const uint16_t kLenExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
const uint16_t kDistBase[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
const uint16_t kDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

bool InflateCodes(InflateState& s, const Huffman& lencode, const Huffman& distcode) {
    while (true) {
        int sym = Decode(s, lencode);
        if (sym < 0) return false;
        if (sym < 256) {
            s.out.push_back(static_cast<uint8_t>(sym));
        } else if (sym == 256) {
            return true;
        } else {
            sym -= 257;
            if (sym >= 29) return false;
            int eb = s.Bits(kLenExtra[sym]);
            if (eb < 0) return false;
            int len = kLenBase[sym] + eb;
            int ds = Decode(s, distcode);
            if (ds < 0 || ds >= 30) return false;
            int db = s.Bits(kDistExtra[ds]);
            if (db < 0) return false;
            size_t dist = static_cast<size_t>(kDistBase[ds]) + static_cast<size_t>(db);
            if (dist > s.out.size()) return false;
            size_t from = s.out.size() - dist;
            for (int i = 0; i < len; ++i) s.out.push_back(s.out[from + i]);
        }
    }
}

bool InflateStored(InflateState& s) {
    s.bitBuf = 0;
    s.bitCnt = 0;
    if (s.pos + 4 > s.inLen) return false;
    unsigned len  = s.in[s.pos] | (s.in[s.pos + 1] << 8);
    unsigned nlen = s.in[s.pos + 2] | (s.in[s.pos + 3] << 8);
    s.pos += 4;
    if (len != (~nlen & 0xFFFFu)) return false;
    if (s.pos + len > s.inLen) return false;
    s.out.insert(s.out.end(), s.in + s.pos, s.in + s.pos + len);
    s.pos += len;
    return true;
}

bool InflateFixed(InflateState& s) {
    static Huffman lencode, distcode;
    static bool init = false;
    if (!init) {
        uint16_t lengths[288];
        int sym = 0;
        for (; sym < 144; ++sym) lengths[sym] = 8;
        for (; sym < 256; ++sym) lengths[sym] = 9;
        for (; sym < 280; ++sym) lengths[sym] = 7;
        for (; sym < 288; ++sym) lengths[sym] = 8;
        Construct(lencode, lengths, 288);
        for (sym = 0; sym < 30; ++sym) lengths[sym] = 5;
        Construct(distcode, lengths, 30);
        init = true;
    }
    return InflateCodes(s, lencode, distcode);
}

bool InflateDynamic(InflateState& s) {
    static const uint8_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
    uint16_t lengths[320];
    Huffman lencode, distcode;

    int nlen = s.Bits(5), ndist = s.Bits(5), ncode = s.Bits(4);
    if (nlen < 0 || ndist < 0 || ncode < 0) return false;
    nlen += 257; ndist += 1; ncode += 4;
    if (nlen > 286 || ndist > 30) return false;

    int index = 0;
    for (; index < ncode; ++index) {
        int v = s.Bits(3);
        if (v < 0) return false;
        lengths[order[index]] = static_cast<uint16_t>(v);
    }
    for (; index < 19; ++index) lengths[order[index]] = 0;

    if (Construct(lencode, lengths, 19) != 0) return false;

    index = 0;
    while (index < nlen + ndist) {
        int symbol = Decode(s, lencode);
        if (symbol < 0) return false;
        if (symbol < 16) {
            lengths[index++] = static_cast<uint16_t>(symbol);
        } else {
            int len = 0, rep;
            if (symbol == 16) {
                if (index == 0) return false;
                len = lengths[index - 1];
                rep = s.Bits(2);
                if (rep < 0) return false;
                rep += 3;
            } else if (symbol == 17) {
                rep = s.Bits(3);
                if (rep < 0) return false;
                rep += 3;
            } else {
                rep = s.Bits(7);
                if (rep < 0) return false;
                rep += 11;
            }
            if (index + rep > nlen + ndist) return false;
            while (rep--) lengths[index++] = static_cast<uint16_t>(len);
        }
    }
    if (lengths[256] == 0) return false;

    int err = Construct(lencode, lengths, nlen);
    if (err && (err < 0 || nlen != lencode.count[0] + lencode.count[1])) return false;
    err = Construct(distcode, lengths + nlen, ndist);
    if (err && (err < 0 || ndist != distcode.count[0] + distcode.count[1])) return false;
    return InflateCodes(s, lencode, distcode);
}

uint32_t Adler32(const uint8_t* p, size_t n) {
    uint32_t a = 1, b = 0;
    while (n) {
        size_t chunk = n < 5552 ? n : 5552;
        for (size_t i = 0; i < chunk; ++i) { a += p[i]; b += a; }
        a %= 65521; b %= 65521;
        p += chunk; n -= chunk;
    }
    return (b << 16) | a;
}

}  // namespace

bool ZlibDecompress(const uint8_t* src, size_t srcLen, Bytes& out) {
    out.clear();
    if (srcLen < 6) return false;
    unsigned cmf = src[0], flg = src[1];
    if ((cmf * 256 + flg) % 31 != 0) return false;
    if ((cmf & 0x0F) != 8) return false;       // deflate
    if (flg & 0x20) return false;              // preset dictionary not supported

    InflateState s{src + 2, srcLen - 2, 0, 0, 0, out};
    int last;
    do {
        last = s.Bits(1);
        int type = s.Bits(2);
        if (last < 0 || type < 0) return false;
        bool ok;
        if (type == 0)      ok = InflateStored(s);
        else if (type == 1) ok = InflateFixed(s);
        else if (type == 2) ok = InflateDynamic(s);
        else                ok = false;
        if (!ok) return false;
    } while (!last);

    // Adler-32 follows on the next byte boundary.
    if (s.pos + 4 > s.inLen) return false;
    const uint8_t* t = s.in + s.pos;
    uint32_t want = (static_cast<uint32_t>(t[0]) << 24) | (static_cast<uint32_t>(t[1]) << 16) |
                    (static_cast<uint32_t>(t[2]) << 8) | t[3];
    return want == Adler32(out.data(), out.size());
}

}  // namespace compress
