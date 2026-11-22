// compress.h - decompressors shared by the extractors (no external dependencies).
#pragma once

#include "common.h"

namespace compress {

// Okumura-style LZSS: 4096-byte ring buffer starting at 0xFEE, flag byte read LSB-first
// (1 = literal, 0 = 2-byte match: offset = b1 | (b2 & 0xF0) << 4, length = (b2 & 0x0F) + 3).
//
//  invert  : every input byte (flags, literals, match bytes) is complemented first.
//            Used by the "old Xor + LZSS" executables ("LZSS" signature = B3 A5 AC AC).
//  outSize : number of bytes to produce; 0 = decode until the input is exhausted
//            (hard-capped at 64 MiB).
// Returns the bytes actually produced (shorter than outSize if the stream ends early).
Bytes LzssDecompress(const uint8_t* src, size_t srcLen, size_t outSize, bool invert = false);

// LH5 (8 KiB window) as used by old_PC98 resources. Returns false if the stream is corrupt.
// `out` receives whatever was decoded up to the point of failure.
bool LzhDecompress(const uint8_t* src, size_t srcLen, size_t outSize, Bytes& out);

// Adaptive arithmetic (range) coder over 257 symbols (256 = end of data), used by TYPE60 resources
// (port of ArithmeticDecoder in extract_test_V2.py). `maxOut` caps the output (corrupt streams
// would otherwise never end). Returns false on a decoding error; `out` holds what was decoded so far.
bool ArithDecompress(const uint8_t* src, size_t srcLen, size_t maxOut, Bytes& out);

// zlib stream (RFC 1950/1951), self-contained inflate. Verifies the Adler-32 trailer.
// Returns false on any error; `out` holds the data decoded so far.
bool ZlibDecompress(const uint8_t* src, size_t srcLen, Bytes& out);

}  // namespace compress
