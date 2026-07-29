#!/usr/bin/env python3
"""
LZSS decompressor for the compressed resource format used by this game,
reverse-engineered from a decompiled loader (sub_405E80 / sub_408D30 /
sub_408DC0) plus empirical validation against BMP and EXE/.sbn resources.

=== Container layout ===

Two resource containers have been identified so far:

  BMP-style (loaded via fopen by the decompiled loader):
      offset 0: uint32 LE  - decompressed size
      offset 4: uint8      - "mode" byte, parameterizes the LZSS below
      offset 5: uint8      - unused/padding (always observed as 0x00)
      offset 6: LZSS stream starts here

  EXE/.sbn-style (all 19 sample files share this header):
      offset 0-3: fixed 4-byte header that just echoes "MZ\x90\x00" -
                  NOT a size field (files with different decompressed
                  sizes had an identical header)
      offset 4:   LZSS stream starts here, always mode 4
      No size is stored - decoding naturally stops when the compressed
      input is exhausted, since standalone .sbn files have no trailing
      padding.

=== LZSS parameters (from the decompiled init/decode routines) ===

The "mode" byte parameterizes the whole scheme:
    N (window size)       = 256 << mode
    LEN_MASK               = (256 >> mode) - 1      # how many low bits
                                                       # of the 2nd match
                                                       # byte are length
    F (max match length)   = LEN_MASK + 3
    initial write pos       = N - F
    initial buffer fill     = 0x00

    flags byte, read LSB-first: 1 = literal byte, 0 = 2-byte match
    match encoding (2 bytes: c1, c2):
        length    = (c2 & LEN_MASK) + 3
        match_pos = ((c2 & ~LEN_MASK) << mode) | c1

    mode 4 is the special case that reduces to the "classic" fixed
    12-bit-position/4-bit-length split (N=4096, length 3..18) - this is
    what all EXE/.sbn resources use, basically classic LZSS0

Usage:
    Single file:
        python3 lzss_decompress.py ETEH0003.sbn
        python3 lzss_decompress.py 07.bmp decoded.bmp
        python3 lzss_decompress.py resource.bin out.bmp --size 90054

    Bulk (all files in a folder):
        python3 lzss_decompress.py ./compressed_dir ./decompressed_dir
        python3 lzss_decompress.py ./compressed_dir           # writes next to input
        python3 lzss_decompress.py ./compressed_dir ./out --recursive
"""

import argparse
import struct
import sys
import time
from pathlib import Path

# Signature -> (label, output extension)
KNOWN_SIGNATURES = [
    (b"BM", "BMP", ".bmp"),
    (b"MZ", "EXE/DLL", ".exe"),
    (b"PK\x03\x04", "ZIP", ".zip"),
    (b"RIFF", "RIFF (WAV/AVI/etc.)", ".riff"),
    (b"\x89PNG", "PNG", ".png"),
    (b"GIF8", "GIF", ".gif"),
]


def lzss_decode(data: bytes, start: int, mode: int, out_size: int = None,
                 fill: int = 0x00) -> bytearray:
    """Decompress the mode-parameterized LZSS stream starting at data[start:].

    If out_size is given, decoding stops once that many bytes have been
    produced. Otherwise it decodes until the input is exhausted (the
    normal case for standalone single-resource files, which have no
    trailing padding).
    """
    N = 256 << mode
    LEN_MASK = (256 >> mode) - 1
    F = LEN_MASK + 3
    r = N - F
    buf = bytearray([fill]) * N
    out = bytearray()
    append = out.append
    pos = start
    data_len = len(data)
    flags = 0

    while pos < data_len:
        if out_size is not None and len(out) >= out_size:
            break

        flags >>= 1
        if not (flags & 0x100):
            if pos >= data_len:
                break
            flags = data[pos] | 0xFF00
            pos += 1

        if flags & 1:
            # literal byte
            if pos >= data_len:
                break
            c = data[pos]
            pos += 1
            append(c)
            buf[r] = c
            r += 1
            if r == N:
                r = 0
        else:
            # match: 2-byte (c1, c2) pair
            if pos + 1 >= data_len:
                break
            c1 = data[pos]
            c2 = data[pos + 1]
            pos += 2
            match_pos = ((c2 & ~LEN_MASK) << mode) | c1
            length = (c2 & LEN_MASK) + 3
            if out_size is not None:
                remaining = out_size - len(out)
                if length > remaining:
                    length = remaining
            for _ in range(length):
                cc = buf[match_pos % N]
                append(cc)
                buf[r] = cc
                r += 1
                if r == N:
                    r = 0
                match_pos += 1

    if out_size is not None:
        out = out[:out_size]
    return out


def is_valid_bmp_header(sample: bytes) -> bool:
    if len(sample) < 30 or sample[:2] != b"BM":
        return False
    offset = struct.unpack_from("<I", sample, 10)[0]
    bisize = struct.unpack_from("<I", sample, 14)[0]
    return offset == 54 or bisize in (12, 40, 64, 108, 124)


def is_valid_exe_header(sample: bytes) -> bool:
    return sample[:2] == b"MZ" and b"program" in sample[:100]


def identify(sample: bytes):
    for sig, label, ext in KNOWN_SIGNATURES:
        if sample.startswith(sig):
            return label, ext
    return "unknown", ".bin"


def detect_container(data: bytes, probe: int = 140):
    """Returns (start_offset, mode, kind)."""
    # BMP-style: mode byte is stored explicitly in the header.
    if len(data) > 8:
        mode = data[4]
        if 0 <= mode <= 6:
            sample = lzss_decode(data, 6, mode, out_size=probe)
            if is_valid_bmp_header(bytes(sample)):
                return 6, mode, "BMP"

    # EXE/.sbn-style: fixed 4-byte echo header, stream at offset 4, mode 4.
    if len(data) > 6:
        sample = lzss_decode(data, 4, 4, out_size=probe)
        if is_valid_exe_header(bytes(sample)):
            return 4, 4, "EXE"

    # Fallback: brute-force small offsets/modes for unrecognized types.
    for start in range(0, 16):
        for mode in range(0, 7):
            sample = lzss_decode(data, start, mode, out_size=probe)
            if len(sample) >= min(probe, 16) and bytes(sample[:2]) in (b"BM", b"MZ"):
                return start, mode, "unknown"

    return 0, 4, "unknown"


def decompress_bytes(data: bytes, start: int = None, mode: int = None,
                      size: int = None):
    """Returns (decoded_bytes, start_used, mode_used, label, ext)."""
    if start is None or mode is None:
        det_start, det_mode, _kind = detect_container(data)
        if start is None:
            start = det_start
        if mode is None:
            mode = det_mode
    out = lzss_decode(data, start=start, mode=mode, out_size=size)
    label, ext = identify(bytes(out[:8]))
    return out, start, mode, label, ext


def decompress_one(in_path: Path, out_path: Path = None, start: int = None,
                    mode: int = None, size: int = None, quiet: bool = False) -> Path:
    data = in_path.read_bytes()
    t0 = time.time()
    out, used_start, used_mode, label, ext = decompress_bytes(
        data, start=start, mode=mode, size=size)
    elapsed = time.time() - t0

    out_path = _apply_naming(in_path, out_path, ext, explicit_output=out_path)

    if size is not None and len(out) != size:
        if not quiet:
            print(f"[warn] {in_path.name}: only decoded {len(out)} of "
                  f"{size} expected bytes")

    out_path.write_bytes(out)
    if not quiet:
        print(f"[ok] {in_path.name} -> {out_path.name}  "
              f"({len(out)} bytes, start={used_start}, mode={used_mode}, "
              f"type={label}, {elapsed:.2f}s)")
    return out_path


def _apply_naming(in_path: Path, out_dir_or_path: Path, ext: str, explicit_output=None) -> Path:
    """Build the auto-named output path, prefixing with 'dec_' when the
    detected output extension matches the input's own extension (so we
    never silently overwrite a same-named/same-extension compressed file,
    e.g. compressed BMP resources that already end in .bmp)."""
    if explicit_output is not None:
        return explicit_output
    base_name = in_path.stem + ext
    if in_path.suffix.lower() == ext.lower():
        base_name = "dec_" + base_name
    if out_dir_or_path is not None and out_dir_or_path.is_dir():
        return out_dir_or_path / base_name
    return in_path.with_name(base_name)


def decompress_directory(in_dir: Path, out_dir: Path = None, start: int = None,
                          mode: int = None, recursive: bool = False):
    if out_dir is None:
        out_dir = in_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    pattern = "**/*" if recursive else "*"
    files = [p for p in sorted(in_dir.glob(pattern)) if p.is_file()]
    if not files:
        print(f"[warn] no files found in {in_dir}")
        return

    print(f"[info] processing {len(files)} file(s) from {in_dir} -> {out_dir}")
    ok, failed = 0, 0
    for f in files:
        try:
            data = f.read_bytes()
            t0 = time.time()
            out, used_start, used_mode, label, ext = decompress_bytes(
                data, start=start, mode=mode)
            elapsed = time.time() - t0
            out_name = f.stem + ext
            if f.suffix.lower() == ext.lower():
                out_name = "dec_" + out_name
            out_path = out_dir / out_name
            out_path.write_bytes(out)
            print(f"[ok] {f.name} -> {out_path.name}  "
                  f"({len(out)} bytes, start={used_start}, mode={used_mode}, "
                  f"type={label}, {elapsed:.2f}s)")
            ok += 1
        except Exception as e:
            print(f"[fail] {f.name}: {e}")
            failed += 1

    print(f"[info] done: {ok} succeeded, {failed} failed")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="compressed input file OR a directory of them")
    ap.add_argument("output", nargs="?", default=None,
                     help="output file (single mode) or output directory "
                          "(bulk mode). If omitted, output is named/placed "
                          "automatically next to the input (prefixed with "
                          "'dec_' if the detected extension matches the "
                          "input's own extension).")
    ap.add_argument("--start", type=int, default=None,
                     help="explicit stream start offset (skip auto-detect)")
    ap.add_argument("--mode", type=int, default=None,
                     help="explicit LZSS mode byte (skip auto-detect)")
    ap.add_argument("--size", type=int, default=None,
                     help="expected decompressed size (single-file mode "
                          "only) - stops decoding exactly at this length")
    ap.add_argument("--recursive", action="store_true",
                     help="in bulk mode, recurse into subdirectories")
    args = ap.parse_args()

    in_path = Path(args.input)

    if in_path.is_dir():
        out_dir = Path(args.output) if args.output else None
        decompress_directory(in_path, out_dir, start=args.start, mode=args.mode,
                              recursive=args.recursive)
    else:
        explicit_out = Path(args.output) if args.output else None
        decompress_one(in_path, explicit_out, start=args.start, mode=args.mode,
                        size=args.size)