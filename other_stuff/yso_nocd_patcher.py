#!/usr/bin/env python3
"""
yso_nocd_patcher.py  (universal / signature-based)

Disables the disc-authentication routine found in yso_win.exe by locating
it via a masked byte signature instead of a fixed file offset, so the same
script works against other builds/versions of the exe as long as this
routine's code is unchanged (only the addresses it references -- IAT thunks,
internal call targets, data addresses, and the disc's volume-serial
constant -- may differ; those positions are wildcarded in the signature).

What the routine does (recovered via Capstone disassembly + import
resolution): it calls GetDriveTypeA to check the target is a CD-ROM drive,
calls GetVolumeInformationA and compares the returned volume serial number
against a hardcoded constant, and checks for a specific file on the disc.
Five conditional jumps gate that logic; patching them forces every check to
report "disc present and valid".

Usage:
    python yso_nocd_patcher.py yso_win.exe [-o out.exe]

If -o is omitted, the input is patched in place (a .bak backup is written
first).
"""

import argparse
import shutil
import struct
import sys

try:
    import pefile
except ImportError:
    sys.exit("This script requires the 'pefile' package: pip install pefile")

# ---------------------------------------------------------------------------
# Masked signature for the disc-check routine, captured from a reference
# build (yso_win.exe) at VA 0x0040ee40-0x0040ef98. `None` = wildcard byte
# (call/jmp/jcc relative displacements, absolute IAT/data addresses, and the
# volume-serial constant) -- everything else must match literally.
# ---------------------------------------------------------------------------
PATTERN = [
    246, 195, 1, 15, 132, None, None, None, None, 141, 84, 36, 20, 82, 198, 132, 36, 220, 2, 0,
    0, 0, 255, 21, None, None, None, None, 131, 248, 5, 15, 133, None, None, None, None, 85, 85,
    141, 68, 36, 44, 80, 141, 76, 36, 40, 81, 85, 104, 128, 1, 0, 0, 141, 148, 36, 240, 2, 0, 0,
    82, 141, 68, 36, 48, 80, 255, 21, None, None, None, None, 133, 192, 15, 132, None, None, None,
    None, 51, 201, 137, 76, 36, 41, 137, 76, 36, 45, 137, 76, 36, 49, 102, 137, 76, 36, 53, 198,
    68, 36, 40, 0, 136, 76, 36, 55, 51, 246, 139, 20, 181, None, None, None, None, 106, 11, 82,
    141, 68, 36, 48, 80, 232, None, None, None, None, 141, 76, 36, 52, 81, 141, 148, 36, 232, 2,
    0, 0, 82, 232, None, None, None, None, 131, 196, 20, 133, 192, 116, 11, 70, 131, 254, 1, 114,
    205, 233, None, None, None, None, 138, 68, 36, 20, 85, 85, 106, 3, 85, 106, 1, 104, 0, 0, 0,
    128, 141, 76, 36, 80, 81, 136, 68, 36, 84, 255, 215, 138, 84, 36, 20, 85, 85, 106, 3, 85, 106,
    1, 104, 0, 0, 0, 128, 141, 68, 36, 112, 80, 136, 84, 36, 116, 255, 215, 141, 72, 1, 133, 201,
    15, 132, None, None, None, None, 85, 80, 255, 21, None, None, None, None, 59, 245, 15, 133,
    None, None, None, None, 61, None, None, None, None, 15, 133, None, None, None, None, 15, 182,
    21, None, None, None, None, 161, None, None, None, None, 51, 201, 102, 139, 13, None, None,
    None, None, 198, 4, 2, 1, 81, 255, 21, None, None, None, None, 198, 5, None, None, None, None,
    255, 15, 182, 21, None, None, None, None, 161, None, None, None, None, 128, 60, 2, 0, 117, 20,
    138, 84, 36, 20, 254, 194, 209, 235, 59, 221, 136, 84, 36, 20, 15, 133, None, None, None, None,
    15, 182, 5, None, None, None, None,
]

# (offset_in_pattern, instruction_length, transform, extra)
#   'jmp_new'    -> replace with near jmp (E9 + rel32) targeting
#                   match_start + extra, NOP-padded to fill `length`
#   'nop'        -> fill with NOPs
#   'flip_short' -> change a short-jcc opcode to EB (jmp short), keep the
#                   already-present displacement byte (same target)
PATCH_POINTS = [
    (0x1F, 6, "jmp_new", 0x52),    # skip GetDriveTypeA / GetVolumeInformationA gate
    (0x9B, 2, "flip_short", None), # force the file-loop success branch
    (0xE3, 6, "nop", None),        # remove the volume-label-length failure jump
    (0xF3, 6, "jmp_new", 0x104),   # skip the volume-serial-number compare
    (0x13B, 2, "flip_short", None),# force the final flag check to succeed
]

assert len(PATTERN) == 344


def find_pattern(data: bytes):
    """Return every file offset where PATTERN matches (respecting wildcards)."""
    n = len(PATTERN)
    # Anchor on the longest contiguous run of literal (non-wildcard) bytes
    # for a fast first pass, then verify the full pattern at each hit.
    best_start, best_len = 0, 0
    i = 0
    while i < n:
        if PATTERN[i] is not None:
            j = i
            while j < n and PATTERN[j] is not None:
                j += 1
            if j - i > best_len:
                best_start, best_len = i, j - i
            i = j
        else:
            i += 1
    anchor = bytes(PATTERN[best_start:best_start + best_len])

    matches = []
    start = 0
    while True:
        idx = data.find(anchor, start)
        if idx == -1:
            break
        cand = idx - best_start
        start = idx + 1
        if cand < 0 or cand + n > len(data):
            continue
        ok = True
        for k, expect in enumerate(PATTERN):
            if expect is not None and data[cand + k] != expect:
                ok = False
                break
        if ok:
            matches.append(cand)
    return matches


def apply_patch(data: bytearray, match_off: int, va_of_offset) -> None:
    for p_off, length, kind, extra in PATCH_POINTS:
        instr_off = match_off + p_off
        if kind == "nop":
            data[instr_off:instr_off + length] = b"\x90" * length
        elif kind == "flip_short":
            data[instr_off] = 0xEB  # jcc rel8 -> jmp rel8 (displacement byte untouched)
        elif kind == "jmp_new":
            instr_va = va_of_offset(instr_off)
            target_va = va_of_offset(match_off + extra)
            rel = target_va - (instr_va + 5)
            new_bytes = b"\xe9" + struct.pack("<i", rel)
            new_bytes += b"\x90" * (length - len(new_bytes))
            data[instr_off:instr_off + length] = new_bytes
        else:
            raise AssertionError(kind)


def main() -> int:
    ap = argparse.ArgumentParser(description="Universal signature-based no-CD patcher for yso_win.exe")
    ap.add_argument("input", help="Path to the exe to patch")
    ap.add_argument("-o", "--output", help="Output path (default: patch in place, with a .bak backup)")
    args = ap.parse_args()

    with open(args.input, "rb") as f:
        raw = f.read()

    try:
        pe = pefile.PE(args.input, fast_load=True)
    except pefile.PEFormatError as e:
        print(f"[!] Not a valid PE file: {e}", file=sys.stderr)
        return 1

    def va_of_offset(file_off: int) -> int:
        rva = pe.get_rva_from_offset(file_off)
        return pe.OPTIONAL_HEADER.ImageBase + rva

    matches = find_pattern(raw)

    if not matches:
        print("[!] Disc-check signature not found. This build's code for that "
              "routine differs from the reference, or it's already patched.",
              file=sys.stderr)
        return 1
    if len(matches) > 1:
        print(f"[!] Signature matched {len(matches)} locations "
              f"({', '.join(hex(m) for m in matches)}); refusing to guess. "
              f"Inspect the binary manually.", file=sys.stderr)
        return 1

    match_off = matches[0]
    match_va = va_of_offset(match_off)
    print(f"[+] Found disc-check routine at file offset 0x{match_off:X} (VA 0x{match_va:X})")

    data = bytearray(raw)
    apply_patch(data, match_off, va_of_offset)
    
    pe.close()  # Release the memory-mapped file before overwriting it

    if args.output:
        out_path = args.output
    else:
        backup_path = args.input + ".bak"
        shutil.copyfile(args.input, backup_path)
        print(f"[+] Backed up original to {backup_path}")
        out_path = args.input

    with open(out_path, "wb") as f:
        f.write(data)

    print(f"[+] Patched 5 disc-check jump(s), wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())