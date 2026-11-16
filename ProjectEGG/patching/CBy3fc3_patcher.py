#!/usr/bin/env python3
"""
CBy3fc3 Launcher Check Patcher
Patches the jne→NOP at the call site of the launcher validation function.

What it patches (x86 asm inside sub_41C2B0):
  E8 xx xx xx xx   call  sub_41C570        (the validator)
  83 C4 0C         add   esp, 0C           (__cdecl 3-arg cleanup)
  85 C0            test  eax, eax
  75 xx            jne   error_path        ← patched to 90 90 (NOP NOP)
  ; fall-through:
  mov eax, 1                               ← game continues here always
  ret 8

sub_41C570 returns 0 on success, non-zero on failure.
jne jumps to the MessageBox+ret0 error path on failure.
NOPping it makes execution always fall through to mov eax,1 / ret 8.
"""

import sys
import shutil
from pathlib import Path

MARKER = b"CBy3fc3"

# Full precise pattern:
#   83 C4 0C        = add esp, 0C  (cdecl 3-arg cleanup after the call)
#   85 C0           = test eax, eax
#   75 ??           = jne  error_path
#   B8 01 00 00 00  = mov eax, 1   (the success return — structurally required)
#
# The mov eax,1 is the key: it's the success return value of sub_41C2B0 and
# must be present in every game using this check. This makes the pattern
# unique even across games where the jne operand (jump distance) differs.
PATTERN = b"\x83\xC4\x0C\x85\xC0\x75"
PATTERN_SUFFIX = b"\xB8\x01\x00\x00\x00"   # mov eax, 1  (2 bytes after jne)
JNE_OFF = 5    # offset of 0x75 within PATTERN

JNE     = 0x75
NOP     = 0x90


def find_marker(data: bytes) -> int | None:
    idx = data.find(MARKER)
    return idx if idx != -1 else None


def find_patch_sites(data: bytes) -> list[int]:
    """
    Find all occurrences of:
      E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 ?? B8 01 00 00 00
    Returns the offset of the 75 byte in each match.

    The B8 01 00 00 00 (mov eax, 1) suffix is the success-return of
    sub_41C2B0 and is structurally required in every game using this
    check — it uniquely identifies the right site regardless of the
    jne operand value.
    """
    sites = []
    start = 0
    while True:
        idx = data.find(PATTERN, start)
        if idx == -1:
            break
        call_pos = idx - 5
        jne_pos  = idx + JNE_OFF
        suffix_pos = jne_pos + 2          # B8 01 00 00 00 starts 2 bytes after 75
        if (call_pos >= 0
                and data[call_pos] == 0xE8
                and data[suffix_pos:suffix_pos + len(PATTERN_SUFFIX)] == PATTERN_SUFFIX):
            sites.append(jne_pos)
        start = idx + 1
    return sites


def patch(data: bytearray, offset: int) -> None:
    assert data[offset] == JNE, \
        f"Expected 0x75 at 0x{offset:X}, got 0x{data[offset]:02X}"
    data[offset]     = NOP   # NOP the jne opcode
    data[offset + 1] = NOP   # NOP the jne operand


def summarise_site(data: bytes | bytearray, jne_offset: int) -> str:
    # E8 is 5 bytes before our pattern (83 C4 0C 85 C0), pattern is 5 bytes before jne
    call_pos = jne_offset - 5 - 5
    rel      = int.from_bytes(data[call_pos+1:call_pos+5], "little", signed=True)
    target   = (call_pos + 5 + rel) & 0xFFFFFFFF
    jump_op  = data[jne_offset + 1]
    return (
        f"  jne +0x{jump_op:02X}  @ file offset 0x{jne_offset:08X}"
        f"  (after call to raw VA offset 0x{target:08X})"
    )



def main() -> None:
    if len(sys.argv) < 2:
        print("CBy3fc3 ProjectEGG games patcher. For games that don't launch.")
        print(f"Usage: {sys.argv[0]} <game.exe> [--dry-run]")
        print()
        print("  --dry-run   Analyse only, do not write any files.")
        sys.exit(1)

    path     = Path(sys.argv[1])
    dry_run  = "--dry-run" in sys.argv

    if not path.exists():
        print(f"Error: file not found: {path}")
        sys.exit(1)

    raw = path.read_bytes()
    print(f"File    : {path}")
    print(f"Size    : {len(raw)} bytes  (0x{len(raw):X})")
    print()

    # ── Step 1: confirm marker ────────────────────────────────────────────────
    marker_pos = find_marker(raw)
    if marker_pos is None:
        print("Marker CBy3fc3 not found — this may not be a supported exe.")
        sys.exit(1)
    print(f"Marker CBy3fc3 found at 0x{marker_pos:08X}")
    print()

    # ── Step 2: find patch sites ──────────────────────────────────────────────
    sites = find_patch_sites(raw)

    if not sites:
        print("No patch site found.")
        print("Pattern: E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 ??")
        print("The exe may use a different compiler optimisation or calling convention.")
        sys.exit(1)

    print(f"Found {len(sites)} patch site(s):")
    for s in sites:
        print(summarise_site(raw, s))
    print()

    if len(sites) > 1:
        print("WARNING: Multiple sites matched — patching all.")
        print()


    if dry_run:
        print("Dry-run mode — no files written.")
        sys.exit(0)

    # ── Step 3: backup ────────────────────────────────────────────────────────
    backup = path.with_suffix(path.suffix + ".bak")
    if not backup.exists():
        shutil.copy2(path, backup)
        print(f"Backup  : {backup}")
    else:
        print(f"Backup  : {backup} (already exists, skipped)")

    # ── Step 4: patch ─────────────────────────────────────────────────────────
    patched = bytearray(raw)
    for s in sites:
        patch(patched, s)
        print(f"Patched : 0x{s:08X}  75 ?? → 90 90")

    path.write_bytes(patched)
    print()
    print(f"Done — {path} patched successfully.")
    #print( "The launcher check will always pass, no arguments needed.")


if __name__ == "__main__":
    main()