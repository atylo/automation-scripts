import sys
import os
import struct
import zlib

def extract_archive(path, out_dir="extract"):
    with open(path, "rb") as f:
        data = f.read()

    count = struct.unpack_from("<I", data, 0)[0]
    print(f"Entries: {count}")

    pos = 4
    entries = []

    for i in range(count):
        offset, size = struct.unpack_from("<II", data, pos)
        pos += 8
        entries.append((offset, size))

    # ----------------------------
    # consistency check
    # ----------------------------

    ok = True
    for i in range(count - 1):
        off, size = entries[i]
        next_off, _ = entries[i + 1]

        if off + size != next_off:
            ok = False
            print(
                f"  [!] entry {i}: "
                f"end=0x{off+size:X} next=0x{next_off:X}"
            )

    os.makedirs(out_dir, exist_ok=True)

    # ----------------------------
    # decompress + rebuild ROM
    # ----------------------------
    rom_parts = []

    for i, (offset, size) in enumerate(entries):

        blob = data[offset:offset + size]

        try:
            out = zlib.decompress(blob)

            rom_parts.append(out)

            # out_path = os.path.join(out_dir, f"{i:03}.bin")
            # with open(out_path, "wb") as f:
                # f.write(out)

            print(f"[{i:03}] OK comp={len(blob)} decomp={len(out)}")

        except Exception as e:
            print(f"[{i:03}] FAIL comp={len(blob)} {e}")

    # ----------------------------
    # final reconstruction
    # ----------------------------
    rom = b"".join(rom_parts)

    rom_path = os.path.join(out_dir, infile + ".rom")
    with open(rom_path, "wb") as f:
        f.write(rom)

    print(f"\n[+] ROM reconstructed: {len(rom)} bytes")
    print(f"[+] saved to {rom_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file> [out_dir]")
        sys.exit(1)

    infile = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else "extract"

    extract_archive(infile, outdir)