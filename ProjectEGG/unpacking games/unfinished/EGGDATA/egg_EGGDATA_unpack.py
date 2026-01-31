import argparse
import re
import struct
import zlib
from pathlib import Path
from hashlib import md5

try:
    from Crypto.Cipher import AES
except Exception as e:
    raise SystemExit("pycryptodome is required. pip install pycryptodome") from e

CHUNK_SIZE = 0x100  # 256 bytes
EGG_MAGIC = b"EGGDATA "
EGG_HEADER_SKIP = 8 + 0x18  # skip 8 ('EGGDATA ') + 0x18 => total 0x20

# -------------------------------
# Utilities
# -------------------------------
def read_c_string(buf: bytes, off: int, n: int) -> str:
    """Read up to n bytes and stop at first 0x00; return ASCII-ish."""
    return buf[off : off + n].split(b"\x00", 1)[0].decode("ascii", "ignore")

def chunked_aes_decrypt(data: bytes, base_key: bytes) -> bytes:
    """QuickBMS-like per-chunk AES-ECB, first 4 key bytes ^= chunk_index (LE)."""
    out = bytearray()
    key_inc = struct.unpack_from("<I", base_key, 0)[0]
    n_full = len(data) // CHUNK_SIZE
    for i in range(n_full):
        cur_key = bytearray(base_key)
        tmp = key_inc ^ i
        struct.pack_into("<I", cur_key, 0, tmp)
        cipher = AES.new(bytes(cur_key), AES.MODE_ECB)
        off = i * CHUNK_SIZE
        out.extend(cipher.decrypt(data[off : off + CHUNK_SIZE]))
    # pass-through remainder (like QuickBMS DUMP append)
    if len(data) % CHUNK_SIZE:
        out.extend(data[n_full * CHUNK_SIZE :])
    return bytes(out)

def config_key_from_exe_name(exe_name: str) -> bytes:
    """MD5(exe_name) XOR 0xFF => 16-byte key."""
    base = md5(exe_name.encode("utf-8")).digest()
    return bytes(b ^ 0xFF for b in base)

def find_egg_regions(exe_bytes: bytes):
    """Yield (payload_start, payload_end_exclusive) for each EGGDATA region."""
    positions = []
    pos = 0
    while True:
        idx = exe_bytes.find(EGG_MAGIC, pos)
        if idx == -1:
            break
        positions.append(idx)
        pos = idx + 1
    # Convert to payload regions: [idx + 0x20, next_idx) or EOF
    regions = []
    for i, idx in enumerate(positions):
        payload_start = idx + EGG_HEADER_SKIP
        payload_end = positions[i + 1] if i + 1 < len(positions) else len(exe_bytes)
        if payload_start < payload_end:
            regions.append((payload_start, payload_end))
    return regions

def extract_files_from_decrypted_data(data: bytes, out_dir: Path):
    """
    Implements your DUMP_EXTRACT routine:
    Walk records: TYPE='DATA'|'NEXT'|'END'
    - DATA: (OFFSET, SIZE, NAME[0x14]); read chunk at OFFSET*CHUNK_SIZE
      If starts with 'COMPZIP ' then zlib decompress the payload body (SIZE-0x10).
    - NEXT: jump to OFFSET*CHUNK_SIZE
    - END: stop
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    files = []
    off = 0
    while off + 4 <= len(data):
        TYPE = data[off : off + 4]
        off += 4
        if TYPE.startswith(b"END"):
            break
        if TYPE == b"NEXT":
            if off + 4 > len(data):
                break
            next_off, = struct.unpack_from("<I", data, off)
            off += 4
            off = next_off * CHUNK_SIZE
            continue
        if TYPE == b"DATA":
            if off + 8 + 0x14 > len(data):
                break
            entry_off, entry_size = struct.unpack_from("<II", data, off)
            off += 8
            name = read_c_string(data, off, 0x14).strip() or "NONAME"
            off += 0x14

            file_off = entry_off * CHUNK_SIZE
            if file_off + min(entry_size, 8) > len(data):
                # out-of-bounds entry; skip
                continue

            sign = data[file_off : file_off + 8]
            # COMPZIP (zlib) block
            if sign == b"COMPZIP " and entry_size >= 0x10:
                try:
                    xsize, _dummy = struct.unpack_from("<II", data, file_off + 8)
                    comp_off = file_off + 0x10
                    comp_end = file_off + entry_size
                    comp_payload = data[comp_off:comp_end]
                    decomp = zlib.decompress(comp_payload)
                    # if xsize present and matches, fine; otherwise still write out
                    out_path = out_dir / f"{name}.bin"
                    out_path.write_bytes(decomp)
                    files.append(out_path)
                except Exception:
                    # write the raw block if zlib fails
                    raw_path = out_dir / f"{name}_COMPZIP_error.bin"
                    raw_path.write_bytes(data[file_off : file_off + entry_size])
                    files.append(raw_path)
            else:
                # Normal raw chunk
                out_path = out_dir / f"{name}.bin"
                out_path.write_bytes(data[file_off : file_off + entry_size])
                files.append(out_path)
        else:
            # unknown tag; stop to avoid desync
            break
    return files

# -------------------------------
# Main pipeline
# -------------------------------
def process_exe(exe_path: Path, exe_name: str):
    exe_bytes = exe_path.read_bytes()
    regions = find_egg_regions(exe_bytes)
    if not regions:
        raise RuntimeError("No EGGDATA regions found in executable. "
                           "If this is an old title without EGGDATA, use --config/--data mode.")

    # First region -> CONFIG (by convention). Decrypt with MD5(exe_name)^0xFF
    cfg_start, cfg_end = regions[0]
    cfg_enc = exe_bytes[cfg_start:cfg_end]
    cfg_key = config_key_from_exe_name(exe_name)
    cfg_dec = chunked_aes_decrypt(cfg_enc, cfg_key)
    Path(f"{exe_name}_CONFIG.dec.txt").write_bytes(cfg_dec)

    m = re.search(br"YekTpyrc=([0-9A-Fa-f]{32})", cfg_dec)
    if not m:
        raise RuntimeError("AES key not found in decrypted CONFIG (YekTpyrc=...).")
    aes_key_hex = m.group(1).decode("ascii")
    data_key = bytes.fromhex(aes_key_hex)

    print(f"[+] AES key from CONFIG: {aes_key_hex}")

    # Remaining regions -> DATA blobs
    all_outputs = []
    for idx, (d_start, d_end) in enumerate(regions[1:], start=1):
        data_enc = exe_bytes[d_start:d_end]
        data_dec = chunked_aes_decrypt(data_enc, data_key)
        raw_out = Path(f"{exe_name}_DATA_{idx}.bin")
        raw_out.write_bytes(data_dec)

        # Extract files
        out_dir = Path("extracted") / f"{exe_name}_DATA_{idx}"
        out_files = extract_files_from_decrypted_data(data_dec, out_dir)
        print(f"[+] DATA[{idx}]: extracted {len(out_files)} files to {out_dir}")
        all_outputs.extend(out_files)

    if len(regions) == 1:
        print("[!] Only one EGGDATA region found (CONFIG). No DATA regions present.")
    return all_outputs

def process_standalone(config_path: Path, data_path: Path, exe_name: str):
    # CONFIG standalone (trim 0x20 first, per your clarification)
    cfg_key = config_key_from_exe_name(exe_name)
    cfg_enc = config_path.read_bytes()[0x20:]
    cfg_dec = chunked_aes_decrypt(cfg_enc, cfg_key)
    Path(f"{exe_name}_CONFIG.dec.txt").write_bytes(cfg_dec)

    m = re.search(br"YekTpyrc=([0-9A-Fa-f]{32})", cfg_dec)
    if not m:
        raise RuntimeError("AES key not found in decrypted CONFIG (YekTpyrc=...).")
    aes_key_hex = m.group(1).decode("ascii")
    data_key = bytes.fromhex(aes_key_hex)
    print(f"[+] AES key from CONFIG: {aes_key_hex}")

    # DATA standalone (trim 0x20 before decrypt)
    data_enc = data_path.read_bytes()[0x20:]
    data_dec = chunked_aes_decrypt(data_enc, data_key)
    raw_out = Path(f"{exe_name}_DATA_1.bin")
    raw_out.write_bytes(data_dec)

    out_dir = Path("extracted") / f"{exe_name}_DATA_1"
    out_files = extract_files_from_decrypted_data(data_dec, out_dir)
    print(f"[+] DATA[1]: extracted {len(out_files)} files to {out_dir}")
    return out_files

# -------------------------------
# CLI
# -------------------------------
def main():
    ap = argparse.ArgumentParser(description="Project EGG extractor (CONFIG+DATA) from EXE or standalone files.")
    ap.add_argument("exe", nargs="?", help="Path to GAME.EXE (will scan for EGGDATA regions).")
    ap.add_argument("--exe-name", help="EXE base name (no extension). Defaults to stem of --exe or --data/--config mode.")
    ap.add_argument("--config", help="Standalone CONFIG file (if no EXE).")
    ap.add_argument("--data", help="Standalone DATA file (if no EXE).")
    args = ap.parse_args()

    if args.exe:
        exe_path = Path(args.exe)
        exe_name = args.exe_name or exe_path.stem
        outputs = process_exe(exe_path, exe_name)
        if outputs:
            print("[*] Done.")
        return

    if args.config and args.data:
        config_path = Path(args.config)
        data_path = Path(args.data)
        exe_name = args.exe_name or "GAME"
        outputs = process_standalone(config_path, data_path, exe_name)
        if outputs:
            print("[*] Done.")
        return

    raise SystemExit("Provide either an EXE path, or both --config and --data.")

if __name__ == "__main__":
    main()
