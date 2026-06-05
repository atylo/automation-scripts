#!/usr/bin/env python3
"""
Extractor for custom MSX emulator archive format.
Handles three entry types found in the archive:
  1. Code/data modules (load-address + flags header)
  2. Compressed asset entries (hash + size header)
  3. Embedded ZIP sections (PK signature)
"""

import struct
import os
import sys
import zlib
import zipfile
import io

MAGIC = 0x46DEE5EF  # found at offset 32 in header block

def read32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]

def read32s(data, offset):
    return struct.unpack_from('<i', data, offset)[0]

def read16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def extract_code_module(data, offset, out_root):
    """
    Code/data module entry layout (from decompiled loader):
      +00  4  unknown / index
      +04  4  data size
      +08  4  load address
      +0C  4  data size (repeated)
      +10  4  flags  (0x81000002 = data, 0x81000003 = code)
      +14  4  alignment field  (e.g. 0x0F000030)
      +18  variable  null-terminated filename
      then  D0 FF FF FF  marker
      then  <size> bytes of payload
    Returns (bytes_consumed, filename) or None if not matched.
    """
    if offset + 0x18 > len(data):
        return None
    size      = read32(data, offset + 0x04)
    load_addr = read32(data, offset + 0x08)
    size2     = read32(data, offset + 0x0C)
    flags     = read32(data, offset + 0x10)
    align     = read32(data, offset + 0x14)

    # Sanity: flags high byte should be 0x81, size should be sane
    if (flags >> 24) != 0x81:
        return None
    if size == 0 or size > 0x200000:
        return None
    if size != size2:
        return None

    # Read null-terminated filename
    name_start = offset + 0x18
    name_end   = data.find(b'\x00', name_start)
    if name_end == -1 or name_end - name_start > 256:
        return None
    filename = data[name_start:name_end].decode('ascii', errors='replace')

    # After filename+null, expect D0 FF FF FF marker (with possible padding)
    # align to next position after null byte
    pos = name_end + 1
    # skip any alignment padding
    while pos < len(data) and pos < name_end + 8:
        if data[pos:pos+4] == b'\xD0\xFF\xFF\xFF':
            break
        pos += 1

    if data[pos:pos+4] != b'\xD0\xFF\xFF\xFF':
        return None
    pos += 4

    if pos + size > len(data):
        return None

    payload = data[pos:pos + size]
    _save(out_root, filename, payload)
    entry_type = 'code' if (flags & 0xFF) == 0x03 else 'data'
    print(f"  [{entry_type}] {filename}  ({size} bytes @ 0x{load_addr:08X})")
    return pos + size - offset


def extract_compressed_asset(data, offset, out_root):
    """
    Compressed asset entry layout (from hex samples):
      +00  2  flags/type
      +02  2  unknown
      +04  4  hash1 (CRC?)
      +08  4  hash2 (CRC?)
      +0C  4  compressed size
      +10  3  compression method flags
      +13  1  padding?
      +14  4  filename length
      +18  <fnlen> filename bytes
      then <compressed_size> bytes payload
    Returns (bytes_consumed, filename) or None.
    """
    if offset + 0x18 > len(data):
        return None

    flags    = read16(data, offset + 0x00)
    comp_sz  = read32(data, offset + 0x0C)
    fn_len   = read32(data, offset + 0x14)

    if fn_len == 0 or fn_len > 512:
        return None
    if comp_sz == 0 or comp_sz > 0x400000:
        return None

    name_start = offset + 0x18
    if name_start + fn_len > len(data):
        return None

    filename = data[name_start:name_start + fn_len].decode('ascii', errors='replace')
    if not filename.startswith('msx/'):
        return None

    payload_start = name_start + fn_len
    if payload_start + comp_sz > len(data):
        return None

    payload = data[payload_start:payload_start + comp_sz]

    method = read16(data, offset + 0x10)
    if method & 0x0200:  # deflate
        try:
            payload = zlib.decompress(payload, -15)
            print(f"  [asset/deflate] {filename}  ({comp_sz} -> {len(payload)} bytes)")
        except Exception:
            print(f"  [asset/raw]     {filename}  ({comp_sz} bytes, decompress failed)")
    else:
        print(f"  [asset/stored]  {filename}  ({comp_sz} bytes)")

    _save(out_root, filename, payload)
    return payload_start + comp_sz - offset


def extract_zip_section(data, offset, out_root):
    """
    Extract all files from an embedded ZIP section starting at offset.
    Returns the number of bytes consumed.
    """
    # Find end of ZIP: scan for end-of-central-directory record
    eocd = data.find(b'PK\x05\x06', offset)
    if eocd == -1:
        end = len(data)
    else:
        end = eocd + 22

    zip_data = data[offset:end]
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_data))
        for info in zf.infolist():
            payload = zf.read(info.filename)
            _save(out_root, info.filename, payload)
            print(f"  [zip]           {info.filename}  ({info.compress_size} -> {info.file_size} bytes)")
        zf.close()
    except Exception as e:
        print(f"  [zip] failed to parse ZIP section: {e}")
    return end - offset


def _save(out_root, filename, payload):
    out_path = os.path.join(out_root, filename.replace('/', os.sep))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(payload)


def extract(archive_path, out_root='extracted'):
    with open(archive_path, 'rb') as f:
        data = f.read()

    print(f"Loaded {len(data)} bytes from {archive_path}")
    print(f"Output to: {out_root}/\n")

    offset = 0
    entries = 0

    while offset < len(data):
        # Check for embedded ZIP
        if data[offset:offset+2] == b'PK':
            sig = read32(data, offset)
            if sig in (0x04034B50, 0x02014B50):
                print(f"[ZIP section @ 0x{offset:08X}]")
                consumed = extract_zip_section(data, offset, out_root)
                offset += consumed
                entries += 1
                continue

        # Check for code/data module (flags pattern 0x810000xx)
        if offset + 0x20 < len(data):
            flags = read32(data, offset + 0x10)
            if (flags >> 24) == 0x81 and (flags & 0xFF) in (0x01, 0x02, 0x03):
                consumed = extract_code_module(data, offset, out_root)
                if consumed:
                    offset += consumed
                    entries += 1
                    continue

        # Check for compressed asset (starts with 00 08 or 0E 2D etc, has msx/ path)
        if offset + 0x18 < len(data):
            fn_len = read32(data, offset + 0x14)
            if 4 <= fn_len <= 256:
                name_start = offset + 0x18
                if data[name_start:name_start+4] == b'msx/':
                    consumed = extract_compressed_asset(data, offset, out_root)
                    if consumed:
                        offset += consumed
                        entries += 1
                        continue

        offset += 1  # advance byte by byte if no match

    print(f"\nDone. {entries} entries extracted.")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: elate_ext.py <archive_file> [output_dir]")
        sys.exit(1)
    archive = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else 'extracted'
    extract(archive, out_dir)