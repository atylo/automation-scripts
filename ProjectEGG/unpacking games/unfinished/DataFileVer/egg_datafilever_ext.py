import struct
import sys
import os

# --- 1. PE & MEMORY TOOLS ---

def get_pe_sections(exe_data):
    try:
        e_lfanew = struct.unpack_from("<I", exe_data, 0x3C)[0]
        pe_header = e_lfanew

        image_base = struct.unpack_from("<I", exe_data, pe_header + 52)[0]
        num_sections = struct.unpack_from("<H", exe_data, pe_header + 6)[0]
        opt_size = struct.unpack_from("<H", exe_data, pe_header + 20)[0]
        sec_table = pe_header + 24 + opt_size

        sections = []
        for i in range(num_sections):
            sec_off = sec_table + (i * 40)
            virt_addr = struct.unpack_from("<I", exe_data, sec_off + 12)[0]
            raw_size = struct.unpack_from("<I", exe_data, sec_off + 16)[0]
            raw_ptr = struct.unpack_from("<I", exe_data, sec_off + 20)[0]
            name = exe_data[sec_off:sec_off+8].strip(b'\x00')

            sections.append({
                'name': name,
                'start': image_base + virt_addr,
                'end': image_base + virt_addr + raw_size,
                'raw_ptr': raw_ptr
            })
        return image_base, sections
    except:
        return None, []

def va_to_offset(va, sections):
    for sec in sections:
        if sec['start'] <= va < sec['end']:
            return sec['raw_ptr'] + (va - sec['start'])
    return None

def is_valid_va(va, sections):
    for sec in sections:
        if sec['start'] <= va < sec['end']:
            return True
    return False

def find_nested_pe(data):
    """Find nested PE (exe inside exe). Returns offset or 0 if none."""
    idx = 1  # Start after first byte to skip outer PE
    while idx < len(data) - 0x100:
        idx = data.find(b'MZ', idx)
        if idx == -1:
            return 0
        # Verify it's a valid PE
        if idx + 0x40 < len(data):
            try:
                e_lfanew = struct.unpack_from('<I', data, idx + 0x3C)[0]
                if 0x40 <= e_lfanew < 0x400 and idx + e_lfanew + 4 < len(data):
                    pe_sig = data[idx + e_lfanew:idx + e_lfanew + 4]
                    if pe_sig == b'PE\x00\x00':
                        return idx
            except:
                pass
        idx += 1
    return 0

# --- 2. DECRYPTION & DECOMPRESSION ---

def decrypt_blob(blob, key):
    """Reverses the custom Rotate + XOR encryption."""
    # Pass 1: Rotation
    out = bytearray(len(blob))
    curr = key
    for i, b in enumerate(blob):
        rot = (curr >> 3) & 0x7
        out[i] = ((b << rot) | (b >> (8 - rot))) & 0xFF
        curr = b
    # Pass 2: XOR
    final = bytearray(len(out))
    xor_k = key
    for i in range(len(out)):
        final[i] = out[i] ^ xor_k
        xor_k = out[i]
    return final

def decompress_lzss(data, output_size):
    """Reverses the custom LZSS compression."""
    output = bytearray()
    text_buf = bytearray(4096)
    r = 0xfee
    src_idx = 0
    flags = 0

    while src_idx < len(data) and len(output) < output_size:
        flags >>= 1
        if (flags & 0x100) == 0:
            if src_idx >= len(data): break
            c = data[src_idx]
            src_idx += 1
            flags = c | 0xFF00

        if (flags & 1) != 0:
            if src_idx >= len(data): break
            c = data[src_idx]
            src_idx += 1
            output.append(c)
            text_buf[r] = c
            r = (r + 1) & 0xFFF
        else:
            if src_idx + 1 >= len(data): break
            i = data[src_idx]
            j = data[src_idx + 1]
            src_idx += 2
            offset = i | ((j & 0xF0) << 4)
            count = (j & 0x0F) + 3
            for k in range(count):
                c = text_buf[(offset + k) & 0xFFF]
                output.append(c)
                text_buf[r] = c
                r = (r + 1) & 0xFFF
    return output

# --- 3. TYPE 1 DETECTION (String XREF approach) ---

def find_disk_name_strings(data):
    """Find disk name strings like 'DISK 1', 'DISK 2', 'DISK A', etc."""
    disk_strings = []
    patterns = [b'DISK 1', b'DISK 2', b'DISK 3', b'DISK 4', b'DISK 5',
                b'DISK A', b'DISK B', b'DISK C', b'DISK D',
                b'DISKA', b'DISKB', b'DISKC', b'USER']

    for pattern in patterns:
        idx = 0
        while True:
            idx = data.find(pattern, idx)
            if idx == -1:
                break
            end = idx
            while end < len(data) and data[end] != 0:
                end += 1
            disk_strings.append((idx, data[idx:end].decode('ascii', errors='ignore')))
            idx += 1
    return disk_strings

def find_xrefs_to_va(data, target_va):
    """Find references to a VA in the file."""
    va_bytes = struct.pack('<I', target_va)
    xrefs = []
    idx = 0
    while True:
        idx = data.find(va_bytes, idx)
        if idx == -1:
            break
        xrefs.append(idx)
        idx += 1
    return xrefs

def is_valid_disk_entry_13(decomp, va, comp, data_len, image_base):
    """Check if 13-byte entry values look valid (decomp, va, comp)."""
    if not (100000 < decomp < 5000000):
        return False
    if not (image_base < va < image_base + 0x1000000):
        return False
    if not (10000 < comp < 5000000):
        return False
    file_off = va - image_base
    if file_off <= 0 or file_off >= data_len:
        return False
    if file_off + comp > data_len:
        return False
    return True

def is_valid_disk_entry_17(decomp, va, comp, data_len, image_base):
    """Check if 17-byte entry values look valid (decomp, unknown, va, comp)."""
    if not (100000 < decomp < 5000000):
        return False
    if not (image_base < va < image_base + 0x1000000):
        return False
    if not (10000 < comp < 5000000):
        return False
    file_off = va - image_base
    if file_off <= 0 or file_off >= data_len:
        return False
    if file_off + comp > data_len:
        return False
    return True

def try_parse_type1_entries_with_terminator(data, start_offset, image_base):
    """
    Parse Type 1 entries using 93 6F terminator.
    Supports both 13-byte (decomp,va,comp,key) and 17-byte (decomp,unknown,va,comp,key) formats.
    Scans byte-by-byte after key until non-zero (next entry) or 93 6F (end).
    """
    entries = []
    offset = start_offset

    # First, detect entry format by trying both
    # Try 13-byte format first: decomp(4) + va(4) + comp(4) + key(1)
    if offset + 13 <= len(data):
        decomp = struct.unpack_from('<I', data, offset)[0]
        va = struct.unpack_from('<I', data, offset + 4)[0]
        comp = struct.unpack_from('<I', data, offset + 8)[0]

        if is_valid_disk_entry_13(decomp, va, comp, len(data), image_base):
            # 13-byte format
            entry_data_size = 13  # decomp + va + comp + key
            va_offset = 4
        else:
            # Try 17-byte format: decomp(4) + unknown(4) + va(4) + comp(4) + key(1)
            if offset + 17 <= len(data):
                va = struct.unpack_from('<I', data, offset + 8)[0]
                comp = struct.unpack_from('<I', data, offset + 12)[0]
                if is_valid_disk_entry_17(decomp, va, comp, len(data), image_base):
                    entry_data_size = 17
                    va_offset = 8
                else:
                    return []
            else:
                return []
    else:
        return []

    # Now parse all entries with detected format
    while offset + entry_data_size <= len(data):
        decomp = struct.unpack_from('<I', data, offset)[0]
        va = struct.unpack_from('<I', data, offset + va_offset)[0]
        comp = struct.unpack_from('<I', data, offset + va_offset + 4)[0]
        key = data[offset + entry_data_size - 1]

        file_off = va - image_base
        if not (0 < file_off < len(data) and file_off + comp <= len(data)):
            break

        entries.append({
            'decomp': decomp,
            'va': va,
            'blob_off': file_off,
            'comp': comp,
            'key': key
        })

        # Move past the key byte
        offset += entry_data_size

        # Scan for zeros until we hit non-zero or 93 6F
        while offset < len(data):
            if data[offset] != 0x00:
                break
            offset += 1

        # Check for 93 6F terminator
        if offset + 1 < len(data) and data[offset:offset+2] == b'\x93\x6F':
            break  # End of entries

        # Check if next bytes could be a valid decomp (should be around 1281968 = 0x138FB0)
        if offset + 4 <= len(data):
            next_decomp = struct.unpack_from('<I', data, offset)[0]
            if not (100000 < next_decomp < 5000000):
                break

    return entries

def find_type1_metadata(data, image_base):
    """
    Find Type 1 disk metadata by searching for 93 6F terminator.
    Structure: FF padding -> 4-8 zeros -> entries -> 93 6F
    Entry formats: 13-byte (decomp,va,comp,key) or 17-byte (decomp,unknown,va,comp,key)
    """
    entries = []

    # Search for 93 6F terminator in the second half of file
    search_start = len(data) // 2
    terminator = b'\x93\x6F'

    idx = search_start
    while True:
        idx = data.find(terminator, idx)
        if idx == -1:
            break

        # Look backwards for FF padding + zeros + entries
        # Search up to 0x200 bytes back for the start of entries
        for back in range(0x10, 0x200):
            check_pos = idx - back
            if check_pos < 0:
                break

            # Look for FF padding followed by zeros
            if data[check_pos:check_pos+4] == b'\xff\xff\xff\xff':
                # Find where zeros end
                j = check_pos + 4
                while j < idx and data[j] == 0x00:
                    j += 1

                zero_count = j - (check_pos + 4)
                if zero_count >= 4 and j < idx:
                    # Try to parse entries from j
                    test_entries = try_parse_type1_entries_with_terminator(data, j, image_base)
                    if len(test_entries) > len(entries):
                        entries = test_entries
                        break

        if entries:
            break
        idx += 1

    # Fallback: original method if 93 6F approach didn't work
    if not entries:
        search_start = len(data) // 2
        for i in range(search_start, len(data) - 24):
            if data[i:i+4] == b'\xff\xff\xff\xff':
                j = i + 4
                while j < len(data) and data[j] == 0x00:
                    j += 1
                zero_count = j - (i + 4)
                if zero_count >= 4 and j + 16 <= len(data):
                    test_entries = try_parse_type1_entries_with_terminator(data, j, image_base)
                    if len(test_entries) > len(entries):
                        entries = test_entries

    return entries

# --- 4. TYPE 2/3/4 DETECTION (E9 0B signature approach) ---

def find_type234_metadata(data, image_base, sections):
    """
    Find Type 2/3/4 disk metadata using Init function and E9 0B signature.
    Returns list of entries or empty list if not found.
    """
    # Find .data section
    data_sec = next((s for s in sections if b'.data' in s['name']), None)
    if not data_sec:
        data_sec = sections[-2] if len(sections) >= 2 else None

    if not data_sec:
        return []

    ptr_loc = data_sec['raw_ptr'] + 4
    if ptr_loc + 4 > len(data):
        return []

    init_func_va = struct.unpack_from("<I", data, ptr_loc)[0]
    init_offset = va_to_offset(init_func_va, sections)

    if not init_offset:
        return []

    # Search for E9 0B 00 00 00 signature
    sig = b'\xE9\x0B\x00\x00\x00'
    window = data[init_offset : init_offset + 5000]
    sig_idx = window.find(sig)

    if sig_idx == -1:
        return []

    code_start = init_offset + sig_idx + len(sig)

    # Scrape MOV [mem], imm instructions
    found_values = []
    cursor = code_start
    limit = cursor + 3000

    while cursor < limit and cursor + 10 <= len(data):
        if data[cursor] == 0xC7 and data[cursor+1] == 0x05:
            val = struct.unpack_from("<I", data, cursor + 6)[0]
            found_values.append(val)
            cursor += 10
        else:
            cursor += 1

    # Process found values into disk entries
    entries = []
    i = 0
    while i < len(found_values) - 1:
        blob_va = found_values[i]
        comp_size = found_values[i+1]

        if is_valid_va(blob_va, sections) and (100 < comp_size < 50_000_000):
            blob_offset = va_to_offset(blob_va, sections)

            if blob_offset and blob_offset >= 8:
                try:
                    key = data[blob_offset - 4]
                    decomp_size = struct.unpack_from("<I", data, blob_offset - 8)[0]

                    if decomp_size > comp_size:
                        entries.append({
                            'decomp': decomp_size,
                            'va': blob_va,
                            'blob_off': blob_offset,
                            'comp': comp_size,
                            'key': key
                        })
                        i += 2
                        continue
                except:
                    pass
        i += 1

    return entries

# --- 5. MAIN EXTRACTION LOGIC ---

def validate_d88(data):
    """Check if data is a valid D88 disk image by checking header structure.
    D88 header:
      0x00-0x0F (16 bytes): disk_name (shift-jis)
      0x10 (1 byte): comment_terminator (null)
      0x11-0x19 (9 bytes): reserved (all zeros)
      0x1A (1 byte): write_protect_flag
      0x1B (1 byte): media_flag (0x00=2D, 0x10=2DD, 0x20=2HD)
      0x1C-0x1F (4 bytes): disk_size
      0x20+ : track offset table
    """
    if len(data) < 0x2B0:
        return False, ""

    # Get disk name (16 bytes, shift-jis or ascii)
    name_bytes = bytes(data[0:16]).rstrip(b'\x00')
    try:
        name_str = name_bytes.decode('ascii')
    except:
        try:
            name_str = name_bytes.decode('shift-jis', errors='replace')
        except:
            name_str = "[binary]"

    # Check comment terminator (0x10 should be 0x00)
    if data[0x10] != 0x00:
        return False, name_str

    # Check reserved bytes (0x11-0x19 should be 0x00)
    reserved = data[0x11:0x1A]
    if reserved != b'\x00' * 9:
        return False, name_str

    # Check media type (0x1B) - valid values: 0x00, 0x10, 0x20, 0x30, 0x40
    media_type = data[0x1B]
    if media_type not in (0x00, 0x10, 0x20, 0x30, 0x40):
        return False, name_str

    # Check disk size matches actual data size
    disk_size = struct.unpack_from('<I', data, 0x1C)[0]
    if disk_size != len(data):
        return False, name_str

    # Check first track offset (should be >= 0x2B0)
    first_track = struct.unpack_from('<I', data, 0x20)[0]
    if first_track != 0 and first_track < 0x2B0:
        return False, name_str

    return True, name_str

def extract_disks(exe_path, output_dir=None):
    """Universal disk extractor for all types."""
    print(f"=== Extracting from {os.path.basename(exe_path)} ===")

    with open(exe_path, 'rb') as f:
        data = f.read()

    print(f"File size: {len(data)} bytes")

    image_base, sections = get_pe_sections(data)
    if not image_base:
        print("Error: Could not parse PE header")
        return 0

    print(f"Image base: 0x{image_base:X}")

    # Check for nested PE (exe inside exe)
    nested_pe_offset = find_nested_pe(data)
    if nested_pe_offset:
        print(f"Nested PE at: 0x{nested_pe_offset:X}")

    # Try Type 2/3/4 approach first (E9 0B signature)
    entries = find_type234_metadata(data, image_base, sections)
    detected_type = "2/3/4"

    if not entries:
        # Fall back to Type 1 approach (string xrefs)
        entries = find_type1_metadata(data, image_base)
        detected_type = "1"

    if not entries:
        print("Error: Could not find disk metadata (tried both Type 1 and Type 2/3/4 approaches)")
        return 0

    print(f"Detected as Type {detected_type}")
    print(f"Found {len(entries)} disk entries\n")

    # Determine output directory
    if output_dir is None:
        output_dir = os.path.dirname(exe_path) or '.'

    base_name = os.path.splitext(os.path.basename(exe_path))[0]

    # Extract each disk
    extracted = 0
    for idx, e in enumerate(entries):
        print(f"Disk {idx + 1}:")
        print(f"  Decomp: {e['decomp']}, Comp: {e['comp']}, Key: 0x{e['key']:02X}")

        blob_off = e['blob_off']

        # For Type 1 with nested PE, adjust offset
        if detected_type == "1" and nested_pe_offset:
            blob_off = nested_pe_offset + e['blob_off']
            print(f"  Blob offset: 0x{e['blob_off']:X} -> 0x{blob_off:X} (nested PE adjusted)")
        else:
            print(f"  Blob offset: 0x{blob_off:X}")

        if blob_off + e['comp'] > len(data):
            print("  ERROR: Blob extends beyond file!")
            continue

        blob = data[blob_off : blob_off + e['comp']]

        print("  Decrypting...")
        decrypted = decrypt_blob(blob, e['key'])

        print("  Decompressing...")
        decompressed = decompress_lzss(decrypted, e['decomp'])

        print(f"  Result: {len(decompressed)} bytes")

        # Validate D88 header
        valid, header_name = validate_d88(decompressed)
        # Handle non-ASCII names for console output
        try:
            display_name = header_name.encode('ascii').decode('ascii')
        except:
            display_name = header_name.encode('ascii', errors='replace').decode('ascii')
        if valid:
            print(f'  Header name: "{display_name}" (valid D88)')
        else:
            print(f'  WARNING: Invalid D88 header!')
            if display_name:
                print(f'  Header name: "{display_name}"')

        # Save with appropriate extension
        out_name = os.path.join(output_dir, f"{base_name}_disk_{idx + 1}.d88")
        with open(out_name, 'wb') as out:
            out.write(decompressed)
        print(f"  Saved to {out_name}\n")
        extracted += 1

    print(f"Extraction complete. {extracted}/{len(entries)} disks extracted.")
    return extracted

def main():
    if len(sys.argv) < 2:
        print("egg_datafilever_ext")
        print("Usage: python egg_datafilever_ext.py <game.exe> [output_dir]")
        print("\nSupports Type 1 (string xref metadata) and Type 2/3/4 (E9 0B signature)")
        return

    exe_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(exe_path):
        print(f"Error: File not found: {exe_path}")
        return

    extract_disks(exe_path, output_dir)

if __name__ == "__main__":
    main()
