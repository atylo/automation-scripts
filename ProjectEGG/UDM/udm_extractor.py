import os
import sys
import struct
import zlib
import io

def find_udm_headers(f):
    MAGIC = b'UDM '
    offsets = set()

    f.seek(0)
    data = f.read() 

    pos = 0
    while (pos := data.find(MAGIC, pos)) != -1:
        if pos + 6 <= len(data):
            v = struct.unpack_from('<H', data, pos + 4)[0]
            if 1 <= v <= 899:
                offsets.add(pos)
        pos += 1

    return sorted(offsets)

def read_string_1(f):
    length_byte = f.read(1)
    if not length_byte: return ""
    return f.read(length_byte[0]).decode('shift_jis', errors='replace')

def parse_udf_stream(udf_bytes: bytes) -> tuple[bytes | None, str]:
    """
    Parses a decompressed UDF stream in memory.
    Returns (extracted_bytes, "Fully Extracted") if it's a pure insert patch.
    Returns (None, "reason") if it requires a base file, is truncated, or is invalid.
    """
    if len(udf_bytes) < 10:
        return None, "File too small"

    header = udf_bytes[:10]
    magic, version, chunk_size = struct.unpack('<4sHI', header)

    # parse the Target Size if version is 110
    target_size = None
    if version == 110:
        target_size, = struct.unpack('<Q', udf_bytes[10:18])
        stream_offset = 18
    elif version == 100:
        stream_offset = 10
    else:
        return None, f"Unsupported version: {version} (0x{version:04X})"

    if magic != b'UDF ':
        return None, "Invalid UDF magic"

    stream = io.BytesIO(udf_bytes[stream_offset:])
    out_buffer = bytearray()

    try:
        while True:
            opcode_byte = stream.read(1)
            if not opcode_byte:
                break

            opcode = opcode_byte[0]

            if opcode == 0:     # EOF marker
                break
            elif opcode in (1, 2, 3):   # Copy from Old File (delta; out of scope)
                return None, "Requires base file"

            elif opcode == 4:   # Insert 1 raw chunk
                data = stream.read(chunk_size)
                if len(data) != chunk_size:
                    return None, f"Opcode 4: truncated chunk (got {len(data)}, expected {chunk_size})"
                out_buffer.extend(data)

            elif opcode == 5:   # Insert N raw chunks
                size_field = stream.read(4)
                if len(size_field) != 4:
                    return None, "Opcode 5: truncated count field"
                count, = struct.unpack('<I', size_field)
                expected = count * chunk_size
                data = stream.read(expected)
                if len(data) != expected:
                    return None, f"Opcode 5: truncated data (got {len(data)}, expected {expected})"
                out_buffer.extend(data)

            elif opcode == 6:   # Insert exact byte count
                size_field = stream.read(4)
                if len(size_field) != 4:
                    return None, "Opcode 6: truncated size field"
                exact_size, = struct.unpack('<I', size_field)
                data = stream.read(exact_size)
                if len(data) != exact_size:
                    return None, f"Opcode 6: truncated data (got {len(data)}, expected {exact_size})"
                out_buffer.extend(data)

            else:
                return None, f"Unknown opcode 0x{opcode:02X} encountered. Halting."

    except struct.error:
        return None, "Malformed UDF instruction stream"
        
    if version == 110 and len(out_buffer) != target_size:
        return None, f"Size mismatch: got {len(out_buffer)} bytes, expected {target_size:,}"

    return bytes(out_buffer), "Fully Extracted"

def walk_fat(f, files_a, files_b, files_c, base_offset, file_size):
    """
    Fully parses the FAT starting right after manifest_offset.
    Returns the parsed file_list on success, or None if the walk fails
    partway through — which means this candidate is wrong, or the file
    is corrupted/truncated. There is no silent partial-success case.
    """
    total_files = files_a + files_b + files_c
    file_list = []
    last_good_blob_offset = 0
    last_good_comp_size = 0

    for files_parsed in range(total_files):
        name_len_byte = f.read(1)
        if not name_len_byte:
            return None
        name_len = name_len_byte[0]
        if name_len == 0 or name_len > 256:
            return None

        name_bytes = f.read(name_len)
        if len(name_bytes) != name_len:
            return None
        try:
            filename = name_bytes.decode('shift_jis', errors='strict')
        except UnicodeDecodeError:
            return None

        entry_pos = f.tell()
        if files_parsed < files_a:
            file_type = 'A'
        elif files_parsed < files_a + files_b:
            file_type = 'B'
        else:
            file_type = 'C'

        blob_offset, comp_size, valid_found = 0, 0, False

        if file_type in ('A', 'B'):
            for metadata_len in range(8, 65, 8):
                if entry_pos + metadata_len + 16 > file_size:
                    break
                f.seek(entry_pos + metadata_len)
                meta_bytes = f.read(16)
                if len(meta_bytes) < 16:
                    continue
                    
                # Try uint64 first (v2.x format)
                try_blob_offset, try_comp_size = struct.unpack('<QQ', meta_bytes)
                if 0 < try_comp_size and (base_offset + try_blob_offset + try_comp_size) <= file_size:
                    blob_offset, comp_size = try_blob_offset, try_comp_size
                    last_good_blob_offset, last_good_comp_size = blob_offset, comp_size
                    valid_found = True
                    f.seek(entry_pos + metadata_len + 16)
                    break

                # Try uint32 (v1.x format) — blob/comp fit in first 8 bytes
                try_blob_offset, try_comp_size = struct.unpack('<II', meta_bytes[:8])
                if 0 < try_comp_size and (base_offset + try_blob_offset + try_comp_size) <= file_size:
                    blob_offset, comp_size = try_blob_offset, try_comp_size
                    last_good_blob_offset, last_good_comp_size = blob_offset, comp_size
                    valid_found = True
                    f.seek(entry_pos + metadata_len + 8)  # advance only 8, not 16
                    break

            if not valid_found:
                is_last_entry = (files_parsed == total_files - 1)
                remaining_fat_bytes = file_size - entry_pos
                if is_last_entry and remaining_fat_bytes > 16:
                    blob_offset = last_good_blob_offset + last_good_comp_size
                    comp_size = file_size - (base_offset + blob_offset)
                else:
                    return None  # desync — reject this candidate entirely

        file_list.append({'filename': filename, 'blob_offset': blob_offset,
                           'comp_size': comp_size, 'type': file_type})

    return file_list
    
def extract_udm_archive(file_path, base_offset, output_dir="extracted"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    file_list = []
    file_size = os.path.getsize(file_path)

    with open(file_path, 'rb') as f:       
        print(f"Found valid UDM signature at file offset: 0x{base_offset:08X}")
        f.seek(base_offset + 4)

        #  1. Parse Global Header 
        version = struct.unpack('<H', f.read(2))[0]
        major, minor, patch = version // 100, (version // 10) % 10, version % 10
        print(f"\nUDM Archive Version {major}.{minor}.{patch}.0 (0x{version:X})\n")

        game_name = read_string_1(f)
        old_ver   = read_string_1(f)
        new_ver   = read_string_1(f)
        company   = read_string_1(f)

        print("--- UDM Archive Metadata ---")
        print(f"Game:    {game_name}")
        print(f"Update:  {old_ver} -> {new_ver}")
        print(f"Company: {company}")
        print("----------------------------\n")
        
        
        print("Locating FAT manifest...")
        curr_pos = f.tell()
        f.seek(base_offset)
        udm_start = f.read()
        z_idx = udm_start.find(b'\x78\x9c', curr_pos - base_offset)
        search_end = (base_offset + z_idx) if z_idx != -1 else file_size
        
        f.seek(curr_pos)
        
        
        # 2. Strict, Fallback-Proof Scanner 
        # Instead of guessing padding, we scan the space between the company name
        # and zlib_start. We keep the LAST valid 16-byte block we find, guaranteeing
        # we bypass all variable-length ReadMe text and Registry configurations.
        search_space = f.read(search_end - curr_pos)
        manifest_offset = -1
        candidates = []
        flag_size, bool_count, is_comp_idx = 16, 4, 3
        
        for i in range(len(search_space) - flag_size):
            chunk = search_space[i:i+flag_size]
            # First 4 bytes must be pure booleans, haven't witnessed otherwise.
            if any(b not in (0, 1) for b in chunk[:bool_count]):
                continue
            
            v123, v121, v120 = struct.unpack('<III', chunk[bool_count:flag_size])
            if any(v > 10000 for v in (v123, v121, v120)):
                continue
            if v123 + v121 + v120 == 0:
                continue
            
            
            # The next byte must be a valid string length for the first filename
            if i + flag_size < len(search_space):
                name_len = search_space[i+flag_size]
                if 0 < name_len <= 256:
                    # Look ahead and attempt to decode the filename string
                    if i + flag_size+1 + name_len <= len(search_space):
                        test_name_bytes = search_space[i+flag_size+1 : i+flag_size+1+name_len]
                        # Valid filenames rarely contain raw escape characters or nulls
                        # Reject if it contains raw control characters (ASCII < 32)
                        if any(b < 32 for b in test_name_bytes):
                            continue
                        try:
                            test_name = test_name_bytes.decode('shift_jis', errors='strict')
                            manifest_offset = curr_pos + i
                            candidates.append(curr_pos + i)
                            #print(f"Added candidate at offset: 0x{curr_pos + i:X}")
                        except UnicodeDecodeError:
                            # If it can't decode as Shift-JIS, it's likely false positive binary data
                            continue
                    
        if manifest_offset == -1:
            print("Error: Could not locate configuration manifest.")
            return
            
        for c in reversed(candidates):
            f.seek(c)
            flags_data = f.read(flag_size)
            fa, fb, fc = struct.unpack('<III', flags_data[bool_count:flag_size])
            #f.seek(c+flag_size)
            result = walk_fat(f, fa, fb, fc, base_offset, file_size)
            if result is not None:
                is_compressed = flags_data[is_comp_idx] == 1
                files_a, files_b, files_c = fa, fb, fc
                file_list = result
                break
        else:
            print("Error: no candidate manifest produced a fully consistent FAT.")
            return

            
        print(f"Archive Config: Compressed Data: {is_compressed}")
        print(f"File Entries: {files_a} (Standard), {files_b} (Full Files), {files_c} (Delete Rules)")
              

        payload_count = sum(1 for entry in file_list if entry['comp_size'] > 0)
        rule_count = len(file_list) - payload_count
        print(f"\nFAT cleaned. Found {payload_count} payloads and {rule_count} deletion rules.")

        #  4. Extract & Parse
        if payload_count >= 40:
            print(f"Extracting {payload_count} files...")

        for file_info in file_list:
            if file_info['comp_size'] == 0:
                print(f"File {file_info['filename']} is marked for deletion.")
                continue
            
            try:
                f.seek(base_offset + file_info['blob_offset'])
                compressed_data = f.read(file_info['comp_size'])

                if is_compressed:
                    uncompressed_data = zlib.decompress(
                        compressed_data, wbits=zlib.MAX_WBITS | 32
                    )
                else:
                    uncompressed_data = compressed_data

                final_data = uncompressed_data
                out_name = file_info['filename']

                # UDF inline parsing logic
                if file_info['type'] == 'A' and uncompressed_data.startswith(b"UDF "):
                    extracted_payload, status_msg = parse_udf_stream(uncompressed_data)
                    
                    if extracted_payload:
                        final_data = extracted_payload
                        patch_status = f"UDF Patch -> {status_msg}"
                    else:
                        out_name += ".udf" # Append .udf so we know it isn't a rebuilt file
                        patch_status = f"UDF Patch -> Saved Raw ({status_msg})"
                else:
                    patch_status = "Full File Replacement"
                if payload_count < 40:
                    print(f"Extracting {file_info['filename']} [{patch_status}]...")

                # Directory Traversal Sanitizer Protection
                clean_name = out_name.replace('\\', '/').lstrip('/')
                parts = [p for p in clean_name.split('/') if p and p != '..']
                out_path = os.path.join(output_dir, *parts)
                
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                
                with open(out_path, 'wb') as out_f:
                    out_f.write(final_data)

            except Exception as e:
                print(f"  [!] Error extracting {file_info['filename']}: {e}")
                
    print("Extraction complete.")
    
if __name__ == "__main__":
    print("# Ultimate UDM and UDF extractor v0.8")
    if len(sys.argv) < 2:
        print("Extractor for udm Self Extract Updater exes, including UDM archives and differential UDF patches,")
        print("which may contain full content data and be \'pure inserts\'.")
        print(f"Usage: python {os.path.basename(sys.argv[0])} <input_file> [output_dir]")
        sys.exit(1)

    input_file = sys.argv[1]
    base_out_dir = ( sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(input_file)[0] )

    if not os.path.isfile(input_file):
        print(f"Error: file not found: {input_file}")
        sys.exit(1)

    with open(input_file, 'rb') as f:
        offsets = find_udm_headers(f)

    if not offsets:
        print("Error: UDM signature (55 44 4D 20) not found in file.")
        sys.exit(1)

    for index, offset in enumerate(offsets, start=1):
        out_dir = f"{base_out_dir}_{index}"
        extract_udm_archive(input_file, offset, out_dir)