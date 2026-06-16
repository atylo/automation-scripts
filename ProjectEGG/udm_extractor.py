import os
import sys
import struct
import zlib
import io

def find_udm_header(f):
    MAGIC = b'UDM ' # usually at 0x32000
    f.seek(0)
    data = f.read()
    pos = 0
    while True:
        pos = data.find(MAGIC, pos)
        if pos == -1:
            return -1
        if pos + 6 <= len(data):
            version = struct.unpack_from('<H', data, pos + 4)[0]
            # version encodes from 2 bytes as MMmP (e.g. 123 = v1.2.3); 900+ would be v9.x which might not exist
            if 1 <= version <= 899:
                return pos
        pos += 1

def read_string_1(f):
    length_byte = f.read(1)
    if not length_byte: return ""
    return f.read(length_byte[0]).decode('shift_jis', errors='replace')

def read_string_4(f):
    length = struct.unpack('<I', f.read(4))[0]
    return f.read(length).decode('shift_jis', errors='replace')

def parse_udf_stream(udf_bytes: bytes) -> tuple[bytes | None, str]:
    """
    Parses a decompressed UDF stream in memory.
    Returns (extracted_bytes, "Fully Extracted") if it's a pure insert patch.
    Returns (None, "reason") if it requires a base file, is truncated, or is invalid.
    """
    if len(udf_bytes) < 18:
        return None, "File too small"

    header = udf_bytes[:18]
    magic, version, chunk_size, target_size = struct.unpack('<4sHIQ', header)

    if magic != b'UDF ':
        return None, "Invalid UDF magic"
    
    if version != 110:
        print(f"Unknown version: {version} (0x{version:04X}, might not parse well.")

    stream = io.BytesIO(udf_bytes[18:])
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
                return None, f"Requires base file (Opcode {opcode})"

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
                return None, f"Unknown opcode 0x{opcode:02X}"

    except struct.error:
        return None, "Malformed UDF instruction stream"

    if len(out_buffer) != target_size:
        return None, f"Size mismatch: got {len(out_buffer)} bytes, expected {target_size}"

    return bytes(out_buffer), "Fully Extracted"

def extract_udm_archive(file_path, output_dir="extracted"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    file_list = []
    file_size = os.path.getsize(file_path)

    with open(file_path, 'rb') as f:
        #  0. Locate the embedded UDM blob 
        base_offset = find_udm_header(f)
        if base_offset == -1:
            print("Error: UDM signature (55 44 4D 20) not found in file.")
            return
            
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
        # Find the exact start of the zlib stream
        curr_pos = f.tell()
        f.seek(base_offset)
        data_tail = f.read()
        z_idx = data_tail.find(b'\x78\x9c', curr_pos - base_offset)
        zlib_start = base_offset + z_idx if z_idx != -1 else file_size
        f.seek(curr_pos)

        # 2. Strict, Fallback-Proof Scanner 
        # Instead of guessing padding, we scan the space between the company name
        # and zlib_start. We keep the LAST valid 18-byte block we find, guaranteeing
        # we bypass all variable-length ReadMe text and Registry configurations.
        search_space = f.read(zlib_start - curr_pos)
        manifest_offset = -1
        candidates = []
        
        for i in range(len(search_space) - 18):
            chunk = search_space[i:i+18]
            # First 6 bytes must be pure booleans
            if any(b not in (0, 1) for b in chunk[:6]):
                continue
            
            v123, v121, v120 = struct.unpack('<III', chunk[6:18])
            #if v123 + v121 + v120 == 0 or v123 + v121 + v120 > 5000:
            if any(v > 1000 for v in (v123, v121, v120)):
                continue
            if v123 + v121 + v120 == 0:
                continue
            
            flaggies = struct.unpack('<HHH', chunk[:6]) # Too strict?
            if sum(flaggies) + v123 == 0:
                continue
                
            # The next byte must be a valid string length for the first filename
            if i + 18 < len(search_space):
                name_len = search_space[i+18]
                if 0 < name_len <= 128:
                    manifest_offset = curr_pos + i
                    candidates.append(curr_pos + i)
                    
        if manifest_offset == -1:
            print("Error: Could not locate configuration manifest.")
            return
            
        # print(f"candidates: {candidates}")
        # for c in candidates:
            # f.seek(c)
            # cand = f.read(18)
            # print(f"Candidate @ {hex(c)}: {cand.hex(' ')}")
            
        f.seek(manifest_offset)
        flags_data = f.read(18)
        is_compressed = flags_data[5] == 1
        files_a, files_b, files_c = struct.unpack('<III', flags_data[6:18])

        print(f"Archive Config: Compressed Data: {is_compressed}")
        print(f"File Entries:   {files_a} (Standard), {files_b} (Full Files), {files_c} (Delete Rules)")
        
        # 3. Build file index using FAT Guesser
        print("\nBuilding and validating file index...")
        
        last_good_blob_offset = 0
        last_good_comp_size = 0
        files_parsed = 0
        
        total_files = files_a + files_b + files_c
        for _ in range(total_files):
        #while f.tell() < zlib_start: Worse way of looping?
            name_len_byte = f.read(1)
            if not name_len_byte:
                break
            name_len = name_len_byte[0]
            if name_len == 0 or name_len > 128:
                break

            filename = f.read(name_len).decode('shift_jis', errors='replace')
            entry_pos = f.tell()
            
            if files_parsed < files_a:
                file_type = 'A' # Standard Patch (UDF)
            elif files_parsed < files_a + files_b:
                file_type = 'B' # Full File Replacement
            else:
                file_type = 'C' # Deletion Rule
                
            blob_offset = 0
            comp_size = 0
            valid_found = False
            
            # probe for metadata block size; format uses variable-length pre-metadata padding
            # Deletion Rules ('C') do not possess an archive data payload size format
            if file_type in ('A', 'B'):
                for metadata_len in range(8, 65, 8):
                    if entry_pos + metadata_len + 16 > zlib_start:
                        continue
                    
                    f.seek(entry_pos + metadata_len)
                    meta_bytes = f.read(16)
                    if len(meta_bytes) < 16:
                        continue
                    
                    try_blob_offset, try_comp_size = struct.unpack('<QQ', meta_bytes)

                    if 0 < try_comp_size and (base_offset + try_blob_offset + try_comp_size) <= file_size:
                        blob_offset = try_blob_offset
                        comp_size = try_comp_size
                    
                        last_good_blob_offset = blob_offset
                        last_good_comp_size = comp_size
                        valid_found = True
                    
                        f.seek(entry_pos + metadata_len + 16)
                        break

                if not valid_found:
                    remaining_fat_bytes = zlib_start - entry_pos
                    if remaining_fat_bytes <= 16:
                        file_list.append({
                            'filename': filename, 'blob_offset': 0, 'comp_size': 0, 'type': file_type
                        })
                        f.seek(zlib_start)
                        files_parsed += 1
                        break # kinda strict and brittle, should be fixed
                    else:
                        blob_offset = last_good_blob_offset + last_good_comp_size
                        comp_size = file_size - (base_offset + blob_offset)
                        print(f"  [!] Bogus metadata for {filename}. Sequential fallback: (comp_size=0x{comp_size:X})")
                        file_list.append({
                            'filename': filename, 'blob_offset': blob_offset, 'comp_size': comp_size, 'type': file_type
                        })
                        files_parsed += 1
                        break # kinda strict and brittle too

            file_list.append({
                'filename': filename, 'blob_offset': blob_offset, 'comp_size': comp_size, 'type': file_type
            })
            files_parsed += 1

        payload_count = sum(1 for entry in file_list if entry['comp_size'] > 0)
        rule_count = len(file_list) - payload_count
        print(f"\nFAT cleaned. Found {payload_count} payloads and {rule_count} deletion rules.")

        #  4. Extract & Parse 
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

if __name__ == "__main__":
    print("# Ultimate UDM and UDF extractor v0.5")
    if len(sys.argv) < 2:
        print("Extractor for udm Self Extract Updater exes, including UDM archives and differential UDF patches,")
        print("which may contain full content data and be \'pure inserts\'.")
        print(f"Usage: python {os.path.basename(sys.argv[0])} <input_file> [output_dir]")
        sys.exit(1)

    input_file = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else f"{sys.argv[1]}_extracted"

    if not os.path.isfile(input_file):
        print(f"Error: file not found: {input_file}")
        sys.exit(1)

    extract_udm_archive(input_file, out_dir)
