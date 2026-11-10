import sys
import struct
import os

def read_null_terminated_string(data: bytes, start_idx: int):
    """Reads a C-style string, defaulting to Shift-JIS (cp932) for Japanese games."""
    end_idx = data.find(b'\x00', start_idx)
    if end_idx == -1:
        return "", start_idx
    
    raw_bytes = data[start_idx:end_idx]
    try:
        string_val = raw_bytes.decode('cp932')
    except UnicodeDecodeError:
        string_val = raw_bytes.decode('latin-1', errors='ignore')
        
    return string_val, end_idx + 1

def analyze_patcher(file_path: str):
    print(f"[*] Analyzing executable: {file_path}")
    
    try:
        with open(file_path, 'rb') as f:
            patch_data = f.read()
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        return

    payload_offset = patch_data.find(b'Diff', 20000)
    if payload_offset == -1:
        print("[-] 'Diff' signature not found.")
        return

    print(f"\n[+] Archive start found at offset: 0x{payload_offset:X}")
    file_count = 0

    while payload_offset < len(patch_data):
        if patch_data[payload_offset : payload_offset + 4] != b'Diff':
            print(f"\n[+] Reached end of valid Diff structures at 0x{payload_offset:X}")
            break

        flag_byte = patch_data[payload_offset + 6]
        if flag_byte & 0x80:
            print("\n[+] End-of-Archive marker reached. Parsing complete.")
            break

        file_count += 1
        print(f"\n{'='*50}")
        print(f"--- Patch Entry #{file_count} @ 0x{payload_offset:X} ---")
        
        ver_major = patch_data[payload_offset + 4]
        ver_minor = patch_data[payload_offset + 5]
        version = ver_major * 100 + ver_minor

        exp_orig_crc = struct.unpack("<I", patch_data[payload_offset + 8 : payload_offset + 12])[0]
        exp_patch_crc = struct.unpack("<I", patch_data[payload_offset + 12 : payload_offset + 16])[0]
        new_file_size = struct.unpack("<I", patch_data[payload_offset + 20 : payload_offset + 24])[0]
        print(f"[*] Version: {version}")
        print(f"[*] Expected Original CRC32 : 0x{exp_orig_crc:08X}")
        print(f"[*] Expected Patched CRC32  : 0x{exp_patch_crc:08X}")
        print(f"[*] Expected Target Size    : {new_file_size} bytes")

        strings_start = payload_offset + 31
        target_filename, ptr = read_null_terminated_string(patch_data, strings_start)
        secondary_string, ptr = read_null_terminated_string(patch_data, ptr)
        
        path_prefix = ""
        if version > 100:
            path_prefix, ptr = read_null_terminated_string(patch_data, ptr)

        print(f"[*] Target Filename : '{target_filename}'")
        print(f"[*] Update Context  : '{secondary_string}'")

        cmd_word = struct.unpack("<H", patch_data[ptr : ptr + 2])[0]
        accumulated_bytes = 0
        
        if cmd_word == 0x8000:
            print("    [*] Special 0x8000 marker found. Skipping instruction loop.")
            ptr += 6
            accumulated_bytes = new_file_size

        insert_count, insert_bytes = 0, 0
        copy_count, copy_bytes = 0, 0
        
        # Buffer to hold the completely new file data
        reconstructed_data = bytearray()

        while accumulated_bytes < new_file_size and ptr < len(patch_data):
            cmd_word = struct.unpack("<H", patch_data[ptr : ptr + 2])[0]
            is_copy_cmd = (cmd_word & 0x8000) != 0
            
            if not is_copy_cmd:
                # INSERT COMMAND
                length = cmd_word
                
                # Grab the raw bytes from the patch payload
                raw_bytes = patch_data[ptr + 2 : ptr + 2 + length]
                reconstructed_data.extend(raw_bytes)
                
                ptr += 2 + length
                insert_count += 1
                insert_bytes += length
                accumulated_bytes += length
            else:
                # COPY COMMAND
                length = cmd_word & 0x7FFF
                ptr += 6
                
                copy_count += 1
                copy_bytes += length
                accumulated_bytes += length

        print(f"    [*] Operations : {copy_count} COPY, {insert_count} INSERT")
        
        if accumulated_bytes == new_file_size:
            print(f"    [+] Checksum boundaries align perfectly ({new_file_size:,} bytes).")
            
            # --- FULL REPLACEMENT EXTRACTION CHECK ---
            if copy_count == 0 and insert_count > 0:
                print("    [!] Full Replacement detected! Extracting file...")
                
                # Sanitize filename (replace folder slashes with underscores so it dumps safely in the current dir)
                safe_filename = target_filename.replace('\\', '_').replace('/', '_')
                out_name = f"extracted_{safe_filename}"
                
                try:
                    with open(out_name, 'wb') as out_file:
                        out_file.write(reconstructed_data)
                    print(f"    [+] Successfully saved to: {out_name}")
                except Exception as e:
                    print(f"    [-] Failed to save extracted file: {e}")
        else:
            print(f"    [-] WARNING: Loop exited abnormally. Calculated: {accumulated_bytes:,}")

        payload_offset = ptr

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("AjariSoft patcher parser 0.2 (1.0.5.0")
        print(f"Usage: python {sys.argv[0]} <path_to_patcher.exe>")
        sys.exit(1)
        
    analyze_patcher(sys.argv[1])