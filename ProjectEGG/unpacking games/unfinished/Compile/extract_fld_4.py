import os
import re
import struct
from struct import unpack
from sys import argv

# ==========================================
# DECRYPTION CONFIGURATION
# ==========================================
SET_MODE = 0  
SET_KEY  = -1677351266  # 0x9C00001E
# ==========================================

# --- DECOMPRESSION (CNX v2) ---

def decompress_cnx(data):
    """
    Decompresses Atlus CNX v2 using the exact logic from sub_414F30.
    """
    if len(data) < 16 or data[:4] != b"CNX\x02":
        return data, "bin"

    # Header Parsing (Big Endian)
    ext_raw = data[4:7]
    try:
        extension = ext_raw.decode("ascii", errors="ignore")
        extension = "".join(c for c in extension if c.isalnum()).lower()
        if not extension: extension = "bmp"
    except:
        extension = "bmp"

    # Decompressed size is Big Endian at offset 12
    decomp_size = struct.unpack(">I", data[12:16])[0]
    
    input_ptr = 16
    output = bytearray()
    
    # Mirroring the while ( dword_836CCC < dword_836CD0 ) loop from sub_414E80
    while len(output) < decomp_size and input_ptr < len(data):
        control = data[input_ptr]
        input_ptr += 1
        
        # If control byte is 0, the sub_414F30 function returns 2 (End of Block)
        if control == 0:
            break

        # Process 4 tokens (2 bits each) per control byte
        for _ in range(4):
            if len(output) >= decomp_size:
                break
                
            op = control & 0x03
            control >>= 2
            
            if op == 0: # Case 0: Skip/Metadata block
                if input_ptr < len(data):
                    skip_len = data[input_ptr]
                    input_ptr += (skip_len + 1)
                # sub_414F30 returns 1 here, triggering a new control byte read
                break 
                
            elif op == 1: # Case 1: Single Literal
                if input_ptr < len(data):
                    output.append(data[input_ptr])
                    input_ptr += 1
                    
            elif op == 2: # Case 2: LZ Match (The logic from sub_4150A0)
                if input_ptr + 1 < len(data):
                    # v8 = v6[1] | (v6[0] << 8)
                    v8 = (data[input_ptr] << 8) | data[input_ptr+1]
                    input_ptr += 2
                    
                    length = (v8 & 0x1F) + 4
                    offset = (v8 >> 5) + 1
                    
                    # sub_4150A0 loop
                    for _ in range(length):
                        if len(output) >= decomp_size: break
                        back_ptr = len(output) - offset
                        if back_ptr >= 0:
                            output.append(output[back_ptr])
                        else:
                            output.append(0) # Padding
                            
            elif op == 3: # Case 3: Multi-literal block
                if input_ptr < len(data):
                    count = data[input_ptr]
                    input_ptr += 1
                    for _ in range(count):
                        if input_ptr < len(data):
                            output.append(data[input_ptr])
                            input_ptr += 1
                            
    return bytes(output), extension

# --- DECRYPTION UTILITIES ---

def generate_seed(mode, key_value):
    """Replicates sub_406EC0 logic for Seed Generation."""
    if mode == 0:
        return int(key_value) & 0xFFFFFFFF
    elif mode == 1:
        result = 1103515245
        s_bytes = str(key_value).encode('ascii')[:12]
        for v3 in s_bytes:
            v4 = (result * (1103515245 - v3)) & 0xFFFFFFFF
            result = (v4 + v3 + 12345) & 0xFFFFFFFF
        return result
    return 0

def decrypt_data(ciphertext, seed):
    """Replicates sub_407090: The Backwards Rolling XOR/Sub Cipher."""
    remainder = len(ciphertext) % 4
    if remainder != 0:
        ciphertext += b'\x00' * (4 - remainder)
    
    data = list(struct.unpack(f'<{len(ciphertext)//4}I', ciphertext))
    
    v2 = seed
    v3 = len(ciphertext) - 4 
    i = (seed + v3) & 0xFFFFFFFF
    
    for idx in range(len(data) - 1, -1, -1):
        v6 = (v2 + i) & 0xFFFFFFFF
        v7 = (data[idx] - i) & 0xFFFFFFFF
        v8 = (v2 ^ v7) & 0xFFFFFFFF
        
        data[idx] = v8
        
        v2_minus_v8 = (v2 - v8) & 0xFFFFFFFF
        v2 = ((v6 << 8) ^ (v2_minus_v8 >> 8)) & 0xFFFFFFFF
        v2 &= 0xFFFFFFFF 
        i = (i - 3) & 0xFFFFFFFF

    decrypted_bytes = struct.pack(f'<{len(data)}I', *data)
    
    padded_size = len(decrypted_bytes)
    if padded_size >= 8:
        original_size = struct.unpack('<I', decrypted_bytes[-8:-4])[0]
        expected_padded_size = 4 * ((original_size + 3) // 4) + 8
        
        if padded_size == expected_padded_size:
            return decrypted_bytes[:original_size]
    return decrypted_bytes

# --- FILENAME UTILITIES ---

def sanitize_filename(name):
    return re.sub(r'[\x00-\x1f*?:"<>|]', "_", name)

def decode_string(raw):
    raw = raw.split(b"\x00", 1)[0]
    for enc in ("cp932", "shift_jis", "utf-8", "latin1"):
        try:
            decoded = raw.decode(enc)
            normalized = decoded.replace("\\", os.sep).replace("/", os.sep)
            return sanitize_filename(normalized)
        except:
            continue
    return "unknown"

# --- CORE LOGIC ---

def get_header_info(f, magic):
    raw_size = f.read(4)
    if len(raw_size) < 4: return 0, "", 0
    hdr_size = unpack("<I", raw_size)[0]
    
    raw_count = f.read(4)
    if len(raw_count) < 4: return 0, "", hdr_size
    count = unpack("<I", raw_count)[0]

    sub_dir = ""
    if magic == b"FLDF0300":
        f.read(4) 
        dir_len = hdr_size - 20
        if dir_len > 0:
            sub_dir = decode_string(f.read(dir_len))
        print(f"    [+] FLDF0300 | Header: {hdr_size} bytes | Files: {count} | Path: '{sub_dir}'")
    else:
        print(f"    [+] FLDF0200 | Header: {hdr_size} bytes | Files: {count}")
    
    return count, sub_dir, hdr_size

def get_entries(f, count, magic, hdr_size):
    f.seek(hdr_size)
    entries = []
    
    for i in range(count):
        if magic == b"FLDF0200":
            raw = f.read(20)
            if len(raw) < 20: break
            name_raw, offset, size = unpack("<12sII", raw)
            flag = 0 
        else:
            raw = f.read(24)
            if len(raw) < 24: break
            flag, offset, size, name_raw = unpack("<III12s", raw)
        
        entries.append((decode_string(name_raw), offset, size, flag))
    return entries

def extract_and_recurse(f, entries, filesize, current_out_dir, seed):
    for i, (name, offset, size, flag) in enumerate(entries):
        if offset + size > filesize:
            print(f"    [{i:03}] {name} -> ERROR: Out of bounds")
            continue

        f.seek(offset)
        data = f.read(size)
        
        status = "CLEAN"
        
        # 1. Decryption Layer
        if (flag & 1):
            data = decrypt_data(data, seed)
            status = "DECRYPTED"
            
        # 2. Decompression Layer
        if data.startswith(b"CNX"):
            data, ext = decompress_cnx(data)
            # Replace original extension with the one from the CNX header
            base_name = os.path.splitext(name)[0]
            safe_name = f"{base_name}.{ext}"
            status += " + DECOMPRESSED"
        else:
            safe_name = name if "." in name else f"{name}.bin"

        out_name = f"{safe_name}"
        out_path = os.path.join(current_out_dir, out_name)

        try:
            with open(out_path, "wb") as out:
                out.write(data)
            print(f"    [{i:03}] {out_name} ({len(data)} bytes) [{status}]")

            # 3. Recursion Layer (for nested archives)
            if data.startswith(b"FLDF"):
                unpack_fld(out_path, current_out_dir)
                
        except OSError as e:
            print(f"    [{i:03}] Failed to write {out_name}: {e}")

def unpack_fld(filepath, target_root):
    if not os.path.exists(filepath) or os.path.isdir(filepath):
        return

    filesize = os.path.getsize(filepath)
    if filesize < 12: return

    seed = generate_seed(SET_MODE, SET_KEY)

    with open(filepath, "rb") as f:
        magic = f.read(8)
        if not magic.startswith(b"FLDF"):
            return 

        print(f"\n--- Processing: {os.path.basename(filepath)} ---")
        
        count, header_dir, hdr_size = get_header_info(f, magic)
        entries = get_entries(f, count, magic, hdr_size)
        
        final_dir = os.path.join(target_root, header_dir) if header_dir else target_root
        os.makedirs(final_dir, exist_ok=True)

        extract_and_recurse(f, entries, filesize, final_dir, seed)

def main():
    if len(argv) < 2:
        print("Usage: python script.py <file.fld>")
        return

    input_file = argv[1]
    base_out = os.path.splitext(os.path.basename(input_file))[0]
    
    unpack_fld(input_file, base_out)
    print("\n[+] Done.")

if __name__ == "__main__":
    main()