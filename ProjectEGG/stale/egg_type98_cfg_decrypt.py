import argparse
from pathlib import Path
import struct
import os
import binascii

#For EGG type archives if they exist EGG\x00 01 00 00 00
def unpack_egg_file(file_path, asset_id):
    with open(file_path, 'rb') as f:
        # Header Checks
        signature = f.read(4)
        if signature != b'EGG\x00':
            print("Invalid Magic")
            return
            
        f.seek(0x48)
        file_asset_id = struct.unpack('<I', f.read(4))[0]
        uncompressed_size = struct.unpack('<I', f.read(4))[0]
        expected_crc = struct.unpack('<I', f.read(4))[0]
        seed_byte = struct.unpack('<B', f.read(1))[0]
        
        if file_asset_id != asset_id:
            print(f"Asset ID mismatch: {file_asset_id} != {asset_id}")
            return

        # Read Payload
        encrypted_payload = f.read()
        
    print(f"Decrypting {len(encrypted_payload)} bytes...")
    decrypted_data = decrypt_v1(encrypted_payload, seed_byte)
    
    print(f"Decompressing to {uncompressed_size} bytes...")
    final_data = lzss_decompress(decrypted_data, uncompressed_size)
    
    
    return final_data
    
def parse_config_file(decrypted_data):
    if len(decrypted_data) != 223: # 0xDF
        print("Error: Invalid config file size.")
        return

    # Unpack based on the struct layout
    # Structure: I (ID), 64s (Title), 64s (ProdID), I (Flag), B (Byte1), B (Byte2), H (Short), ...
    
    config_id = struct.unpack('<I', decrypted_data[0:4])[0]
    
    # Strings are null-terminated within their 64-byte buffers
    raw_title = decrypted_data[4:68]
    title_str = raw_title.split(b'\x00')[0].decode('shift_jis', errors='replace')
    
    raw_prod = decrypted_data[68:132]
    prod_str = raw_prod.split(b'\x00')[0].decode('ascii', errors='replace')
    
    # Specific Settings mapped from 0x85
    val_85 = decrypted_data[0x85]
    val_87 = struct.unpack('<H', decrypted_data[0x87:0x89])[0]
    val_8A = struct.unpack('<I', decrypted_data[0x8A:0x8E])[0]
    
    print("=== Config Dump ===")
    print(f"Config ID:      {config_id}")
    print(f"Game Title:     {title_str}")
    print(f"Product ID:     {prod_str}")
    print("-" * 20)
    print(f"Setting 0x85:   0x{val_85:02X}")
    print(f"Setting 0x87:   0x{val_87:04X}")
    print(f"Setting 0x8A:   0x{val_8A:08X}")


# --- Key Derivation ---
def calculate_password_hash(password_input):
    if not password_input:
        return 0
    
    val = 0xFF
    
    # FIX: Handle raw bytes/bytearray directly to support Japanese IDs
    if isinstance(password_input, (bytes, bytearray)):
        password_bytes = password_input
    else:
        # Fallback for string input (Shift-JIS is standard for PC-98)
        password_bytes = password_input.encode('shift_jis', errors='replace')

    for char_byte in password_bytes:
        val ^= char_byte
    return val
    
# --- Decryption (XOR Stream + Bit Rotation) ---
def decrypt_v1(encrypted_data, seed_byte, password_input=None):
    print("Running decrypt_v1")
    data = list(encrypted_data)
    length = len(data)
    
    # 1. Calculate Key Hash
    key_hash = calculate_password_hash(password_input)
    
    combined_key = (key_hash ^ seed_byte) & 0xFF
    prng_state = combined_key
    # Layer 1: PRNG XOR
    for i in range(length):
        prng_state = (prng_state * 0x1000 + 0x24d69) % 0xae529
        xor_mask = (prng_state * 0x100) // 0xae529
        data[i] ^= (xor_mask & 0xFF)
    # Layer 2: Bit Rotation
    shift_amount = (combined_key >> 3) & 7
    for i in range(length):
        byte_val = data[i]
        current_shift = shift_amount
        shift_amount = (byte_val & 0x38) >> 3
        # Rotate Left
        data[i] = ((byte_val << current_shift) | (byte_val >> (8 - current_shift))) & 0xFF
    # Layer 3: CBC Chain
    chain_key = combined_key
    for i in range(length):
        original_byte = data[i]
        data[i] ^= chain_key
        chain_key = original_byte
    return bytes(data)
    
# --- NEW Decryption Routine (Variant 2) ---
def decrypt_v2(encrypted_data, seed_byte, password_input=None):
    print("Running decrypt_v2")
    data = list(encrypted_data)
    length = len(data)
    
    # Calculate Base Hash
    key_hash = calculate_password_hash(password_input)
    
    # CHANGE 1: The key is Inverted (~)
    # uVar4 = (uint)(byte)~(bVar3 ^ param_6);
    combined_key = (~(key_hash ^ seed_byte)) & 0xFF
    
    # Layer 1: PRNG XOR (Constants are identical)
    prng_state = combined_key
    for i in range(length):
        prng_state = (prng_state * 0x1000 + 0x24d69) % 0xae529
        xor_mask = (prng_state * 0x100) // 0xae529
        data[i] ^= (xor_mask & 0xFF)
    # Layer 2: Bit Rotation
    # CHANGE 2: Initial shift is >> 2 (was 3)
    shift_amount = (combined_key >> 2) & 7
    
    for i in range(length):
        byte_val = data[i]
        current_shift = shift_amount
        
        # CHANGE 3: Mask is 0x1C and shift is >> 2
        # uVar5 = (bVar1 & 0x1c) >> 2;
        shift_amount = (byte_val & 0x1C) >> 2
        
        # Rotate Left (Standard)
        data[i] = ((byte_val << current_shift) | (byte_val >> (8 - current_shift))) & 0xFF
    # Layer 3: CBC Chain (Identical)
    chain_key = combined_key
    for i in range(length):
        original_byte = data[i]
        data[i] ^= chain_key
        chain_key = original_byte
    return bytes(data)


# --- Decompression Function (LZSS) ---
def lzss_decompress(compressed_data, uncompressed_size):
    output = bytearray()
    dictionary = bytearray(4096)
    dict_pos = 0xFEE
    src_idx = 0
    flags = 0
    flag_bit_count = 0
    
    while len(output) < uncompressed_size and src_idx < len(compressed_data):
        # Refill flags register if empty
        if flag_bit_count == 0:
            # The code reads 8 bits, but processes bit-by-bit
            # (local_c & 0x100) check implies a 9th bit marker
            flags = compressed_data[src_idx] | 0xFF00 # simulated marker
            src_idx += 1
            flag_bit_count = 8
        
        # Check Lowest Bit
        is_literal = (flags & 1)
        flags >>= 1
        flag_bit_count -= 1
        
        if is_literal:
            byte_val = compressed_data[src_idx]
            src_idx += 1
            output.append(byte_val)
            dictionary[dict_pos] = byte_val
            dict_pos = (dict_pos + 1) & 0xFFF
        else:
            if src_idx + 1 >= len(compressed_data): break
            b1 = compressed_data[src_idx]
            b2 = compressed_data[src_idx+1]
            src_idx += 2
            
            # Decode Offset/Length
            # Offset: (b1) | (b2 upper 4 bits) << 4
            offset = b1 | ((b2 & 0xF0) << 4)
            # Length: (b2 lower 4 bits) + 3
            length = (b2 & 0x0F) + 3
            
            for _ in range(length):
                byte_val = dictionary[(offset + _) & 0xFFF] # Look up in history
                # byte_val = dictionary[(dict_pos - offset - 1) & 0xFFF] # should be relative offset?
                output.append(byte_val)
                dictionary[dict_pos] = byte_val
                dict_pos = (dict_pos + 1) & 0xFFF
    return output

    
# --- Main Unpacker Function ---
def process_file(file_path, decrypt_func, password_input):
    print(f"\nProcessing: {file_path}")
    
    
    with open(file_path, 'rb') as f:
        header_peek = f.read(4)
        f.seek(0) # FIX: Reset pointer
        
        # --- Type 1: Generic Container (Starts with 01 00 00 00) ---
        # Used by: CFG, FD, FONT, BIOS, SOUND, HD
        if header_peek == b'\x01\x00\x00\x00':
            print(">> Detected Type 1 Container (Standard)")
            # Read Header
            version = struct.unpack('<I', f.read(4))[0]
            uncompressed_size = struct.unpack('<I', f.read(4))[0]
            expected_crc = struct.unpack('<I', f.read(4))[0]
            seed_byte = struct.unpack('<B', f.read(1))[0]
        
            encrypted_payload = f.read()
        
            try:
                decrypted = decrypt_func(encrypted_payload, seed_byte, password_input)
                final_data = lzss_decompress(decrypted, uncompressed_size)
            except Exception as e:
                print(f"Decompression Failed! Password might be wrong. ({e})")
                return None
            
            print(f"Unpacked {len(final_data)} bytes.")
        
            # Return the data for further processing
            return final_data
        # --- Type 2: EGG File (Starts with "EGG") ---
        elif header_peek == b'EGG\x00':
            pprint("Detected Type 2 (EGG) Container")
            print("Warning: EGG unpacking logic is not yet implemented.")
            
        else:
            print(f"Unknown file format. Header: {header_peek.hex().upper()}")
            return None

            
# --- Helper: Hex Dump for Debugging ---
def print_hexdump(data, length=64):
    print(f"--- Header Dump (First {length} bytes) ---")
    print(binascii.hexlify(data[:length], ' ', 1).decode('utf-8').upper())
    print("-" * 40)


# --- Updated FD Extractor ---
def extract_fd_container(decrypted_data, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    offset = 0
    total_len = len(decrypted_data)
    file_index = 1
    
    # Debug: Check the very first chunk header
    #print_hexdump(decrypted_data)
    print(f"--- Extracting FD Container ({total_len} bytes) ---")
    while offset < total_len:
        # Safety Check
        if (total_len - offset) < 0x2B1:
            # print(f"End of stream reached (remaining bytes: {total_len - offset}).")
            break
        # Read Chunk Size at Offset + 0x1C
        size_offset = offset + 0x1C
        chunk_total_size = struct.unpack('<I', decrypted_data[size_offset:size_offset+4])[0]
        # Validations
        if chunk_total_size == 0:
            print(f"Error: Chunk {file_index} claims size 0 at file offset 0x{offset:X}.")
            print("Dumping invalid header context:")
            print_hexdump(decrypted_data[offset:offset+64])
            break
            
        if (offset + chunk_total_size) > total_len:
            print(f"Error: Chunk {file_index} size {chunk_total_size} exceeds file end.")
            break
        # Extract
        chunk_data = decrypted_data[offset : offset + chunk_total_size]
        filename = f"disk_{file_index:03d}.d88"
        out_path = os.path.join(output_dir, filename)
        
        with open(out_path, 'wb') as f:
            f.write(chunk_data)
        
        print(f"Extracted: {filename} (Size: {chunk_total_size})")
        offset += chunk_total_size
        file_index += 1

            
# --- Main Workflow ---
def main():
    if not os.path.exists("CFG"):
        print("Error: CFG file is missing. Cannot determine version or Product ID.")
        return

    # --- Step 1: Detect Version from CFG ---
    with open("CFG", 'rb') as f:
        f.seek(4) # Skip Magic 01 00 00 00
        cfg_size = struct.unpack('<I', f.read(4))[0]
    
    print(f"Detected CFG Uncompressed Size: 0x{cfg_size:X}")
    # Set Version Specifics
    if cfg_size == 0xDF:
        print(">> Mode: Version 1 (Standard)")
        decrypt_algo = decrypt_v1
        id_offset = 0x44
    elif cfg_size == 0x9E or cfg_size == 0x9F:
        print(">> Mode: Version 2 (Pbins)")
        decrypt_algo = decrypt_v2
        id_offset = 0x4
    else:
        print(">> Unknown CFG size. Defaulting to Version 1 logic.")
        decrypt_algo = decrypt_v1
        id_offset = 0x44
    # --- Step 2: Unpack CFG & Get Product ID ---
    cfg_data = process_file("CFG", decrypt_algo, None)
    
    product_id_byte = None # Stores raw bytes to avoid encoding issues
    if cfg_data:
        # Dump decrypted CFG for reference
        with open("CFG.decrypted.bin", "wb") as f: f.write(cfg_data)
        
        # Extract ID
        if len(cfg_data) > id_offset + 64:
            # Read 64 bytes max, split at null
            raw_str = cfg_data[id_offset : id_offset + 64]
            # Keep as raw bytes!
            product_id_byte = raw_str.split(b'\x00')[0]
            
            # For display only
            try:
                display_id = product_id_byte.decode('shift_jis', errors='ignore')
            except:
                display_id = str(product_id_byte)
            print(f">> Found Product ID: {display_id}")
        else:
            print(">> Error: CFG too small for ID offset.")

    # --- Step 3: Unpack FD Archive ---
    # Pass the raw bytes here
    if os.path.exists("FD"):
        fd_data = process_file("FD", decrypt_algo, product_id_bytes)
        if fd_data:
            extract_fd_container(fd_data, "FD_Extracted")

        
    # --- Step 4: Unpack HD Image ---
    if os.path.exists("HD"):
        hd_data = process_file("HD", decrypt_algo, product_id_byte)
        if hd_data:
             with open("HD.decrypted.fdi", "wb") as f:
                f.write(hd_data)
             print(f">> Saved HD.decrypted.fdi")


    # --- Step 5: Unpack Optional Files ---
    
    # These always use their own filename as the password
    # Added HD to the list
    optional_files = ["FONT", "SOUND", "BIOS"]
    
    for filename in optional_files:
        # Only attempt if file exists
        if os.path.exists(filename):
            data = process_file(filename, decrypt_algo, filename)
            if data:
                with open(f"{filename}.decrypted.bin", "wb") as f:
                    f.write(data)
                print(f">> Saved {filename}.decrypted.bin")


if __name__ == "__main__":
    main()