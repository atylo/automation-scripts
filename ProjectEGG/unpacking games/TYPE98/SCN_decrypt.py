# Script to extract .d88 scenario disks from .SCN files
import os
import sys
import struct

def calculate_password_hash(password_input):
    if not password_input:
        return 0
    
    val = 0xFF
    
    # Handle raw bytes/bytearray directly to support Japanese IDs
    if isinstance(password_input, (bytes, bytearray)):
        password_bytes = password_input
    else:
        # Fallback for string input (Shift-JIS is standard for PC-98)
        password_bytes = password_input.encode('shift_jis', errors='replace')

    for char_byte in password_bytes:
        val ^= char_byte
    return val
    
    
def decrypt_v1(encrypted_data, seed_byte, password_input=None):
    
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
    
def lzss_decompress(compressed_data, uncompressed_size):
    output = bytearray()
    dictionary = bytearray(4096)
    dict_pos = 0xFEE
    src_idx = 0
    flags = 0
    flag_bit_count = 0
    
    while len(output) < uncompressed_size and src_idx < len(compressed_data):
        if flag_bit_count == 0:
            if src_idx >= len(compressed_data): break
            flags = compressed_data[src_idx] | 0xFF00
            src_idx += 1
            flag_bit_count = 8
        
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
            
            offset = b1 | ((b2 & 0xF0) << 4)
            length = (b2 & 0x0F) + 3
            
            for _ in range(length):
                byte_val = dictionary[(offset + _) & 0xFFF]
                output.append(byte_val)
                dictionary[dict_pos] = byte_val
                dict_pos = (dict_pos + 1) & 0xFFF
                
    return output
    
def process_file(file_path, password_input):
    print(f"\nProcessing: {file_path}")
    
    
    with open(file_path, 'rb') as f:

        # Read Header
        SCN_thing = struct.unpack('<I', f.read(4))[0]
        version = struct.unpack('<I', f.read(4))[0]
        uncompressed_size = struct.unpack('<I', f.read(4))[0]
        expected_crc = struct.unpack('<I', f.read(4))[0]
        seed_byte = struct.unpack('<B', f.read(1))[0]
        
        
        encrypted_payload = f.read()
        
        try:
            decrypted = decrypt_v1(encrypted_payload, seed_byte, password_input)
            final_data = lzss_decompress(decrypted, uncompressed_size)
        except Exception as e:
                print(f"Decompression Failed! ({e})")
                return None
            
        print(f"Unpacked {len(final_data)} bytes.")
        return final_data


def main():
    if len(sys.argv) < 2:
        print("Usage: python SCN_decrypt.py <file.scn>")
        return

    scn_file = sys.argv[1]
    # Password is the exe name that loads the Scenario files, apparently
    password = "EFAL0081"
    data = process_file(scn_file, password)
    
    if data:
        out_name = f"{scn_file}.d88"
        try:
            with open(out_name, "wb") as out:
                out.write(data)
            print(f"-> Success! Extracted to {out_name}")
        except IOError as e:
            print(f"Error writing file: {e}")

if __name__ == "__main__":
    main()