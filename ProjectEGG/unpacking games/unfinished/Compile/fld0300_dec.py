import struct
import sys
import os

# ==========================================
# CONFIGURATION - Set your keys here
# ==========================================
# Mode 0: Use the hardcoded integer from WinMain
# Mode 1: Use a string-based key
# Mode 2: System Time based, requires external context
SET_MODE = 0  
SET_KEY  = -1677351266  # 0x9C00001E
# Use integer for Mode 0, "String" for Mode 1
# MODE_1_SEED = generate_seed(1, "SampleKey")
# ==========================================

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
        
    elif mode == 2:
        print("[!] Mode 2 requires System Time context. Leaving empty.")
        return None

def decrypt_data(ciphertext, seed):
    """Replicates sub_407090: The Backwards Rolling XOR/Sub Cipher."""
    # Ensure 4-byte alignment
    padding_needed = (4 - (len(ciphertext) % 4)) % 4
    ciphertext += b'\x00' * padding_needed
    
    data = list(struct.unpack(f'<{len(ciphertext)//4}I', ciphertext))
    
    v2 = seed
    v3 = len(ciphertext) - 4 
    i = (seed + v3) & 0xFFFFFFFF
    
    # Process the buffer backwards
    for idx in range(len(data) - 1, -1, -1):
        v6 = (v2 + i) & 0xFFFFFFFF
        v7 = (data[idx] - i) & 0xFFFFFFFF
        v8 = (v2 ^ v7) & 0xFFFFFFFF
        
        data[idx] = v8
        
        v2_minus_v8 = (v2 - v8) & 0xFFFFFFFF
        v2 = ((v6 << 8) ^ (v2_minus_v8 >> 8)) & 0xFFFFFFFF
        i = (i - 3) & 0xFFFFFFFF

    decrypted_bytes = struct.pack(f'<{len(data)}I', *data)
    
    # Metadata Check: Extract original size from the footer
    try:
        original_size = struct.unpack('<I', decrypted_bytes[-8:-4])[0]
        if 0 < original_size < len(decrypted_bytes):
            return decrypted_bytes[:original_size]
    except:
        pass
        
    return decrypted_bytes

def main():
    if len(sys.argv) < 2:
        print("Usage: python decryptor.py <filename>")
        return

    input_path = sys.argv[1]
    if not os.path.exists(input_path):
        print(f"[-] Error: {input_path} not found.")
        return

    # 1. Initialize Seed
    seed = generate_seed(SET_MODE, SET_KEY)
    print(f"[*] Mode: {SET_MODE} | Key: {SET_KEY} | Final Seed: {hex(seed)}")

    # 2. Read File
    with open(input_path, "rb") as f:
        encrypted_data = f.read()

    # 3. Decrypt
    print(f"[*] Decrypting {input_path}...")
    decrypted_data = decrypt_data(encrypted_data, seed)

    # 4. Save with dec_ prefix
    file_dir, file_name = os.path.split(input_path)
    output_path = os.path.join(file_dir, f"dec_{file_name}")

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    print(f"[+] Done! Saved to: {output_path}")

if __name__ == "__main__":
    main()