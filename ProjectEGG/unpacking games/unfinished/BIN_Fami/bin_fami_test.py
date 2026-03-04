import argparse
import sys

def decrypt_buffer(data, seed):
    """
    Performs the 3-pass decryption on a generic buffer.
    We use this for both the small header check and the final full decryption.
    """
    length = len(data)
    # Make a mutable copy so we don't modify the input in place if we don't want to
    buf = bytearray(data)

    # --- PASS 1: Variable Rotate Copy ---
    # We iterate and write to the buffer.
    # Note: We can operate in-place or separate buffer. 
    # For Pass 1, the logic relies on the original 'curr_raw', so we can't 
    # overwrite data[i] before reading it if we were strictly in-place, 
    # but since we made a copy 'buf' and read from 'data', it's safe.
    
    # To strictly follow the logic: read from 'data', write to 'buf'.
    prev_byte = seed
    for i in range(length):
        curr_raw = data[i] # Read from original immutable source
        shift = (prev_byte >> 3) & 7
        
        # Rotate Left logic
        val = ((curr_raw << shift) | (curr_raw >> (8 - shift))) & 0xFF
        buf[i] = val
        
        prev_byte = curr_raw

    # --- PASS 2: CBC XOR Chain (In-place on buf) ---
    chain_key = seed
    for i in range(length):
        raw_val = buf[i]
        buf[i] = (raw_val ^ chain_key) & 0xFF
        chain_key = raw_val

    # --- PASS 3: LCG Stream XOR (In-place on buf) ---
    prng_state = seed
    
    # Optimization: constant used in loop
    MULT = 0x1000
    ADD = 0x24D69
    MOD = 0xAE529
    
    for i in range(length):
        # LCG Update
        prng_state = (prng_state * MULT + ADD) % MOD
        
        # Fixed-point division simulation
        xor_mask = (prng_state << 8) // MOD
        
        buf[i] = (buf[i] ^ (xor_mask & 0xFF)) & 0xFF
        
    return buf

def main():
    parser = argparse.ArgumentParser(description="ProjectEGG BIN_Fami brute Decrypter")
    parser.add_argument("input", help="The number file from .rsrc/BIN folder")
    parser.add_argument("output", help="Output filename")
    args = parser.parse_args()

    try:
        with open(args.input, "rb") as f:
            raw_data = f.read()

        file_len = len(raw_data)
        print(f"[*] Loaded {file_len} bytes.")

        # --- OPTIMIZATION START ---
        # Instead of decrypting the whole file, we slice the first 512 bytes.
        # This is enough to cover the "first 512 bytes" requirement.
        header_slice = raw_data[:512]
        
        found_key = None
        
        print("[*] Brute-forcing header (0x00 - 0xFF)...")
        
        for candidate_key in range(256):
            # Decrypt only the small slice
            decrypted_header = decrypt_buffer(header_slice, candidate_key)
            
            # Check for the signature in the first 512 bytes
            if b"FDS" in decrypted_header[:512]:
                print(f"\n[!] MATCH FOUND! Key: {hex(candidate_key)}")
                found_key = candidate_key
                break
            
            # Progress indicator (overwrites same line)
            if candidate_key % 16 == 0:
                sys.stdout.write(f"\rScanning key: {hex(candidate_key)}...")
                sys.stdout.flush()
        
        print("") # Clear line
        
        if found_key is not None:
            print(f"[*] Decrypting full file with key {hex(found_key)}...")
            # Now we decrypt the FULL file exactly once
            full_decrypted_body = decrypt_buffer(raw_data, found_key)
            
            with open(args.output, "wb") as f:
                f.write(full_decrypted_body)
            print(f"[+] Success! Saved to {args.output}")
            
        else:
            print("[-] Failed: 'FDS' header not found with any key.")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()