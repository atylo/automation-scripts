# a script for obfuscation used only in DAIVA6, apparently. for a nes rom inside a blob with NZ signature, Nes + zipped
import sys
import struct

def lzss_decompress(compressed_data: bytes, uncompressed_size: int) -> bytearray:
    """
    Decompresses the LZSS payload (Equivalent to sub_4102E0).
    Uses a 4096-byte sliding dictionary initialized with zeros.
    """
    history = bytearray(4096)
    history_pos = 4078 # From v7 = 4078
    output = bytearray()
    
    src_idx = 0
    
    while src_idx < len(compressed_data) and len(output) < uncompressed_size:
        # Read the 8-bit control flag
        control_byte = compressed_data[src_idx]
        src_idx += 1
        
        # Process each bit in the control byte (from LSB to MSB)
        for bit in range(8):
            if src_idx >= len(compressed_data) or len(output) >= uncompressed_size:
                break
                
            # If bit is 1 (Literal Mode)
            if (control_byte & (1 << bit)) != 0:
                b = compressed_data[src_idx]
                src_idx += 1
                
                output.append(b)
                history[history_pos] = b
                history_pos = (history_pos + 1) & 0xFFF
                
            # If bit is 0 (Dictionary Match Mode)
            else:
                if src_idx + 1 >= len(compressed_data):
                    break
                    
                b1 = compressed_data[src_idx]
                b2 = compressed_data[src_idx + 1]
                src_idx += 2
                
                # Position is 12 bits: lower 8 bits in b1, upper 4 bits in b2
                pos = b1 | ((b2 & 0xF0) << 4)
                
                # Length is 4 bits (lower 4 bits of b2) + 2. 
                # The C code loops while `v13 <= v19`, effectively copying Length + 3 bytes.
                match_len = (b2 & 0x0F) + 3
                
                for _ in range(match_len):
                    if len(output) >= uncompressed_size:
                        break
                        
                    b = history[pos & 0xFFF]
                    output.append(b)
                    history[history_pos] = b
                    history_pos = (history_pos + 1) & 0xFFF
                    pos += 1

    return output


def extract_blobs(data: bytes, offset: int) -> bytearray:
    seed           = data[offset]
    raw_header     = data[offset + 1 : offset + 16]
    raw_payload    = data[offset + 16:]
    
    # Decrypt the 15-byte header
    decrypted_header  = bytearray(15)
    for i in range(15):
        key = (seed + 71 * (i + 1) + 90) & 0xFF
        decrypted_header[i] = raw_header[i] ^ key
        

    uncompressed_size = struct.unpack("<I", decrypted_header[3:7])[0]
    compressed_size   = struct.unpack("<I", decrypted_header[7:11])[0]
    expected_checksum = struct.unpack("<I", decrypted_header[11:15])[0]
    
    print(f"\n    -> seed: {seed:X} , key: {key:X}")
    print(f"    -> Expected Compressed Size:   {compressed_size} bytes")
    print(f"    -> Expected Uncompressed Size: {uncompressed_size} bytes")
    print(f"    -> Expected Data Checksum:     {hex(expected_checksum)}")
    
    if compressed_size > 4_000_000 or uncompressed_size > 4_000_000:
        print(" Weird size. Skipping.")
        return None
        
    # 5. Decrypt the compressed payload
    compressed_payload = raw_payload[:compressed_size]
    decrypted_payload = bytearray(len(compressed_payload))
    for i in range(len(compressed_payload)):
        key = (seed + 53 * i + 90) & 0xFF
        decrypted_payload[i] = compressed_payload[i] ^ key


    # 6. LZSS Decompression
    unpacked_data = lzss_decompress(decrypted_payload, uncompressed_size)
    print(f"[+] Decompressed to {len(unpacked_data)} bytes.")

    # 7. Checksum Verification
    calculated_checksum = sum(unpacked_data) & 0xFFFFFFFF # Keep it 32-bit bounded if necessary
    
    if calculated_checksum != expected_checksum:
        print(f"[-] Checksum mismatch! Expected: {expected_checksum}, Got: {calculated_checksum}")
        return None
        
    print("[+] Checksum verified successfully!")
    return unpacked_data


def scan_for_blobs(data: bytes) -> list:
    print(f"[*] Scanning {len(data)} bytes...")
    offsets = []
    
    for offset in range(len(data) - 16):
        skey = data[offset]
        header = data[offset + 1 : offset + 16]

        # Decrypt just bytes 1 and 2 to check magic
        b1 = header[1] ^ ((skey + 71 * 2 + 90) & 0xFF)
        b2 = header[2] ^ ((skey + 71 * 3 + 90) & 0xFF)
        
        # The NZ signature
        if b1 == ord('N') and b2 == ord('Z'):
            print(f"[+] Potential blob found at offset {hex(offset)}, key={hex(skey)}")
            offsets.append(offset)
            
    return  offsets

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_exe>")
        sys.exit(1)
    
    exe_path = sys.argv[1]
    with open(exe_path, "rb") as f:
        data = f.read()
    
    offsets = scan_for_blobs(data)
    
    for i, offset in enumerate(offsets):
        unpacked_data = extract_blobs(data, offset)
        
        if unpacked_data is None:
            continue
            
        out_filename = f"daiva6_{i}_{hex(offset)}.bin"
        with open(out_filename, "wb") as f:
            f.write(unpacked_data)
        print(f"[+] Written {len(unpacked_data)} bytes to {out_filename}\n")
