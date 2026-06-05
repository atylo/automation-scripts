import sys

def decrypt_and_validate(raw_data):
    if len(raw_data) < 2:
        print("[-] Error: Data block is too small to contain a header.")
        return False

    expected_checksum = raw_data[0]
    payload_length = raw_data[1]

    # Boundary check matching the original logic (max 0x40 bytes)
    if payload_length == 0 or payload_length > 0x40:
        print(f"[-] Error: Invalid payload length ({payload_length} bytes).")
        return False

    if len(raw_data) < (2 + payload_length):
        print("[-] Error: Reached EOF before reading the full payload.")
        return False

    running_checksum = 0
    decrypted_text = bytearray()

    # Loop through the payload chunk
    for i in range(payload_length):
        original_byte = raw_data[2 + i]
        
        # Keep checksum bounded to 8-bit unsigned integer (0-255)
        running_checksum = (running_checksum + original_byte) & 0xFF

        # Nibble Swap: Shift right 4, shift left 4, and mask to 8 bits
        decrypted_byte = (original_byte >> 4) | ((original_byte << 4) & 0xFF)
        decrypted_text.append(decrypted_byte)

    # Verify integrity
    if running_checksum == expected_checksum:
        print(f"[+] Checksum MATCHED! (Expected: 0x{expected_checksum:02X}, Calculated: 0x{running_checksum:02X})")
        return decrypted_text
    else:
        print(f"[-] Checksum FAILED! (Expected: 0x{expected_checksum:02X}, Calculated: 0x{running_checksum:02X})")
        return None

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <target_executable.exe>")
        sys.exit(1)

    filename = sys.argv[1]

    try:
        # Read the entire file as bytes
        with open(filename, "rb") as f:
            buffer = f.read()
    except Exception as e:
        print(f"[-] Error: Could not read file {filename}. Reason: {e}")
        sys.exit(1)

    # Define the target signature
    signature = b"Dr0Wy3K"
    
    # Find the offset of the signature
    offset = buffer.find(signature)

    if offset == -1:
        print(f"[-] Signature '{signature.decode()}' not found in the executable.")
        sys.exit(1)

    print(f"[+] Found signature '{signature.decode()}' at offset 0x{offset:X}")

    # Extract the data directly following the signature
    data_block = buffer[offset + len(signature):]

    print("[*] Extracting and decrypting payload...")
    decrypted_payload = decrypt_and_validate(data_block)

    if decrypted_payload:
        # Format Hex Output
        hex_output = " ".join(f"{b:02X}" for b in decrypted_payload)
        print(f"[+] Decrypted Hex: {hex_output}")

        # Format ASCII Output (replacing non-printable characters with '.')
        ascii_output = "".join(chr(b) if 32 <= b <= 126 else "." for b in decrypted_payload)
        print(f"[+] Decrypted ASCII: {ascii_output}")

if __name__ == "__main__":
    main()