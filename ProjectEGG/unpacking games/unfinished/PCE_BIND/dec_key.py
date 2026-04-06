def transform_hex_to_ascii(hex_string: str) -> str:
    # Parse hex string → bytes
    data = bytearray(int(b, 16) for b in hex_string.split())

    if len(data) != 8:
        raise ValueError("Input must be exactly 8 bytes")

    # Apply transformation
    for i in range(8):
        data[i] = ((data[i] + 119) ^ (51 * i)) & 0xFF

    # Convert to ASCII (non-printables will look weird)
    return data.decode('ascii', errors='replace')
    
inp = "CE 06 AE 53 85 58 8B DD"
print(transform_hex_to_ascii(inp))