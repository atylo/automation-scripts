# Script to decrypt ROMs and files from old ProjectEGG games made before 2009-2010
import argparse
from pathlib import Path

# Define the decryption keys
KEY_1 = bytes.fromhex("B4 D1 B4 BD B4 AF B8 BD B1 BF BC B4 B0 BC AE DD") # MSX Association in Japanese
KEY_2 = bytes.fromhex("33 53 93 63 A3 C3 35 55 95 65 A5 C5 36 56 96 66") # Used for only 8 games apparently

def decrypt_msxplayer_old(data: bytes, key: bytes) -> bytes: # swap(data) ^ key
    if (data[0] & 0xF0) == 0x80: # 0x8X
        # Header Mode (e.g., DISK.ROM, dsks)
        ecx = data[0]
        start_offset = 1
        shift_amount = 4 - (ecx & 3)
        key_base = ecx & 0xFC
    else:
        # Raw Mode (e.g., MSX.ROM)
        start_offset = 0
        shift_amount = 4
        key_base = 0

    output = bytearray(len(data) - start_offset)

    for i, byte in enumerate(data[start_offset:]):
        # Nibble swap / shift
        transformed = ((byte << 8) | byte) >> shift_amount
        transformed &= 0xFF

        # XOR with rotating key
        key_index = (key_base + i) & 0x0F
        output[i] = transformed ^ key[key_index]

    return bytes(output)

def decrypt_d4e(data: bytes, key: bytes) -> bytes: # swap(data ^ key_byte)
    length = len(data)
    output = bytearray(data)
    
    for i in range(length):
        # 1. Fetch the key byte (looping every 16 bytes)
        key_byte = key[i & 0xF]
        
        # 2. XOR the data byte with the key byte
        xor_result = output[i] ^ key_byte
        
        # 3. Nibble Swap (High 4 bits <-> Low 4 bits)
        output[i] = ((xor_result << 4) | (xor_result >> 4)) & 0xFF

    return bytes(output)

def main():
    parser = argparse.ArgumentParser(description="Decrypt ROMs and files.")
    parser.add_argument("input", type=Path, help="Path to the encrypted file.")
    # Add the type argument, restricting inputs to exactly 1 or 2
    parser.add_argument("type", type=int, choices=[1, 2], help="Decryption type: 1 (MSXPlayer Old) or 2 (MSX D4E)")
    args = parser.parse_args()

    raw = args.input.read_bytes()

    # Route to the correct function and key based on the 'type' argument
    if args.type == 1:
        plain = decrypt_msxplayer_old(raw, KEY_1)
    elif args.type == 2:
        plain = decrypt_d4e(raw, KEY_2)

    ext = "".join(args.input.suffixes)
    out_path = args.input.parent / f"{args.input.stem}.ROM"
    out_path.write_bytes(plain)

    print(f"Decrypted {args.input.name} using Type {args.type}.")
    print(f"Output saved to: {out_path}")
    print(f"Size: {len(plain)} bytes")

if __name__ == "__main__":
    main()