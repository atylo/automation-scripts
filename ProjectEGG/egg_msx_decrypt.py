#Scirpt to decrypt ROMs and files from old MSX ProjectEGG games made before 2009-2010
import argparse
from pathlib import Path

KEY = bytes.fromhex(
    "B4 D1 B4 BD B4 AF B8 BD B1 BF BC B4 B0 BC AE DD" # MSX Association in Japanese
)

def decrypt(data: bytes) -> bytes:
    if len(data) < 2:
        raise ValueError("File too small")

    # First byte is the control byte (ECX)
    ecx = data[0]

    shift_amount = 4 - (ecx & 3) # maybe a useless check
    key_base = ecx & 0xFC

    output = bytearray(len(data) - 1)

    for i, byte in enumerate(data[1:]):
        transformed = ((byte << 8) | byte) >> shift_amount
        transformed &= 0xFF

        key_index = (key_base + i) & 0x0F
        output[i] = transformed ^ KEY[key_index]

    return bytes(output)

def main():
    parser = argparse.ArgumentParser(description="Decryptor")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    raw = args.input.read_bytes()
    plain = decrypt(raw)
    args.output.write_bytes(plain)

    print(f"Decrypted {len(plain)} bytes")

if __name__ == "__main__":
    main()
