import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import struct

def encrypt_function(input_file_path, encrypted_file_path, key):
    CHUNK_SIZE = 0x100

    # Read the contents of the file into memory_file
    with open(input_file_path, 'rb') as file:
        memory_file = file.read()

    CHUNKS = len(memory_file) // CHUNK_SIZE
    print(f"CHUNK_SIZE {CHUNK_SIZE}")

    key_inc = struct.unpack("<I", bytes.fromhex(key)[:4])[0]
    print(f"key {key}")
    print(f"key_inc {key_inc}")
    print("Encrypting AES")

    encrypted_data = b""
    for i in range(CHUNKS):
        tmp = key_inc ^ i
        key = struct.pack("<I", tmp) + b'\x00' * 12  # Pad the key to 16 bytes

        # Simulate the putvarchr operation
        tmp_packed = struct.pack("<I", tmp)
        key = (
            key[:0] +
            tmp_packed +
            key[struct.calcsize("<I"):]
        )

        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_chunk = cipher.encrypt(pad(memory_file[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE], AES.block_size))
        encrypted_data += encrypted_chunk

    # Write the encrypted data to the output file
    with open(encrypted_file_path, "wb") as output_file:
        output_file.write(encrypted_data)

# Replace 'input_file.txt' with the actual path to your input file
input_file_path = 'path/to/your/input_file.txt'

# Replace 'encrypted_file.enc' with the desired path for the encrypted output file
encrypted_file_path = 'path/to/your/encrypted_file.enc'

# Provide the actual key used for encryption
key = '8e8ce97bb81a1b6ee678486dde8b61bb'  # Replace with the actual key

# Example usage of encrypt_function
encrypt_function(input_file_path, encrypted_file_path, key)
