import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct

def decrypt_function(encrypted_file_path, decrypted_file_path, key):
    CHUNK_SIZE = 0x100

    # Read the contents of the encrypted file into memory_file
    with open(encrypted_file_path, 'rb') as file:
        memory_file = file.read()

    CHUNKS = len(memory_file) // CHUNK_SIZE
    print(f"CHUNK_SIZE {CHUNK_SIZE}")

    key_inc = struct.unpack("<I", bytes.fromhex(key)[:4])[0]
    print(f"key {key}")
    print(f"key_inc {key_inc}")
    print("Decrypting AES")

    decrypted_data = b""
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
        decrypted_chunk = cipher.decrypt(memory_file[i * CHUNK_SIZE : (i + 1) * CHUNK_SIZE])
        decrypted_chunk = unpad(decrypted_chunk, AES.block_size)
        decrypted_data += decrypted_chunk

    # Write the decrypted data to the output file
    with open(decrypted_file_path, "wb") as output_file:
        output_file.write(decrypted_data)

# Replace 'encrypted_file.enc' with the actual path to your encrypted file
encrypted_file_path = 'test.enc'

# Replace 'decrypted_file.txt' with the desired path for the decrypted output file
decrypted_file_path = 'test_decrypted.txt'

# Replace 'KEY_FROM_ENCRYPTION' with the key used during encryption
key = 'f6709432b9de2c8c3521b17cd9d84b09'

# Call the decrypt_function with the calculated key
decrypt_function(encrypted_file_path, decrypted_file_path, key)
