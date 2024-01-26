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
input_file_path = 'test.txt'

# Replace 'encrypted_file.enc' with the desired path for the encrypted output file
encrypted_file_path = 'test.enc'

# Extract EXE_NAME from the filename
exe_name = os.path.splitext(os.path.basename(input_file_path))[0]

# Calculate MD5 hash of EXE_NAME
md5_hash = hashlib.md5(exe_name.encode()).hexdigest()

# Convert MD5 hash to bytes
md5_bytes = bytes.fromhex(md5_hash)

# Set XOR key
xor_key = 0xFF

# Apply XOR encryption
encrypted_key_bytes = bytes(x ^ xor_key for x in md5_bytes)

# Convert the result back to hex
key = encrypted_key_bytes.hex()

# Print the result
print(f"EXE_NAME: {exe_name}")
print(f"KEY: {key}")

# Call the encrypt_function with the calculated key
encrypt_function(input_file_path, encrypted_file_path, key)