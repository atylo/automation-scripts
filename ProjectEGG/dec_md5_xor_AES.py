import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct

def dump_function(memory_file, dump_original_resources, exe_name, dump_ext, key):
    CHUNK_SIZE = 0x100
    CHUNKS = len(memory_file) // CHUNK_SIZE
    print(f"CHUNK_SIZE {CHUNK_SIZE}")
    
    key_inc = struct.unpack("<I", bytes.fromhex(key)[:4])[0]
    print(f"key {key}")
    print(f"key_inc {key_inc}")
    print("Decrypting AES")

    decrypted_data = b''
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
        decrypted_data += decrypted_chunk
    
    if dump_original_resources != 0:
        name = f"{exe_name}.{dump_ext}"
        with open(name, "wb") as output_file:
            output_file.write(decrypted_data)

# Replace 'input_file.bin' with the actual path to your input file
input_file_path = 'test.enc'

# Read the contents of the file into memory_file
with open(input_file_path, 'rb') as file:
    memory_file = file.read()


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

# Example usage of dump_function
dump_original_resources = 1  # provide the dump_original_resources value
dump_ext = 'txt'  # provide the dump_ext value
dump_function(memory_file, dump_original_resources, exe_name, dump_ext, key)
