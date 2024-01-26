# Some silly attempt to decrypt ProjectEGG logs,
# I don't really understand half of the script, it was converted from a quickbms script for projectegg exe games.

import os
import datetime
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct

def dump_function(memory_file, key):
    CHUNK_SIZE = 0x100
    CHUNKS = len(memory_file) // CHUNK_SIZE
    print(f"CHUNKS {CHUNKS}")

    key_inc = struct.unpack("<I", bytes.fromhex(key)[:4])[0]
    print(f"key {key}")
    print(f"key_inc {key_inc}")
    print("Decrypting AES")

    decrypted_data = b""
    for i in range(CHUNKS):
        tmp = key_inc ^ i
        print(f"tmp {tmp}")
        #key = struct.pack("<I", tmp) + b'\x00' * 12  # Pad the key to 16 bytes

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
    

    name = f"{filename_end}.{dump_ext}"
    with open(name, "wb") as output_file:
        output_file.write(decrypted_data)

def get_time(file_path):
    try:
        # Get file information
        file_info = os.stat(file_path)

        # Get the creation time of the file
        creation_time_timestamp = os.path.getctime(file_path)

        # Convert the timestamp to a datetime object
        creation_time_datetime = datetime.datetime.fromtimestamp(creation_time_timestamp)

        # Format the datetime object as per your specified format
        formatted_timestamp = creation_time_datetime.strftime("%Y%m%d%H%M%S")

        # Get the file name with extension
        file_name = os.path.splitext(os.path.basename(file_path))[0]

        # Combine the formatted timestamp with the file name
        result = f"{formatted_timestamp}{file_name}"

        return result
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

# Example usage
file_path = r"C:\Users\leasty\Desktop\dlclient\dlclient.log"
time_name = get_time(file_path)

if time_name:
    print(f"Formatted last modified timestamp with file name: {time_name}")

#print("Input the file name")
exe_name = time_name

# Read the contents of the file into memory_file
with open(file_path, 'rb') as file:
    memory_file = file.read()

# Extract EXE_NAME from the filename
filename_end = os.path.splitext(os.path.basename(file_path))[0]

# Calculate MD5 hash of EXE_NAME
md5_hash = hashlib.md5(exe_name.encode()).hexdigest()

# Convert MD5 hash to bytes
md5_bytes = bytes.fromhex(md5_hash)

# Apply XOR encryption
xor_key = 0xFF
encrypted_key_bytes = bytes(x ^ xor_key for x in md5_bytes)

# Convert the result back to hex
key = encrypted_key_bytes.hex()

# Print the result
print(f"EXE_NAME: {exe_name}")
print(f"KEY: {key}")

# Example usage of dump_function
dump_ext = 'txt'
dump_function(memory_file, key)
