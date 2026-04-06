import struct
import os

# --- Helper Functions ---
def rol32(val, shift):
    return ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF

def ror32(val, shift):
    return ((val >> shift) | (val << (32 - shift))) & 0xFFFFFFFF

# The Session Key we found
SESSION_KEY = 0xC04CAFB4

def get_subkey(a2):
    """Translates sub_10003e1a"""
    shift = (a2 + 0x11) % 32
    return ror32(SESSION_KEY, shift)

# --- Descrambling Functions ---
def descramble_dword0(a1, val):
    shift = (a1 + 0x49) % 32
    return (rol32(val, shift) + a1 - get_subkey(a1) + 0x660BCDDB) & 0xFFFFFFFF

def descramble_dword1(a1, val):
    shift = (a1 + 0x55) % 32
    return (rol32(val, shift) + a1 - get_subkey(a1) + 0x48219C77) & 0xFFFFFFFF

def descramble_dword2(a1, val):
    shift = (a1 + 0x13) % 32
    return (rol32(val, shift) + a1 - get_subkey(a1) + 0x357712D9) & 0xFFFFFFFF

def descramble_dword3(a1, val):
    shift = (a1 + 0x23) % 32
    # Note: C++ code subtracts the constant here
    return (rol32(val, shift) + a1 - get_subkey(a1) - 0x73FB64DA) & 0xFFFFFFFF

# --- Main Parser ---
def parse_archive(file_path):
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return

    with open(file_path, "rb") as f:
        # We know from your memory dump:
        # File Table Offset = 40, Size = 16
        f.seek(40)
        table_data = f.read(16)
        
        # We also know the data offset is 68
        DATA_OFFSET = 68 

    # Calculate how many 16-byte entries there are
    num_entries = len(table_data) // 16
    print(f"--- Parsing File Table ({num_entries} Entries found) ---\n")

    for i in range(num_entries):
        # Read 16 bytes (4 integers) at a time
        chunk = table_data[i*16 : (i+1)*16]
        d0, d1, d2, d3 = struct.unpack("<IIII", chunk)

        # The 'a1' variable in C++ is the dword index (entry_index * 4)
        a1 = i * 4

        # Descramble
        dec_d0 = descramble_dword0(a1, d0)
        dec_d1 = descramble_dword1(a1 + 1, d1)
        dec_d2 = descramble_dword2(a1 + 2, d2)
        dec_d3 = descramble_dword3(a1 + 3, d3)

        print(f"File #{i+1}:")
        print(f"  Internal Offset:    {dec_d0} (Absolute: {DATA_OFFSET + dec_d0})")
        print(f"  Compressed Size:    {dec_d1} bytes")
        print(f"  Decompressed Size:  {dec_d2} bytes")
        print(f"  Flags/Unknown:      {hex(dec_d3)}")
        print("-" * 40)

# Run it!
parse_archive("encs0001.bnd") # Change this to your actual filename if different