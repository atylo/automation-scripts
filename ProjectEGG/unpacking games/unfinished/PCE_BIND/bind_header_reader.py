import struct
import sys
import time

def mask32(val):
    return val & 0xFFFFFFFF

def ror(val, n):
    val = mask32(val)
    return mask32((val >> n) | (val << (32 - n)))

def rol(val, n):
    val = mask32(val)
    return mask32((val << n) | (val >> (32 - n)))

# --- Entry Descrambling ---
def get_subkey(session_key, a2):
    return ror(session_key, (a2 + 0x11) % 32)

def descramble_dword0(session_key, a1, val):
    return mask32(rol(val, (a1 + 0x49) % 32) + a1 - get_subkey(session_key, a1) + 0x660BCDDB)

def descramble_dword1(session_key, a1, val):
    return mask32(rol(val, (a1 + 0x55) % 32) + a1 - get_subkey(session_key, a1) + 0x48219C77)

def descramble_dword2(session_key, a1, val):
    return mask32(rol(val, (a1 + 0x13) % 32) + a1 - get_subkey(session_key, a1) + 0x357712D9)

def descramble_dword3(session_key, a1, val):
    return mask32(rol(val, (a1 + 0x23) % 32) + a1 - get_subkey(session_key, a1) - 0x73FB64DA)


def parse_full_bind_header(filepath):
    with open(filepath, "rb") as f:
        raw_data = f.read()

    # --- Project ID ---
    project_id = ""
    for i in range(8):
        project_id += chr(((raw_data[8+i] + 119) ^ (51 * i)) & 0xFF)
    print("[*] Project ID:", project_id)

    v2 = 0
    v3 = 0
    for char in project_id:
        val = ord(char)
        v2 = mask32(val + 16 * v2)
        v3 += val

    session_key = ror(mask32(v2 - 2083412177), (v3 + 61) % 32)

    def get_factor(a2):
        return ror(session_key, (a2 + 17) % 32)

    raw = struct.unpack('<6I', raw_data[16:40])

    v_16 = mask32(mask32(rol(raw[0], 7)  - get_factor(11)) + 0x4CBD70AA)
    v_20 = mask32(mask32(rol(raw[1], 15) - get_factor(13)) + 0x68CC8AEE)
    v_24 = mask32(mask32(rol(raw[2], 9)  - get_factor(15)) - 0x7F61DB27)
    v_28 = mask32(mask32(rol(raw[3], 19) - get_factor(17)) + 0x12BDD8CF)
    v_32 = mask32(mask32(rol(raw[4], 27) - get_factor(19)) + 0x56E54C39)
    v_36 = mask32(mask32(rol(raw[5], 5)  - get_factor(21)) - 0x4F8FF389)


    print(f"[*] Session Key: 0x{session_key:08X}")
    print("-" * 40)
    print("Number of files:", v_20 // 16)
    print(f"Data[16] (File Table Offset):  {v_16} (0x{v_16:08X})")
    print(f"Data[20] (File Table Size): {v_20} bytes (0x{v_20:08X})")
    print(f"Data[24] (Metadata Offset):  {v_24} (0x{v_24:08X})")
    print(f"Data[28] (Metadata Size): {v_28} bytes (0x{v_28:08X})")
    print(f"Data[32] (Data Offset):  {v_32} (0x{v_32:08X})")
    print(f"Data[36] (Data size?):  {v_36} (0x{v_36:08X})")
    print("-" * 40)

    # --- File Table Parsing ---
    entry_size = 16
    num_entries = v_20 // entry_size

    print(f"--- Parsing File Table ({num_entries} entries) ---\n")

    for i in range(num_entries):
        entry_off = v_16 + i * entry_size
        chunk = raw_data[entry_off:entry_off + entry_size]

        if len(chunk) < 16:
            print(f"[!] Truncated entry {i}")
            break

        d0, d1, d2, d3 = struct.unpack("<4I", chunk)

        a1 = i * 4

        dec_d0 = descramble_dword0(session_key, a1,     d0)
        dec_d1 = descramble_dword1(session_key, a1 + 1, d1)
        dec_d2 = descramble_dword2(session_key, a1 + 2, d2)
        dec_d3 = descramble_dword3(session_key, a1 + 3, d3)
        #data1 = raw_data[v_32 + dec_d0 : v_32 + dec_d0 + dec_d2]
        #data2 = raw_data[dec_d1 : dec_d1 + dec_d2]
        #real_offset = v_32 + (dec_d1 - base)

        print(f"File #{i+1}:")
        print(f"dec_d0 Internal Offset:    {hex(dec_d0)} (Absolute: {hex(v_32 + dec_d1)})")
        print(f"dec_d1 Data offset:        {hex(dec_d1)}")
        print(f"dec_d2 Actual file size:   {dec_d2} bytes")
        print(f"dec_d3 Flags/Unknown:      {hex(dec_d3)}")
        
        print("-" * 40)


if __name__ == "__main__":
    print("\nBind format reader 0.2\n")


    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <archive.bnd/etc/ptc>")
        RED = "\033[31m"
        RESET = "\033[0m"

        print(RED + """
         One ring to rule them all,
        One ring to find them,
        One ring to bring them all
        and in the darkness bind them""" + RESET)
        sys.exit(1)

    parse_full_bind_header(sys.argv[1])