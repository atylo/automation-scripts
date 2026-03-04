import re
import binascii

def find_fuzzy_call(filename):
    print(f"[*] Scanning {filename} for PUSH/CALL proximity...")

    # ---------------------------------------------------------
    # THE PATTERN EXPLAINED
    # ---------------------------------------------------------
    # \x6A        = Match exact byte 0x6A (PUSH)
    # (.)         = Capture group 1: The Resource ID (1 byte)
    # (.{0,20}?)  = Capture group 2: The "Gap" (0 to 20 bytes). 
    #               The '?' makes it "non-greedy" (finds smallest gap).
    # \xFF\x15    = Match exact bytes 0xFF 0x15 (CALL)
    # (....)      = Capture group 3: The Call Address (4 bytes)
    # ---------------------------------------------------------
    
    # We use re.DOTALL so the dot (.) matches everything, including newlines (0x0A)
    regex = rb'\x6A(.)(.{0,20}?)\xFF\x15(....)'

    try:
        with open(filename, "rb") as f:
            data = f.read()
            
            # Find all occurrences
            matches = list(re.finditer(regex, data, re.DOTALL))
            
            if not matches:
                print("[-] No matches found.")
                return

            print(f"[+] Found {len(matches)} candidate(s):\n")

            for match in matches:
                start_offset = match.start()
                
                # Extract our captured groups
                res_id_byte = match.group(1)
                gap_bytes = match.group(2)
                call_addr_bytes = match.group(3)
                
                # Convert to helpful formats
                res_id_int = int.from_bytes(res_id_byte, "little")
                res_id_hex = res_id_byte.hex().upper()
                gap_len = len(gap_bytes)
                call_addr_hex = binascii.hexlify(call_addr_bytes).decode().upper()

                print(f"Offset: {hex(start_offset)}")
                print(f" - PUSH ID: 0x{res_id_hex} (Decimal: {res_id_int})")
                print(f" - Gap Size: {gap_len} bytes")
                print(f" - CALL Address: [0x{call_addr_hex}]")
                print("-" * 30)

    except FileNotFoundError:
        print(f"[!] File {filename} not found.")

# Usage
find_fuzzy_call("ETEL2002.EXE")