SESSION_KEY = 0xC04CAFB4

def ror32(val, amt):
    return ((val >> amt) | (val << (32 - amt))) & 0xFFFFFFFF

def decrypt_metadata_block(hex_str, entry_size=12):
    # Clean the input string and convert to bytes
    raw_data = bytes.fromhex(hex_str.replace(" ", "").replace("\n", ""))

    # Process each file entry (12 bytes each)
    for entry_idx in range(0, len(raw_data), entry_size):
        chunk = raw_data[entry_idx : entry_idx + entry_size]
        filename = []
        
        # RESET the string index (i) for every new file entry
        for i, b in enumerate(chunk):
            # 1. Reverse the bitwise rotation
            rot_amt = (i + 3) % 8
            rotated_byte = ((b << rot_amt) | (b >> (8 - rot_amt))) & 0xFF
            
            # 2. Calculate SubKey (index + 0x11 + 0x11)
            shift = (i + 0x22) % 32
            current_subkey = ror32(SESSION_KEY, shift)
            key_byte = current_subkey & 0xFF
            
            # 3. Final subtraction
            res_byte = (rotated_byte - key_byte) & 0xFF
            
            # Debug output for the first few entries
            #if entry_idx < 24: # Limit debug output so it doesn't flood
            #   print(f"{'Index':<6} | {'Enc Hex':<8} | {'Rot':<4} | {'SubKey':<10} | {'Char'}")
            #   print("-" * 50)
            #    char_disp = chr(res_byte) if 32 <= res_byte <= 126 else f"0x{res_byte:02X}"
            #    print(f"{i:<6} | {b:02X}       | {rot_amt:<4} | {current_subkey:08X} | {char_disp}")
            
            if res_byte == 0: break
            filename.append(chr(res_byte))
            
        print(f"--> File Entry {entry_idx // entry_size:02}: {''.join(filename)}")
        print("-" * 50)

# The full hex block from your first message
big_hex_dump = "2A 75 7B 7B DD 8F 71 61 54 6F 02 00 2A 75 7B 7B DD 8F F1 61 54 6F 02 00 2A 75 7B 7B DD 8F 72 61 54 6F 02 00 2A 75 7B 7B DD 8F F2 61 54 6F 02 00 2A 75 7B 7B DD 8F 73 61 54 6F 02 00 2A 75 7B 7B DD 8F F3 61 54 6F 02 00 2A 75 7B 7B DD 8F 74 61 54 6F 02 00 2A 75 7B 7B DD 90 EF 61 54 6F 02 00 2A 75 7B 7B DD 90 70 61 54 6F 02 00 2A 75 7B 7B DD 90 F0 61 54 6F 02 00 2A 75 7B 7B DD 90 71 61 54 6F 02 00 2A 75 7B 7B DD 90 F1 61 54 6F 02 00 2A 75 7B 7B DD 90 72 61 54 6F 02 00 2A 75 7B 7B DD 90 F2 61 54 6F 02 00 2A 75 7B 7B DD 90 73 61 54 6F 02 00 2A 75 7B 7B DD 90 F3 61 54 6F 02 00 2A 75 7B 7B DD 90 74 61 54 6F 02 00 2A 75 7B 7B DD 91 EF 61 54 6F 02 00 2A 75 7B 7B DD 91 70 61 54 6F 02 00 2A 75 7B 7B DD 91 F0 61 54 6F 02 00 2A 75 7B 7B DD 91 71 61 54 6F 02 00 2A 75 7B 7B DD 91 F1 61 54 6F 02 00 2A 75 7B 7B DD 91 72 61 54 6F 02 00 2A 75 7B 7B DD 91 F2 61 54 6F 02 00 2A 75 7B 7B DD 91 73 61 54 6F 02 00 2A 75 7B 7B DD 91 F3 61 54 6F 02 00 2A 75 7B 7B 6C D7 93 61 F3 D0 F1 00 46 D3 12 73 14 AE 7B A9 2B C0 59 6F 00 27 56 13 B3 D9 C1 0E F1 00"

decrypt_metadata_block(big_hex_dump)