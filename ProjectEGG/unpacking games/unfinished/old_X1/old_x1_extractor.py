import struct
import sys
import os

def descramble(data, base_offset=0):
    output = bytearray()
    for i, byte_val in enumerate(data):
        # Ensure 32-bit arithmetic like the original C code
        v5 = (base_offset + i) & 0xFFFFFFFF
        shift = v5 & 7
        rotated = ((byte_val << shift) & 0xFF) | (byte_val >> (8 - shift))
        output.append((v5 ^ rotated) & 0xFF)
    return output

def extract_all_disks(exe_path):
    with open(exe_path, "rb") as f:
        data = f.read()

    print(f"=== Scanning {os.path.basename(exe_path)} ===")
    
    base_name = os.path.splitext(exe_path)[0]
    out_dir = os.path.dirname(os.path.abspath(exe_path))
    physical_off = 0
    disk_count = 0
    search_limit = len(data) - 0x20

    while physical_off < search_limit:
        found_disk = False
        
        # Try offsets 0-7 in case the key counter doesn't reset between disks
        # We check range(8) just in case a secondary disk is slightly offset
        for v_start in range(8):
            test_chunk = data[physical_off : physical_off + 0x20]
            decrypted = descramble(test_chunk, v_start)
            
            media_type = decrypted[0x1B]
            disk_size = struct.unpack_from('<I', decrypted, 0x1C)[0]

            # D88 Header Validation
            if media_type in [0x00, 0x10, 0x20] and 0x400 <= disk_size < 4000000:
                name_part = decrypted[:17].replace(b'\x00', b'')
                if len(name_part) == 0 or all(32 <= b <= 126 or b > 128 for b in name_part):
                    if physical_off + disk_size > len(data):
                        continue
                    disk_count += 1
                    disk_name_str = name_part.decode('shift-jis', errors='replace') or f"Disk_{disk_count}"
                    
                    print(f"\n[+] Disk {disk_count} found!")
                    print(f"    Physical Offset: 0x{physical_off:X}")
                    print(f"    Virtual Start:   0x{v_start:X}")
                    print(f"    Size:            {disk_size} bytes")
                    print(f"    Label:           {disk_name_str}")

                    # Extract and descramble
                    disk_data = data[physical_off : physical_off + disk_size]
                    decrypted_disk = descramble(disk_data, v_start)

                    out_path = os.path.join(out_dir, f"{os.path.basename(base_name)}_disk{disk_count}.d88")
                    with open(out_path, "wb") as out_f:
                        out_f.write(decrypted_disk)
                    
                    # Advance the pointer past the current disk
                    physical_off += disk_size
                    found_disk = True
                    break
        
        if not found_disk:
            # Advance by 4 bytes (alignment) to keep searching
            physical_off += 4

    if disk_count == 0:
        print("[-] No disks found.")
    else:
        print(f"\nFinished. Extracted {disk_count} disks.")

def main():
    if len(sys.argv) < 2:
        print("\n===Old X1 Extractor (ROL+XOR descramble, no compression)===\n")
        print("Usage: python desc_test2.py <game.exe>")
    else:
        extract_all_disks(sys.argv[1])

if __name__ == "__main__":
    main()
