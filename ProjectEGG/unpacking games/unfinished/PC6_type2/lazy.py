import pymem
import struct
import os

# =========================================================================
#  CONFIGURATION
# =========================================================================

PROCESS_NAME = "ETAE0017.EXE"     # Update if needed
LIST_HEAD_ADDR = 0x004BFDC0       # Keep the address you found

# =========================================================================
#  THE SCRIPT
# =========================================================================

def main():
    print(f"Attaching to {PROCESS_NAME}...")
    try:
        pm = pymem.Pymem(PROCESS_NAME)
    except Exception as e:
        print(f"Error: Is the emulator running? {e}")
        return

    print(f"Reading List Head from {hex(LIST_HEAD_ADDR)}...")
    
    try:
        current_node_ptr = pm.read_int(LIST_HEAD_ADDR)
    except:
        print("Error: Failed to read head pointer.")
        return

    if current_node_ptr == 0:
        print("List is empty.")
        return

    print(f"Head Node found at {hex(current_node_ptr)}. Scanning ALL allocations > 1KB...")
    print("-" * 70)

    count = 0
    dump_count = 0
    
    # Use a set to avoid re-dumping same pointers if list circles
    seen_nodes = set()

    while current_node_ptr != 0:
        if current_node_ptr in seen_nodes: break
        seen_nodes.add(current_node_ptr)
        count += 1
        
        if count > 20000: break # Safety limit

        try:
            # --- Read Header ---
            next_ptr = pm.read_int(current_node_ptr)
            
            # Offset 0x08: Filename Pointer (char*)
            file_name_ptr = pm.read_int(current_node_ptr + 0x08)
            
            # Offset 0x10: Data Size
            data_size = pm.read_int(current_node_ptr + 0x10)
            
            # Offset 0x18: Allocation Number
            alloc_num = pm.read_int(current_node_ptr + 0x18)

            # --- Filter: Anything bigger than 1KB ---
            if data_size > 1024:
                
                # Try to read the Debug Filename (Source code file)
                source_file = "Unknown"
                if file_name_ptr != 0:
                    try:
                        # Read string up to 64 chars
                        source_file = pm.read_string(file_name_ptr, 64)
                    except:
                        pass # String might be unreadable/paged out

                print(f"[+] Node: {hex(current_node_ptr)} | Alloc #{alloc_num}")
                print(f"    Size: {hex(data_size)} ({data_size} bytes)")
                print(f"    Source: {source_file}")

                # --- Dump Data ---
                data_ptr = current_node_ptr + 0x20
                
                # Quick Z80 check (F3 31 = DI, LD SP)
                sig = pm.read_bytes(data_ptr, 2)
                is_z80 = (sig == b'\xF3\x31')
                if is_z80: print("    [!] Z80 SIGNATURE DETECTED")

                # Sanity check: Don't dump massive garbage (limit 5MB)
                if data_size < 5 * 1024 * 1024:
                    out_name = f"Dump_{alloc_num}_sz{hex(data_size)}.bin"
                    try:
                        blob = pm.read_bytes(data_ptr, data_size)
                        with open(out_name, "wb") as f:
                            f.write(blob)
                        print(f"    -> Saved to {out_name}")
                        dump_count += 1
                    except Exception as e:
                        print(f"    -> Read Failed: {e}")
                else:
                    print("    -> Skipped (Too Large)")
                
                print("-" * 40)

        except Exception as e:
            # Memory read error (node might be corrupt or unmapped)
            pass

        current_node_ptr = next_ptr

    print(f"Done. Scanned {count} nodes. Dumped {dump_count} blocks.")

if __name__ == "__main__":
    main()