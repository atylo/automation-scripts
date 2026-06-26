import struct
import sys
import os

debug = True

def parse_udf(file_path):
    
    with open(file_path, 'rb') as f:
        # Parse the 10-Byte Header
        # <4s : 4-byte char array (Magic)
        # H   : unsigned short / 2 bytes (Version)
        # I   : unsigned int / 4 bytes (Chunk Size)
        header_data = f.read(10)
        if len(header_data) < 10:
            print("Error: File is too small to be a valid UDF patch.")
            return

        magic, version, chunk_size = struct.unpack('<4sHI', header_data)
        
        # Conditionally parse the Target Size if version is 110
        target_size = None
        if version == 110:
            target_size, = struct.unpack('<Q', f.read(8))

            
        if magic != b"UDF ":
            print("\nWarning: The magic isn't 'UDF '. This might not be a valid file.\n")
            return
            
        print(f"\nAnalyzing UDF Patch: {os.path.basename(file_path)}")    
        print("### UDF HEADER ###")
        print(f"Magic:       {magic}")
        print(f"Version:     {version} (0x{version:04X})") # UDM version in reverse?
        print(f"Chunk Size:  {chunk_size} bytes")
        if target_size is not None:
            print(f"Target Size: {target_size} bytes")

        if version == 100:
            op1_size, op2_size, op3_size = 4, 8, 8
            op1_fmt, op2_fmt, op3_fmt = '<I', '<II', '<II'
        else:
            # If it's not 100 or 110, print warn but default to 110 logic
            if version != 110:
                print(f"\n!!!Unknown version: {version} (0x{version:04X}). Defaulting to version 110 opcode payload sizes.")
            
            op1_size, op2_size, op3_size = 8, 12, 12
            op1_fmt, op2_fmt, op3_fmt = '<Q', '<QI', '<QI'
            
        if chunk_size != 100:
            print(f"!!!Unusual chunk size: {chunk_size}")
            
        # Save the file position right after the header to reset later
        instruction_start_pos = f.tell()
        
        # --- PASS 1: SCAN & COUNT OPCODES ---
        opcode_counts = {i: 0 for i in range(7)}
        unknown_opcode = False
        
        while True:
            opcode_byte = f.read(1)
            if not opcode_byte:
                break
                
            opcode = opcode_byte[0]
            
            # Tally the opcode
            if opcode in opcode_counts:
                opcode_counts[opcode] += 1
            else:
                unknown_opcode = True
                break
            
            # Fast-forward the file pointer based on the opcode's payload size
            if opcode == 0:
                break
            elif opcode == 1:
                f.seek(op1_size, os.SEEK_CUR)
            elif opcode == 2:
                f.seek(op2_size, os.SEEK_CUR)
            elif opcode == 3:
                f.seek(op3_size, os.SEEK_CUR)
            elif opcode == 4:
                f.seek(chunk_size, os.SEEK_CUR)
            elif opcode == 5:
                count_data = f.read(4)
                if len(count_data) < 4: break
                count, = struct.unpack('<I', count_data)
                f.seek(count * chunk_size, os.SEEK_CUR)
            elif opcode == 6:
                size_data = f.read(4)
                if len(size_data) < 4: break
                exact_size, = struct.unpack('<I', size_data)
                f.seek(exact_size, os.SEEK_CUR)

        # Output the totals
        print("\n### OPCODE FREQUENCY ###")
        for op, count in opcode_counts.items():
            print(f"Opcode {op}: {count}")

        if unknown_opcode:
            print("\n[!] Warning: Unknown opcode encountered during scanning.")

        # Check for extractability (No references to an Old File)
        count_123 = opcode_counts[1] + opcode_counts[2] + opcode_counts[3]
        if count_123 == 0:
            print("\n[+] ZERO Old-File references (Opcodes 1, 2, 3) detected.")
            print("[+] This file can be extracted.")
        elif count_123 <= 6:
            print("[+] This file Might be extracted.")
        else:
            print("Too much missing data.")
            print("\n[+] This file is a bust.")


        #user_choice = input("\nParse the full instruction stream? (yes/NO): ").strip().lower()
        if debug == False:
            #print("Exiting parser.")
            return

        # --- DETAILED PARSING ---
        print("\n### INSTRUCTION STREAM ###")
        # Reset the file pointer back to the start of the instruction stream
        f.seek(instruction_start_pos)
        
        instruction_count = 0
        
        while True:
            # Read exactly 1 byte for the opcode
            opcode_byte = f.read(1)
            if not opcode_byte:
                print("\n[!] Unexpected End of File reached before Opcode 0.")
                break
                
            opcode = opcode_byte[0]
            instruction_count += 1
            
            if opcode == 0:
                print(f"[{instruction_count:04d}] Opcode 0: End of File.")
                break
                
            elif opcode == 1:
                # Read dynamic offset
                offset, = struct.unpack(op1_fmt, f.read(op1_size))
                print(f"[{instruction_count:04d}] Opcode 1: Copy 1 chunk ({chunk_size} bytes) from Old File @ offset 0x{offset:X}")
                
            elif opcode == 2:
                # Read dynamic offset + count
                offset, count = struct.unpack(op2_fmt, f.read(op2_size))
                bytes_to_copy = count * chunk_size
                print(f"[{instruction_count:04d}] Opcode 2: Copy {count} chunks ({bytes_to_copy} bytes) from Old File @ offset 0x{offset:X}")
                
            elif opcode == 3:
                # Read dynamic offset + exact size
                offset, exact_size = struct.unpack(op3_fmt, f.read(op3_size))
                print(f"[{instruction_count:04d}] Opcode 3: Copy exactly {exact_size} bytes from Old File @ offset 0x{offset:X}")
                
            elif opcode == 4:
                # Action: Read 'chunk_size' bytes of raw data
                raw_data = f.read(chunk_size)
                if len(raw_data) != chunk_size:
                    print(f"\n[!] Error: Opcode 4 payload truncated. Got {len(raw_data)} of {chunk_size} bytes.")
                    break
                print(f"[{instruction_count:04d}] Opcode 4: Insert 1 chunk ({chunk_size} bytes) of raw data from patch")
                
            elif opcode == 5:
                # Read 4 bytes (Count)
                count_data = f.read(4)
                if len(count_data) != 4:
                    print("\n[!] Error: Opcode 5 count field truncated.")
                    break
                count, = struct.unpack('<I', count_data)
                bytes_to_read = count * chunk_size
                # Action: Read 'bytes_to_read' bytes of raw data
                raw_data = f.read(bytes_to_read)
                if len(raw_data) != bytes_to_read:
                    print(f"Opcode 5: truncated data (got {len(raw_data)}, expected {bytes_to_read})")
                    break
                print(f"[{instruction_count:04d}] Opcode 5: Insert {count} chunks ({bytes_to_read} bytes) of raw data from patch")
                
            elif opcode == 6:
                # Read 4 bytes (Exact Size)
                size_data = f.read(4)
                if len(size_data) != 4:
                    print("\n[!] Error: Opcode 6 count field truncated.")
                    break
                exact_size, = struct.unpack('<I', size_data)
                # Action: Read 'exact_size' bytes of raw data
                raw_data = f.read(exact_size)
                if len(raw_data) != exact_size:
                    print(f"Opcode 6: truncated data (got {len(raw_data)}, expected {exact_size})")
                    break
                print(f"[{instruction_count:04d}] Opcode 6: Insert exactly {exact_size} bytes of raw data from patch")
                
            else:
                print(f"\n[!] FATAL: Unknown Opcode {opcode} (0x{opcode:02X}) encountered. Halting parser.")
                break

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Read UDF patches structure reader 0.4")
        print(f"Usage: python {sys.argv[0]} <path_to_udf>")
    else:
        target_file = sys.argv[1]
        if os.path.exists(target_file):
            parse_udf(target_file)
        else:
            print(f"Error: File '{target_file}' not found.")