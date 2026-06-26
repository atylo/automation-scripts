import struct
import sys
import os

IO_CHUNK_LIMIT = 1024 * 1024

def count_opcodes(f, chunk_size, start_offset, op1_size, op2_size, op3_size, op2_fmt, op3_fmt):
    # --- SCAN & COUNT OPCODES ---
    f.seek(0, os.SEEK_END)
    file_size = f.tell()
    f.seek(start_offset)
    opcode_counts = {i: 0 for i in range(7)}
    missing_bytes = 0
    opcode_0_offset = None
    
    while True:
        opcode_byte = f.read(1)
        if not opcode_byte:
            break
            
        opcode = opcode_byte[0]
        
        # Tally the opcode
        if opcode in opcode_counts:
            opcode_counts[opcode] += 1
        else:
            raise ValueError(f"Unknown Opcode {opcode} (0x{opcode:02X}) encountered. Halt.")
        
        # Fast-forward the file pointer, but track missing bytes for Opcodes 1, 2, and 3
        if opcode == 0:
            opcode_0_offset = f.tell() - 1
            break
            
        elif opcode == 1:
            f.seek(op1_size, os.SEEK_CUR)
            missing_bytes += chunk_size
            
        elif opcode == 2:
            data = f.read(op2_size)
            if len(data) != op2_size:
                raise ValueError("Truncated file encountered while parsing Opcode 2.")
            offset, count = struct.unpack(op2_fmt, data)
            missing_bytes += count * chunk_size
            
        elif opcode == 3:
            data = f.read(op3_size)
            if len(data) != op3_size:
                raise ValueError("Truncated file encountered while parsing Opcode 3.")
            offset, exact_size = struct.unpack(op3_fmt, data)
            missing_bytes += exact_size
            
        elif opcode == 4:
            f.seek(chunk_size, os.SEEK_CUR)
        elif opcode == 5:
            count_data = f.read(4)
            if len(count_data) < 4:
                raise ValueError("Truncated file encountered while parsing Opcode 5.")
            count, = struct.unpack('<I', count_data)
            f.seek(count * chunk_size, os.SEEK_CUR)
        elif opcode == 6:
            size_data = f.read(4)
            if len(size_data) < 4:
                raise ValueError("Truncated file encountered while parsing Opcode 6.")
            exact_size, = struct.unpack('<I', size_data)
            f.seek(exact_size, os.SEEK_CUR)

    # Output the totals
    print("\n### OPCODE FREQUENCY ###")
    for op, count in opcode_counts.items():
        print(f"Opcode {op}: {count}")
        
    if opcode_counts[0] != 1:
        print("SUS")
    
    if opcode_0_offset is not None:
        remaining = file_size - f.tell()
        if remaining > 0:
            extra_data = f.read(min(remaining, 64))
            print(f"Notice: {remaining} bytes after Opcode 0: {extra_data.hex(' ')}")


    return missing_bytes

def reconstruct_udf_with_zeros(file_path, output_filename="reconstructed_file.bin"):
    print(f"Reconstructing UDF Patch: {os.path.basename(file_path)}")
    
    with open(file_path, 'rb') as f, open(output_filename, 'wb') as out_f:
        header_data = f.read(10)
        if len(header_data) < 10:
            print("Error: File is too small to be a valid UDF patch.")
            return

        magic, version, chunk_size = struct.unpack('<4sHI', header_data)
        
        # Conditionally parse the Target Size if version is 110
        target_size = None
        if version != 100:
            target_size, = struct.unpack('<Q', f.read(8))
        if version > 899:
            print(f"Impossible version: {version} (0x{version:04X}). Halt.")
            return
            
        if magic != b"UDF ":
            print("Warning: Magic number is not 'UDF '. Proceeding anyway...\n")
        
        print(f"UDF patch version: {version} (0x{version:04X})")
        if version == 100:
            print("Probably from a 1.3.0.0 UDM archive.")
        if version == 110:
            print("Probably from a 2.3.0.0 UDM archive.")
        
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
            print(f"!!!Unusual chunk size: {chunk_size}\n")
            
        # Check if worth extracting.
        inst_pos = f.tell()
        try:
            # Pass op2_fmt and op3_fmt so we can accurately read the metadata payloads
            missing_bytes = count_opcodes(f, chunk_size, inst_pos, op1_size, op2_size, op3_size, op2_fmt, op3_fmt)
        except ValueError as e:
            print(f"Error during scan: {e}")
            return
            
        if missing_bytes > 200: # Should be zero?
            print(f"\n[!] WARNING: This patch relies on {missing_bytes:,} bytes from the Old File.")
            #print("Injecting zeros for these missing bytes will result in an incomplete/corrupted output.")
            choice = input("Proceed anyway? (y/n): ").strip().lower()

            if choice not in ("y", "yes"):
                print("Aborted.")
                out_f.close()
                os.remove(output_filename)
                return

            print("Proceeding...\n")
        
        f.seek(inst_pos)
        #print(f"Target File Size: {target_size} bytes")
        print("Injecting zeros for missing data...\n")
        
        instruction_count = 0
        total_written = 0
        
        # Valid concern: Can the offsets in 1, 2, and 3 be pointing out of order, to far or previous output offset?
        # However, because Opcodes 4, 5, and 6 are purely sequential literal writes, it is highly probable that the
        # entire architecture of this patch format assumes the Target File is written strictly from start to finish.
        
        while True:
            opcode_byte = f.read(1)
            if not opcode_byte:
                print("\n[!] Unexpected End of File reached before Opcode 0.")
                break
                
            opcode = opcode_byte[0]
            instruction_count += 1
            
            if opcode == 0:
                print(f"[{instruction_count:04d}] Opcode 0: End of File. Reconstruction complete.")
                break
                
            elif opcode == 1:
                # Read dynamic bytes (Offset)
                if len(f.read(op1_size)) != op1_size:
                    print("\n[!] Error: Opcode 1 metadata truncated.")
                    break
                # Write 1 chunk of zeros
                out_f.write(b'\x00' * chunk_size)
                total_written += chunk_size
                
            elif opcode == 2:
                # Read dynamic bytes (Offset + Count)
                data = f.read(op2_size)
                if len(data) != op2_size:
                    print("\n[!] Error: Opcode 2 metadata truncated.")
                    break
                offset, count = struct.unpack(op2_fmt, data)
                bytes_to_write = count * chunk_size
                
                # Write N chunks of zeros
                while bytes_to_write > 0:
                    chunk = min(bytes_to_write, IO_CHUNK_LIMIT)
                    out_f.write(b'\x00' * chunk)
                    bytes_to_write -= chunk
                    total_written += chunk
                
            elif opcode == 3:
                # Read dynamic bytes (Offset + Exact Size)
                data = f.read(op3_size)
                if len(data) != op3_size:
                    print("\n[!] Error: Opcode 3 metadata truncated.")
                    break
                offset, exact_size = struct.unpack(op3_fmt, data)
                # Write exact bytes of zeros
                while exact_size > 0:
                    chunk = min(exact_size, IO_CHUNK_LIMIT)
                    out_f.write(b'\x00' * chunk)
                    exact_size -= chunk
                    total_written += chunk
                
            elif opcode == 4:
                # Read raw data and write to file
                raw_data = f.read(chunk_size)
                if len(raw_data) != chunk_size:
                    print(f"\n[!] Error: Opcode 4 payload truncated. Got {len(raw_data)} of {chunk_size} bytes.")
                    break
                written = out_f.write(raw_data)
                total_written += written
                
            elif opcode == 5:
                # Read 4 bytes (Count), then read raw data
                count_data = f.read(4)
                if len(count_data) != 4:
                    print("\n[!] Error: Opcode 5 count field truncated.")
                    break
                count, = struct.unpack('<I', count_data)
                bytes_to_read = count * chunk_size
                while bytes_to_read > 0:
                    chunk = min(bytes_to_read, IO_CHUNK_LIMIT)
                    raw_data = f.read(chunk)
                    if len(raw_data) != chunk:
                        print("\n[!] Error: Opcode 5 payload truncated.")
                        return
                    out_f.write(raw_data)
                    bytes_to_read -= chunk
                    total_written += chunk
                
            elif opcode == 6:
                # Read 4 bytes (Exact Size), then read raw data
                size_data = f.read(4)
                if len(size_data) != 4:
                    print("\n[!] Error: Opcode 6 count field truncated.")
                    break
                exact_size, = struct.unpack('<I', size_data)
                while exact_size > 0:
                    chunk = min(exact_size, IO_CHUNK_LIMIT)
                    raw_data = f.read(chunk)
                    if len(raw_data) != chunk:
                        print("\n[!] Error: Opcode 6 payload truncated.")
                        return
                    out_f.write(raw_data)
                    exact_size -= chunk
                    total_written += chunk
                
            else:
                print(f"\n[!] FATAL: Unknown Opcode {opcode} (0x{opcode:02X}) encountered.")
                break

        if target_size is not None:
            print("-" * 30)
            print(f"Expected Size: {target_size:,} bytes")
            print(f"Actual Written: {total_written:,} bytes")
        
            if target_size == total_written:
                print("Success! Reconstructed file matches expected target size.")
            else:
                print("Warning: Reconstructed size does not match target size.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Read UDF patches extractor 0.6")
        print(f"Usage: python {os.path.basename(sys.argv[0])} <path_to_udf_file> [output_file]")
    else:
        target_file = sys.argv[1]
        out_file = sys.argv[2] if len(sys.argv) > 2 else f"{target_file}.bin"
        
        if os.path.exists(target_file):
            reconstruct_udf_with_zeros(target_file, out_file)
        else:
            print(f"Error: File '{target_file}' not found.")