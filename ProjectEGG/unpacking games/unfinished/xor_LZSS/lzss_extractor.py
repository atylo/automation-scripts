import struct
import sys
import mmap
import os

# --- Helper Functions ---

def save_extracted_asset(data, default_filename):
    """
    Checks if the data contains .d88 disk images. If so, splits and extracts them.
    Otherwise, saves the data normally.
    """
    # Quick sanity check: D88 headers are 0x2B0 (688) bytes long.
    if len(data) >= 0x2B0:
        disk_size = struct.unpack("<I", data[0x1C:0x20])[0]
        track_0_offset = struct.unpack("<I", data[0x20:0x24])[0]
        
        # Heuristic: Valid size range, and track 0 usually starts at 0x2B0.
        if 0x2B0 <= disk_size <= len(data) and track_0_offset == 0x2B0:
            print(f"    [*] Detected D88 disk image bundle! Extracting disks...")
            offset = 0
            disk_count = 0
            #base_filename = os.path.splitext(default_filename)[0]
            
            while offset + 0x2B0 <= len(data):
                # 1. Extract Disk Name (First 16 bytes, null-terminated, Shift-JIS encoded)
                name_bytes = data[offset : offset + 16]
                disk_name = name_bytes.split(b'\0')[0].decode('shift_jis', 'ignore').strip()
                if not disk_name:
                    disk_name = f"Disk_{disk_count + 1}"
                
                # Make the filename filesystem-safe
                safe_name = "".join(c for c in disk_name if c.isalnum() or c in "._- ")
                
                # 2. Extract Disk Size
                d_size = struct.unpack("<I", data[offset + 0x1C : offset + 0x20])[0]
                
                # Break if we hit corrupted/garbage data
                if d_size < 0x2B0 or offset + d_size > len(data):
                    break
                    
                # 3. Save the individual D88 file
                base_out_name = f"{safe_name}.d88"
                out_name = base_out_name
                
                counter = 1
                while os.path.exists(out_name):
                    out_name = f"{safe_name}_{counter}.d88"
                    counter += 1
                
                with open(out_name, "wb") as out:
                    out.write(data[offset : offset + d_size])
                
                print(f"      -> Saved: {out_name} (Size: {d_size} bytes)")
                
                offset += d_size
                disk_count += 1
                
            return # Exit early, we handled the saving

    # Fallback: Save as a normal file if not a D88
    with open(default_filename, "wb") as out:
        out.write(data)

# --- PE Parsing Helpers ---
def find_all_pe_headers(mm):
    pe_list = []
    offset = 0
    print(f"[*] Scanning for PE executables...")
    while True:
        mz_offset = mm.find(b'MZ', offset)
        if mz_offset == -1: break
        if mz_offset + 0x3C + 4 > len(mm):
            offset = mz_offset + 1; continue
        e_lfanew = struct.unpack("<I", mm[mz_offset+0x3C : mz_offset+0x40])[0]
        pe_header_offset = mz_offset + e_lfanew
        if pe_header_offset + 0x38 > len(mm):
            offset = mz_offset + 1; continue
        if mm[pe_header_offset : pe_header_offset+4] == b'PE\0\0':
            try:
                image_base = struct.unpack("<I", mm[pe_header_offset+0x34 : pe_header_offset+0x38])[0]
                print(f"    [+] Found PE at Offset 0x{mz_offset:X} (ImageBase: 0x{image_base:X})")
                pe_list.append({'offset': mz_offset, 'image_base': image_base})
            except: pass
        offset = mz_offset + 1
    return pe_list

# --- Extraction Logic ---
def lzss_decompress(compressed_data, explicit_size=None):
    history = bytearray(4096); history_ptr = 0xFEE
    output = bytearray(); src_ptr = 6; flags = 0
    SAFETY_LIMIT = 64 * 1024 * 1024
    while True:
        if explicit_size and len(output) >= explicit_size: break
        if not explicit_size and len(output) >= SAFETY_LIMIT: break
        flags = flags >> 1
        if (flags & 0x100) == 0:
            if src_ptr >= len(compressed_data): break
            b = compressed_data[src_ptr]; src_ptr += 1
            flags = 0xFF00 | ((~b) & 0xFF)
        if (flags & 1):
            if src_ptr >= len(compressed_data): break
            val = (~compressed_data[src_ptr]) & 0xFF; src_ptr += 1
            output.append(val); history[history_ptr] = val
            history_ptr = (history_ptr + 1) & 0xFFF
        else:
            if src_ptr + 1 >= len(compressed_data): break
            b1 = (~compressed_data[src_ptr]) & 0xFF
            b2 = (~compressed_data[src_ptr+1]) & 0xFF; src_ptr += 2
            offset = ((b2 & 0xF0) << 4) | b1
            length = (b2 & 0x0F) + 3
            for _ in range(length):
                val = history[offset]; output.append(val)
                history[history_ptr] = val; history_ptr = (history_ptr + 1) & 0xFFF
                offset = (offset + 1) & 0xFFF
                if explicit_size and len(output) >= explicit_size: break
                if not explicit_size and len(output) >= SAFETY_LIMIT: break
    return output

def find_asm_size_strategy(mm, data_va, pe_start, pe_end):
    target_bytes = struct.pack("<I", data_va)
    chunk_to_search = mm[pe_start:pe_end]
    found_any_reference = False

    patterns = [
        b'\x68' + target_bytes, # PUSH Imm32
        b'\xB8' + target_bytes, # MOV EAX, Imm32
        b'\xB9' + target_bytes, # MOV ECX, Imm32
        b'\xBA' + target_bytes, # MOV EDX, Imm32
        b'\xBB' + target_bytes, # MOV EBX, Imm32
        b'\xBE' + target_bytes, # MOV ESI, Imm32
        b'\xBF' + target_bytes  # MOV EDI, Imm32
    ]

    for pattern in patterns:
        off = 0
        while True:
            local_off = chunk_to_search.find(pattern, off)
            if local_off == -1: break
            
            found_any_reference = True
            
            # Look back for Size, but STOP if we hit a RET (0xC3)
            # which indicates we've crossed into a different function.
            check_start = max(0, local_off - 50)
            check_chunk = chunk_to_search[check_start : local_off]
            
            # Find the last RET in this window
            last_ret = check_chunk.rfind(b'\xC3')
            # If a RET exists, only look at instructions AFTER the RET
            valid_chunk = check_chunk[last_ret + 1:] if last_ret != -1 else check_chunk

            # Check for PUSH 0 in the valid function window
            if b'\x6A\x00' in valid_chunk: 
                return ("HEADER", 0)

            # Check for PUSH Imm32 in the valid function window
            push_idx = valid_chunk.rfind(b'\x68')
            if push_idx != -1 and push_idx + 5 <= len(valid_chunk):
                size_val = struct.unpack("<I", valid_chunk[push_idx+1 : push_idx+5])[0]
                if 0 < size_val < 50*1024*1024: 
                    return ("HARDCODED", size_val)
                    
            off = local_off + 1
    
    if found_any_reference:
        return ("REF_FOUND", 0)
        
    return None

def process_pe(mm, f, pe_info, end_offset):
    pe_start = pe_info['offset']
    image_base = pe_info['image_base']
    def rel_offset_to_va(abs_offset): return image_base + (abs_offset - pe_start)
    def va_to_rel_offset(va): return pe_start + (va - image_base)

    signature = b'\xB3\xA5\xAC\xAC'
    start_search = pe_start
    extracted_offsets = set()

    print(f"\n=== Processing PE at 0x{pe_start:X} ===")

    while True:
        data_offset = mm.find(signature, start_search)
        if data_offset == -1 or data_offset >= end_offset: break
        start_search = data_offset + 1
        if data_offset in extracted_offsets: continue
        
        data_va = rel_offset_to_va(data_offset)
        print(f"\n[+] Found Sig at 0x{data_offset:X} (VA 0x{data_va:X})")
        
        # --- 1. TOC Check ---
        found_toc = False
        packed_va = struct.pack("<I", data_va)
        toc_search = pe_start
        while True:
            toc_ptr = mm.find(packed_va, toc_search, end_offset)
            if toc_ptr == -1: break
            try:
                f.seek(toc_ptr - 4); name_va = struct.unpack("<I", f.read(4))[0]
                if name_va >= image_base:
                    name_off = va_to_rel_offset(name_va)
                    if pe_start <= name_off < end_offset:
                        f.seek(toc_ptr + 4); size = struct.unpack("<I", f.read(4))[0]
                        if 0 < size < 50_000_000:
                            f.seek(name_off); name = f.read(64).split(b'\0')[0].decode('utf-8', 'ignore')
                            name = name.split("\\")[-1]
                            print(f"    [Strategy: TOC] Found '{name}' (Size: {size})")
                            f.seek(data_offset); blob = f.read(size+8192)
                            
                            decompressed = lzss_decompress(blob, size)
                            save_extracted_asset(decompressed, name)
                            
                            found_toc = True; break
            except: pass
            toc_search = toc_ptr + 1
        
        if found_toc: extracted_offsets.add(data_offset); continue

        # --- 2. ASM Check ---
        asm_strategy = find_asm_size_strategy(mm, data_va, pe_start, end_offset)
        
        if asm_strategy:
            st_type, st_val = asm_strategy
            
            # Initial attempt at extraction using ASM hints
            if st_type in ["HEADER", "HARDCODED"]:
                final_size = 0
                if st_type == "HEADER":
                    f.seek(data_offset); raw = f.read(6)
                    # Use the bit-flipped header logic
                    final_size = ((~raw[5] & 0xFF) << 8) | (~raw[4] & 0xFF)
                    print(f"    [Strategy: ASM] PUSH 0 -> Trusted Header: {final_size}")
                else:
                    final_size = st_val
                    print(f"    [Strategy: ASM] Hardcoded Size: {final_size}")
                
                if final_size > 0:
                    f.seek(data_offset); blob = f.read(final_size+4096)
                    fn = f"asset_{data_offset:X}.bin"
                    decompressed = lzss_decompress(blob, final_size)
                    save_extracted_asset(decompressed, fn)
                    extracted_offsets.add(data_offset)
                    continue
                else:
                    # Logic Fix: If size is 0, don't orphan! Downgrade to fallback.
                    print("    [!] ASM Header size was 0. Downgrading to Fallback extraction.")
                    st_type = "REF_FOUND"

            # Fallback or Downgraded attempt
            if st_type == "REF_FOUND":
                print(f"    [Strategy: Fallback] Referenced at 0x{data_va:X}, extracting until end-of-stream.")
                f.seek(data_offset); blob = f.read()
                fn = f"asset_{data_offset:X}_fallback.bin"
                decompressed = lzss_decompress(blob, None)
                save_extracted_asset(decompressed, fn)
                extracted_offsets.add(data_offset)
                continue

        # --- 3. Orphan Check ---
        # Only reached if asm_strategy returned None (no references found at all)
        print("    [!] Orphaned Asset: No TOC and no code references.")
        print("        Skipping to avoid garbage.")
        extracted_offsets.add(data_offset)

def main_extraction(path):
    if not os.path.exists(path): 
        print(f"[!] File not found: {path}")
        return
        
    # 1. Get the absolute path before we change directories
    abs_path = os.path.abspath(path)
    
    # 2. Create the output directory based on the executable's name
    out_dir = os.path.splitext(os.path.basename(abs_path))[0]
    os.makedirs(out_dir, exist_ok=True)
    
    # 3. Change the working directory to the new folder
    os.chdir(out_dir)
    print(f"[*] Extracting assets into: {os.getcwd()}")

    # 4. Open the absolute path so we don't lose track of the file
    with open(abs_path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        pes = find_all_pe_headers(mm)
        if not pes: pes = [{'offset': 0, 'image_base': 0x400000}]
        for i, pe in enumerate(pes):
            next_start = pes[i+1]['offset'] if i+1 < len(pes) else len(mm)
            process_pe(mm, f, pe, next_start)

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: python lzss_extractor.py <file.exe>")
    else: main_extraction(sys.argv[1])