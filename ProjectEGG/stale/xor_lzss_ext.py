import struct
import sys
import mmap
import os

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
    SAFETY_LIMIT = 16 * 1024 * 1024 
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
    """
    Returns:
    - ("HEADER", 0) -> Found 'PUSH 0'
    - ("HARDCODED", size) -> Found 'PUSH Size'
    - ("REF_FOUND", 0) -> Found reference to Address, but NO Size PUSH (Use Fallback)
    - None -> Address never referenced (Orphan)
    """
    target_bytes = struct.pack("<I", data_va)
    chunk_to_search = mm[pe_start:pe_end]
    
    found_any_reference = False

    # Define patterns to search (Register passing & Stack passing)
    patterns = [b'\xB9' + target_bytes, b'\x68' + target_bytes]

    for pattern in patterns:
        off = 0
        while True:
            local_off = chunk_to_search.find(pattern, off)
            if local_off == -1: break
            
            # We found a reference! 
            found_any_reference = True
            
            # Look back 20 bytes for Size
            check_start = max(0, local_off - 20)
            check_chunk = chunk_to_search[check_start : local_off]
            
            # Check PUSH 0
            if b'\x6A\x00' in check_chunk: return ("HEADER", 0)

            # Check PUSH Imm32
            push_idx = check_chunk.rfind(b'\x68')
            if push_idx != -1 and push_idx + 5 <= len(check_chunk):
                size_val = struct.unpack("<I", check_chunk[push_idx+1 : push_idx+5])[0]
                if 0 < size_val < 50*1024*1024: return ("HARDCODED", size_val)
                    
            off = local_off + 1
    
    # If we exit the loop, we found references but no clear size strategy
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
                            with open(name, "wb") as out: out.write(lzss_decompress(blob, size))
                            found_toc = True; break
            except: pass
            toc_search = toc_ptr + 1
        
        if found_toc: extracted_offsets.add(data_offset); continue

        # --- 2. ASM Check ---
        asm_strategy = find_asm_size_strategy(mm, data_va, pe_start, end_offset)
        
        if asm_strategy:
            st_type, st_val = asm_strategy
            
            # CASE A: Explicit ASM Strategy Found
            if st_type in ["HEADER", "HARDCODED"]:
                final_size = 0
                if st_type == "HEADER":
                    f.seek(data_offset); raw = f.read(6)
                    final_size = ((~raw[5] & 0xFF) << 8) | (~raw[4] & 0xFF)
                    print(f"    [Strategy: ASM] PUSH 0 -> Trusted Header: {final_size}")
                else:
                    final_size = st_val
                    print(f"    [Strategy: ASM] Hardcoded Size: {final_size}")
                
                if final_size > 0:
                    f.seek(data_offset); blob = f.read(final_size+4096)
                    fn = f"asset_{data_offset:X}.bin"
                    with open(fn, "wb") as out: out.write(lzss_decompress(blob, final_size))
                    extracted_offsets.add(data_offset); continue

            # CASE B: Reference Found, but Size Unknown -> FALLBACK
            elif st_type == "REF_FOUND":
                print("    [Strategy: Fallback] Referenced in code, but size unknown.")
                print("    -> Performing Blind Extraction...")
                f.seek(data_offset); blob = f.read()
                data = lzss_decompress(blob, None)
                fn = f"asset_{data_offset:X}_fallback.bin"
                with open(fn, "wb") as out: out.write(data)
                extracted_offsets.add(data_offset); continue

        # --- 3. Orphan Check ---
        # If we reach here, asm_strategy was None (No TOC, No References)
        print("    [!] Orphaned Asset: No TOC and no code references.")
        print("        Skipping to avoid garbage.")
        extracted_offsets.add(data_offset)

def main_extraction(path):
    if not os.path.exists(path): return
    with open(path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        pes = find_all_pe_headers(mm)
        if not pes: pes = [{'offset': 0, 'image_base': 0x400000}]
        for i, pe in enumerate(pes):
            next_start = pes[i+1]['offset'] if i+1 < len(pes) else len(mm)
            process_pe(mm, f, pe, next_start)

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: python xor_lzss_ext.py <file.exe>")
    else: main_extraction(sys.argv[1])