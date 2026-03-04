import struct
import sys
import os

# =========================================================================
#  PART 1: PE FILE PARSER (The "Map")
# =========================================================================

class PEFile:
    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, "rb") as f:
            self.data = f.read()
        
        # 1. Parse DOS Header to find PE Header
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        
        # 2. Parse Optional Header (Standard PE32 offset for ImageBase)
        # Magic(4) + FileHeader(20) + OptionalHeader.ImageBase(28) = 52 bytes
        self.image_base = struct.unpack_from("<I", self.data, e_lfanew + 0x34)[0]
        
        # 3. Parse Section Table
        num_sections = struct.unpack_from("<H", self.data, e_lfanew + 6)[0]
        size_opt_header = struct.unpack_from("<H", self.data, e_lfanew + 20)[0]
        section_table_offset = e_lfanew + 24 + size_opt_header
        
        self.sections = []
        for i in range(num_sections):
            header_offset = section_table_offset + (i * 40)
            # Name, VirtualSize, VirtualAddr, RawSize, RawPtr
            name, v_size, v_addr, r_size, r_ptr = struct.unpack_from("<8sIIII", self.data, header_offset)
            self.sections.append({
                'name': name.decode().strip('\x00'),
                'v_addr': v_addr, 
                'v_size': v_size, 
                'r_ptr': r_ptr, 
                'r_size': r_size
            })

    def va_to_offset(self, va):
        """Converts Virtual Address (RAM) to File Offset (Disk)"""
        rva = va - self.image_base
        for section in self.sections:
            # Check if the address falls inside this section's memory range
            if section['v_addr'] <= rva < (section['v_addr'] + max(section['v_size'], section['r_size'])):
                return section['r_ptr'] + (rva - section['v_addr'])
        return None
        
    def is_valid_va(self, va):
        return self.va_to_offset(va) is not None

# =========================================================================
#  PART 2: HUFFMAN DECOMPRESSION ENGINE
# =========================================================================

class BitReader:
    def __init__(self, data):
        self.data = data
        self.ptr = 0
        self.bits_left = 0
        self.current_byte = 0

    def read_bit(self):
        if self.bits_left == 0:
            if self.ptr >= len(self.data): return 0
            self.current_byte = self.data[self.ptr]
            self.ptr += 1
            self.bits_left = 8
        # MSB First Logic
        bit = (self.current_byte >> (self.bits_left - 1)) & 1
        self.bits_left -= 1
        return bit

    def read_byte(self):
        val = 0
        for _ in range(8):
            val = (val << 1) | self.read_bit()
        return val

class HuffmanDecompressor:
    def __init__(self, data):
        self.reader = BitReader(data)
        self.left = {}
        self.right = {}
        self.next_id = 256 # Leaves are 0-255, Nodes start at 256

    def build_tree(self):
        # Recursively build the tree from the stream
        if self.reader.read_bit() == 0:
            return self.reader.read_byte()
        
        node_id = self.next_id
        self.next_id += 1
        self.left[node_id] = self.build_tree()
        self.right[node_id] = self.build_tree()
        return node_id

def decompress_rom(data, uncompressed_size):
    huff = HuffmanDecompressor(data)
    root = huff.build_tree()
    output = bytearray()
    
    # Extract until we hit the expected size
    while len(output) < uncompressed_size:
        node = root
        while node >= 0x100:
            if huff.reader.read_bit() == 0:
                node = huff.left[node]
            else:
                node = huff.right[node]
        output.append(node)
        
    return output

# =========================================================================
#  PART 3: SIGNATURE SCANNERS
# =========================================================================

def scan_stack_pattern(pe_file):
    """
    Looks for the initialization loop: 
    MOV [ESP+X], ADDR1
    MOV [ESP+X+4], ADDR2 ...
    Signature: C7 44 24
    """
    print("  [.] Scanning for Stack Initialization Loop...")
    data = pe_file.data
    offset = 0
    while offset < len(data) - 40:
        try:
            offset = data.index(b'\xC7\x44\x24', offset)
        except ValueError:
            break
            
        base_stack_offset = data[offset + 3]
        pointers = []
        found_chain = True
        
        # Check if 5 consecutive instructions follow the pattern
        for i in range(5):
            inst_ptr = offset + (i * 8)
            if inst_ptr + 8 > len(data): found_chain = False; break
            
            if data[inst_ptr:inst_ptr+3] != b'\xC7\x44\x24': found_chain = False; break
            if data[inst_ptr+3] != (base_stack_offset + (i * 4)): found_chain = False; break
            
            addr = struct.unpack_from("<I", data, inst_ptr + 4)[0]
            pointers.append(addr)
        
        if found_chain:
            # Validate that they are real pointers
            if all(pe_file.is_valid_va(p) for p in pointers):
                print(f"      [+] Found 5 ROMs at code offset {hex(offset)}")
                return pointers
        offset += 1
    return []

def scan_direct_calls(pe_file):
    """
    Looks for the Direct Call pattern:
    PUSH <Arg2>
    PUSH <Arg1> (The ROM Address)
    CALL <Function>
    Signature: 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8
    """
    print("  [.] Scanning for Direct PUSH/CALL patterns...")
    data = pe_file.data
    offset = 0
    pointers = []
    
    while offset < len(data) - 15:
        try:
            offset = data.index(b'\x68', offset)
        except ValueError:
            break
            
        # Check for: PUSH (5 bytes) -> PUSH (5 bytes) -> CALL (Starts with E8)
        if offset + 10 >= len(data): break
        
        # Opcode check: 68 ... 68 ... E8
        if data[offset + 5] == 0x68 and data[offset + 10] == 0xE8:
            
            arg2 = struct.unpack_from("<I", data, offset + 1)[0]
            arg1 = struct.unpack_from("<I", data, offset + 6)[0] # This is the ROM
            
            # Heuristic: Both pushes must be valid addresses
            if pe_file.is_valid_va(arg2) and pe_file.is_valid_va(arg1):
                
                # Deep Check: Does Arg1 point to a valid size header?
                rom_offset = pe_file.va_to_offset(arg1)
                if rom_offset:
                    try:
                        size_header = struct.unpack_from("<I", data, rom_offset)[0]
                        # Valid ROMs are usually > 0 and < 2MB
                        if 0 < size_header < 0x200000:
                            print(f"      [+] Found Call at {hex(offset)} -> ROM VA: {hex(arg1)} (Size: {size_header})")
                            pointers.append(arg1)
                    except:
                        pass
        offset += 1
    return pointers

# =========================================================================
#  PART 4: EXECUTION
# =========================================================================

def main():

    # 1. Argument Parsing
    if len(sys.argv) < 2:
        print("Usage: python pc6_type2_extractor.py emulator.exe")
        return

    exe_path = sys.argv[1]

    if not os.path.exists(exe_path):
        print(f"Error: File '{exe_path}' not found.")
        return

    # 2. Parse PE
    print(f"Parsing {exe_path}...")
    try:
        pe = PEFile(exe_path)
    except Exception as e:
        print(f"Error parsing PE header: {e}")
        return

    # 3. Run Scanners
    rom_pointers = []
    
    # Scan 1: The Stack Loop
    stack_roms = scan_stack_pattern(pe)
    if stack_roms: rom_pointers.extend(stack_roms)

    # Scan 2: The Function Calls
    call_roms = scan_direct_calls(pe)
    if call_roms: rom_pointers.extend(call_roms)

    # Clean up duplicates
    rom_pointers = sorted(list(set(rom_pointers)))

    print(f"\n[!] Total Unique ROMs found: {len(rom_pointers)}")
    print("-" * 60)

    # 4. Extract
    success_count = 0
    for idx, va in enumerate(rom_pointers):
        print(f"Processing ROM #{idx+1} (VA: {hex(va)})...")
        
        offset = pe.va_to_offset(va)
        if offset is None:
            print(f"  -> Error: VA {hex(va)} not in file.")
            continue
            
        try:
            # Read Size
            rom_size = struct.unpack_from("<I", pe.data, offset)[0]
            print(f"  -> Uncompressed Size: {rom_size} bytes ({hex(rom_size)})")
            
            # Read Compressed Data (Size + 16KB Slack)
            compressed_data = pe.data[offset + 4 : offset + 4 + rom_size + 16384]
            
            # Decompress
            result = decompress_rom(compressed_data, rom_size)
            
            # Save
            filename = f"ROM_{hex(va)}_offset_{hex(offset)}.bin"
            with open(filename, "wb") as f:
                f.write(result)
            print(f"  -> Success! Saved to {filename}")
            success_count += 1
            
        except Exception as e:
            print(f"  -> Extraction Failed: {e}")
        print("-" * 60)

    print(f"\nDone. Extracted {success_count}/{len(rom_pointers)} files.")

if __name__ == "__main__":
    main()