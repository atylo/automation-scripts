import struct
import sys
import os

# =========================================================================
#  PART 1: PE FILE PARSER
# =========================================================================

class PEFile:
    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, "rb") as f:
            self.data = f.read()
        
        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        self.image_base = struct.unpack_from("<I", self.data, e_lfanew + 0x34)[0]
        
        num_sections = struct.unpack_from("<H", self.data, e_lfanew + 6)[0]
        size_opt_header = struct.unpack_from("<H", self.data, e_lfanew + 20)[0]
        section_table_offset = e_lfanew + 24 + size_opt_header
        
        self.sections = []
        for i in range(num_sections):
            header_offset = section_table_offset + (i * 40)
            name, v_size, v_addr, r_size, r_ptr = struct.unpack_from("<8sIIII", self.data, header_offset)
            clean_name = name.decode().strip('\x00')
            self.sections.append({
                'name': clean_name,
                'v_addr': v_addr, 
                'r_ptr': r_ptr, 
                'r_size': r_size
            })

    def get_section_data(self, section_name):
        for s in self.sections:
            if s['name'] == section_name:
                start = s['r_ptr']
                end = start + s['r_size'] 
                return start, self.data[start:end]
        return None, None
    
    def offset_to_va(self, offset):
        for s in self.sections:
            if s['r_ptr'] <= offset < s['r_ptr'] + s['r_size']:
                return self.image_base + s['v_addr'] + (offset - s['r_ptr'])
        return 0

# =========================================================================
#  PART 2: HUFFMAN ENGINE
# =========================================================================

class SafeBitReader:
    def __init__(self, data):
        self.data = data
        self.ptr = 0
        self.bits_left = 0
        self.current_byte = 0
        self.failed = False

    def read_bit(self):
        if self.failed: raise IndexError()
        if self.bits_left == 0:
            if self.ptr >= len(self.data):
                self.failed = True
                raise IndexError()
            self.current_byte = self.data[self.ptr]
            self.ptr += 1
            self.bits_left = 8
        bit = (self.current_byte >> (self.bits_left - 1)) & 1
        self.bits_left -= 1
        return bit

    def read_byte(self):
        val = 0
        for _ in range(8):
            val = (val << 1) | self.read_bit()
        return val

class HuffmanValidator:
    def __init__(self, data):
        self.reader = SafeBitReader(data)
        self.node_count = 0
        self.left = {}
        self.right = {}
        self.next_id = 256

    def build_tree_safe(self, depth=0):
        if depth > 40: raise ValueError("Tree too deep") # Infinite loop protection
        self.node_count += 1
        if self.node_count > 600: raise ValueError("Too many nodes") # Tree size protection

        bit = self.reader.read_bit()
        if bit == 0:
            return self.reader.read_byte()
        
        node_id = self.next_id
        self.next_id += 1
        self.left[node_id] = self.build_tree_safe(depth + 1)
        self.right[node_id] = self.build_tree_safe(depth + 1)
        return node_id

# =========================================================================
#  PART 3: SCANNER
# =========================================================================

def scan_data_section(pe_file, max_size_kb=300):
    print("Extracting .data section...")
    base_offset, raw_data = pe_file.get_section_data(".data")
    
    if raw_data is None:
        print("Error: Could not find .data section.")
        return

    # Strict limit in bytes
    LIMIT_BYTES = max_size_kb * 1024 

    print(f"Scanning {len(raw_data)} bytes of .data...")
    print(f"Criteria: Header > 0 AND Header <= {max_size_kb} KB")
    print("-" * 60)

    found_count = 0
    
    # Iterate through .data with 4-byte alignment
    for i in range(0, len(raw_data) - 8, 4):
        
        # 1. READ HEADER (The supposed uncompressed size)
        candidate_size = struct.unpack_from("<I", raw_data, i)[0]
        
        # [FILTER 1] Strict Header Check
        if candidate_size <= 0 or candidate_size > LIMIT_BYTES:
            continue
            
        # 2. VALIDATE STREAM
        stream_data = raw_data[i+4 : i+4 + 2048] # Grab 2KB for validation
        
        # Optimization: Skip if starts with empty padding
        if stream_data[:16] == b'\x00' * 16: continue

        try:
            validator = HuffmanValidator(stream_data)
            
            # Step A: Build Tree
            root = validator.build_tree_safe()
            
            # Step B: Dry Run (Decompress up to 16 bytes to check validity)
            test_len = min(candidate_size, 16)
            for _ in range(test_len):
                node = root
                safety = 0
                while node >= 0x100:
                    safety += 1
                    if safety > 40: raise ValueError("Loop stuck")
                    if validator.reader.read_bit() == 0: node = validator.left[node]
                    else: node = validator.right[node]
            
            # If we get here, it looks like valid compressed data
            file_offset = base_offset + i
            va = pe_file.offset_to_va(file_offset)
            
            print(f"[+] Candidate at Offset {hex(file_offset)} (VA: {hex(va)}) | Size: {candidate_size} bytes")
            
            # 3. FULL EXTRACTION WITH LIMIT CHECK
            # Grab full data + slack from the main file
            full_blob = pe_file.data[file_offset + 4 : file_offset + 4 + candidate_size + 8192]
            
            try:
                full_val = HuffmanValidator(full_blob)
                full_root = full_val.build_tree_safe()
                
                out_buffer = bytearray()
                
                # Decompress until done OR limit hit
                while len(out_buffer) < candidate_size:
                    
                    # [FILTER 2] Output Size Guard
                    if len(out_buffer) > LIMIT_BYTES:
                        raise ValueError(f"Output exceeded {max_size_kb}KB limit. Garbage data.")
                        
                    node = full_root
                    while node >= 0x100:
                        if full_val.reader.read_bit() == 0: node = full_val.left[node]
                        else: node = full_val.right[node]
                    out_buffer.append(node)
                
                # Final Save
                output_filename = f"Extracted_{hex(va)}.bin"
                with open(output_filename, "wb") as f:
                    f.write(out_buffer)
                print(f"    -> Saved {output_filename}")
                found_count += 1
                
            except Exception as e:
                print(f"    -> Extraction aborted: {e}")
            
        except (ValueError, IndexError):
            continue

    print("-" * 60)
    print(f"Scan complete. Extracted {found_count} valid files.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <emulator.exe>")
    else:
        # Check if file exists
        if not os.path.exists(sys.argv[1]):
            print(f"Error: {sys.argv[1]} not found.")
        else:
            pe = PEFile(sys.argv[1])
            scan_data_section(pe)