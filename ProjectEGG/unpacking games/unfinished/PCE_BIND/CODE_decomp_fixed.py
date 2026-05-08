import struct
import os

# --- BITWISE HELPERS ---
def mask32(val): 
    return val & 0xFFFFFFFF

def rol32(val, n): 
    return mask32((val << (n % 32)) | (val >> (32 - (n % 32))))

def ror32(val, n): 
    return mask32((val >> (n % 32)) | (val << (32 - (n % 32))))

# --- XOR PRNG ---
class ArchivePRNG:
    def __init__(self, seed):
        self.state = mask32(seed)
        
    def get_byte(self):
        self.state = mask32(self.state * 0x81 + 1)
        return (self.state ^ (self.state >> 8)) & 0xFF

class CodeArchive:
    def __init__(self, file_path):
        self.file_path = file_path
        with open(file_path, "rb") as f:
            self.raw = f.read()

    def decompress_lzss_xor(self, data, xor_seed):
        prng = ArchivePRNG(xor_seed)
        src = 0
        dst = bytearray()
        
        while src < len(data):
            ctrl = data[src]
            src += 1
            mode = ctrl >> 6
            count = ctrl & 0x3F

            if mode == 0:  # Case 0: XOR Literals
                for _ in range(count + 1):
                    if src < len(data):
                        dst.append(data[src] ^ prng.get_byte())
                        src += 1
            
            elif mode == 1: # Case 1: XOR Fill (RLE)
                length = count + 2
                if src < len(data):
                    val = data[src] ^ prng.get_byte()
                    src += 1
                    dst.extend([val] * length)

            elif mode == 2: # Case 2: LZ Copy
                length = count + 3
                if src + 1 < len(data):
                    high = data[src]
                    low = data[src+1]
                    src += 2
                    
                    rel_offset = (high << 8) | low
                    back_ptr = len(dst) - length - rel_offset
                    
                    for _ in range(length):
                        if 0 <= back_ptr < len(dst):
                            dst.append(dst[back_ptr])
                            back_ptr += 1
                        else:
                            dst.append(0)
            
            elif mode == 3: # Case 3: End
                break
                
        return dst

    def unpack(self, output_file="ASSEMBLED_CODE.BIN"):
        # 1. Read Encrypted Table Count and Global Seed
        enc_count, enc_seed = struct.unpack('<II', self.raw[0x14:0x1C])
        
        file_count = mask32(ror32(enc_count, 15) + 0x19E5C86F)
        global_seed = mask32(ror32(enc_seed, 21) + 0x56E08CE3)
        
        print(f"[*] Detected CODE Archive")
        print(f"[*] Total Chunks to assemble: {file_count}")
        print(f"[*] Global Seed: 0x{global_seed:08X}")
        print("-" * 40)

        # 2. Extract File Table Array
        table_offset = 0x20
        table_size = file_count * 4
        table_data = self.raw[table_offset : table_offset + table_size]
        file_table = struct.unpack(f'<{file_count}I', table_data)

        # 3. Process Data Block
        data_start = table_offset + table_size
        
        # Buffer to hold all concatenated decompressed data
        full_archive_data = bytearray()

        for i in range(file_count):
            # Start Offset Calculation
            if i == 0:
                start_off = 0
            else:
                prev_val = file_table[i - 1]
                rot_start = (i + 12) % 32
                start_off = mask32(rol32(prev_val, rot_start) + 0x24CD8FAA + i)

            # End Offset / Size Calculation
            curr_val = file_table[i]
            rot_end = (i + 13) % 32
            raw_end = rol32(curr_val, rot_end)
            
            # Size formula mapped directly from iVar6
            size = mask32((raw_end - start_off) + 0x24CD8FAB + i)

            absolute_offset = data_start + start_off
            compressed_data = self.raw[absolute_offset : absolute_offset + size]

            if size > 0:
                # Decompress
                decompressed = self.decompress_lzss_xor(compressed_data, global_seed)
                # Concatenate immediately
                full_archive_data.extend(decompressed)
                print(f"[+] Appended chunk {i:04d} | Comp Size: {size} -> Clean Size: {len(decompressed)}")
            else:
                print(f"[-] Skipped empty chunk {i:04d}")

        # 4. Save the monolithic file
        with open(output_file, "wb") as f_out:
            f_out.write(full_archive_data)
            
        print("-" * 40)
        print(f"[*] Success! Saved monolithic archive to: {output_file}")
        print(f"[*] Total Assembled Size: {len(full_archive_data)} bytes")

if __name__ == "__main__":
    archive = CodeArchive("data002.rec") # Point to your .rec file
    archive.unpack(output_file="GAME_CODE.BIN")