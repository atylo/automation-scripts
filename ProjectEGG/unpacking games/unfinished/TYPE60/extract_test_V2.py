import struct
import os
import sys
import pefile
import mmap

# -----------------------------------------------------------------------------
# 1. Custom CRC-32 (Forward/Normal Poly 0x04C11DB7)
# -----------------------------------------------------------------------------
def generate_crc_table():
    poly = 0x04C11DB7
    table = []
    for i in range(256):
        crc = i << 24
        for _ in range(8):
            if (crc & 0x80000000):
                crc = (crc << 1) ^ poly
            else:
                crc = crc << 1
        table.append(crc & 0xFFFFFFFF)
    return table

CRC_TABLE = generate_crc_table()

def alicesoft_crc32(data):
    """
    Matches sub_41C960: Forward CRC-32, Init 0xFFFFFFFF, Final NOT
    """
    crc = 0xFFFFFFFF
    for byte in data:
        # Index = Current Byte XOR Top Byte of CRC
        index = (byte ^ (crc >> 24)) & 0xFF
        # Update = (CRC shifted left) XOR Table Value
        crc = (CRC_TABLE[index] ^ (crc << 8)) & 0xFFFFFFFF
    return ~crc & 0xFFFFFFFF

# -----------------------------------------------------------------------------
# 2. Decryption (Verified)
# -----------------------------------------------------------------------------
def decrypt_aw4(encrypted_data):
    if len(encrypted_data) < 13: return None, None
    header = encrypted_data[:13]
    version, uncompressed_size, expected_crc, seed_byte = struct.unpack('<IIIB', header)
    
    payload = bytearray(encrypted_data[13:])
    
    state = seed_byte & 0xffffffff
    LCG_M = 0xae529
    LCG_A = 0x1000
    LCG_C = 0x24d69
    
    for i in range(len(payload)):
        state = (state * LCG_A + LCG_C) % LCG_M
        xor_key = (state * 0x100) // LCG_M
        payload[i] ^= (xor_key & 0xFF)

    return payload, (version, uncompressed_size, expected_crc)

# -----------------------------------------------------------------------------
# 3. Decompression (Arithmetic Decoder)
# -----------------------------------------------------------------------------
class ArithmeticDecoder:
    def __init__(self, bitstream):
        self.stream = bitstream
        self.ptr = 0
        self.total_len = len(bitstream)
        self.code = 0
        self.low = 0
        self.range = 0xFFFFFFFF
        
        self.num_symbols = 257
        self.freq = [1] * self.num_symbols
        self.cum_freq = [i for i in range(self.num_symbols + 1)]
        
        for _ in range(4):
            self.code = (self.code << 8) | self._read_byte()

    def _read_byte(self):
        if self.ptr < self.total_len:
            b = self.stream[self.ptr]
            self.ptr += 1
            return b
        return 0

    def update_model(self, symbol):
        # Increment frequency
        self.freq[symbol] += 1
        
        # Update cumulative frequencies
        for i in range(symbol + 1, self.num_symbols + 1):
            self.cum_freq[i] += 1
            
        # Rescale if total freq hits limit (sub_41CA40 logic)
        if self.cum_freq[self.num_symbols] >= 0x10000:
            self.cum_freq[0] = 0
            current_cum = 0
            for i in range(self.num_symbols):
                # Specific AliceSoft Rescale Formula: (freq | 2) >> 1
                new_freq = (self.freq[i] | 2) >> 1
                self.freq[i] = new_freq
                current_cum += new_freq
                self.cum_freq[i+1] = current_cum

    def decompress(self):
        output = bytearray()
        while True:
            total_freq = self.cum_freq[self.num_symbols]
            if total_freq == 0: break 
            
            step = self.range // total_freq
            value = (self.code - self.low) // step
            
            # Find Symbol
            symbol = 0
            # Optimization: Binary search or just loop. 257 items is small enough.
            for i in range(self.num_symbols):
                if self.cum_freq[i] <= value < self.cum_freq[i+1]:
                    symbol = i
                    break
            
            if symbol == 256: break # EOF
            output.append(symbol)
            
            self.range = step * self.freq[symbol]
            self.low += step * self.cum_freq[symbol]
            self.update_model(symbol)
            
            # Renormalization
            while ((self.low ^ (self.low + self.range)) & 0xFF000000) == 0:
                self.code = ((self.code << 8) | self._read_byte()) & 0xFFFFFFFF
                self.range = (self.range << 8) & 0xFFFFFFFF
                self.low = (self.low << 8) & 0xFFFFFFFF
                
            while self.range < 0x10000:
                self.range = ((-self.low) & 0xFFFF) << 8
                self.code = ((self.code << 8) | self._read_byte()) & 0xFFFFFFFF
                self.low = (self.low << 8) & 0xFFFFFFFF

        return output

# -----------------------------------------------------------------------------
# 4. Main Processing
# -----------------------------------------------------------------------------
def process_file(data, name_hint):
    decrypted, header = decrypt_aw4(data)
    if not decrypted: return

    version, tgt_size, expected_crc = header
    
    print(f"    -> Decompressing {name_hint}...")
    try:
        decoder = ArithmeticDecoder(decrypted)
        final_data = decoder.decompress()
    except Exception as e:
        print(f"    [!] Decompression Error: {e}")
        final_data = decrypted

    # Verify using Custom CRC
    calc_crc = alicesoft_crc32(final_data)
    
    if calc_crc == expected_crc:
        print(f"[+] SUCCESS: {name_hint}")
        print(f"    CRC Matched: {hex(calc_crc)}")
        
        # Extension guessing
        ext = ".bin"
        if b"N60" in final_data[:200]: ext = ".rom"
        elif b"PC-6001" in final_data[:200]: ext = ".rom"
        
        out_name = f"{name_hint}{ext}"
        with open(out_name, "wb") as f:
            f.write(final_data)
        print(f"    Saved: {out_name}\n")
    else:
        print(f"[-] CRC Mismatch for {name_hint}")
        print(f"    Expected: {hex(expected_crc)}")
        print(f"    Calculated: {hex(calc_crc)}")
        with open(f"{name_hint}_FAIL.bin", "wb") as f:
            f.write(final_data)
        print("")


def extract_resources(pe, exe_name):
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        print("[!] No resources found.")
        return

    print("[*] Scanning resources...")

    for r_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_name = str(r_type.name) if r_type.name else str(r_type.id)

        # Only care about BIN-like resources
        if "BIN" not in type_name.upper() and type_name != "10":
            continue

        for r_id in r_type.directory.entries:
            id_name = str(r_id.name) if r_id.name else str(r_id.id)

            for r_lang in r_id.directory.entries:
                data_rva = r_lang.data.struct.OffsetToData
                size = r_lang.data.struct.Size

                data = pe.get_data(data_rva, size)

                if len(data) < 13:
                    continue

                name_hint = f"{id_name}"
                print(f"[+] Found resource: {name_hint} (Size: {size})")

                process_file(data, name_hint)

def find_all_pe_headers(f):
    pe_list = []
    offset = 0
    print(f"[*] Scanning for PE executables...")
    while True:
        mz_offset = f.find(b'MZ', offset)
        if mz_offset == -1: break
        if mz_offset + 0x3C + 4 > len(f):
            offset = mz_offset + 1; continue
        e_lfanew = struct.unpack("<I", f[mz_offset+0x3C : mz_offset+0x40])[0]
        pe_header_offset = mz_offset + e_lfanew
        if pe_header_offset + 0x38 > len(f):
            offset = mz_offset + 1; continue
        if f[pe_header_offset : pe_header_offset+4] == b'PE\0\0':
            try:
                image_base = struct.unpack("<I", f[pe_header_offset+0x34 : pe_header_offset+0x38])[0]
                #print(f"    [+] Found PE at Offset 0x{mz_offset:X} (ImageBase: 0x{image_base:X})")
                pe_list.append({'offset': mz_offset, 'image_base': image_base})
            except: pass
        offset = mz_offset + 1
    return pe_list
 
def main():
    if len(sys.argv) != 2:
        print("Usage: python bin_pc6_extractor.py <file.exe>")
        return

    exe_path = sys.argv[1]

    if not os.path.exists(exe_path):
        print(f"[!] File not found: {exe_path}")
        return
    
    with open(exe_path, "rb") as f:
        file_data = f.read()

    offset_list = find_all_pe_headers(file_data)

    if not offset_list:
        print("[!] No PE found.")
        return

    for idx, pe_info in enumerate(offset_list):
        if idx == 0:
            continue
        offset = pe_info['offset']
        print(f"[+] PE #{idx} found at 0x{offset:X}")
        embedded_pe = pefile.PE(data=file_data[offset:])
        print("[+] Embedded PE parsed successfully.")
        exe_base_name = os.path.splitext(os.path.basename(exe_path))[0]
        extract_resources(embedded_pe, f"{exe_base_name}_pe{idx}")

if __name__ == "__main__":
    main()