import struct
import os
# BIND 42 49 4E 44 01 01 00 80 0x444E4942 \x42\x49\x4E\x44\x01\x01\x00\x80

# --- CONFIGURATION ---
DEBUG_MODE = True  # True for full details | False for progress only
# ---------------------

def mask32(val): return val & 0xFFFFFFFF
def ror(val, n): return mask32((mask32(val) >> n) | (mask32(val) << (32 - n)))
def rol(val, n): return mask32((mask32(val) << n) | (mask32(val) >> (32 - n)))

class BindArchive:
    def __init__(self, file_path, debug=False):
        self.file_path = file_path
        self.debug = debug
        with open(file_path, "rb") as f:
            self.raw = f.read()
        self.session_key = 0
        self.header = {}

    def get_factor(self, a2):
        return ror(self.session_key, (a2 + 17) % 32)

    def derive_header(self):
        # 1. Project ID & Session Key
        project_id = "".join([chr(((self.raw[8+i] + 119) ^ (51 * i)) & 0xFF) for i in range(8)])
        v2, v3 = 0, 0
        for char in project_id:
            val = ord(char)
            v2 = mask32(val + 16 * v2)
            v3 += val
        self.session_key = ror(mask32(v2 - 2083412177), (v3 + 61) % 32)

        # 2. Decrypt the 6 Table Integers
        raw = struct.unpack('<6I', self.raw[16:40])
        self.header = {
            'table_off': mask32(mask32(rol(raw[0], 7)  - self.get_factor(11)) + 0x4CBD70AA),
            'table_sz':  mask32(mask32(rol(raw[1], 15) - self.get_factor(13)) + 0x68CC8AEE),
            'meta_off':  mask32(mask32(rol(raw[2], 9)  - self.get_factor(15)) - 0x7F61DB27),
            'meta_sz':   mask32(mask32(rol(raw[3], 19) - self.get_factor(17)) + 0x12BDD8CF),
            'data_off':  mask32(mask32(rol(raw[4], 27) - self.get_factor(19)) + 0x56E54C39),
        }

        # Restoration of the block you liked!
        if self.debug:
            print(f"{'='*60}")
            print(f"DEBUG: HEADER INFO")
            print(f"{'='*60}")
            print(f"Project ID:      {project_id}")
            print(f"Session Key:     0x{self.session_key:08X}")
            print(f"Table Offset:    {self.header['table_off']} (0x{self.header['table_off']:X})")
            print(f"Table Size:      {self.header['table_sz']} bytes (0x{self.header['table_sz']:X})")
            print(f"Metadata Offset: {self.header['meta_off']} (0x{self.header['meta_off']:X})")
            print(f"Data Offset:     {self.header['data_off']} (0x{self.header['data_off']:X})")
            print(f"{'='*60}\n")
        else:
            print(f"[*] Project ID: {project_id} | Session Key: 0x{self.session_key:08X}")

    def decrypt_metadata(self, raw_bytes):
        dec_bytes = bytearray()
        for i, b in enumerate(raw_bytes):
            rot_amt = (i + 3) % 8
            rotated = ((b << rot_amt) | (b >> (8 - rot_amt))) & 0xFF
            subkey = ror(self.session_key, (i + 34) % 32)
            res = (rotated - (subkey & 0xFF)) & 0xFF
            dec_bytes.append(res)
        
        name = "".join(chr(b) for b in dec_bytes if b != 0)
        return dec_bytes, name

    def descramble_data(self, data, file_size):
        decrypted = bytearray()
        param_2 = file_size 
        iVar5 = param_2 + 0x61
        for b in data:
            subkey = self.get_factor(iVar5 - 0x4a) & 0xFF
            b_sub = (b - subkey) & 0xFF
            shift = iVar5 % 8
            rotated = ((b_sub << shift) | (b_sub >> (8 - shift))) & 0xFF
            res = (rotated + param_2 - 0x23) & 0xFF
            decrypted.append(res)
            param_2 -= 1
            iVar5 -= 1
        return decrypted

    def unpack(self, output_dir="extracted"):
        if not os.path.exists(output_dir): os.makedirs(output_dir)
        num_files = self.header['table_sz'] // 16
        
        for i in range(num_files):
            # 1. File Table Entry
            t_pos = self.header['table_off'] + (i * 16)
            raw_t = self.raw[t_pos : t_pos + 16]
            d = struct.unpack('<4I', raw_t)
            idx = i * 4
            
            m_ptr = (rol(d[0], (idx + 73) % 32) + idx - self.get_factor(idx) + 0x660BCDDB) & 0xFFFFFFFF
            f_off = (rol(d[1], (idx + 1 + 85) % 32) + (idx + 1) - self.get_factor(idx + 1) + 0x48219C77) & 0xFFFFFFFF
            f_sz  = (rol(d[2], (idx + 2 + 19) % 32) + (idx + 2) - self.get_factor(idx + 2) + 0x357712D9) & 0xFFFFFFFF
            
            # 2. Metadata Entry
            m_pos = self.header['meta_off'] + m_ptr
            raw_m = self.raw[m_pos : m_pos + 12]
            dec_m, fname = self.decrypt_metadata(raw_m)
            
            # 3. Data Extraction
            d_pos = self.header['data_off'] + f_off
            raw_data = self.raw[d_pos : d_pos + f_sz]
            clean_data = self.descramble_data(raw_data, f_sz)
            peek = clean_data[:4].hex().upper()

            # --- OUTPUT ---
            if self.debug:
                print(f"FILE {i:03}: {fname}")
                print(f"  [FileTable Entry @ {t_pos} (0x{t_pos:X})]")
                print(f"    Raw Hex: {raw_t.hex(' ').upper()}")
                print(f"    Dec Hex: {m_ptr:08X} {f_off:08X} {f_sz:08X} {d[3]:08X}")
                print(f"  [Metadata Entry @ {m_pos} (0x{m_pos:X})]")
                print(f"    Raw Hex: {raw_m.hex(' ').upper()}")
                print(f"    Dec Hex: {dec_m.hex(' ').upper()}")
                print(f"  [Data Block]")
                print(f"    Absolute Offset: {d_pos} (0x{d_pos:X})")
                print(f"    File Size:       {f_sz} bytes (0x{f_sz:X})")
                print(f"    Header Peek:     0x{peek}")
                print("-" * 60)
            else:
                print(f"[+] Saved: {fname:<20} | Peek: 0x{peek} | Size: {f_sz} (0x{f_sz:X})")

            # Save
            safe_name = "".join(c for c in fname if c.isalnum() or c in "._- ")
            with open(os.path.join(output_dir, safe_name), "wb") as f:
                f.write(clean_data)

# Run
archive = BindArchive("encs0001.etc", debug=DEBUG_MODE)
archive.derive_header()
archive.unpack()
