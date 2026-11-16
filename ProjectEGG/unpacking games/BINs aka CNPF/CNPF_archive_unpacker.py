import struct
import os
from enum import IntEnum

# --- 1. Enums ---
class CPDFileCompressType(IntEnum):
    NONE = 0
    SLIDE = 1  # LZSS
    MAX = 2
    
class CPDFileType(IntEnum):
    MAINEXE = 0
    README = 1
    KYODAKU = 2
    DATA = 3              # manifest says 'data', usually uncompressed exe 
    MANUAL = 4
    SUBEXE = 5
    MATCHEXE = 6
    MP3 = 7
    CHILDEXE = 8
    LOCKBIN = 9
    SETUPEXE = 10
    STARTEXE = 11         # (0x0B) main game exe
    EMDSOUND = 12         # (0x0C) 'smd' / zip
    MSXROMIMG = 13        # (0x0D)
    SCENARIO_SCN = 14     # (0x0E) manifest says 'scn'
    COMPILESTATION = 15
    MAX = 16

# --- 2. LZSS Decompression Algorithm ---
def decompress_lzss(data):
    """
    Decompresses CNPF LZSS format.
    Handles the 4-byte 'Decompressed Size' header inside the payload.
    """
    if len(data) < 4:
        return b""

    # 1. Read the Decompressed Size
    # We strip these 4 bytes off the front so the loop starts at the Flag Byte
    # (The value is technically ignored by the algorithm but must be removed)
    _ = struct.unpack('<I', data[0:4])[0]
    
    # 2. Start Pointer after those 4 bytes
    src_ptr = 4
    
    output = bytearray()
    
    # Ring Buffer Settings
    buffer = bytearray(4096)
    buf_idx = 4078 # Starts at 0xFEE
    flags = 0

    while src_ptr < len(data):
        # Shift flags (consume 1 bit)
        flags >>= 1
        
        # Check if we need a new Flag Byte
        # (0x100 is the sentinel bit we set below)
        if (flags & 0x100) == 0:
            if src_ptr >= len(data): break
            c = data[src_ptr]
            src_ptr += 1
            
            # Set the high bit so we know when 8 shifts have happened
            flags = c | 0xFF00
        
        # Check LSB (Least Significant Bit)
        if (flags & 1) == 1:
            # --- LITERAL (1 Byte) ---
            if src_ptr >= len(data): break
            val = data[src_ptr]
            src_ptr += 1
            
            output.append(val)
            buffer[buf_idx] = val
            buf_idx = (buf_idx + 1) & 4095
        else:
            # --- REFERENCE (2 Bytes) ---
            if src_ptr + 1 >= len(data): break
            b1 = data[src_ptr]
            b2 = data[src_ptr + 1]
            src_ptr += 2
            
            # Offset: b1 | (upper nibble of b2 shifted)
            offset = b1 | ((b2 & 0xF0) << 4)
            # Length: (lower nibble of b2) + 3
            length = (b2 & 0x0F) + 3
            
            for _ in range(length):
                val = buffer[(offset + _) & 4095]
                output.append(val)
                buffer[buf_idx] = val
                buf_idx = (buf_idx + 1) & 4095

    return bytes(output)

# --- 3. Main Unpacker Class ---
class CNPFUnpacker:
    def __init__(self, filepath):
        self.filepath = filepath
        self.f = open(filepath, "rb")

    def unpack(self):
        # A. Read Container Header (20 bytes)
        # Sig(4), Ver(4), ArchSize(4), ManifEnd(4), FileCount(4)
        header = self.f.read(20)
        sig, ver, arch_size, manif_end, file_count = struct.unpack('<4s4sIII', header)
        
        if sig != b'CNPF':
            print("Invalid Magic Header")
            return

        # FIX: The variable was named 'ver' in struct.unpack, not 'ver_bytes'
        ver_str = ver.decode('ascii', errors='ignore')
        print(f"Container Version: {ver_str}")
        
        # Detect Modes based on Version
        is_vr06 = "VR06" in ver_str
        is_vr02 = "VR02" in ver_str
        
        entry_header_size = 9 if is_vr06 else 6

        # B. Read Manifest
        manif_len = manif_end - 20
        manif_bytes = self.f.read(manif_len)
        try:
            manif_str = manif_bytes.decode('shift_jis').strip('\x00')
        except:
            manif_str = manif_bytes.decode('utf-8', errors='ignore')

        items = [x for x in manif_str.split(',') if x] # Remove empty strings
        
        filenames = []
        if is_vr02:
            # VR02: Every item is a filename [File, File, File]
            filenames = items
        else:
            # VR05/07/B5: Pairs [File, Attr, File, Attr]
            filenames = [items[i] for i in range(0, len(items), 2)]
            
        print(f"Files found in manifest: {len(filenames)}")

        # C. Extract Files
        for i in range(file_count):
            if i >= len(filenames): break
            filename = filenames[i]
            
            # Read Header
            fh = self.f.read(entry_header_size)
            if len(fh) < entry_header_size: break

            if is_vr06:
                comp_byte, type_byte, _, _, _, payload_size = struct.unpack('<BBBBBI', fh)
            else:
                comp_byte, type_byte, payload_size = struct.unpack('<BBI', fh)
            
            try:
                ftype = CPDFileType(type_byte)
                ctype = CPDFileCompressType(comp_byte)
            except:
                ftype = type_byte
                ctype = comp_byte
                
            type_name = ftype.name if isinstance(ftype, CPDFileType) else f"Unknown_({type_byte})"
            comp_name = ctype.name if isinstance(ctype, CPDFileCompressType) else str(comp_byte)
            
            print(f"  > Type: {type_name} (0x{type_byte:02X}) | Compression: {comp_name} | Size: {payload_size}")
            
            # Read Payload
            payload = self.f.read(payload_size)
            
            # Decompress if needed
            if ctype == CPDFileCompressType.SLIDE:
                print("    > Decompressing...")
                payload = decompress_lzss(payload)

            # --- Output Handling ---
            # IMPROVEMENT: Handle subdirectories instead of flattening
            # Fix backslashes for non-Windows systems
            clean_path = filename.replace('\\', os.path.sep)
            
            # Create subdirectories if they exist in the manifest path
            dir_name = os.path.dirname(clean_path)
            if dir_name and not os.path.exists(dir_name):
                os.makedirs(dir_name)
            
            # Save file
            with open(clean_path, "wb") as out:
                out.write(payload)
                print(f"    > Saved: {clean_path}")

    def close(self):
        self.f.close()

# --- Usage ---
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        if os.path.exists(target_file):
            unpacker = CNPFUnpacker(target_file)
            unpacker.unpack()
            unpacker.close()
        else:
            print(f"File {target_file} not found. Please verify the path.")
    else:
        print("Provide a .bin file")