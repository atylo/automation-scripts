import struct
import os
import re
import sys

def sanitize_filename(filename):
    """Removes characters that are illegal in Windows/Linux filenames."""
    return re.sub(r'[\\/*?:"<>|]', "_", filename)

def is_legacy_wlk(f):
    """Structurally validates the legacy 14-byte format."""
    f.seek(0)
    try:
        # File needs to be at least big enough for header + 2 entries
        f.seek(0, 2)
        file_size = f.tell()
        if file_size < 32: 
            return False
            
        f.seek(0)
        num_entries, _ = struct.unpack('<HH', f.read(4))
        
        # Check 1: Reasonable number of entries
        if num_entries == 0 or num_entries > 1000:
            return False
            
        # Check 2: Contiguous Math & Audio Rates
        if num_entries >= 2:
            off1, sz1, rate1, _ = struct.unpack('<IIIH', f.read(14))
            off2, sz2, rate2, _ = struct.unpack('<IIIH', f.read(14))
            
            # Are the files packed back-to-back?
            if off1 + sz1 != off2:
                return False
                
            # Are the sample rates standard audio frequencies?
            valid_rates = [8000, 11025, 22050, 32000, 44100, 48000]
            if rate1 not in valid_rates or rate2 not in valid_rates:
                return False
                
            return True
        else:
            # Fallback check if the archive only has 1 file
            off1, sz1, rate1, _ = struct.unpack('<IIIH', f.read(14))
            valid_rates = [8000, 11025, 22050, 32000, 44100, 48000]
            return (off1 + sz1 <= file_size) and (rate1 in valid_rates)
            
    except struct.error:
        return False
    finally:
        f.seek(0) # Always reset pointer when done

def extract_v1(f, file_path):
    """Extracts the older, headerless WLK format."""
    num_entries, _ = struct.unpack('<HH', f.read(4))
    print(f"[*] Extracting Legacy (V1) Archive with {num_entries} files...")
    
    directory = []
    for i in range(num_entries):
        raw = f.read(14)
        offset, size, srate, flags = struct.unpack('<IIIH', raw)
        
        name = f"sample_{i:03d}.wav"
        directory.append({'name': name, 'off': offset, 'sz': size, 'rate': srate})
        
    save_files(f, file_path, directory)

def extract_v2(f, file_path):
    """Extracts the newer WLKF0200 format with metadata strings."""
    num_entries, flags = struct.unpack('<HH', f.read(4))
    print(f"[*] Extracting WLKF0200 (V2) Archive with {num_entries} files...")
    
    entry_size = 22
    has_metadata = False
    if (flags & 1): 
        entry_size = 28
        has_metadata = True
    if (flags & 2): 
        entry_size += 6

    directory = []
    for i in range(num_entries):
        raw = f.read(entry_size)
        _, _, offset, size, srate = struct.unpack('<BBIII', raw[:14])
        
        name = f"sample_{i:03d}.wav"
        
        if has_metadata:
            str_ptr, str_len = struct.unpack('<IH', raw[22:28])
            if str_ptr > 0 and str_len > 0:
                current_pos = f.tell()
                f.seek(str_ptr)
                try:
                    raw_bytes = f.read(str_len).split(b'\x00')[0]
                    decoded_name = raw_bytes.decode('cp932').strip()
                    if ".wav" in decoded_name.lower():
                        decoded_name = decoded_name.lower().split(".wav")[0] + ".wav"
                    name = sanitize_filename(decoded_name)
                except:
                    pass
                f.seek(current_pos)

        directory.append({'name': name, 'off': offset, 'sz': size, 'rate': srate})
        
    save_files(f, file_path, directory)

def save_files(f, file_path, directory):
    """Generates WAV headers and dumps the PCM audio data to disk."""
    out_dir = os.path.splitext(file_path)[0]
    if not os.path.exists(out_dir): 
        os.makedirs(out_dir)

    for entry in directory:
        f.seek(entry['off'])
        data = f.read(entry['sz'])
        
        with open(os.path.join(out_dir, entry['name']), 'wb') as out_f:
            header = struct.pack('<4sI4s4sIHHIIHH4sI',
                b'RIFF', 36 + entry['sz'], b'WAVE', b'fmt ', 16, 1, 1, 
                entry['rate'], entry['rate'] * 2, 2, 16, b'data', entry['sz'])
            out_f.write(header)
            out_f.write(data)
        print(f"  [+] Saved: {entry['name']} ({entry['rate']}Hz)")

def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_wlk.py <archive_name>")
        sys.exit(1)

    file_path = sys.argv[1]
    
    if not os.path.exists(file_path):
        print(f"[-] Error: File '{file_path}' not found.")
        sys.exit(1)

    with open(file_path, 'rb') as f:
        # Check for WLKF0200 Magic String first
        magic = f.read(8)
        if magic == b'WLKF0200':
            print(f"[*] Detected WLKF0200 Archive: {os.path.basename(file_path)}")
            extract_v2(f, file_path)
            
        # If not WLKF0200, do a strict structural check for legacy
        elif is_legacy_wlk(f):
            print(f"[*] Detected WLKF Legacy Archive: {os.path.basename(file_path)}")
            
            extract_v1(f, file_path)
            
        # Fails both checks
        else:
            print(f"[-] Error: '{os.path.basename(file_path)}' is an unknown archive type.")

if __name__ == "__main__":
    main()