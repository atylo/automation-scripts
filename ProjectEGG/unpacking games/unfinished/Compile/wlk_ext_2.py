import struct
import os
import re
import sys

def sanitize_filename(filename):
    """Removes characters that are illegal in Windows/Linux filenames."""
    return re.sub(r'[\\/*?:"<>|]', "_", filename)

def is_legacy_wlk(f):
    """Structurally validates the legacy 14-byte format directly from C logic."""
    f.seek(0)
    try:
        f.seek(0, 2)
        file_size = f.tell()
        if file_size < 16:
            return False

        f.seek(0)
        # Read count and increment by 1 as required by C logic
        (raw_count,) = struct.unpack("<H", f.read(2))
        num_entries = raw_count + 1
        
        # Check 1: Reasonable number of entries
        if num_entries == 0 or num_entries > 1000:
            return False

        valid_rates = [8000, 11025, 22050, 32000, 44100, 48000]

        if num_entries >= 2:
            # Check 2: Contiguous Math & Audio Rates
            # Entry structure is <BBIII (14 bytes)
            b0, fl, off1, sz1, rate1 = struct.unpack("<BBIII", f.read(14))
            b0, fl, off2, sz2, rate2 = struct.unpack("<BBIII", f.read(14))

            # Contiguous offsets check
            if off1 + sz1 != off2:
                return False
            
            # Are the sample rates standard audio frequencies?
            if rate1 not in valid_rates or rate2 not in valid_rates:
                return False

            return True
        else:
            # Fallback check if the archive has only 1 file
            b0, fl, off1, sz1, rate1 = struct.unpack("<BBIII", f.read(14))
            return (off1 + sz1 <= file_size) and (rate1 in valid_rates)

    except struct.error:
        return False
    finally:
        f.seek(0) # Always reset pointer when done

def extract_v1(f, file_path):
    """Extracts the legacy headerless WLK format aka 0x0110"""
    f.seek(0)
    # Read count and increment by 1 as required by C logic
    (raw_count,) = struct.unpack("<H", f.read(2))
    num_entries = raw_count + 1
    print(f"[*] Extracting Legacy (V1) Archive with {num_entries} files...")

    directory = []
    for i in range(num_entries):
        raw = f.read(14)
        # <BBIII: 1-byte unknown, 1-byte wav flags, 4-byte offset, 4-byte size, 4-byte rate
        b0, entry_flags, offset, size, srate = struct.unpack("<BBIII", raw)
        
        channels = 2 if (entry_flags & 0x40) else 1
        name = f"sample_{i:03d}.wav"
        directory.append({"name": name, "off": offset, "sz": size, "rate": srate, "channels": channels})

    save_files(f, file_path, directory)

def extract_v2(f, file_path):
    """Extracts the newer WLKF0200 format with metadata strings."""
    num_entries, flags = struct.unpack('<HH', f.read(4))
    print(f"[*] Extracting WLKF0200 (V2) Archive with {num_entries} files...")
    debug = 0
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
        b0, entry_flags, offset, size, srate, unk_a, unk_b = struct.unpack('<BBIIIII', raw[:22])
        # b0 is sound Preemption Priority, 00 - FF?
        # unk_a and unk_b are probably 
        # Runtime Buffer / Wave Format Pointer / Pan / Volume and DirectSound Buffer Handle / Playback Status
        
        
        # TODO: implement bit reading
        # Bit 0 (0x01): Channel Allocation behavior (1 = Force new buffer instance, 0 = Rewind/reuse active instance if playing).
        # Bit 5 (0x20): Looping Flag (1 = Pass DSBPLAY_LOOPING to IDirectSoundBuffer::Play, 0 = One-shot).
        # Bit 6 (0x40): Channel Count (1 = Stereo / 2 Channels, 0 = Mono / 1 Channel).
        # Bit 7 (0x80): Bit Depth (1 = 16-bit PCM, 0 = 8-bit PCM).
        
        channels = 2 if (entry_flags & 0x40) else 1
        # bit_depth = entry_flags & 0x80
        # looping_flag = entry_flags & 0x20
        # alloc_status = entry_flags & 0x01
        
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

        directory.append({'name': name, 'off': offset, 'sz': size, 'rate': srate, "channels": channels})
        
        if (flags & 2) and debug:
            # Original full directory file path, not used by extraction
            # Slice the last 6 bytes of the 34-byte entry
            str2_ptr, str2_len = struct.unpack('<IH', raw[28:34])
            if str2_ptr > 0 and str2_len > 0:
                current_pos = f.tell()
                f.seek(str2_ptr)
                try:
                    raw_bytes2 = f.read(str2_len).split(b'\x00')[0]
                    decoded_metadata = raw_bytes2.decode('cp932').strip()
                    print(f"    -> Extra Metadata: {decoded_metadata}")
                except Exception:
                    pass
                f.seek(current_pos)
        
    save_files(f, file_path, directory)

def save_files(f, file_path, directory):
    """Generates WAV headers and dumps the PCM audio data to disk."""
    out_dir = os.path.splitext(file_path)[0]
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    for entry in directory:
        f.seek(entry["off"])
        data = f.read(entry["sz"])

        channels = entry.get("channels", 1)
        rate = entry["rate"]
        bits_per_sample = 16
        block_align = channels * (bits_per_sample // 8)
        byte_rate = rate * block_align

        with open(os.path.join(out_dir, entry["name"]), "wb") as out_f:
            header = struct.pack(
                "<4sI4s4sIHHIIHH4sI",
                b"RIFF",
                36 + entry["sz"],
                b"WAVE",
                b"fmt ",
                16,
                1,  # PCM Format
                channels,  # 1 for Mono, 2 for Stereo
                rate,
                byte_rate,
                block_align,
                bits_per_sample,
                b"data",
                entry["sz"],
            )
            out_f.write(header)
            out_f.write(data)
        print(f"  [+] Saved: {entry['name']} ({entry['rate']}Hz)")

def main():
    if len(sys.argv) < 2:
        print("Compile WLK archive extractor")
        print("Usage: python wlk_ext_2.py <archive_name>")
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