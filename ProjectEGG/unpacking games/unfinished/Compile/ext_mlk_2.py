import struct
from struct import unpack
from sys import argv
import os
import re


def sanitize_filename(name):
    return re.sub(r'[<>:"/\\|?*]', "_", name)


def detect_filetype(data):
    if data.startswith(b"MThd"):
        return "mid"
    elif data.startswith(b"ID3") or data[:2] == b"\xFF\xFB":
        return "mp3"
    return "bin"


def decode_text(data):
    # Try common encodings in order of likelihood
    for enc in ("cp932", "shift_jis", "utf-8", "latin1"):
        try:
            text = data.decode(enc).strip()
            if text:
                return text
        except:
            continue
    return None


def is_reasonable_name(s):
    if not s:
        return False
    # Reject mostly non-printable garbage
    printable = sum(c.isprintable() for c in s)
    return printable / len(s) > 0.7


def extract_midi_name(data):
    try:
        if not data.startswith(b"MThd"):
            return None

        i = data.find(b"MTrk")
        if i == -1:
            return None

        i += 8  # skip MTrk + length

        while i < len(data) - 3:
            if data[i] == 0xFF:
                meta_type = data[i + 1]
                length = data[i + 2]

                if meta_type == 0x03:  # Track name
                    raw = data[i + 3:i + 3 + length]
                    text = decode_text(raw)

                    if text and is_reasonable_name(text):
                        return sanitize_filename(text)

                i += 3 + length
            else:
                i += 1

    except:
        return None

    return None


def decompress_cnx(data):
    """
    Decompresses Atlus CNX v2 using the exact logic from sub_414F30.
    """
    if len(data) < 16 or data[:4] != b"CNX\x02":
        return data, "bin"

    # Header Parsing (Big Endian)
    ext_raw = data[4:7]
    try:
        extension = ext_raw.decode("ascii", errors="ignore")
        extension = "".join(c for c in extension if c.isalnum()).lower()
        if not extension: extension = "bmp"
    except:
        extension = "bmp"

    # Decompressed size is Big Endian at offset 12
    decomp_size = struct.unpack(">I", data[12:16])[0]
    
    input_ptr = 16
    output = bytearray()
    
    # Mirroring the while ( dword_836CCC < dword_836CD0 ) loop from sub_414E80
    while len(output) < decomp_size and input_ptr < len(data):
        control = data[input_ptr]
        input_ptr += 1
        
        # If control byte is 0, the sub_414F30 function returns 2 (End of Block)
        if control == 0:
            break

        # Process 4 tokens (2 bits each) per control byte
        for _ in range(4):
            if len(output) >= decomp_size:
                break
                
            op = control & 0x03
            control >>= 2
            
            if op == 0: # Case 0: Skip/Metadata block
                if input_ptr < len(data):
                    skip_len = data[input_ptr]
                    input_ptr += (skip_len + 1)
                # sub_414F30 returns 1 here, triggering a new control byte read
                break 
                
            elif op == 1: # Case 1: Single Literal
                if input_ptr < len(data):
                    output.append(data[input_ptr])
                    input_ptr += 1
                    
            elif op == 2: # Case 2: LZ Match (The logic from sub_4150A0)
                if input_ptr + 1 < len(data):
                    # v8 = v6[1] | (v6[0] << 8)
                    v8 = (data[input_ptr] << 8) | data[input_ptr+1]
                    input_ptr += 2
                    
                    length = (v8 & 0x1F) + 4
                    offset = (v8 >> 5) + 1
                    
                    # sub_4150A0 loop
                    for _ in range(length):
                        if len(output) >= decomp_size: break
                        back_ptr = len(output) - offset
                        if back_ptr >= 0:
                            output.append(output[back_ptr])
                        else:
                            output.append(0) # Padding
                            
            elif op == 3: # Case 3: Multi-literal block
                if input_ptr < len(data):
                    count = data[input_ptr]
                    input_ptr += 1
                    for _ in range(count):
                        if input_ptr < len(data):
                            output.append(data[input_ptr])
                            input_ptr += 1
                            
    return bytes(output), extension


def main():
    if len(argv) < 2:
        print("Usage: script.py <file>")
        return

    input_path = argv[1]
    base_name = os.path.splitext(os.path.basename(input_path))[0]
    out_dir = base_name

    os.makedirs(out_dir, exist_ok=True)

    with open(input_path, "rb") as f:
        filesize = os.path.getsize(input_path)

        num_files = f.read(1)[0]
        print(f"[+] Number of files: {num_files}")

        entries = []

        for i in range(num_files):
            raw = f.read(9)
            if len(raw) < 9:
                print(f"[!] Unexpected EOF at entry {i}")
                break

            unk, offset, size = unpack("<?II", raw)
            print(f"[{i:02}] flag={unk} offset=0x{offset:08X} size={size}")
            entries.append((i, unk, offset, size))

        print(f"\n[+] Extracting to folder: {out_dir}\n")

        for i, unk, offset, size in entries:
            if offset + size > filesize:
                print(f"[{i:02}] Skipping (out of bounds)")
                continue

            f.seek(offset)
            data = f.read(size)

            # Check for CNX compression signature
            if data.startswith(b"CNX\x02"):
                print(f"[{i:02}] CNX compression detected, decompressing...")
                data, ext = decompress_cnx(data)
            else:
                ext = detect_filetype(data)

            name = None
            if ext == "mid":
                name = extract_midi_name(data)

            if name:
                filename = f"{i:02}_{name}.{ext}"
            else:
                filename = f"{i:02}_{offset:08X}.{ext}"

            full_path = os.path.join(out_dir, filename)

            with open(full_path, "wb") as out:
                out.write(data)

            print(f"[{i:02}] -> {full_path} (flag={unk})")


if __name__ == "__main__":
    main()