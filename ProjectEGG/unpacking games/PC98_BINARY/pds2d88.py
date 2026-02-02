import struct
import sys
import os

def parse_pds_disk(data, start_offset):
    """
    Parses a single PDS disk image starting at start_offset.
    Returns: (tracks_data, next_offset, is_valid)
    """
    ptr = start_offset
    file_size = len(data)

    # 1. Check Magic
    if ptr + 3 > file_size:
        return [], ptr, False
    
    magic = data[ptr:ptr+3]
    if magic.lower() != b'pds':
        return [], ptr, False

    # Skip Header (3 bytes Magic + 1 byte Ver + 1 byte Pad = 5 bytes)
    ptr += 5
    
    tracks_data = []
    
    # 2. Parse Tracks
    while ptr < file_size:
        # Check if we've hit the start of a NEW PDS file (concatenated)
        # We look ahead to see if the next bytes are a PDS signature
        if ptr + 3 <= file_size:
            if data[ptr:ptr+3].lower() == b'pds':
                # Found a new header, finish current disk
                break

        # Read Track Header (Num Sectors)
        num_sectors = data[ptr]
        ptr += 1
        
        # If 0 sectors, might be padding or empty track, just continue
        if num_sectors == 0:
            continue

        current_track_blob = bytearray()
        track_c = 0
        track_h = 0
        
        # Read Sectors
        for _ in range(num_sectors):
            if ptr + 6 > file_size: 
                break # EOF inside track
            
            # PDS Sector Header
            c, h, r, f1, sec_type, size_param = struct.unpack("BBBBBB", data[ptr:ptr+6])
            ptr += 6
            
            track_c, track_h = c, h

            # Size Calculation
            # Logic: Try shift (sec_type << size), if 0 or result 0, use linear (128 * size)
            sector_size = 0
            if sec_type > 0:
                sector_size = sec_type << size_param
            
            if sector_size == 0:
                sector_size = 128 * size_param

            if ptr + sector_size > file_size:
                break # EOF inside data

            sector_payload = data[ptr:ptr+sector_size]
            ptr += sector_size
            
            # D88 Sector Header (16 bytes)
            # N-code: 0=128, 1=256, 2=512, 3=1024
            if sector_size == 128: n = 0
            elif sector_size == 256: n = 1
            elif sector_size == 512: n = 2
            elif sector_size == 1024: n = 3
            else: n = 1

            d88_sec_header = struct.pack(
                "<BBBBHBBB5sH",
                c, h, r, n,
                num_sectors,
                0x00,       # Density (00=Double)
                0x00,       # Deleted
                0x00,       # Status
                b'\x00'*5,  # Reserved
                sector_size
            )
            
            current_track_blob.extend(d88_sec_header)
            current_track_blob.extend(sector_payload)
            
        if len(current_track_blob) > 0:
            tracks_data.append((track_c, track_h, current_track_blob))

    return tracks_data, ptr, True

def save_d88(tracks_data, output_filename):
    """
    Saves parsed tracks to a D88 file.
    """
    # Analyze Geometry for Header
    max_cylinder = 0
    total_size = 0
    for c, h, blob in tracks_data:
        if c > max_cylinder: max_cylinder = c
        total_size += len(blob) - (len(blob)//(16+256))*16 # Approximate raw size check

    # Disk Type Detection
    media_type = 0x00 # Default 2D
    type_str = "2D (360KB)"

    if max_cylinder > 45:
        # Check size to distinguish 2DD (720KB) from 2HD (1.2MB)
        # Rough threshold: 2DD is ~640-730KB. 2HD is > 1MB.
        raw_payload_size = sum(len(t[2]) for t in tracks_data)
        if raw_payload_size > 800000:
            media_type = 0x20 # 2HD
            type_str = "2HD (1.2MB)"
        else:
            media_type = 0x10 # 2DD
            type_str = "2DD (640KB/720KB)"

    print(f"  - Detected: {type_str}, Max Cyl: {max_cylinder}")

    # Build File
    header_size = 0x2B0
    total_d88_size = sum(len(t[2]) for t in tracks_data)
    
    with open(output_filename, 'wb') as out:
        # 1. Disk Name (16 bytes) - BLANK as requested
        out.write(b'\x00' * 16)
        
        # 2. Reserved (10 bytes)
        out.write(b'\x00' * 10)
        
        # 3. Write Protect (1 byte)
        out.write(b'\x00')
        
        # 4. Media Type (1 byte)
        out.write(struct.pack("B", media_type))
        
        # 5. Disk Size (4 bytes)
        out.write(struct.pack("<I", header_size + total_d88_size))

        # 6. Track Offset Table (164 * 4 bytes)
        offsets = [0] * 164
        current_offset = header_size
        sorted_tracks = []
        
        for c, h, blob in tracks_data:
            idx = c * 2 + h
            if idx < 164:
                offsets[idx] = current_offset
                current_offset += len(blob)
                sorted_tracks.append(blob)
        
        for off in offsets:
            out.write(struct.pack("<I", off))
            
        # 7. Track Data
        for blob in sorted_tracks:
            out.write(blob)

    print(f"  - Saved: {output_filename}")

def convert_file(input_path):
    print(f"Processing {input_path}...")
    
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print("  Error: File not found.")
        return

    ptr = 0
    image_count = 0
    
    while ptr < len(data):
        # Attempt to parse a disk at current ptr
        tracks, next_ptr, valid = parse_pds_disk(data, ptr)
        
        if valid:
            image_count += 1
            # Generate filename: original_1.d88, original_2.d88
            base, _ = os.path.splitext(input_path)
            out_name = f"{base}_{image_count}.d88"
            
            save_d88(tracks, out_name)
            
            ptr = next_ptr
        else:
            # If invalid and we are at start, scan forward? 
            # Or just assume file must contain PDS data.
            # If we just finished a disk, next_ptr should point to next 'pds' or EOF.
            # If we are here, it means bytes at 'ptr' were not 'pds'.
            # We can advance 1 byte to search, but typically concatenated files are aligned.
            if ptr == len(data): break
            ptr += 1

    if image_count == 0:
        print("  No PDS signatures found.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pds2d88.py <file.bin>")
    else:
        for f in sys.argv[1:]:
            convert_file(f)