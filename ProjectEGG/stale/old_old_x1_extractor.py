import struct
import sys
import os

def rol(val, shift):
    """Rotate Left: Shifts bits left, wrapping them around."""
    shift &= 7
    return ((val << shift) | (val >> (8 - shift))) & 0xFF

def descramble(data):
    """
    Decrypts data using ROL + XOR with index.
    Algorithm: Rotate Left by (index & 7), then XOR with (index & 0xFF).
    """
    output = bytearray()
    for i, byte_val in enumerate(data):
        key = i & 0xFF
        shift = key & 7
        rotated = rol(byte_val, shift)
        decrypted_byte = rotated ^ key
        output.append(decrypted_byte)
    return output

def get_pe_info(data):
    """Get image base and section info from PE header."""
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    image_base = struct.unpack_from('<I', data, e_lfanew + 52)[0]

    num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    sec_table = e_lfanew + 24 + opt_size

    sections = []
    for i in range(num_sections):
        sec_off = sec_table + i * 40
        name = data[sec_off:sec_off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
        virt_addr = struct.unpack_from('<I', data, sec_off + 12)[0]
        raw_size = struct.unpack_from('<I', data, sec_off + 16)[0]
        raw_ptr = struct.unpack_from('<I', data, sec_off + 20)[0]
        sections.append({
            'name': name,
            'va_start': image_base + virt_addr,
            'va_end': image_base + virt_addr + raw_size,
            'raw_ptr': raw_ptr
        })

    return image_base, sections

def va_to_offset(va, sections):
    """Convert VA to file offset."""
    for sec in sections:
        if sec['va_start'] <= va < sec['va_end']:
            return sec['raw_ptr'] + (va - sec['va_start'])
    return 0

def find_blobs(data, image_base, sections):
    """Find blob pointers and sizes in .data section."""
    # Find .data section
    data_sec = None
    for sec in sections:
        if '.data' in sec['name']:
            data_sec = sec
            break

    if not data_sec:
        return []

    data_start = data_sec['raw_ptr']

    # Look for blob VA array (3 consecutive VAs pointing to .rdata)
    # Typically at offset 0x30 in .data section
    blobs = []

    # Search for pattern: 2-3 valid VAs followed by zero
    for search_off in range(data_start, data_start + 0x1000, 4):
        vas = []
        for i in range(3):
            va = struct.unpack_from('<I', data, search_off + i * 4)[0]
            if va == 0:
                break
            offset = va_to_offset(va, sections)
            # Lower threshold to 0x10000 to handle more variants
            if offset and 0x10000 <= offset < len(data):
                vas.append((va, offset))
            else:
                break

        if len(vas) >= 2:
            # Check if next DWORD is 0 (end of array)
            next_val = struct.unpack_from('<I', data, search_off + len(vas) * 4)[0]
            if next_val == 0:
                # Found blob array - calculate sizes from gaps
                # Last blob size estimated from file/section end
                sizes = []
                for i in range(len(vas) - 1):
                    gap = vas[i+1][1] - vas[i][1]
                    sizes.append(gap)

                # Skip if gaps are too small (< 100KB) - not disk data
                if sizes and min(sizes) < 100000:
                    continue

                # For last blob, use same size as previous blobs (they're usually same format)
                if len(sizes) > 0:
                    sizes.append(sizes[0])
                else:
                    # Fallback: estimate from section end
                    last_offset = vas[-1][1]
                    for sec in sections:
                        sec_end = sec['raw_ptr'] + (sec['va_end'] - sec['va_start'])
                        if sec['raw_ptr'] <= last_offset < sec_end:
                            sizes.append(sec_end - last_offset)
                            break

                if len(sizes) == len(vas):
                    for i, (va, offset) in enumerate(vas):
                        blobs.append({
                            'va': va,
                            'offset': offset,
                            'size': sizes[i]
                        })
                    return blobs

    return blobs

def validate_d88(data):
    """Validate D88 header and return disk info."""
    if len(data) < 0x20:
        return None

    # Get disk info
    name = data[:17].split(b'\x00')[0].decode('shift-jis', errors='replace')
    media = data[0x1B]
    disk_size = struct.unpack_from('<I', data, 0x1C)[0]

    # Only check: disk size at 0x1C must match actual data size
    if disk_size != len(data):
        return None

    return {
        'name': name,
        'media': media,
        'size': disk_size
    }

def extract(exe_path):
    print(f"=== Extracting from {os.path.basename(exe_path)} ===")

    with open(exe_path, 'rb') as f:
        data = f.read()

    print(f"File size: {len(data)} bytes")

    image_base, sections = get_pe_info(data)
    print(f"Image base: 0x{image_base:X}")

    for sec in sections:
        print(f"  {sec['name']:8s}: VA 0x{sec['va_start']:08X}, raw 0x{sec['raw_ptr']:06X}")

    # Find blobs
    blobs = find_blobs(data, image_base, sections)

    if not blobs:
        print("Error: Could not find blob metadata")
        return

    print(f"\nFound {len(blobs)} blobs\n")

    base_name = os.path.splitext(os.path.basename(exe_path))[0]
    out_dir = os.path.dirname(exe_path)

    for idx, blob in enumerate(blobs):
        print(f"Disk {idx + 1}:")
        print(f"  Offset: 0x{blob['offset']:X}, Size: {blob['size']}")

        # First descramble header to get actual D88 size
        header_data = data[blob['offset']:blob['offset'] + 0x20]
        decrypted_header = descramble(header_data)
        actual_size = struct.unpack_from('<I', decrypted_header, 0x1C)[0]

        # Use actual D88 size if it's larger than estimated (and reasonable)
        extract_size = blob['size']
        if actual_size > blob['size'] and actual_size < blob['size'] * 2:
            extract_size = actual_size
            print(f"  Adjusted size to D88 header value: {actual_size}")

        # Extract and descramble full blob
        blob_data = data[blob['offset']:blob['offset'] + extract_size]
        decrypted = descramble(blob_data)

        # Validate D88
        d88_info = validate_d88(decrypted)
        if d88_info:
            media_str = {0x00: '2D', 0x10: '2DD', 0x20: '2HD'}.get(d88_info['media'], '??')
            print(f"  D88 name: \"{d88_info['name']}\", media: {media_str}, size: {d88_info['size']}")
            print(f"  Valid D88: Yes")
        else:
            print(f"  Valid D88: No (header validation failed)")

        # Save
        out_name = os.path.join(out_dir, f"{base_name}_disk_{idx + 1}.d88")
        with open(out_name, 'wb') as out:
            out.write(decrypted)
        print(f"  Saved to {out_name}\n")

    print("Extraction complete.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        extract(sys.argv[1])
    else:
        print("Old X1 Extractor (ROL+XOR descramble, no compression)")
        print("Usage: python old_x1_extractor.py <game.exe>")
