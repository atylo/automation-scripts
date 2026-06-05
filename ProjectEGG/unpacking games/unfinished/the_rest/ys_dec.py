import struct
import sys
import os

def decompress_arithmetic(data, start_offset):
    print(f"[+] Starting decompression at offset: {hex(start_offset)}")
    
    # --- Step 1: Parse the Frequency Table (Header) ---
    # The header contains 256 frequency counts encoded as VLQ.
    freqs = [0] * 257
    ptr = start_offset
    
    for i in range(256):
        if ptr >= len(data):
            print("Error: Unexpected EOF in header")
            return None
        
        byte1 = data[ptr]
        ptr += 1
        
        if byte1 & 0x80:
            # VLQ: If high bit is set, combine with next byte
            if ptr >= len(data): return None
            byte2 = data[ptr]
            ptr += 1
            # Formula from ASM: v7 = v6 & 0x7F | (*v4++ << 7)
            val = (byte1 & 0x7F) | (byte2 << 7)
            freqs[i] = val
        else:
            freqs[i] = byte1

    # Frequency for the "Stop Symbol" (256) is implicitly 1
    freqs[256] = 1 
    
    # --- Step 2: Build Cumulative Distribution Function (CDF) ---
    # cdf[i] = sum(freqs[0]...freqs[i])
    cdf = [0] * 257
    current_total = 0
    for i in range(257):
        current_total += freqs[i]
        cdf[i] = current_total
        
    total_freq = cdf[256]
    print(f"[+] Total Frequency Count: {total_freq}")

    # --- Step 3: Initialize Decoder State ---
    # Load initial 4-byte code (Big Endian)
    # C Code: v11 = v4[3] | ((v4[2] | (v9 << 8)) << 8)
    if ptr + 4 > len(data): return None
    code = struct.unpack(">I", data[ptr:ptr+4])[0]
    ptr += 4
    
    low = 0
    range_val = 0xFFFFFFFF # v10 = -1 in C (unsigned 32-bit)
    
    output = bytearray()
    
    # --- Step 4: Decoding Loop ---
    while True:
        # Calculate the size of a single unit
        # C Code: v10 / v45[256]
        unit = range_val // total_freq
        
        # Calculate the scaled value within the current range
        # C Code: (v36 - v2) / unit
        scaled_value = (code - low) // unit
        
        # --- Symbol Lookup (Binary Search) ---
        # Find symbol 'sym' such that cdf[sym-1] <= scaled_value < cdf[sym]
        # (Implementation matches std::upper_bound logic seen in ASM)
        l, r = 0, 256
        while l < r:
            mid = (l + r) // 2
            if cdf[mid] > scaled_value:
                r = mid
            else:
                l = mid + 1
        sym = l
        
        # --- Check for End of Stream ---
        if sym == 256:
            print(f"[+] Stop Symbol found at output size: {len(output)} bytes")
            break
            
        output.append(sym)
        
        # --- Update Range and Low ---
        # C Code: v10 = v43 * v46[v37] (Range = Unit * Frequency)
        range_val = (unit * freqs[sym]) & 0xFFFFFFFF
        
        # C Code: v2 += v43 * v45[v37 - 1] (Low += Unit * PreviousCDF)
        prev_cdf = cdf[sym-1] if sym > 0 else 0
        low = (low + unit * prev_cdf) & 0xFFFFFFFF
        
        # --- Renormalization Phase 1 ---
        # "Zoom in" if high bits of low and low+range match
        # C Code: while ( (v2 ^ (v10 + v2)) < 0x1000000 )
        while True:
            # Check if top 8 bits are identical
            check = low ^ ((low + range_val) & 0xFFFFFFFF)
            if check >= 0x1000000:
                break
            
            # Shift out a byte and read a new one
            new_byte = 0
            if ptr < len(data):
                new_byte = data[ptr]
                ptr += 1
            
            # Update state (<< 8)
            code = ((code << 8) | new_byte) & 0xFFFFFFFF
            range_val = (range_val << 8) & 0xFFFFFFFF
            low = (low << 8) & 0xFFFFFFFF

        # --- Renormalization Phase 2 (Underflow) ---
        # Handle cases where range becomes too small but doesn't share top bits
        # C Code: while ( v10 < 0x1000000 )
        while range_val < 0x1000000:
            new_byte = 0
            if ptr < len(data):
                new_byte = data[ptr]
                ptr += 1
                
            code = ((code << 8) | new_byte) & 0xFFFFFFFF
            
            # C Code: v10 = -256 * v2 (This handles the underflow expansion)
            # -x in 2's complement is (~x + 1)
            range_val = (-(low << 8)) & 0xFFFFFFFF
            
            low = (low << 8) & 0xFFFFFFFF

    return output

def find_and_extract(filename):
    try:
        with open(filename, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("File not found.")
        return

    # Signature from your hex dump: A1 05 B6 0C C9 0B
    # This corresponds to freq[0]=673, freq[1]=1590, freq[2]=1481
    signature = b'\xA1\x05\xB6\x0C\xC9\x0B'
    #signature = b'\x9D\xEA\x2B\x00\xDB\x07'
    
    #offset = data.find(signature)
    offset = 0x0
    
    if offset == -1:
        print("[-] Signature not found. If you know the exact offset, modify the script.")
        # Optional: Manual override if you know the address in the dump
        # offset = 0x432740 - (ImageBase if dumping from memory)
        return

    print(f"[+] Found compression signature at offset: {hex(offset)}")
    
    decompressed_data = decompress_arithmetic(data, offset)
    
    if decompressed_data:
        out_name = filename + "_extracted.bin"
        with open(out_name, "wb") as f:
            f.write(decompressed_data)
        print(f"[+] Decompression successful! Wrote {len(decompressed_data)} bytes to {out_name}")
    else:
        print("[-] Decompression failed.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extractor.py <path_to_executable_or_dump>")
    else:
        find_and_extract(sys.argv[1])