import struct
import os

def decompress_exact_asm(compressed_data):
    # Convert to mutable bytearray
    inp = bytearray(compressed_data)
    
    # --- 1. Decrypt Header (FUN_0047c980) ---
    # Reverses the first 0x8C0 (2240) bytes
    header_limit = 0x8C0
    if len(inp) < header_limit:
        header_limit = len(inp)
    
    # In-place reverse
    inp[:header_limit] = inp[:header_limit][::-1]

    # --- 2. Read Size ---
    if len(inp) < 4:
        print("Error: Input too short")
        return None
        
    # Little Endian Read
    total_out_size = struct.unpack("<I", inp[:4])[0]
    in_ptr = 4
    
    # Adjust for the header bytes themselves being part of the stream count logic in some variants,
    # but based on assembly 'sub edx, 4', the size at [ESP+1C] is likely the file size.
    # The output size logic in the loop relies on 'param_2' (allocated buffer size or similar).
    # Let's trust the header value is the Decompressed Size.
    
    print(f"Header parsed. Decompressed size: {total_out_size}")
    
    output = bytearray()
    
    # Ring Buffer 4096 bytes (DAT_0050af4c)
    ring_buffer = bytearray(4096)
    ring_idx = 0xFEE 
    flags = 0

    # --- 3. LZSS Loop ---
    # We must track remaining output size to know when to stop
    remaining = total_out_size
    
    while remaining > 0:
        flags >>= 1
        
        # Refill Flags (0x100 sentinel)
        if (flags & 0x100) == 0:
            if in_ptr >= len(inp): break
            raw = inp[in_ptr]
            in_ptr += 1
            flags = 0xFF00 | (raw ^ 0x96)

        if (flags & 1) == 0:
            # --- MATCH ---
            if in_ptr + 1 >= len(inp): break
            b1 = inp[in_ptr]
            b2 = inp[in_ptr + 1]
            in_ptr += 2
            
            # ASSEMBLY LOGIC:
            # mov al, byte ptr ds:[esi]     (b1)
            # xor eax, 96
            # inc esi
            # mov ecx, eax
            # and eax, F
            # and ecx, F0
            # shl ecx, 4
            # or edi, ecx
            # add eax, 2   <-- CRITICAL FIX: +2, not +3
            
            # Length
            length = ((b2 ^ 0x96) & 0x0F) + 2
            
            # Offset
            offset = ((b1 ^ 0x96) | ((b2 ^ 0x96) & 0xF0) << 4)
            
            if length > remaining: length = remaining
            remaining -= length
            
            for _ in range(length):
                val = ring_buffer[(offset) & 0xFFF]
                offset += 1
                output.append(val)
                
                ring_buffer[ring_idx] = val
                ring_idx = (ring_idx + 1) & 0xFFF
                
        else:
            # --- LITERAL ---
            if in_ptr >= len(inp): break
            raw = inp[in_ptr]
            in_ptr += 1
            
            val = raw ^ 0x96
            output.append(val)
            remaining -= 1
            
            ring_buffer[ring_idx] = val
            ring_idx = (ring_idx + 1) & 0xFFF

    # --- 4. Swizzle (Reversal) Loop ---
    # Matches: etel2002.47C900
    # Stride: 0xD5 (213)
    # Range:  0xD4 (212)
    # Start:  0
    
    swizzled = bytearray(output)
    out_len = len(swizzled)
    i = 0
    stride = 0xD5
    
    while i < out_len:
        chunk_end = i + 0xD4
        
        # Handle last partial chunk
        if chunk_end >= out_len:
            chunk_end = out_len - 1
            
        # Reverse the chunk [i ... chunk_end] inclusive
        # Python slice is exclusive at end, so +1
        swizzled[i : chunk_end+1] = swizzled[i : chunk_end+1][::-1]
        
        i += stride

    return swizzled

if __name__ == "__main__":
    input_file = "145"
    output_file = "valis_asm_fix.gen"

    if os.path.exists(input_file):
        with open(input_file, "rb") as f:
            data = f.read()
        
        result = decompress_exact_asm(data)
        
        if result:
            with open(output_file, "wb") as f:
                f.write(result)
            print(f"Success! Wrote {len(result)} bytes to {output_file}")
            
            # Diagnostics
            print(f"Vectors: {result[:4].hex().upper()}")
            if len(result) > 0x100:
                print(f"Header:  {result[0x100:0x110]}")
            if len(result) > 0x1C8:
                print(f"Title:   {result[0x1C8:0x1D0]}")
        else:
            print("Decompression failed.")
    else:
        print(f"File {input_file} not found.")