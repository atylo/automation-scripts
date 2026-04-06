def decompress_pce_data(compressed_data, seed=0):
    """
    Python implementation of FUN_1000c52d.
    Decodes a custom Tagged LZSS + XOR-LCG stream.
    """
    src_ptr = 0
    dest = bytearray()
    
    # Global state for the PRNG (Linear Congruential Generator)
    # Equivalent to DAT_103678b8 in the C code
    prng_state = seed

    def get_next_key():
        nonlocal prng_state
        # DAT_103678b8 = DAT_103678b8 * 0x81 + 1;
        prng_state = (prng_state * 0x81 + 1) & 0xFFFFFFFF
        
        # return (byte)state ^ (byte)(state >> 8)
        low_byte = prng_state & 0xFF
        high_byte = (prng_state >> 8) & 0xFF
        return low_byte ^ high_byte

    while src_ptr < len(compressed_data):
        # Read the control byte
        control = compressed_data[src_ptr]
        src_ptr += 1
        
        # Top 2 bits = Mode/Command
        mode = control >> 6
        # Lower 6 bits = Length factor
        count_bits = control & 0x3F

        if mode == 0:
            # MODE 0: Decrypted Literals
            # iVar3 = (uVar2 & 0x3f) + 1
            length = count_bits + 1
            for _ in range(length):
                key = get_next_key()
                val = compressed_data[src_ptr] ^ key
                dest.append(val)
                src_ptr += 1

        elif mode == 1:
            # MODE 1: Decrypted RLE (Run-Length Encoding)
            # uVar2 = (uVar2 & 0x3f) + 2
            length = count_bits + 2
            key = get_next_key()
            val = compressed_data[src_ptr] ^ key
            src_ptr += 1
            for _ in range(length):
                dest.append(val)

        elif mode == 2:
            # MODE 2: LZSS Reference (Dictionary Copy)
            # iVar3 = (uVar2 & 0x3f) + 3
            length = count_bits + 3
            
            # Read 16-bit offset (Big Endian based on short cast in C)
            high = compressed_data[src_ptr]
            low = compressed_data[src_ptr + 1]
            src_ptr += 2
            offset_val = (high << 8) | low
            
            # The C code calculates the back-reference relative to the 
            # current end of the buffer, subtracting the length.
            # pbVar6 = pbVar8 + (-iVar3 - offset_val)
            # In Python, we can just slice the existing 'dest' array.
            start_index = len(dest) - length - offset_val
            
            for i in range(length):
                # Copy from the already decompressed data
                dest.append(dest[start_index + i])

        elif mode == 3:
            # MODE 3: End of Stream
            break

    return dest