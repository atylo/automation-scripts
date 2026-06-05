import sys
import struct
import os
import time

def find_code_pointer(data):
    # Signature: PUSH EBX, PUSH EBP, PUSH ESI, LEA EAX
    # 53 55 56 8D 80
    sig = b'\x53\x55\x56\x8D\x80'
    pos = data.find(sig)
    
    # Fallback for slightly different prologue (PUSH EBP, PUSH ESI...)
    if pos == -1:
        sig = b'\x55\x56\x8D\x80'
        pos = data.find(sig)
        if pos == -1: return None

    # Extract the address from the LEA instruction (4 bytes after 8D 80)
    lea_offset = data.find(b'\x8D\x80', pos) + 2
    virtual_addr = struct.unpack("<I", data[lea_offset:lea_offset+4])[0]
    
    # Convert to File Offset (ImageBase 0x400000)
    return virtual_addr - 0x400000

def try_decompress_at(data, offset, filename):
    print(f"[>] Testing offset {hex(offset)}...")
    
    # --- 1. Parse Header ---
    freqs = []
    ptr = offset
    try:
        for _ in range(256):
            if ptr >= len(data): return False
            b1 = data[ptr]; ptr += 1
            if b1 & 0x80:
                b2 = data[ptr]; ptr += 1
                val = (b1 & 0x7F) | (b2 << 7)
            else:
                val = b1
            freqs.append(val)
    except: return False

    freqs.append(1) # Stop Symbol
    
    # CDF
    cdf = [0] * 257
    total = 0
    for i in range(257): total += freqs[i]; cdf[i] = total
    total_freq = cdf[256]
    
    if total_freq == 0: return False

    # Data Stream Start
    ptr = offset
    for x in freqs[:-1]: ptr += 2 if x >= 128 else 1
    
    if ptr + 4 > len(data): return False
    code = struct.unpack(">I", data[ptr:ptr+4])[0]
    ptr += 4
    
    low = 0; range_val = 0xFFFFFFFF
    output = bytearray()
    
    # --- 2. Decode Loop ---
    try:
        while len(output) < 4000000: # Cap at 4MB
            unit = range_val // total_freq
            if unit == 0: break
            scaled = (code - low) // unit
            
            l, r = 0, 256
            while l < r:
                mid = (l + r) // 2
                if cdf[mid] > scaled: r = mid
                else: l = mid + 1
            sym = l
            
            if sym == 256:
                # SUCCESS CONDITION: We hit stop symbol.
                # Only save if it looks like a ROM (>1MB)
                if len(output) > 1000000:
                    print(f"\n[!!!] SUCCESS! Decoded {len(output)} bytes.")
                    
                    # Padding Logic
                    target = 0
                    if len(output) <= 1572864: target = 1572864
                    elif len(output) <= 2097152: target = 2097152
                    
                    if target > 0 and (target - len(output)) < 100000:
                         print(f"[+] Padding to {target} bytes...")
                         output.extend(b'\x00' * (target - len(output)))
                    
                    out_name = f"{filename}_rom.sfc"
                    with open(out_name, "wb") as f: f.write(output)
                    print(f"[SUCCESS] Saved to {out_name}")
                    return True
                else:
                    return False # Too small
            
            output.append(sym)
            range_val = (unit * freqs[sym]) & 0xFFFFFFFF
            prev_cdf = cdf[sym-1] if sym > 0 else 0
            low = (low + unit * prev_cdf) & 0xFFFFFFFF
            
            while True:
                check = low ^ ((low + range_val) & 0xFFFFFFFF)
                if check >= 0x1000000: break
                new_byte = data[ptr] if ptr < len(data) else 0; ptr += 1
                code = ((code << 8) | new_byte) & 0xFFFFFFFF
                range_val = (range_val << 8) & 0xFFFFFFFF
                low = (low << 8) & 0xFFFFFFFF
            while range_val < 0x1000000:
                new_byte = data[ptr] if ptr < len(data) else 0; ptr += 1
                code = ((code << 8) | new_byte) & 0xFFFFFFFF
                range_val = (-(low << 8)) & 0xFFFFFFFF
                low = (low << 8) & 0xFFFFFFFF
    except: pass
    
    return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_force.py <file>")
        return
        
    filename = sys.argv[1]
    with open(filename, "rb") as f:
        data = f.read()
        
    base_offset = find_code_pointer(data)
    
    if not base_offset:
        print("[-] Code signature not found.")
        return

    print(f"[+] Code points to: {hex(base_offset)}")
    print("[+] Attempting offsets relative to pointer (0, -4, -8)...")

    # Priority 1: Exact match (Ys IV)
    if try_decompress_at(data, base_offset, filename): return
    
    # Priority 2: Shifted -4 (Ys V)
    if try_decompress_at(data, base_offset - 4, filename): return
    
    # Priority 3: Shifted -8 (Just in case)
    if try_decompress_at(data, base_offset - 8, filename): return

    print("[-] Failed to extract a valid ROM.")

if __name__ == "__main__":
    main()