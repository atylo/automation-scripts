import sys
import struct
import os
import zlib

# =========================================================================
# 1. LAYOUT DEFINITIONS (Slicing Blueprints)
# =========================================================================
# Format: Mode_ID: [ (Description, Size_in_Hex), ... ]

LAYOUTS = {
    0: [ # PC-6001 (Original)
        ("MainRAM", 0x4000), 
        ("WorkRAM", 0x1000)
    ],
    1: [ # PC-6001mkII
        ("MainRAM", 0x8000), 
        ("WorkRAM", 0x2000), 
        ("SubRAM",  0x2000),
        ("VideoRAM",0x8000), 
        ("SaveRAM", 0x4000)
    ],
    2: [ # PC-6001mkII (Extended)
        ("MainRAM", 0x8000), 
        ("WorkRAM", 0x2000), 
        ("SubRAM",  0x2000),
        ("VideoRAM",0x8000), 
        ("SaveRAM", 0x4000), 
        ("ExtRAM",  0x2000)
    ],
    3: [ # PC-6001mkII (Alt) - Same as Mode 1
        ("MainRAM", 0x8000), 
        ("WorkRAM", 0x2000), 
        ("SubRAM",  0x2000),
        ("VideoRAM",0x8000), 
        ("SaveRAM", 0x4000)
    ],
    4: [ # PC-6601 / PC-6001mkII SR
        ("MainRAM", 0x8000), 
        ("WorkRAM", 0x8000), 
        ("SubRAM",  0x2000),
        ("SaveRAM", 0x2000), 
        ("VideoRAM",0x4000), 
        ("ExtRAM",  0x2000)
    ]
}

# =========================================================================
# 2. CRC TABLES (Naming Rules per Mode)
# =========================================================================
# Format: Mode_ID: { "CRC32": "FILENAME", ... }

CRC_TABLES = {
    # MODE 0: PC-6001
    0: {
        "54C03109": "BASICROM.60",
        "B0142D32": "CGROM60.60",
        "FA8E88D9": "BASICROM.61",
        "49C21D08": "CGROM60.61",
    },
    
    # MODE 1: PC-6001mkII
    1: {
        "950AC401": "BASICROM.62", # Variant 1
        "D7E61957": "BASICROM.62", # Variant 2
        "81EB5D95": "CGROM60.62",
        "3CE48C33": "CGROM60m.62",
        "20C8F3EB": "KANJIROM.62",
        "49B4F917": "VOICEROM.62",
        
    },
    
    # MODE 2: PC-6001mkII (Extended)
    # Often shares ROMs with Mode 1, but might have specific ExtRAM files
    2: {
        "950AC401": "BASICROM.62",
        "D7E61957": "BASICROM.62",
        "81EB5D95": "CGROM60.62",
        "3CE48C33": "CGROM60m.62",
        "20C8F3EB": "KANJIROM.62",
        "49B4F917": "VOICEROM.62",
        "DEADBEEF": "EXBASIC.ROM",
    },

    # MODE 4: PC-6601 / SR
    4: {
        # PC-6601
        "C0B01772": "BASICROM.66",
        "D2434F29": "CGROM60.66",
        "3CE48C33": "CGROM66.66", # Note: Shared CRC with Mode 1, but different name!
        "20C8F3EB": "KANJIROM.66",
        "91D078C1": "VOICEROM.66",
        
        # PC-6001mkII SR
        "B6FC2DB2": "SYSTEMROM1.64",
        "55A62A1D": "SYSTEMROM1.64",
        "73BC3256": "CGROM68.64",
        
        # PC-6601 SR
        "B6FC2DB2": "SYSTEMROM1.68", # Same CRC as mkII SR, likely identical file
        "55A62A1D": "SYSTEMROM1.68",
        "73BC3256": "CGROM68.68",
    }
}

# Add Mode 3 to alias Mode 1 table if needed
CRC_TABLES[3] = CRC_TABLES[1]

# =========================================================================
# 3. HELPER FUNCTIONS
# =========================================================================

def calculate_crc32(data):
    return f"{zlib.crc32(data) & 0xFFFFFFFF:08X}"

def get_mode_from_config(config_file):
    try:
        with open(config_file, "rb") as f:
            f.seek(0x84)
            data = f.read(4)
            if len(data) < 4: return None
            return struct.unpack("<I", data)[0]
    except FileNotFoundError:
        return None

def scatter_rom(config_path, rom_path):
    print(f"--- Processing: {rom_path} ---")

    # 1. Get Mode
    mode = get_mode_from_config(config_path)
    if mode is None:
        print("[!] Error: Could not read CONFIG file.")
        return
    
    # 2. Select Layout and CRC Table
    # Fallback to Mode 4 if we encounter a high/unknown mode
    if mode not in LAYOUTS:
        print(f"[!] Warning: Unknown Mode {mode}. Defaulting to Mode 4.")
        mode = 4

    layout = LAYOUTS[mode]
    crc_table = CRC_TABLES.get(mode, {})

    print(f"[+] System Mode Detected: {mode}")
    print(f"[+] Using Layout for Mode {mode} ({len(layout)} chunks)")

    # 3. Load ROM
    try:
        with open(rom_path, "rb") as f:
            rom_data = f.read()
    except FileNotFoundError:
        print(f"[!] Error: ROM file not found.")
        return

    # 4. Extract and Name
    cursor = 0
    output_dir = f"extracted_mode_{mode}"
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"[+] Extracting to folder: {output_dir}/")

    for i, (desc, size) in enumerate(layout):
        if cursor + size > len(rom_data):
            print(f"    [!] Error: ROM too small for Chunk {i}!")
            break

        chunk_data = rom_data[cursor : cursor + size]
        crc = calculate_crc32(chunk_data)
        
        # --- MODE SPECIFIC LOOKUP ---
        if crc in crc_table:
            final_name = crc_table[crc]
            status = f"MATCH -> {final_name}"
        else:
            final_name = f"UNK_{crc}_{desc}.bin"
            status = f"UNKNOWN ({crc})"

        # Write file
        with open(os.path.join(output_dir, final_name), "wb") as out:
            out.write(chunk_data)
            
        print(f"    Chunk {i}: {status:<30} (Size: {hex(size)})")
        cursor += size

    print("\n[+] Extraction Complete.")

# =========================================================================
# MAIN
# =========================================================================
if __name__ == "__main__":
    cfg = "CONFIG.BIN"
    rom = "ROM.BIN"
    
    if len(sys.argv) == 3:
        cfg, rom = sys.argv[1], sys.argv[2]
        
    if os.path.exists(cfg) and os.path.exists(rom):
        scatter_rom(cfg, rom)
    else:
        print("Usage: python script.py <CONFIG_FILE> <ROM_FILE>")