import sys
import os

def patch_binary(filename, signature, patch_bytes):
    # 1. Read the original file
    try:
        with open(filename, "rb") as f:
            buffer = bytearray(f.read())
    except Exception as e:
        print(f"[-] Error: Could not read file {filename}. Reason: {e}")
        return False

    # 2. Search for the signature offset
    offset = buffer.find(signature)
    if offset == -1:
        print(f"[-] Error: Signature '{signature.decode(errors='ignore')}' not found.")
        return False

    print(f"[+] Found Dr0Wy3K signature at offset: 0x{offset:X}")
    
    # Calculate where the modification starts
    patch_start = offset + len(signature)
    patch_end = patch_start + len(patch_bytes)

    # Safety check: Ensure we don't write past the end of the file buffer
    if patch_end > len(buffer):
        print("[-] Error: Patch size exceeds file boundaries.")
        return False

    # 3. Create a backup file before writing changes
    backup_filename = filename + ".bak"
    try:
        with open(backup_filename, "wb") as b:
            b.write(buffer)
        print(f"[+] Backup created successfully: {backup_filename}")
    except Exception as e:
        print(f"[-] Error: Failed to create backup file. Patching aborted. Reason: {e}")
        return False

    # 4. Overwrite the bytes in the buffer
    print(f"[*] Overwriting bytes at 0x{patch_start:X} with: {patch_bytes.hex(' ')}")
    buffer[patch_start:patch_end] = patch_bytes

    # 5. Write the modified buffer back to the original file
    try:
        with open(filename, "wb") as f:
            f.write(buffer)
        print(f"[+] File successfully patched!")
        return True
    except Exception as e:
        print(f"[-] Error: Failed to write changes back to {filename}. Reason: {e}")
        return False

def main():
    if len(sys.argv) != 2:
        print("Dr0Wy3K ProjectEGG games patcher. For games that don't launch")
        print(f"Usage: python {sys.argv[0]} <target_file.exe>")
        sys.exit(1)

    target_file = sys.argv[1]

    if not os.path.exists(target_file):
        print(f"[-] Error: File '{target_file}' does not exist.")
        sys.exit(1)

    # Configuration definitions
    TARGET_SIGNATURE = b"Dr0Wy3K"
    PATCH_DATA = b"\x01\x01\x01"  # The replacement bytes (01 01 01)

    patch_binary(target_file, TARGET_SIGNATURE, PATCH_DATA)

if __name__ == "__main__":
    main()