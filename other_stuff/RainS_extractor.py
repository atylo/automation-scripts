# An old extractor for archives made by RainS release scene group. 
# They also used zlib or cpio archive with a missing 4-bytes header
import os
import sys

def extract_files(archive_path):
    with open(archive_path, "rb") as archive:
        while True:
            # Read file size (decimal) until 0A delimiter
            size_bytes = b""
            while True:
                byte = archive.read(1)
                if not byte or byte == b"\x0A":
                    break
                size_bytes += byte
            
            if not size_bytes.isdigit():
                break  # Stop if file size is invalid
            
            file_size = int(size_bytes.decode("utf-8"))
            
            # Read filename until 0A delimiter
            filename_bytes = b""
            while True:
                byte = archive.read(1)
                if not byte or byte == b"\x0A":
                    break
                filename_bytes += byte
            
            filename = filename_bytes.decode("utf-8", errors="ignore")
            
            # Ensure directory structure exists
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            # Read file data
            file_data = archive.read(file_size)
            
            # Write to extracted file
            with open(filename, "wb") as out_file:
                out_file.write(file_data)
            
            print(f"Extracted: {filename} ({file_size} bytes)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract.py <archive_file>")
        sys.exit(1)
    extract_files(sys.argv[1])
