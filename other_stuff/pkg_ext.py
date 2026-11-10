#!/usr/bin/env python3
import os
import sys
import struct
import lzma
import gzip
import zlib
import tempfile
import stat
import xml.etree.ElementTree as ET
from pathlib import Path

def sanitize_path_for_windows(path_str):
    """Replaces characters illegal in Windows filenames."""
    if sys.platform != 'win32': return path_str
    drive, tail = os.path.splitdrive(path_str)
    parts = tail.replace('\\', '/').split('/')
    
    safe_parts = []
    for part in parts:
        for char in '<>:"|?*':
            part = part.replace(char, '_')
        safe_parts.append(part)
    return drive + os.path.join(*safe_parts)

def extract_xar_payloads(pkg_path, temp_dir):
    """Parses the XAR XML TOC and extracts Payload files in memory-safe chunks."""
    extracted = []
    
    with open(pkg_path, 'rb') as f:
        magic = f.read(4)
        if magic != b'xar!':
            raise ValueError(f"Not a valid XAR archive: {pkg_path.name}")
        
        header = f.read(24)
        size, version, toc_len_comp, toc_len_uncomp, chksum_alg = struct.unpack('>HHQQI', header)
        
        f.seek(size)
        toc_comp = f.read(toc_len_comp)
        toc_xml = zlib.decompress(toc_comp)
        
        heap_offset = size + toc_len_comp
        root = ET.fromstring(toc_xml)
        
        def walk_nodes(node, current_path):
            name_node = node.find('name')
            node_name = name_node.text if name_node is not None else 'unknown'
            path = os.path.join(current_path, node_name) if current_path else node_name
            
            type_node = node.find('type')
            if type_node is not None and type_node.text == 'file' and node_name == 'Payload':
                data_node = node.find('data')
                if data_node is not None:
                    offset = int(data_node.find('offset').text)
                    length = int(data_node.find('length').text)
                    
                    pkg_name = os.path.basename(os.path.dirname(path))
                    out_file = os.path.join(temp_dir, f"{pkg_name}_Payload")
                    
                    f.seek(heap_offset + offset)
                    
                    encoding = data_node.find('encoding')
                    if encoding is not None and encoding.get('style') == 'application/x-gzip':
                        payload_data = f.read(length)
                        try:
                            payload_data = zlib.decompress(payload_data)
                        except zlib.error:
                            payload_data = gzip.decompress(payload_data)
                        with open(out_file, 'wb') as pf:
                            pf.write(payload_data)
                    else:
                        bytes_left = length
                        with open(out_file, 'wb') as pf:
                            while bytes_left > 0:
                                chunk_size = min(bytes_left, 1024 * 1024 * 10)
                                pf.write(f.read(chunk_size))
                                bytes_left -= chunk_size
                                
                    extracted.append((pkg_name, out_file))
            
            for child in node.findall('file'):
                walk_nodes(child, path)
                
        toc_node = root.find('toc')
        if toc_node is not None:
            for child in toc_node.findall('file'):
                walk_nodes(child, "")
                
    return extracted

def extract_pbzx_to_cpio(payload_path, cpio_out_path):
    """Decodes Apple's proprietary PBZX stream into a standard CPIO archive."""
    with open(payload_path, 'rb') as f_in, open(cpio_out_path, 'wb') as f_out:
        magic = f_in.read(4)
        if magic != b'pbzx':
            raise ValueError(f"Not a valid pbzx file. Magic found: {magic}")
            
        f_in.read(8) # Skip flags
        
        while True:
            header = f_in.read(16)
            if len(header) < 16:
                break
            
            chunk_flags, chunk_length = struct.unpack('>QQ', header)
            chunk_data = f_in.read(chunk_length)
            
            if chunk_data.startswith(b'\xfd7zXZ'):
                f_out.write(lzma.decompress(chunk_data))
            else:
                f_out.write(chunk_data)

def search_cpio_pure(cpio_path, output_dir, target_filename="assetutil"):
    """Searches CPIO archive for a specific file, skipping all others."""
    found_count = 0
    
    with open(cpio_path, 'rb') as f:
        while True:
            magic = f.read(6)
            if not magic: break
            
            if magic == b'070707': # odc format
                header = f.read(70)
                if len(header) < 70: break
                mode = int(header[12:18], 8)
                namesize = int(header[53:59], 8)
                filesize = int(header[59:70], 8)
                
                name_bytes = f.read(namesize)
                name = name_bytes.decode('utf-8', 'ignore').rstrip('\x00')
                if name == "TRAILER!!!": break
                
            elif magic in (b'070701', b'070702'): # newc format
                header = f.read(104)
                if len(header) < 104: break
                mode = int(header[8:16], 16)
                namesize = int(header[88:96], 16)
                filesize = int(header[48:56], 16)
                
                name_bytes = f.read(namesize)
                name = name_bytes.decode('utf-8', 'ignore').rstrip('\x00')
                
                pad = (110 + namesize) % 4
                if pad != 0: f.read(4 - pad)
                    
                if name == "TRAILER!!!": break
            else:
                break
            
            safe_name = name.lstrip('/\\')
            is_dir = stat.S_ISDIR(mode)
            is_symlink = stat.S_ISLNK(mode)
            
            # FAST-FORWARD LOGIC: Check if this is the file we want
            current_filename = os.path.basename(safe_name)
            
            if current_filename == target_filename and not is_dir and not is_symlink:
                print(f"  -> Found '{target_filename}' at: {safe_name}")
                
                # Sanitize the full path so we can save it safely on Windows
                safe_path_for_windows = sanitize_path_for_windows(safe_name)
                target_path = os.path.abspath(os.path.join(output_dir, safe_path_for_windows))
                
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with open(target_path, 'wb') as out_f:
                    bytes_left = filesize
                    while bytes_left > 0:
                        chunk = f.read(min(bytes_left, 1024 * 1024 * 10))
                        out_f.write(chunk)
                        bytes_left -= len(chunk)
                found_count += 1
            else:
                # If it's not our target file, instantly skip over its data blocks
                if filesize > 0:
                    f.seek(filesize, os.SEEK_CUR)
            
            if magic in (b'070701', b'070702'):
                pad = filesize % 4
                if pad != 0: f.seek(4 - pad, os.SEEK_CUR)
                
    return found_count

def process_payload(payload_path, output_dir, target_filename="assetutil"):
    """Determines Payload compression and searches it."""
    temp_cpio = f"{payload_path}.cpio"
    
    with open(payload_path, 'rb') as f:
        magic = f.read(4)
        
    if magic == b'pbzx':
        extract_pbzx_to_cpio(payload_path, temp_cpio)
    elif magic.startswith(b'\x1f\x8b'):
        with gzip.open(payload_path, 'rb') as f_in, open(temp_cpio, 'wb') as f_out:
            while True:
                chunk = f_in.read(1024 * 1024 * 10)
                if not chunk: break
                f_out.write(chunk)
    else:
        temp_cpio = payload_path
        
    return search_cpio_pure(temp_cpio, output_dir, target_filename)

def process_pkg(pkg_path, final_output_dir, target_filename="assetutil"):
    """Processes a single PKG file."""
    print(f"\nScanning: {pkg_path.name}")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            payloads = extract_xar_payloads(pkg_path, temp_dir)
        except Exception as e:
            print(f"  -> Error parsing XAR: {e}")
            return
            
        if not payloads:
            print("  -> No payloads found.")
            return
            
        total_found = 0
        for pkg_name, payload_path in payloads:
            target_dir = final_output_dir / pkg_path.stem / pkg_name
            found_count = process_payload(payload_path, target_dir, target_filename)
            total_found += found_count
            
        if total_found == 0:
            print(f"  -> '{target_filename}' not found in this package.")

def main(input_path, final_output_dir, target_filename="assetutil"):
    input_path = Path(input_path).resolve()
    final_output_dir = Path(final_output_dir).resolve()
    print(f"Searching for: {target_filename}")
    
    if not input_path.exists():
        print(f"Error: Input path '{input_path}' does not exist.")
        sys.exit(1)
        
    final_output_dir.mkdir(parents=True, exist_ok=True)
    
    if input_path.is_file():
        # Process single file
        if input_path.suffix.lower() == '.pkg':
            process_pkg(input_path, final_output_dir, target_filename)
        else:
            print("Error: Input file is not a .pkg file.")
    elif input_path.is_dir():
        # Process directory recursively
        pkg_files = list(input_path.rglob('*.pkg'))
        print(f"Found {len(pkg_files)} .pkg files to scan.")
        for pkg_file in pkg_files:
            process_pkg(pkg_file, final_output_dir, target_filename)
            
    print(f"\nDone! Any found '{target_filename}' binaries are in: {final_output_dir}")

if __name__ == "__main__":
    # You can change the target filename here if you want to look for something else later
    TARGET_FILE = "assetutil"
    
    if len(sys.argv) != 3:
        print(f"Usage: python pkg_ext.py <path_to_pkg_or_folder> <output_directory>")
        sys.exit(1)
        
    main(sys.argv[1], sys.argv[2], TARGET_FILE)