#!/bin/python3
import os
import re
from struct import pack, unpack
from sys import argv, exit
import hashlib

if len(argv) < 2 or argv[1] not in ('d88', 'dsk', 'fdi'):
    exit('Usage: egg_disk.py <d88|dsk|fdi>')
    
diskformat = argv[1]
disks = []

# Discover floppy and hard disk files
added_hd_group = False
for i in os.listdir('.'):
    match_fd = re.fullmatch(r'(EGGFDIMG\d+)-INF(?:\..+)?', i)
    if match_fd:
        disks.append((match_fd.group(1), i))  # (floppy disk ID, INF filename)
        continue

    if not added_hd_group:
        match_hd = re.fullmatch(r'(EGGHDIMG\d+)-INF(?:\..+)?', i)
        if match_hd:
            disks.append(('EGGHDIMG', i))  # store disk ID + INF filename
            added_hd_group = True

        
def process_floppy_disk(disk, diskformat, inf_filename):
    tracksizes = []
    outputdata = b''
    try:
        with open(inf_filename, 'rb') as inffile:
            inffile.seek(0x200)
            md5hash = inffile.read(0x10)
            null, readonly, numtracks = unpack('<III', inffile.read(12))
            print(md5hash.hex(), null, readonly, numtracks)
    except FileNotFoundError:
        print(f"ERROR: {disk}-INF not found.")
        return

    if readonly == 1:
        readonly = 0x10

    disktype = b'\x20' if numtracks > 84 else b'\x00'

    for tracknum in range(numtracks):
        # Try to find either .dat or .cl5 file for this track
        fn = f'{disk}-{tracknum}.dat'
        if not os.path.exists(fn):
            fn = f'{disk}-{tracknum}.cl5'
            if not os.path.exists(fn):
                print(f'Warning: {disk}-{tracknum}.dat/.cl5 not found, skipping.')
                if diskformat == "d88":
                    tracksizes.append(0) # Important but hacky: Adds an empty track if the trackfile is missing.
                continue

        with open(fn, 'rb') as file:
            numsectors, = unpack('<I', file.read(4))
            sectoroffs = []
            for i in range(numsectors):
                secoff, = unpack('<I', file.read(4))
                sectoroffs.append(secoff)
                
            if diskformat == 'd88':
                tracksize = 0
                for i in sectoroffs:
                    file.seek(i)
                    head = file.read(0xC)
                    # a, b, c = unpack('<III', head)
                    # print(f'{a:08x}\t{b:08x}\t{c:08x}')
                    datasize, = unpack('<I', head[-4:])
                    # print(tracknum, sectoroffs.index(i), datasize, i)
                    if datasize >= 0xFFFF:  # this doesn't work last I checked
                        print(f"Invalid sector length in track {tracknum}, skipping.")
                        continue
                        # datasize = 0x400
                        # outputdata += head[:4] + pack('B', numsectors) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00' + pack('<H', datasize)
                        # outputdata += '\xFF' * 0x400
                        # file.read(0x3F0)
                    outputdata += head[:4] + pack('B', numsectors) + b'\x00'*9 + pack('<H', datasize)
                    outputdata += file.read(datasize)
                    tracksize += datasize + 0x10
                tracksizes.append(tracksize)
                
                
            elif diskformat in ['dsk', 'fdi']:
                for i in sectoroffs:
                    file.seek(i)
                    head = file.read(0xC)
                    datasize, = unpack('<I', head[-4:])
                    outputdata += file.read(datasize)
                    # print(tracknum, sectoroffs.index(i), datasize, i)

    # Write output
    if diskformat == 'd88':
        NUM_TRACKS = max(len(tracksizes), 164)

    # Compute where the first track data will start (align to 16 bytes)
        startoff = 0x20 + NUM_TRACKS * 4
        if startoff % 16:
            startoff += 16 - (startoff % 16)

    # Build fixed header
        d88_header = b'\x00' * 0x1A
        d88_header += pack('B', readonly)
        d88_header += disktype
        d88_header += pack('<I', len(outputdata) + startoff)  # total size
        d88_header += pack('<I', startoff)                    # first track offset
        
        # Track offset table
        #print(f"tracks list: {tracksizes}")
        offset = startoff + tracksizes[0]  # Calc from second track (1) since we added first offset
        for tsize in tracksizes[1:]: # Already added first offset to the header
            if tsize > 0:
                d88_header += pack('<I', offset)
                offset += tsize
                #print(f"offset: {offset}")
            else:
                d88_header += b'\x00\x00\x00\x00'

# Pad out to NUM_TRACKS entries (all zeroes)
        for _ in range(len(tracksizes), NUM_TRACKS):
            d88_header += b'\x00\x00\x00\x00'

        # Pad header to reach startoff
        if len(d88_header) < startoff:
            d88_header += b'\x00' * (startoff - len(d88_header))

        output_filename = f'fd_{disk}.d88'
        write_and_check(output_filename, d88_header + outputdata, md5hash)
            
    elif diskformat == 'dsk':
        output_filename = f'fd_{disk}.dsk'
        write_and_check(output_filename, outputdata, md5hash=None)
            
    elif diskformat == 'fdi':
        d88_header = pack('<IIIIIIII', 0, 0x90, 0x1000, 0x134000, 0x400, 8, 2, 77)
        d88_header += b'\x00' * (0x1000 - 0x20)
        output_filename = f'fd_{disk}.fdi'
        write_and_check(output_filename, outputdata, md5hash)
            

def process_hard_disk(disk, diskformat, inf_filename):
    if disk != 'EGGHDIMG':  # We now treat EGGHDIMG as a group, not individual files
        return

    if not os.path.exists(inf_filename):
        print(f"ERROR: {inf_filename} not found.")
        return

    # Read metadata from the INF file
    with open(inf_filename, 'rb') as f:
        f.seek(0x210)  # Offset where meaningful data starts
        cyls, = unpack('<I', f.read(4))
        segs_per_cyl, = unpack('<I', f.read(4))
        sectors_per_seg, = unpack('<I', f.read(4))
        sector_size, = unpack('<I', f.read(4))

    total_segments = cyls * segs_per_cyl
    expected_file_size = sectors_per_seg * sector_size

    print(f"Detected HDD Layout: {cyls} cylinders × {segs_per_cyl} segments → {total_segments} segments")
    print(f"Each segment: {sectors_per_seg} sectors × {sector_size} bytes = {expected_file_size} bytes")

    # Collect all EGGHDIMGx.dat files in order
    files = []
    for i in range(total_segments):
        fn = f'{disk}{i}.dat'
        if not os.path.exists(fn):
            print(f"ERROR: Missing segment file: {fn}")
            return
        files.append(fn)

    # Read and concatenate all segments
    fdata = b''
    for fn in files:
        with open(fn, 'rb') as segfile:
            segdata = segfile.read()
            if len(segdata) != expected_file_size:
                print(f"WARNING: {fn} size mismatch (expected {expected_file_size}, got {len(segdata)})")
            fdata += segdata

    if diskformat == 'fdi':
        # Build FDI header
        fullsize = len(fdata) + 0x1000
        hdd_header = pack('<IIIIIIII',
            0,          # Unknown / Reserved
            0x90,       # Offset to disk header (usually 0x90)
            0x1000,     # Offset to image data
            fullsize,   # Total image size
            sector_size,
            sectors_per_seg,
            segs_per_cyl,
            cyls
        )
        hdd_header += b'\x00' * (0x1000 - 0x20)

        with open('hd_EGGHDIMG.fdi', 'wb') as disk:
            disk.write(hdd_header + fdata)
            print(f"Created hard disk image: hd_EGGHDIMG.fdi")

    elif diskformat == 'dsk':
        with open('hd_EGGHDIMG.dsk', 'wb') as disk:
            disk.write(fdata)
            print(f"Created raw disk image: hd_EGGHDIMG.dsk")

    elif diskformat == 'd88':
        print("Format 'd88' is not supported for hard disk images.")


def write_and_check(filename, data, expected_md5=None):
    """Write data to file and optionally check MD5."""
    with open(filename, 'wb') as f:
        f.write(data)
    print(f"Wrote {filename}")
    
    if expected_md5:
        md5 = hashlib.md5()
        md5.update(data)
        if md5.digest() == expected_md5:
            print(f"MD5 check passed for {filename}")
        else:
            print(f"WARNING: MD5 mismatch for {filename}")

# Run processing
for disk, inf_filename in disks:
    if disk.startswith('EGGFDIMG'):
        process_floppy_disk(disk, diskformat, inf_filename)
    elif disk == 'EGGHDIMG':
        process_hard_disk(disk, diskformat, inf_filename)
