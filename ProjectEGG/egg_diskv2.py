#!/bin/python3
import os
import re
from binascii import hexlify
from struct import pack, unpack
from sys import argv, exit

if len(argv) < 2 or argv[1] not in ('d88', 'dsk', 'fdi'):
    exit('Usage: egg_disk.py <d88|dsk|fdi>')
    
diskformat = argv[1]
disks = []

# Discover floppy and hard disk files
added_hd_group = False
for i in os.listdir('.'):
    match_fd = re.match(r'(EGGFDIMG\d+)-INF\.dat$', i)
    if match_fd:
        disks.append(match_fd.group(1))
        continue

    if not added_hd_group and re.match(r'EGGHDIMG\d+\.dat$', i):
        disks.append('EGGHDIMG')  # Add once for the whole hard disk group
        added_hd_group = True

        
def process_floppy_disk(disk, diskformat):
    tracksizes = []
    f = b''
    try:
        with open(f'{disk}-INF.dat', 'rb') as inffile:
            inffile.seek(0x200)
            sha1hash = inffile.read(0x10)
            null, ro, numtracks = unpack('<III', inffile.read(12))
            print(hexlify(sha1hash).decode('ascii'), null, ro, numtracks)
    except FileNotFoundError:
        print(f"ERROR: {disk}-INF.dat not found.")
        return

    if ro == 1:
        ro = 16

    dtype = b'\x20' if numtracks > 84 else b'\x00'

    for d in range(numtracks):
        # Try to find either .dat or .cl5 file for this track
        fn = f'{disk}-{d}.dat'
        if not os.path.exists(fn):
            fn = f'{disk}-{d}.cl5'
            if not os.path.exists(fn):
                print(f'ERROR: {disk}-{d}.dat/.cl5 NOT FOUND')
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
                    ssize, = unpack('<I', head[-4:])
                    # print(d, sectoroffs.index(i), ssize, i)
                    if ssize >= 0xFFFF:  # this doesn't work last I checked
                        print(f"Invalid sector length in track {d}, skipping.")
                        continue
                        # ssize = 0x400
                        # f += head[:4] + pack('B', numsectors) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00' + pack('<H', ssize)
                        # f += '\xFF' * 0x400
                        # file.read(0x3F0)
                    f += head[:4] + pack('B', numsectors) + b'\x00'*9 + pack('<H', ssize)
                    f += file.read(ssize)
                    tracksize += ssize + 0x10
                tracksizes.append(tracksize)
                
                
            elif diskformat in ['dsk', 'fdi']:
                for i in sectoroffs:
                    file.seek(i)
                    head = file.read(0xC)
                    ssize, = unpack('<I', head[-4:])
                    f += file.read(ssize)
                    # print(d, sectoroffs.index(i), ssize, i)

    # Write output
    if diskformat == 'd88':
        fhead = b'\x00' * 0x1A
        fhead += pack('B', ro)
        fhead += dtype
        if len(tracksizes) > 164:
            startoff = 0x20 + len(tracksizes) * 4 + ((len(tracksizes) * 4) % 16)
        else:
            startoff = 0x2B0  # 0x20 + 164 * 4 + ((164 * 4) % 16)
        o = startoff
        fhead += pack('<II', len(f)+o, o)
        for i in tracksizes[1:]:
            o += i
            fhead += pack('<I', o)

        fhead += b'\x00' * abs(startoff - len(fhead))

        with open(f'fd_{disk}.d88', 'wb') as d:
            d.write(fhead+f)
            
    elif diskformat == 'dsk':
        with open(f'fd_{disk}.dsk', 'wb') as d:
            d.write(f)
            
    elif diskformat == 'fdi':
        fhead = pack('<IIIIIIII', 0, 0x90, 0x1000, 0x134000, 0x400, 8, 2, 77)
        fhead += b'\x00' * (0x1000 - 0x20)
        with open(f'fd_{disk}.fdi', 'wb') as d:
            d.write(fhead+f)

def process_hard_disk(disk, diskformat):
    if disk != 'EGGHDIMG':  # We now treat EGGHDIMG as a group, not individual files
        return

    inf_path = f'{disk}-INF.dat'
    if not os.path.exists(inf_path):
        print(f"ERROR: {inf_path} not found.")
        return

    # Read metadata from the INF file
    with open(inf_path, 'rb') as f:
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
        fhead = pack('<IIIIIIII',
            0,          # Unknown / Reserved
            0x90,       # Offset to disk header (usually 0x90)
            0x1000,     # Offset to image data
            fullsize,   # Total image size
            sector_size,
            sectors_per_seg,
            segs_per_cyl,
            cyls
        )
        fhead += b'\x00' * (0x1000 - 0x20)

        with open('hd_EGGHDIMG.fdi', 'wb') as out:
            out.write(fhead + fdata)
            print(f"Created hard disk image: hd_EGGHDIMG.fdi")

    elif diskformat == 'dsk':
        with open('hd_EGGHDIMG.dsk', 'wb') as out:
            out.write(fdata)
            print(f"Created raw disk image: hd_EGGHDIMG.dsk")

    elif diskformat == 'd88':
        print("Format 'd88' is not supported for hard disk images.")



# Run processing
for disk in disks:
    if disk.startswith('EGGFDIMG'):
        process_floppy_disk(disk, diskformat)
    elif disk == 'EGGHDIMG':
        process_hard_disk(disk, diskformat)