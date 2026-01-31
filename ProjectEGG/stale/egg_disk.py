#!/bin/python3
import os
import re
from binascii import hexlify
from struct import pack, unpack
from sys import argv, exit

diskformat = argv[1]
disks = []

tracksizes = []

for i in os.listdir('.'):
	if '-INF.dat' in i:
		disks.append(re.findall(r'EGGFDIMG(\d+)-INF.dat', i)[0])

for disk in disks:
	f = b''
	with open(f'EGGFDIMG{disk}-INF.dat', 'rb') as inffile:
		inffile.seek(0x200)
		sha1hash = inffile.read(0x10)
		null, ro, numtracks = unpack('<III', inffile.read(12))
		print(hexlify(sha1hash).decode('ascii'), null, ro, numtracks)

	if ro == 1:
		ro = 16

	if numtracks > 84:
		dtype = b'\x20'
	else:
		dtype = b'\x00'

	for d in range(numtracks):
		if not os.path.exists(f'EGGFDIMG{disk}-{d}.dat'):
			if os.path.exists(f'EGGFDIMG{disk}-{d}.cl5'):
				fn = f'EGGFDIMG{disk}-{d}.cl5'
			else:
				print(f'ERROR: EGGFDIMG{disk}-{d}.dat NOT FOUND')
				continue
		else:
			fn = f'EGGFDIMG{disk}-{d}.dat'

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
						exit('Invalid sector length found')
						# ssize = 0x400
						# f += head[:4] + pack('B', numsectors) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00' + pack('<H', ssize)
						# f += '\xFF' * 0x400
						# file.read(0x3F0)
					else:
						f += head[:4] + pack('B', numsectors) + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00' + pack('<H', ssize)
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

		with open(f'disk_{disk}.d88', 'wb') as d:
			d.write(fhead+f)
	elif diskformat == 'dsk':
		with open(f'disk_{disk}.dsk', 'wb') as d:
			d.write(f)
	elif diskformat == 'fdi':
		fhead = pack('<IIIIIIII', 0, 0x90, 0x1000, 0x134000, 0x400, 8, 2, 77)
		fhead += b'\x00' * (0x1000 - 0x20)
		with open(f'disk_{disk}.fdi', 'wb') as d:
			d.write(fhead+f)
