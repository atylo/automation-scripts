#!/usr/bin/env python3
"""
GCN/DAT/gcs/CNS File Decompressor and converter
Decompresses custom LZ77/LZSS compressed image container files
used in legacy Japanese game engines? Compile
"""

import argparse
import sys
from pathlib import Path
import struct

def decompress_gcn(data: bytes) -> bytearray:
    """Decompresses a GCN byte stream into uncompressed pixel/header data."""
    in_pos = 0
    out = bytearray()
    data_len = len(data)

    while in_pos < data_len:
        cmd = data[in_pos]
        in_pos += 1

        # Command byte 0x00 signals end-of-stream
        if cmd == 0:
            break

        high = cmd & 0xF0

        try:
            # 0x00: LZ match (1-byte offset, short length)
            if high == 0x00:
                if in_pos >= data_len:
                    break
                length = (cmd & 0x0F) + 2
                offset = data[in_pos]
                in_pos += 1
                for _ in range(length):
                    out.append(out[-offset])

            # 0x10: LZ match (2-byte offset, short length)
            elif high == 0x10:
                if in_pos + 1 >= data_len:
                    break
                length = (cmd & 0x0F) + 2
                offset = data[in_pos] | (data[in_pos + 1] << 8)
                in_pos += 2
                for _ in range(length):
                    out.append(out[-offset])

            # 0x20: LZ match (1-byte offset, long length)
            elif high == 0x20:
                if in_pos + 1 >= data_len:
                    break
                length = ((cmd & 0x0F) << 8) | data[in_pos]
                offset = data[in_pos + 1]
                in_pos += 2
                for _ in range(length):
                    out.append(out[-offset])

            # 0x30: LZ match (2-byte offset, long length)
            elif high == 0x30:
                if in_pos + 2 >= data_len:
                    break
                length = ((cmd & 0x0F) << 8) | data[in_pos]
                offset = data[in_pos + 1] | (data[in_pos + 2] << 8)
                in_pos += 3
                for _ in range(length):
                    out.append(out[-offset])

            # 0x40 / 0x50: Short literal block
            elif high in (0x40, 0x50):
                length = cmd & 0x1F
                if length > 0:
                    out.extend(data[in_pos : in_pos + length])
                    in_pos += length

            # 0x60 / 0x70: Long literal block
            elif high in (0x60, 0x70):
                if in_pos >= data_len:
                    break
                length = ((cmd & 0x1F) << 8) | data[in_pos]
                in_pos += 1
                out.extend(data[in_pos : in_pos + length])
                in_pos += length

            # 0x80 - 0xFF: Combined literal + LZ match
            else:
                lit_len = (cmd & 0x70) >> 4
                if lit_len > 0:
                    out.extend(data[in_pos : in_pos + lit_len])
                    in_pos += lit_len

                if in_pos >= data_len:
                    break
                offset = data[in_pos]
                in_pos += 1
                match_len = (cmd & 0x0F) + 2
                for _ in range(match_len):
                    out.append(out[-offset])

        except IndexError:
            print(
                f"[!] Warning: Offset out of bounds during decompression at offset 0x{in_pos:X}.",
                file=sys.stderr,
            )
            break

    return out

def header8_to_bmp(data: bytes) -> bytes:
  """Parses an 8-byte header image (non-GMP200) and converts it into a standard 32-bit ARGB BMP file."""
  if len(data) < 8:
    raise ValueError("Data buffer is too short for an 8-byte header.")

  # 1. Read Header Fields
  # Bytes 2-3: Width | Bytes 4-5: Height | Bytes 6-7: Color Count - 1
  width, height, raw_colors = struct.unpack_from("<HHH", data, 2)
  num_colors = raw_colors + 1  # Java code adds 1 to header byte 6
  header_size = 8

  # 2. Determine Row Stride (var9 in Java)
  if num_colors <= 16:
    stride = (width + 7) // 8 * 8  # Aligned to 8 pixels (4 bytes)
  elif num_colors <= 256:
    stride = (width + 3) // 4 * 4  # Aligned to 4 pixels (4 bytes)
  else:
    raise ValueError(f"Unsupported color count: {num_colors}")

  # 3. Read Palette Data (4 bytes per color: B, G, R, ~A)
  palette_offset = header_size
  palette = []
  for i in range(num_colors):
    p_off = palette_offset + i * 4
    b, g, r, a = data[p_off : p_off + 4]
    alpha = (~a) & 0xFF  # Invert alpha channel
    palette.append((b, g, r, alpha))

  # 4. Unpack Pixel Data
  pixel_data_offset = palette_offset + (num_colors * 4)
  raw_pixels = data[pixel_data_offset:]

  decoded_indices = []
  if num_colors <= 16:
    # 4-bit nibbles: high nibble first, low nibble second
    total_bytes = (stride * height) // 2
    for i in range(total_bytes):
      if i < len(raw_pixels):
        b = raw_pixels[i]
        decoded_indices.append((b >> 4) & 0x0F)
        decoded_indices.append(b & 0x0F)
      else:
        decoded_indices.extend([0, 0])
  else:
    # 8-bit index per byte
    total_bytes = stride * height
    for i in range(total_bytes):
      if i < len(raw_pixels):
        decoded_indices.append(raw_pixels[i])
      else:
        decoded_indices.append(0)

  # 5. Build 32-bit BGRA BMP Array (Top-Down to Bottom-Up flip)
  bmp_pixels = bytearray()
  for y in range(height - 1, -1, -1):  # Read top-down raw data bottom-up for BMP
    for x in range(width):
      idx = decoded_indices[y * stride + x]
      color = palette[idx] if idx < len(palette) else (0, 0, 0, 255)
      bmp_pixels.extend(bytes([color[0], color[1], color[2], color[3]]))

  # 6. Construct Standard 32-bit BMP File
  dib_size = 40
  bmp_header_size = 14 + dib_size
  file_size = bmp_header_size + len(bmp_pixels)

  file_header = struct.pack(
      "<2sI4sI", b"BM", file_size, b"\x00\x00\x00\x00", bmp_header_size
  )
  dib_header = struct.pack(
      "<IIIHHIIIIII",
      dib_size,
      width,
      height,
      1,  # Planes
      32,  # 32-bit ARGB
      0,  # BI_RGB (uncompressed)
      len(bmp_pixels),
      0,
      0,
      0,
      0,
  )

  return file_header + dib_header + bmp_pixels

def gmp_to_bmp(gmp_data: bytes) -> bytes:
  """Converts an uncompressed GMP-200 byte array into a standard BMP file

  byte array, matching the C# reference implementation.
  """
  if not gmp_data.startswith(b"GMP-200"):
    raise ValueError("Invalid GMP-200 file signature.")

  # Read header fields matching the C# code offsets
  vert_pix = struct.unpack_from("<I", gmp_data, 8)[0]
  hori_pix = struct.unpack_from("<I", gmp_data, 12)[0]
  pal_start = struct.unpack_from("<I", gmp_data, 20)[0]
  data_start = struct.unpack_from("<I", gmp_data, 24)[0]
  used_colors = struct.unpack_from("<H", gmp_data, 28)[0]
  bit_depth = struct.unpack_from("<H", gmp_data, 30)[0]

  bitmap_off = used_colors * 4 + 54
  bitmap_size = vert_pix * hori_pix

  pixel_data = gmp_data[data_start : data_start + bitmap_size]
  if not pixel_data:
    pixel_data = gmp_data[data_start:]

  total_file_size = bitmap_off + len(pixel_data)

  # 1. BMP File Header (14 bytes)
  file_header = struct.pack(
      "<2sI4sI", b"BM", total_file_size, b"\x00\x00\x00\x00", bitmap_off
  )

  # 2. DIB Header / BITMAPINFOHEADER (40 bytes)
  dib_header = struct.pack(
      "<IIIHHIIIIII",
      40,  # DIB header size
      hori_pix,  # Width
      vert_pix,  # Height
      1,  # Planes
      bit_depth,
      0,  # Compression
      len(pixel_data),
      0,
      0,
      used_colors,
      0,
  )

  # 3. Palette data (extracted from palStart / offset 32 onwards)
  palette = gmp_data[pal_start : pal_start + (used_colors * 4)]

  return file_header + dib_header + palette + pixel_data
  
def main():
    parser = argparse.ArgumentParser(
        description="Decompress and convert GCN/DAT/gcs/CNS compressed image files."
    )
    parser.add_argument("input_file", type=Path, help="Path to input .GCN file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Path for output file (default: <input_filename>.bin)",
    )

    args = parser.parse_args()

    input_path: Path = args.input_file
    if not input_path.exists() or not input_path.is_file():
        print(f"[!] Error: File '{input_path}' not found.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Reading: {input_path} ({input_path.stat().st_size} bytes)")
    with open(input_path, "rb") as f:
        compressed_bytes = f.read()

    decompressed_data = decompress_gcn(compressed_bytes)
    
    if decompressed_data.startswith(b"GMP-200\x00"):
        print("[+] GMP-200 type")
        final_data = gmp_to_bmp(decompressed_data)
    elif decompressed_data.startswith(b"\x00\x00"):
        print("[+] Old image type")
        final_data = header8_to_bmp(decompressed_data)
    else:
        final_data = decompressed_data
        
    output_path: Path = (
        args.output if args.output else input_path.with_suffix(".bmp")
    )
    
    with open(output_path, "wb") as f:
        f.write(final_data)

    print(f"[+] Output written to: {output_path}")
    print(f"[+] Decompressed size: {len(final_data)} bytes")


if __name__ == "__main__":
    main()