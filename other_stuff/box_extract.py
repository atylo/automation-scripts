#!/usr/bin/env python3
"""Extract and decode files from this family of .box archives, used by ST-Wing or Studio Wing
スタジオＷＩＮＧ

The four-byte field at the start of the archive is an archive label (for
example, ``No01`` or ``No03``), not a fixed format signature.

Directory layout:
    0x00..0x03  archive label
    0x08..0x0F  version/date text
    0x10..0x13  member count (uint32 little-endian)
    0x20..      member records, 16 bytes each

Each member record contains an 8-byte NUL-padded name, a one-byte flag,
a 24-bit little-endian data offset, and a 16-bit little-endian stored length
at record offsets +13..+14. The first 0x100 bytes of each stored member are
bitwise-complemented (XOR 0xFF); the remainder is unchanged.

Usage:
    python box_extract.py archive.box [output_directory]

Only Python's standard library is required.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

HEADER_SIZE = 0x20
COUNT_OFFSET = 0x10
RECORD_SIZE = 16
HEADER_XOR_LENGTH = 0x100


def u24le(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset:offset + 3], "little")


def u16le(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset:offset + 2], "little")


def decode_name(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", errors="replace")


def safe_filename(name: str) -> str:
    # Archive names are short ASCII identifiers, but don't let malformed
    # names create directories or escape the selected output directory.
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return cleaned or "unnamed"


@dataclass(frozen=True)
class Member:
    index: int
    name: str
    flag: int
    offset: int
    stored_size: int


def parse_archive(blob: bytes) -> tuple[str, str, list[Member]]:
    if len(blob) < HEADER_SIZE:
        raise ValueError("File is too small to contain the archive header.")

    # The first four bytes identify the particular archive (e.g. No01/No03),
    # not the format. Do not require a particular value here.
    archive_label = decode_name(blob[0:4])
    version = blob[8:16].split(b"\0", 1)[0].decode("ascii", errors="replace")
    member_count = int.from_bytes(
        blob[COUNT_OFFSET:COUNT_OFFSET + 4], "little"
    )

    if member_count < 1:
        raise ValueError(f"Implausible member count: {member_count}.")

    directory_end = HEADER_SIZE + member_count * RECORD_SIZE
    if directory_end > len(blob):
        raise ValueError(
            f"Truncated directory: {member_count} records would end at "
            f"0x{directory_end:X}, beyond the file size 0x{len(blob):X}."
        )

    members: list[Member] = []
    for i in range(member_count):
        pos = HEADER_SIZE + i * RECORD_SIZE
        record = blob[pos:pos + RECORD_SIZE]
        name = decode_name(record[:8])
        if not name:
            raise ValueError(f"Empty filename in directory record {i} at 0x{pos:X}.")

        members.append(
            Member(
                index=i,
                name=name,
                flag=record[8],
                offset=u24le(record, 9),
                stored_size=u16le(record, 13),
            )
        )

    # Check the directory and payloads as a whole. In the observed format,
    # payloads are packed consecutively immediately after the directory.
    cursor = directory_end
    for member in sorted(members, key=lambda item: (item.offset, item.index)):
        if member.offset != cursor:
            raise ValueError(
                f"Unexpected gap/overlap before {member.name!r}: expected "
                f"0x{cursor:X}, found 0x{member.offset:X}."
            )
        cursor += member.stored_size
        if cursor > len(blob):
            raise ValueError(
                f"Payload for {member.name!r} extends beyond the end of the archive."
            )

    if cursor != len(blob):
        raise ValueError(
            f"Payloads end at 0x{cursor:X}, but archive ends at 0x{len(blob):X}."
        )

    return archive_label, version, members


def decode_payload(payload: bytes) -> bytes:
    """Undo the archive's XOR-0xFF transform on the first 256 bytes."""
    decoded = bytearray(payload)
    for i in range(min(HEADER_XOR_LENGTH, len(decoded))):
        decoded[i] ^= 0xFF
    return bytes(decoded)


def identify_payload(payload: bytes) -> str:
    if payload.startswith(b"\xFF\xD8\xFF"):
        return ".jpg"
    if len(payload) >= 4 and payload[0] == 0xFF and (payload[1] & 0xE0) == 0xE0:
        return ".mp3"
    return ".bin"


def extract(archive_path: Path, output_dir: Path) -> list[Member]:
    blob = archive_path.read_bytes()
    archive_label, version, members = parse_archive(blob)
    output_dir.mkdir(parents=True, exist_ok=True)

    used_names: set[str] = set()
    counts: dict[str, int] = {}

    for member in members:
        start = member.offset
        end = start + member.stored_size
        stored = blob[start:end]
        if len(stored) != member.stored_size:
            raise ValueError(f"Short read while extracting {member.name!r}.")

        decoded = decode_payload(stored)
        extension = identify_payload(decoded)
        filename = f"{safe_filename(member.name)}{extension}"
        if filename.casefold() in used_names:
            filename = f"{safe_filename(member.name)}_{member.index:03d}{extension}"
        used_names.add(filename.casefold())

        (output_dir / filename).write_bytes(decoded)
        counts[extension] = counts.get(extension, 0) + 1

    print(f"Archive: {archive_path} ({archive_label or 'unnamed'})")
    if version:
        print(f"Version/date field: {version}")
    print(f"Files extracted: {len(members)}")
    print("File types: " + ", ".join(
        f"{extension}: {count}" for extension, count in sorted(counts.items())
    ))
    print(f"Output directory: {output_dir}")
    return members


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract and decode files from this family of BOX archives."
    )
    parser.add_argument("archive", type=Path, help="Path to the BOX archive")
    parser.add_argument(
        "output", type=Path, nargs="?", default=Path("box_extracted"),
        help="Output directory (default: box_extracted)",
    )
    args = parser.parse_args()

    try:
        extract(args.archive, args.output)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
