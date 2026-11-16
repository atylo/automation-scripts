#!/usr/bin/env python3
"""
CBy3fc3 Blob Decryptor & Checker
Finds the launcher validation blob in game exes, decodes and checksums it.
"""

import sys

MARKER      = b"CBy3fc3"
XOR_KEYS    = [0x76, 0x6E]   # byte_41DD60[0], byte_41DD60[1]
MAX_PAYLOAD = 128


def nibble_swap(b: int) -> int:
    return ((b << 4) | (b >> 4)) & 0xFF


def decode_blob(data: bytes, offset: int) -> dict:
    """
    Parse and decode a blob starting at `offset` inside `data`.

    Blob layout:
      [0]      = expected checksum (sum of raw payload bytes, mod 256)
      [1]      = payload length N  (must be 1..128)
      [2..N+1] = encoded payload bytes

    Decode per byte i:
      decoded[i] = XOR_KEYS[i % 2] ^ nibble_swap(raw[i])
    """
    result = {
        "offset":   offset,
        "valid":    False,
        "reason":   "",
        "raw":      b"",
        "decoded":  b"",
        "userid":   "",
        "checksum_expected": 0,
        "checksum_actual":   0,
    }

    if offset + 2 > len(data):
        result["reason"] = "Not enough data for header"
        return result

    expected_checksum = data[offset]
    payload_len       = data[offset + 1]

    result["checksum_expected"] = expected_checksum

    if payload_len == 0 or payload_len > MAX_PAYLOAD:
        result["reason"] = (
            f"Invalid payload length: {payload_len} "
            f"(must be 1..{MAX_PAYLOAD})"
        )
        return result

    end = offset + 2 + payload_len
    if end > len(data):
        result["reason"] = (
            f"Blob truncated: need {payload_len} bytes, "
            f"only {len(data) - offset - 2} available"
        )
        return result

    raw = data[offset + 2 : end]
    result["raw"] = raw

    actual_checksum = sum(raw) & 0xFF
    result["checksum_actual"] = actual_checksum

    decoded = bytes(
        XOR_KEYS[i % 2] ^ nibble_swap(raw[i])
        for i in range(payload_len)
    )
    result["decoded"] = decoded

    try:
        result["userid"] = decoded.decode("ascii")
    except UnicodeDecodeError:
        result["userid"] = decoded.decode("latin-1")

    if actual_checksum != expected_checksum:
        result["reason"] = (
            f"Checksum MISMATCH — "
            f"expected 0x{expected_checksum:02X}, "
            f"got 0x{actual_checksum:02X}"
        )
        return result

    result["valid"]  = True
    result["reason"] = "OK"
    return result


def find_all_markers(data: bytes, marker: bytes) -> list[int]:
    positions = []
    start = 0
    while True:
        idx = data.find(marker, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    return positions


def print_result(r: dict, marker_offset: int) -> None:
    blob_offset = r["offset"]
    print(f"  Marker at file offset : 0x{marker_offset:08X} ({marker_offset})")
    print(f"  Blob   at file offset : 0x{blob_offset:08X} ({blob_offset})")
    print(f"  Checksum expected     : 0x{r['checksum_expected']:02X}")
    print(f"  Checksum actual       : 0x{r['checksum_actual']:02X}")

    if r["raw"]:
        print(f"  Raw payload           : {r['raw'].hex(' ').upper()}")
        print(f"  Decoded bytes (hex)   : {r['decoded'].hex(' ').upper()}")
        print(f"  Decoded userid        : {repr(r['userid'])}")

    status = "VALID" if r["valid"] else f"INVALID — {r['reason']}"
    print(f"  Status                : {status}")


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_exe>")
        sys.exit(1)

    path = sys.argv[1]

    try:
        with open(path, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: file not found: {path}")
        sys.exit(1)
    except PermissionError:
        print(f"Error: permission denied: {path}")
        sys.exit(1)

    print(f"File  : {path}")
    print(f"Size  : {len(data)} bytes (0x{len(data):X})")
    print(f"Marker: {MARKER.decode()} ({MARKER.hex(' ').upper()})")
    print()

    positions = find_all_markers(data, MARKER)

    if not positions:
        print("No CBy3fc3 marker found in this file.")
        sys.exit(1)

    print(f"Found {len(positions)} marker(s):\n")

    all_valid = True
    for i, marker_off in enumerate(positions, 1):
        blob_off = marker_off + len(MARKER)
        print(f"[{i}/{len(positions)}]")
        r = decode_blob(data, blob_off)
        print_result(r, marker_off)
        if not r["valid"]:
            all_valid = False
        print()

    sys.exit(0 if all_valid else 2)


if __name__ == "__main__":
    main()