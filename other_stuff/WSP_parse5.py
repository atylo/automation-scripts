"""WSP patch format - patcher: KAIKI101.EXE (MS-DOS/PC-98, "Touhou Kaikidan" game).

CONTAINER: KAIKI101.EXE is a normal MZ executable, but the WSP archive data
is appended directly after its own 1922-byte load module (the MZ header's
declared image size). The patcher opens its OWN running EXE file, reads and
discards the first 1922 bytes (skipping its own code), and everything after
that is the archive. So: archive_bytes = open(patcher_exe, 'rb').read()[1922:]
- no separate payload file needed if you have the patcher itself.

RECORD FORMAT (see iter_records): a sequence of records, each starting with
a 2-byte little-endian length (INCLUDING the length field itself). A length
of 0 marks the last record, whose true length is instead a fixed 0xE67A
(59002) bytes - this constant is RECORD_LAST_SENTINEL_LEN below.

Two kinds of record:
  - Banner/message records: plain text (Shift-JIS/cp932), terminated with
    '$' (the classic MS-DOS int21h AH=09 string terminator). Just
    displayed to the user by the real patcher, not a file patch.
  - File records: a fixed 40-byte header (see parse_file_header/FILE_HEADER)
    followed immediately (no gap) by that file's patch stream (see
    decode_file_stream). Confirmed identical header shape for both .EXE
    and .txt/.dat records - there is only one record format and one
    processing function in the original (fn0800_0026 in the Reko
    decompilation), applied uniformly regardless of file type.

FILE HEADER FIELDS (all little-endian):
  field_a    - constant 0x0015 (21) in every record seen so far across two
               different archives. Also happens to equal a fixed threshold
               constant used inside decode_file_stream (compared against
               segment length at disassembled offset 0x1CC) - whether
               field_a is literally read into that threshold, or the two
               are just independently the same number, is NOT confirmed.
  field_b    - varies per record. Matches the PRE-PATCH file size exactly
               for 2 of 4 known records (怪綺談.txt, MAINe.EXE) but not the
               other 2 (MAIN.EXE, 怪綺談1.dat) even after trying obvious
               adjustments. Still unidentified - lowest priority open
               question at this point.
  from_datetime / to_datetime - packed FAT (MS-DOS) date/time pairs. Every
               record shares the same to_datetime (1999-02-04 00:00) -
               apparently one release date for the whole archive. Displayed
               timestamps in a real DOS `dir` on the backup files came out
               exactly 1 hour later than the record's stored value across
               every sample - looks like a timezone/DST display quirk in
               the tool used to view them, not a decode bug.
  name1/name2 - plain null-padded cp932 (Shift-JIS) filenames, no special
               casing needed for either field. name2 is empirically name1's
               raw bytes with the first byte dropped (confirmed via a real
               directory listing: the patcher backs up the pre-patch file
               under name2 prefixed with '$', e.g. MAIN.EXE's pre-patch
               backup is $AIN.EXE). For double-byte (kanji) names this byte
               drop shifts character-pair alignment and name2 decodes to
               garbled-looking text - that's expected, not a parsing bug.
  index      - constant 1 in every record seen so far. Purpose unconfirmed.

PATCH STREAM: see decode_file_stream's own docstring - verified directly
against real x86-16 disassembly (capstone) of KAIKI101.EXE, not just Reko's
C reconstruction, which was wrong or ambiguous in several places.

VALIDATION STATUS: decode_file_stream is CONFIRMED byte-for-byte correct -
real MD5 matches against genuine DOSBox-X-patcher output for every record
type tested: MAIN.EXE (2 restarts), MAINe.EXE (0 restarts), and 怪綺談1.dat
(15 restarts, including a partial/short final window near EOF - the
trickiest case). The base-file windowing/restart mechanism (page-in
buffer, window-relative source_ptr with reset-at-restart, and the stale-
leftover-buffer case for a short final window) is fully resolved - see
decode_file_stream's own docstring for the mechanism, confirmed via a mix
of real x86-16 disassembly (capstone) and live DOSBox-X register/memory
inspection. No known remaining defect as of last check.
"""

import os
import struct

RECORD_LAST_SENTINEL_LEN = 0xE67A  # 59002 - used when the length field reads 0
FILE_HEADER = struct.Struct('<HHHHHH12sH12s')  # field_a, field_b, time1, date1, time2, date2, name1, index, name2


def decode_fat_datetime(time_word, date_word):
    year = 1980 + (date_word >> 9)
    month = (date_word >> 5) & 0x0F
    day = date_word & 0x1F
    hour = time_word >> 11
    minute = (time_word >> 5) & 0x3F
    return year, month, day, hour, minute


def iter_records(data):
    """Yield (record_bytes, is_last) for each length-prefixed record.
    record_bytes INCLUDES its own 2-byte length prefix."""
    pos = 0
    while pos + 2 <= len(data):
        length = struct.unpack_from('<H', data, pos)[0]
        is_last = (length == 0)
        if is_last:
            length = RECORD_LAST_SENTINEL_LEN
        length = min(length, len(data) - pos)  # don't run past EOF on the last/truncated record
        yield data[pos:pos + length], is_last
        if is_last:
            break
        pos += length


def is_banner_record(rec):
    """Heuristic: banner/message records are plain text terminated with '$'
    (the MS-DOS int21h AH=09 string terminator), not a 40-byte file header.
    NOTE: the original patcher actually tracks this via a leading-record
    counter (b077C) rather than content inspection - if you know how many
    banner records precede the file records, prefer counting instead."""
    content = rec[2:]
    return content.rstrip(b'\r\n').endswith(b'$')


def parse_file_header(rec):
    """rec is one record's bytes, including its 2-byte length prefix.

    Both name fields are plain null-padded, cp932 (Shift-JIS)-encoded names -
    no special-casing needed. name2 is empirically name1's raw bytes with the
    first byte dropped (matches MAIN.EXE -> ain.exe); for double-byte names
    this shifts the character alignment by one byte and decodes to garbled
    text - that's expected, not a parsing bug.
    """
    (field_a, field_b, time1, date1, time2, date2,
     name1, index, name2) = FILE_HEADER.unpack_from(rec, 2)
    return {
        'field_a': field_a,          # constant 0x0015 in every sample seen - likely archive/format tag
        'field_b': field_b,          # unknown - varies per record, not yet identified
        'from_datetime': decode_fat_datetime(time1, date1),  # per-file, varies
        'to_datetime': decode_fat_datetime(time2, date2),    # shared across records seen so far
        'name1': name1.split(b'\x00', 1)[0].decode('cp932', 'replace'),
        'index': index,
        'name2': name2.split(b'\x00', 1)[0].decode('cp932', 'replace'),
        'stream_offset': 2 + FILE_HEADER.size,  # offset into `rec` where the block/command stream starts
    }


def decode_file_stream(rec, stream_offset, base_file):
    """Decode one file record's patch stream and return the reconstructed
    output bytes.

    VALIDATION STATUS: CONFIRMED byte-for-byte correct via real MD5 matches
    against genuine DOSBox-X-patcher output, for every record type tested:
    MAIN.EXE (2 restarts), MAINe.EXE (0 restarts), 怪綺談1.dat (15 restarts).
    Every part of this function - segment framing, the persistent
    add_delta_1/add_delta_2 state, the extended skip encoding, the
    relocation pass, and the base-file windowing/restart mechanism below -
    is verified against real x86-16 disassembly (capstone) of KAIKI101.EXE
    AND live DOSBox-X register/memory inspection, not just static reading.
    There is no known remaining defect in this function as of last check.

    BASE-FILE WINDOWING / RESTART MECHANISM (fully resolved):
    The real patcher pages the base file through a fixed 0xFA00 (64000)
    byte buffer (fn0800_0489) rather than holding the whole file in memory.
    A "restart" - an extended-literal segment whose decoded length is
    exactly 0 - means that buffer just got reloaded with the next 0xFA00
    byte chunk. Three things happen at every restart (confirmed via
    disassembly at code offset 0x158, "mov word cs:[0x5CE], 0" and the
    call to fn0800_0489 right after):
      1. window_base advances by 0xFA00 (this window's absolute file
         offset).
      2. source_ptr (w05CE) resets to 0 - it is WINDOW-RELATIVE, not a
         running absolute total. This matters: an earlier version of this
         function let source_ptr accumulate forever without resetting,
         which happened to produce numerically identical results as long
         as each window was consumed exactly flush to its own boundary -
         but silently broke wherever it wasn't flush. Do not remove the
         reset.
      3. Critically, fn0800_0489 does NOT clear the buffer before reading
         into it - it just writes a single NUL byte at
         buffer[actual_bytes_just_read] as a sentinel (confirmed at code
         offset 0x49C). Near end-of-file, a window's read can come up
         SHORT (fewer than 0xFA00 bytes available), and everything in the
         buffer past that point is stale leftover content from the
         PREVIOUS window's load - not zeros, not the new window's data.
         Any source reference that lands past the real data for the
         current window must therefore resolve against the PREVIOUS
         window's base offset instead of the current one. This is exactly
         what happens in both MAIN.EXE and 怪綺談1.dat: the one segment
         immediately following each file's LAST restart references a
         position past that final (partial) window's real data, and needs
         prev_window_base rather than window_base to decode correctly.
         Only one level of "previous" is tracked here since only a file's
         FINAL window can plausibly be partial (every earlier window
         always has enough remaining file data to fill it completely).

    All of window_base/prev_window_base is added to the absolute (0xFF)
    and 15-bit-masked source forms directly. The short-relative form does
    NOT get window_base added a second time - it's already relative to
    source_ptr, which is itself window-relative and freshly based via
    window_base/prev_window_base same as everything else through the
    availability check below.

    Top level: the stream is self-terminating (control byte == 0x80
    exactly means done, confirmed at 0x17F/0x184). LITERAL segments
    (control byte high bit set, not exactly 0x80) write bytes straight to
    output from the compressed stream, bypassing the base file entirely.
    COPY segments (high bit clear) read `length` bytes from base_file at
    a computed `source` into a scratch buffer, run the relocation pass
    below (add a small configured delta at scattered positions, or
    overwrite with literal stream bytes - resolved via real disassembly at
    0x2BB-0x2D1, an area Reko's C reconstruction had ambiguous/wrong), then
    emit the scratch buffer.
    """
    SOURCE_PTR_LENGTH_THRESHOLD = 0x15  # confirmed constant at code offset 0x5D4
    WINDOW_SIZE = 0xFA00  # confirmed base-file paging chunk size, code offset 0x492

    out = bytearray()
    pc = stream_offset
    source_ptr = 0       # w05CE - WINDOW-RELATIVE, resets to 0 at every restart
    add_delta_1 = 0       # b05C2 - persistent across segments (never reset at
    add_delta_2 = 0       # w05C4 - segment start in the real code - only a real
                           # 0x80/0xF0/0xE0 prefix updates these; a segment with
                           # no such prefix (or 0xFF) reuses whatever the last
                           # one that had one left behind)
    window_base = 0       # absolute file offset of the current base-file window
    prev_window_base = 0  # absolute file offset of the PREVIOUS window - needed
                           # only for stale-buffer reads past a short final window

    def bytes_available_in_window(wb):
        return max(0, min(WINDOW_SIZE, len(base_file) - wb))

    while True:
        ctrl = rec[pc]; pc += 1

        if ctrl == 0x80:
            break  # end of this file's stream

        if ctrl & 0x80:
            # ---- literal segment ----
            length = ctrl & 0x7F
            if ctrl & 0x40:
                length = ((ctrl & 0x3F) << 8) | rec[pc]; pc += 1
                if length == 0:
                    # restart: base-file window reload
                    prev_window_base = window_base
                    window_base += WINDOW_SIZE
                    source_ptr = 0
                    continue
            out += rec[pc:pc + length]
            pc += length
            continue

        # ---- copy segment ----
        if ctrl != 0:
            length = ctrl
            if ctrl & 0x40:
                length = ((ctrl & 0x3F) << 8) | rec[pc]; pc += 1
        else:
            length = struct.unpack_from('>H', rec, pc)[0]; pc += 2

        update_source_ptr = length > SOURCE_PTR_LENGTH_THRESHOLD

        source_code = rec[pc]; pc += 1
        if (source_code & 0x80) == 0:
            source_rel = source_ptr + source_code
            update_source_ptr = True
        elif source_code == 0xFF:
            source_rel = struct.unpack_from('>H', rec, pc)[0]; pc += 2
        else:
            source_rel = ((source_code & 0x7F) << 8) | rec[pc]; pc += 1

        if update_source_ptr:
            source_ptr = source_rel + length  # stays window-relative

        # resolve window-relative -> absolute file offset, accounting for
        # the current window's real (possibly short, near-EOF) extent
        if source_rel >= bytes_available_in_window(window_base):
            source = source_rel + prev_window_base
        else:
            source = source_rel + window_base

        scratch = bytearray(base_file[source:source + length])
        if len(scratch) < length:
            scratch += bytes(length - len(scratch))

        # ---- relocation/patch pass over `scratch` ----
        has_prefix = True
        prefix = rec[pc]
        if prefix == 0x80:
            add_delta_1 = rec[pc + 1]; pc += 2
        elif prefix == 0xF0:
            add_delta_1 = rec[pc + 1]
            add_delta_2 = struct.unpack_from('<H', rec, pc + 2)[0]
            pc += 4
        elif prefix == 0xE0:
            add_delta_2 = struct.unpack_from('<H', rec, pc + 1)[0]
            pc += 3
        elif prefix == 0xFF:
            pc += 1
        else:
            has_prefix = False  # pc NOT advanced - prefix byte IS opcode #1

        di = 0
        while True:
            opcode = rec[pc]; pc += 1

            delta_mode = False
            if has_prefix:
                if opcode & 0x40:
                    delta_mode = True
                    if opcode <= 0xE0:
                        opcode &= ~0x40
                elif opcode >= 0xA0:
                    opcode |= 0xE0

            if opcode == 0x00:
                out += scratch
                break

            if opcode & 0x80:
                al = opcode & 0x7F
                if al <= 0x5F:
                    skip, unit = al, 2
                else:
                    ax_414 = al & 0x1F
                    al_418 = rec[pc]; pc += 1
                    if ax_414 & 0x10:
                        byte2 = rec[pc]; pc += 1
                        skip = (al_418 << 8) | byte2
                        unit = ax_414 & 0x0F
                    else:
                        skip, unit = al_418, ax_414
            else:
                skip, unit = opcode, 1

            di += skip
            if delta_mode:
                if unit == 1:
                    scratch[di] = (scratch[di] + add_delta_1) & 0xFF
                    di += 1
                else:
                    val = (scratch[di] | (scratch[di + 1] << 8))
                    val = (val + add_delta_2) & 0xFFFF
                    scratch[di] = val & 0xFF
                    scratch[di + 1] = (val >> 8) & 0xFF
                    di += 2
            else:
                for _ in range(unit):
                    scratch[di] = rec[pc]; pc += 1
                    di += 1

    return bytes(out)




def print_file_header(header):
    print("-" * 50)
    print(f"Field A:       {header['field_a']}")
    print(f"Field B:       {header['field_b']}")
    print(f"From datetime: {format_datetime(header['from_datetime'])}")
    print(f"To datetime:   {format_datetime(header['to_datetime'])}")
    print(f"Name 1:        {header['name1']}")
    print(f"Index:         {header['index']}")
    print(f"Name 2:        {header['name2']}")
    print(f"Stream offset: {header['stream_offset']}")


def format_datetime(dt):
    year, month, day, hour, minute = dt
    return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}"


MZ_HEADER = struct.Struct('<2sHH')  # magic, e_cblp, e_cp - enough to compute image size


def load_module_size(patcher_bytes):
    """Size of the patcher's own MZ executable image, i.e. the file offset
    where the appended WSP archive begins. Confirmed for KAIKI101.EXE
    (1922 bytes); computed from the MZ header here instead of hardcoding
    that number, so this works for any similarly-built WSP patcher."""
    magic, e_cblp, e_cp = MZ_HEADER.unpack_from(patcher_bytes, 0)
    if magic != b'MZ':
        raise ValueError(f"{patcher_bytes[:2]!r} is not an MZ executable")
    return (e_cp - 1) * 512 + (e_cblp if e_cblp else 512)


def iter_file_records(archive_bytes):
    """Yield (record_bytes, header) for every FILE record in the archive,
    transparently skipping banner/message records (which parse_file_header
    can't parse - they're plain text, not the 40-byte header)."""
    for record_bytes, is_last in iter_records(archive_bytes):
        if is_banner_record(record_bytes):
            continue
        yield record_bytes, parse_file_header(record_bytes)


def patch_all(patcher_path, base_dir='.', output_dir=None):
    """Read every file record out of a WSP patcher and apply each one whose
    base file can be found on disk.

    For each record, looks for the pre-patch base file at base_dir/name1,
    falling back to base_dir/name2 (the patcher's own backup-name
    convention - e.g. MAIN.EXE's backup is saved as ain.exe - in case the
    caller has a backup file lying around under that name instead). A
    record whose base file isn't found is skipped with a printed message,
    not treated as fatal: the archive can legitimately contain more
    records than any single install has files for (optional/localized
    files, files the user hasn't installed, etc), so one missing file
    shouldn't stop the rest from patching.

    Writes each patched result to output_dir/name1 - never over the base
    file itself, so a run is always non-destructive and repeatable.
    output_dir defaults to base_dir/'patched' and is created if missing.

    Returns a list of (name1, status, detail) tuples for programmatic use;
    status is one of 'patched', 'skipped-missing', or 'error'.
    """
    output_dir = output_dir or os.path.join(base_dir, 'patched')
    os.makedirs(output_dir, exist_ok=True)

    with open(patcher_path, 'rb') as f:
        patcher_bytes = f.read()
    archive = patcher_bytes[load_module_size(patcher_bytes):]

    results = []
    for rec, header in iter_file_records(archive):
        name = header['name1']
        base_path = os.path.join(base_dir, name)
        if not os.path.isfile(base_path):
            alt_path = os.path.join(base_dir, header['name2'])
            if os.path.isfile(alt_path):
                base_path = alt_path
            else:
                print(f"[skip] {name}: base file not found "
                      f"(tried {base_path!r} and {alt_path!r})")
                results.append((name, 'skipped-missing', base_path))
                continue

        try:
            with open(base_path, 'rb') as f:
                base_bytes = f.read()
            patched = decode_file_stream(rec, header['stream_offset'], base_bytes)
        except Exception as e:
            print(f"[error] {name}: {e}")
            results.append((name, 'error', str(e)))
            continue

        out_path = os.path.join(output_dir, name)
        with open(out_path, 'wb') as f:
            f.write(patched)
        print(f"[ok]   {name}: {len(patched)} bytes -> {out_path}")
        results.append((name, 'patched', out_path))

    n_ok = sum(1 for _, s, _ in results if s == 'patched')
    n_skip = sum(1 for _, s, _ in results if s == 'skipped-missing')
    n_err = sum(1 for _, s, _ in results if s == 'error')
    print(f"\n{n_ok} patched, {n_skip} skipped (base file not found), {n_err} errored, "
          f"out of {len(results)} file records in the archive")
    return results


if __name__ == "__main__":
    import sys
    patcher_path = sys.argv[1] if len(sys.argv) > 1 else "KAIKI101.EXE"
    base_dir = sys.argv[2] if len(sys.argv) > 2 else "."
    patch_all(patcher_path, base_dir)