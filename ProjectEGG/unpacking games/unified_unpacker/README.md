# egg_unpack

**egg_unpack** is a unified tool for detecting and extracting most prevelent formats used by ProjectEGG games and related legacy game packages.

Detects supported ProjectEGG obfuscation types and archive files, like BIND, .SCN and CNPF .bin 
It is designed for the formats it recognises; it's not a universal executable or archive unpacker.

It extracts, and names .d88 disks, and concatenates those scattered into chunks.
Splits certain concatenated ROM files into their recognised components when enough of the file can be matched.
And uses an embedded ROM database based on MAME and blueMSX data to identify known ROMs and assign recognised filenames.


## Usage

###Detect a game type

```text
egg_unpack <file>
```

### Extract a file

```text
egg_unpack x <file>
```

### Or extract with debug

```text
egg_unpack d <file>
```


## Output

Extracted files are written to a directory next to the input file. By default, the directory is named after the input filename without its extension.


## Notes and limitations

- Detection relies on known signatures, strings, and structural checks. Unknown or modified formats may not be recognised.
- If more than one supported type matches the same file, extraction stops rather than guessing which extractor should be used.
- `CNPF` archives with compression types other than the implemented LZSS mode are extracted as stored data; they are not decompressed.
- ROM identification depends on a match in the ROM database included with the source. Unrecognised ROM data is still saved, but may keep its original or generic filename.
- Debug mode is useful when an archive is malformed or extraction is incomplete because most warnings and detailed diagnostics are only printed in that mode. It also retains selected intermediate files.

## Changelog

### 0.2.3.1

- **CNPF:** Detect the manifest layout (filenames only or `name,attribute` pairs) and entry-header size (6 or 9 bytes) from the archive data. The version label is treated only as a hint because archives labelled `VR02` exist with and without attributes.
- **CNPF:** Report malformed archive conditions in debug output, including unsupported compression types, unknown file types or version labels, archive-size mismatches, truncated archives, entries that do not end at the archive boundary, manifest/file-count mismatches, duplicate filenames, invalid decompressed sizes, and fewer extracted files than announced.

### 0.2.3

- Added CNPF archive extraction.
- Move EGGDATA disk chunks that cannot be verified into separate `<disk id>_chunks` directories.

### 0.2.2.1

- Fixed EGGDATA disk-chunk assembly for alternate filename patterns.
- Allow assembly when a folder contains both FD and HD chunks.

### 0.2.2

- Added EGGDATA D88 floppy-disk and HD hard-disk chunk assembly.

### 0.2.1.2

- Fixed EGGDATA extraction failures caused by lowercase filenames.
- Added documented exit codes: `0` for successful extraction, `1` for failure, `2` when a detected type has no extractor, and `3` when there is nothing to extract (for example, an MSX player that loads external ROM files).

### 0.2.1.1

- Fixed incorrect disk-name assignment.
- Use resources from embedded executables (nested PE images) for all resource-based formats.
- Save TYPE98 rhythm sample resources (`HH`, `TOP`, `SD`, `BD`, `TOM`, and `RIM`) as `.wav` files.

### 0.2.1

- Fixed ROM extraction and added disk-name assignment.
- Added ROM renaming based on hashes, using a database generated from MAME and blueMSX. MSX ROMs receive their conventional filenames when a match is available.
- Detect bitmaps by their file signature and save them with the `.bmp` extension. Unnamed bitmaps are saved as `EGGLOGO.bmp`.
- Split recognised ROMs from ROM sets stored in a single file (for example, the PC-8801 `BOOT.rom`) into a `<name>_parts` directory.

### 0.2

- Added ROM cutting and extraction support.

### 0.1.3

- Added TYPE60 support.

### 0.1.2

- Added SCN extraction and PDS-to-D88 conversion support.

### 0.1.1

- Added the EGGDATA CONFIG password finder.
- Added command-line modes: detection by default, `x <file>` for extraction, and `d <file>` or `--debug` for verbose extraction output.

### 0.1

- Added extraction support for EGGDATA, TYPE98, old PC-98, old X1, XOR + LZSS, DataFileVer, BIND archives, and both supported MSX player formats.
- Added file-type detection.
