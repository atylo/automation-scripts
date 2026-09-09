# automation-scripts

Scripts I made with the help of AI to solve simple problems and automate stuff. Feel free to use them.

## ProjectEGG

ProjectEGG (Engrossing Game Gallery) has used tons of different obfuscation schemes over the years, and I've created extractors for almost every one of them. The schemes that don't have an extractor yet, or only have an unfinished one are only used in fewer than 3 games: right now that's `BIN_megadrive` and `BIN_Fami`, both under `unpacking games/unfinished`.

The `stale` folder is just old revisions of scripts kept for reference — the maintained versions live in the parent folders.

The list of all the executables produced by ProjectEGG, Compile, and D4E can be found in `unpacking games/All_exe_types.txt`, along with the type of obfuscation used and the MD5 hash of each exe.

### Obfuscation types

Each scheme below is its own folder under `unpacking games/`, unless noted otherwise.

- **EGGDATA** — by far the most common format (well over a thousand titles). An `EGGDATA ` header followed by AES-encrypted, zlib-compressed data. `egg_EGGDATA_unpack.py` handles it.
  (Or project_egg.bms script)
- **TYPE98** / **TYPE98_old** — payloads stored as named Win32 PE resources in a `BIN` folder (FD, HD, FONT, SOUND, BIOS, etc.). `egg_type98_extractor_v2.cpp` reads them via `FindResourceA`/`LoadResource`, and gets the password from the CFG file, while `egg_type98_brute.cpp` brute-forces the per-title single-byte key against a hash+PRNG check.  `SCN_decrypt.py` extracts `.d88` scenario disks out of `.SCN` files.
- **PC98_BINARY** (`old_pc98_aes` / `old_pc98_no_aes`) — older PC-98 executables, split into an AES-encrypted variant and a plain one. `pds2d88.py` also converts the embedded PDS disk images these use into standard `.d88`.
- **DataFileVer**  — a Rotate+XOR scheme ...
- **old Xor + LZSS** (`xor_LZSS` folder) — an older disk-image scheme: XOR-keyed data compressed with LZSS. `lzss_extractor.py` is the current version, `lzss_extractor_old.cpp` is kept as a fallback.
- **MSXPLAYer / D4E MSX** — MSX-platform titles from before 2009/2010, all handled by the single `egg_msx_decrypt.py` script sitting directly in `unpacking games/`: a nibble-swap-and-shift XOR keyed on one of two known keys depending on release.
- **Compile** — FLD, MLK, and WLK archives, LZ77/LZSS-compressed `GCN`/`DAT`/`gcs`/`CNS` image containers specific to Compile-published titles.
- **EGGCONSOLE** (DPAC) — the DPAC archive format used by the Steam re-releases of console-era titles; `dpac_tool.cpp` decrypts it.
- **PCE_BIND** — the PC Engine BIND archive format: header/table parsing plus a CODE-segment decompressor, the main tools is `bind_unpacker.cpp`.
- **TYPE60** — ...
- **PC6_type2** — PC-6001 titles ...
- **old_X1** — Sharp X1 titles; a simple offset-keyed rotate+XOR descrambler.
- **BIN_Fami** / **BIN_megadrive** — Famicom and Mega Drive payloads, and the two genuinely unfinished folders. `BIN_Fami` has a working 3-pass decrypt but no proper extractor wrapped around it yet; `BIN_megadrive` doesn't work and distorts the ROMs.
- **the_rest** — one-off scripts for the handful of games that don't share a scheme with anything else, so a dedicated folder wasn't worth it: `daiva_ext.py` (DAIVA6's NZ+LZSS blob), `elate_ext.py` (Elate's custom MSX-emulator archive, aka EGGMSX? three entry types), `ys_dec.py`/`ys_search.py` (arithmetic-coded compression used in some Ys titles), `weird_msx_string_decr.py` (a one-off MSX string cipher), and `pce_bin_extractor.py` (a bare PCE `.bin` container, kinda PCE BIND related).

### UDM

An extractor for the UDM Self-Extracting Updater — basically a patcher, but one that can contain fully recoverable files (i.e. drop-in replacements). ProjectEGG often uses these for patches to the physical releases sold on ac-mall, like [this one](https://www.amusement-center.com/project/egg/special/package_daivachronicle-re/) (a page with a patcher).

### BIN archives

ProjectEGG distributes (or rather, downloads to your machine) games as special `.bin` archives, which can be extracted with `CNPF_archive_unpacker.py`, or with the `EGGbins.bms` script for QuickBMS (made by einstein95).

### Verification and patching

Some games refuse to run because, in the past, they wrote registration/validation data to the registry during install. To bypass this, use one of the patchers: `Dr0Wy3K_patcher.py` or `CBy3fc3_patcher.py`. The checkers simply verify whether a game has valid data and would therefore run.

If a game or launcher still refuses to start, try running it from cmd like this:

```
DAIVA6.exe mode=start,userid=f or DAIVA6.exe mode=start,userid=1
```
