// eggdisk.h - assembles disk images from the chunk files of EGGDATA archives (port of egg_diskv2.py).
//   EGGFDIMG<n>-INF + EGGFDIMG<n>-<track>   -> fd_EGGFDIMG<n>.d88   (floppy; chunks removed when the MD5 in the INF matches)
//   EGGHDIMG<n>-INF + EGGHDIMG<segment>     -> hd_EGGHDIMG.fdi       (hard disk)
#pragma once

#include "common.h"

namespace eggdisk {

// Looks for chunk files in `dir`, writes the assembled images next to them and returns how many were written.
size_t AssembleDisks(const fs::path& dir);

}  // namespace eggdisk
