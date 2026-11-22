// keyfinder.h - recovers the CONFIG-key "name" of an EGGDATA executable when the EXE file name no
// longer matches (port of finder_fixed2.cpp, using the shared MD5/AES instead of BCrypt).
#pragma once

#include <string>

#include "common.h"

namespace keyfinder {

// `firstBlock` = first 16 bytes of the encrypted CONFIG payload. Tries "GAME", then every
// "E<prefix>NNNN" candidate, NNNN = 0000-9999 (prefix list ordered by frequency). Returns true and the winning
// name when the block decrypts to the CONFIG magic "DATA\x01\x00".
bool FindConfigName(const uint8_t firstBlock[16], std::string& nameOut);

}  // namespace keyfinder
