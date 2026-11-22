// extractors.h - one entry point per supported format. Each returns true on success.
#pragma once

#include <string>

#include "common.h"

struct Context {
    fs::path    input;          // input file
    fs::path    outDir;         // already created: "<input folder>/<input stem>"
    std::string exeName;        // used by EGGDATA for key derivation (default: input stem)
    const Bytes* data = nullptr;  // entire input file
};

bool ExtractEggData(const Context& ctx);                  // EGGDATA  (AES chunks + zlib)
bool ExtractType98(const Context& ctx);                   // TYPE98 / TYPE98_old (BIN resources)
bool ExtractMsxResources(const Context& ctx, int type);   // MSXPLAYer (type 1) / D4E MSX (type 2)
bool ExtractOldPc98(const Context& ctx);                  // old_pc98_aes / old_pc98_no_aes
bool ExtractDataFileVer(const Context& ctx);              // DataFileVer (types 1-4)
bool ExtractOldXorLzss(const Context& ctx);               // old Xor + LZSS
bool ExtractOldX1(const Context& ctx);                    // old_X1
bool ExtractBind(const Context& ctx);                     // "BIND" archives
bool ExtractType60(const Context& ctx);                   // TYPE60 (embedded PE with arithmetic-coded BIN resources)
bool ExtractCnpf(const Context& ctx);                     // CNPF containers (packed game EXEs)
bool ExtractScn(const Context& ctx);                      // .SCN files (encrypted + LZSS D88 image)
