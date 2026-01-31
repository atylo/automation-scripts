#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <cstdint>
#include <filesystem>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <windows.h>

namespace fs = std::filesystem;

// ============================================================================
// UTILITIES
// ============================================================================

void WriteFile(const std::string& filename, const uint8_t* data, size_t size) {
    std::ofstream file(filename, std::ios::binary);
    if (file) {
        file.write((const char*)data, size);
        std::cout << "  -> Saved " << filename << std::endl;
    }
}

void WriteFile(const std::string& filename, const std::vector<uint8_t>& data) {
    WriteFile(filename, data.data(), data.size());
}

// ============================================================================
// RESOURCE LOADING
// ============================================================================

std::vector<uint8_t> LoadResource(HMODULE hModule, const char* resName, const char* resType) {
    HRSRC hRes = FindResourceA(hModule, resName, resType);
    if (!hRes) return {};

    HGLOBAL hData = LoadResource(hModule, hRes);
    if (!hData) return {};

    const uint8_t* ptr = (const uint8_t*)LockResource(hData);
    DWORD size = SizeofResource(hModule, hRes);

    if (!ptr || size == 0) return {};

    return std::vector<uint8_t>(ptr, ptr + size);
}

// ============================================================================
// CRYPTOGRAPHY
// ============================================================================

uint8_t CalcHash(const std::vector<uint8_t>& password) {
    if (password.empty()) return 0;
    uint8_t val = 0xFF;
    for (uint8_t b : password) {
        val ^= b;
    }
    return val;
}

void Decrypt(uint8_t* ptr, size_t len, uint8_t seed, const std::vector<uint8_t>& password, int version) {
    uint8_t key_hash = CalcHash(password);
    uint8_t combined_key;
    uint8_t shift_init;
    uint8_t mask;
    uint8_t shift_r;

    if (version == 1) {
        combined_key = (key_hash ^ seed) & 0xFF;
        shift_init = (combined_key >> 3) & 7;
        mask = 0x38;
        shift_r = 3;
    } else {
        combined_key = (~(key_hash ^ seed)) & 0xFF;
        shift_init = (combined_key >> 2) & 7;
        mask = 0x1C;
        shift_r = 2;
    }

    uint32_t prng = combined_key;
    uint8_t shift = shift_init;
    uint8_t chain = combined_key;

    for (size_t i = 0; i < len; ++i) {
        prng = (prng * 0x1000 + 0x24d69) % 0xae529;
        uint8_t xor_mask = (uint8_t)((prng * 0x100) / 0xae529);
        uint8_t val = ptr[i];
        val ^= xor_mask;

        uint8_t next_shift = (val & mask) >> shift_r;

        if (shift > 0) {
            val = (uint8_t)((val << shift) | (val >> (8 - shift)));
        }

        uint8_t layer2_out = val; 
        val ^= chain;
        ptr[i] = val;

        shift = next_shift;
        chain = layer2_out;
    }
}

// ============================================================================
// COMPRESSION (LZSS)
// ============================================================================

std::vector<uint8_t> DecompressLZSS(const uint8_t* in_ptr, size_t src_len, uint32_t uncompressed_size) {
    std::vector<uint8_t> output;
    output.resize(uncompressed_size); 

    uint8_t history[4096] = {0};
    uint32_t hist_pos = 0xFEE;

    size_t src_idx = 0;
    size_t dst_idx = 0;
    
    uint8_t* out_ptr = output.data();
    uint16_t flags = 0;
    int flag_bits = 0;

    while (dst_idx < uncompressed_size && src_idx < src_len) {
        if (flag_bits == 0) {
            flags = in_ptr[src_idx++];
            flag_bits = 8;
        }

        bool is_literal = (flags & 1);
        flags >>= 1;
        flag_bits--;

        if (is_literal) {
            if (src_idx >= src_len) break;
            uint8_t val = in_ptr[src_idx++];
            
            out_ptr[dst_idx++] = val;
            history[hist_pos] = val;
            hist_pos = (hist_pos + 1) & 0xFFF;
        } 
        else {
            if (src_idx + 1 >= src_len) break;
            uint8_t b1 = in_ptr[src_idx++];
            uint8_t b2 = in_ptr[src_idx++];

            uint32_t offset = b1 | ((b2 & 0xF0) << 4);
            uint32_t length = (b2 & 0x0F) + 3;

            for (uint32_t i = 0; i < length; ++i) {
                if (dst_idx >= uncompressed_size) break;
                uint8_t val = history[(offset + i) & 0xFFF];
                
                out_ptr[dst_idx++] = val;
                history[hist_pos] = val;
                hist_pos = (hist_pos + 1) & 0xFFF;
            }
        }
    }
    return output;
}

// ============================================================================
// PROCESSING
// ============================================================================

std::vector<uint8_t> ProcessData(std::vector<uint8_t>& raw, const std::string& name, int version, const std::vector<uint8_t>& password) {
    if (raw.size() < 13) {
        std::cout << "Error: Resource too small: " << name << std::endl;
        return {};
    }

    std::cout << "Processing: " << name << "... ";

    uint32_t* pMagic = (uint32_t*)raw.data();
    if (*pMagic != 1) {
        std::cout << "Invalid Header Magic." << std::endl;
        return {};
    }

    uint32_t uncompressed_size = *(uint32_t*)(raw.data() + 4);
    uint8_t seed = raw[12];
    
    uint8_t* payload_ptr = raw.data() + 13;
    size_t payload_len = raw.size() - 13;
    
    Decrypt(payload_ptr, payload_len, seed, password, version);

    try {
        std::vector<uint8_t> final_data = DecompressLZSS(payload_ptr, payload_len, uncompressed_size);
        
        if (final_data.size() != uncompressed_size) {
            std::cout << "Warning: Output size mismatch." << std::endl;
        }

        std::string out_name;
        if (name == "HD") {
            out_name = name + ".hdi";
        } 
        else if (name == "FONT" || name == "SOUND" || name == "BIOS" || name == "HH" || name == "TOP" || name == "SD") {
            out_name = name + ".ROM";
        } 
        else {
            out_name = name + ".bin";
        }

        WriteFile(out_name, final_data);
        return final_data;

    } catch (...) {
        std::cout << "Decompression Failed." << std::endl;
        return {};
    }
}

void ExtractFD(const std::vector<uint8_t>& data, const std::string& folder) {
    if (data.empty()) return;
    
    if (!fs::exists(folder)) {
        fs::create_directory(folder);
    }

    size_t offset = 0;
    int count = 1;
    size_t total_len = data.size();

    std::cout << "  -> Splitting FD Archive..." << std::endl;

    const uint8_t* raw_ptr = data.data();

    while (offset + 0x2B1 < total_len) {
        if (offset + 0x20 > total_len) break;
        
        uint32_t chunk_size = *(uint32_t*)(raw_ptr + offset + 0x1C);

        if (chunk_size == 0 || offset + chunk_size > total_len) break;

        std::ostringstream oss;
        oss << folder << "/disk_" << std::setw(3) << std::setfill('0') << count << ".d88";

        WriteFile(oss.str(), raw_ptr + offset, chunk_size);

        offset += chunk_size;
        count++;
    }
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "ProjectEGG TYPE98 extractor" << std::endl;

    if (argc < 2) {
        std::cout << "Usage: Drag the target game EXE onto this executable." << std::endl;
        std::cin.get();
        return 1;
    }

    std::string targetExe = argv[1];
    std::cout << "Target: " << targetExe << std::endl;

    // Load EXE as data only (to access resources)
    HMODULE hLib = LoadLibraryExA(targetExe.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hLib) {
        std::cout << "Failed to load executable resources." << std::endl;
        return 1;
    }

    int version = 1;
    std::vector<uint8_t> product_id;

    // --- Step 1: Detect Version from CFG Resource ---
    std::vector<uint8_t> cfg_raw = LoadResource(hLib, "CFG", "BIN");
    
    if (!cfg_raw.empty() && cfg_raw.size() >= 8) {
        // Reads 4 bytes at offset 4 (The Uncompressed Size field)
        uint32_t cfg_val = *(uint32_t*)(cfg_raw.data() + 4);

        if (cfg_val == 0x9E || cfg_val == 0x9F) {
            version = 2;
        }
        std::cout << "Detected Version: " << version << std::endl;

        // --- Step 2: Unpack CFG ---
        std::vector<uint8_t> cfg_data = ProcessData(cfg_raw, "CFG", version, {});
        
        size_t id_offset = (version == 2) ? 0x04 : 0x44;
        
        // Check if HD resource exists to adjust offset for Version 1
        if (version == 1) {
            HRSRC hHD = FindResourceA(hLib, "HD", "BIN");
            if (hHD) {
                id_offset = 0x04;
            }
        }
        
        if (cfg_data.size() > id_offset + 64) {
            const uint8_t* start = cfg_data.data() + id_offset;
            size_t len = 0;
            while (len < 64 && start[len] != 0) {
                len++;
            }
            product_id.assign(start, start + len);
            
            for(auto b : product_id) std::cout << std::hex << (int)b;
            std::cout << std::dec << std::endl;
        }
    } else {
        std::cout << "CFG resource missing or invalid in BIN folder." << std::endl;
    }

    // --- Step 3: Process FD ---
    std::vector<uint8_t> fd_raw = LoadResource(hLib, "FD", "BIN");
    if (!fd_raw.empty()) {
        std::vector<uint8_t> fd_data = ProcessData(fd_raw, "FD", version, product_id);
        ExtractFD(fd_data, "FD_Extracted");
    }

    // --- Step 4: Process HD ---
    std::vector<uint8_t> hd_raw = LoadResource(hLib, "HD", "BIN");
    if (!hd_raw.empty()) {
        ProcessData(hd_raw, "HD", version, product_id);
    }

    // --- Step 5: Process Optional Files ---
    const char* optionals[] = { "FONT", "SOUND", "BIOS", "HH", "TOP", "SD" };
    for (const char* name : optionals) {
        std::vector<uint8_t> raw = LoadResource(hLib, name, "BIN");
        if (!raw.empty()) {
            std::string s(name);
            std::vector<uint8_t> pw(s.begin(), s.end());
            ProcessData(raw, name, version, pw);
        }
    }

    FreeLibrary(hLib);

    std::cout << "\nDone." << std::endl;
    return 0;
}