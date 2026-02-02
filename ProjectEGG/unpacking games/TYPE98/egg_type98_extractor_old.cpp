#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <cstdint>
#include <filesystem>
#include <cstring>
#include <iomanip>

namespace fs = std::filesystem;

// ============================================================================
// UTILITIES
// ============================================================================

// Reads an entire file into a binary vector
std::vector<uint8_t> ReadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) return {};
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (file.read((char*)buffer.data(), size))
        return buffer;
    return {};
}

// Writes a binary vector to disk
void WriteFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (file) {
        file.write((const char*)data.data(), data.size());
        std::cout << "  -> Saved " << filename << std::endl;
    }
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

// Optimized Decryption Routine
void Decrypt(std::vector<uint8_t>& data, uint8_t seed, const std::vector<uint8_t>& password, int version) {
    uint8_t key_hash = CalcHash(password);
    uint8_t combined_key;
    uint8_t shift_init;
    uint8_t mask;
    uint8_t shift_r;

    // Version Specific Constants
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

    size_t len = data.size();
    uint8_t* ptr = data.data();

    // --- Layer 1: PRNG XOR ---
    uint32_t prng = combined_key;
    for (size_t i = 0; i < len; ++i) {
        prng = (prng * 0x1000 + 0x24d69) % 0xae529;

        uint8_t xor_mask = (uint8_t)((prng * 0x100) / 0xae529);
        ptr[i] ^= xor_mask;
    }

    // --- Layer 2: Bit Rotation ---
    uint8_t shift = shift_init;
    for (size_t i = 0; i < len; ++i) {
        uint8_t val = ptr[i];
        uint8_t current_shift = shift;
        
        // Calculate next shift based on current byte
        shift = (val & mask) >> shift_r;

        // Rotate Left
        // (val << current_shift) | (val >> (8 - current_shift))
        // Note: C++ promotes uint8 to int for shift. Mask 0xFF just to be safe.
        ptr[i] = (uint8_t)((val << current_shift) | (val >> (8 - current_shift)));
    }

    // --- Layer 3: CBC XOR Chain ---
    uint8_t chain = combined_key;
    for (size_t i = 0; i < len; ++i) {
        uint8_t original = ptr[i];
        ptr[i] ^= chain;
        chain = original;
    }
}

// ============================================================================
// COMPRESSION (LZSS)
// ============================================================================

std::vector<uint8_t> DecompressLZSS(const std::vector<uint8_t>& input, uint32_t uncompressed_size) {

    std::vector<uint8_t> output;
    output.resize(uncompressed_size); 

    // Ring Buffer History
    uint8_t history[4096] = {0};
    uint32_t hist_pos = 0xFEE;

    size_t src_idx = 0;
    size_t dst_idx = 0;
    size_t src_len = input.size();
    
    // Direct pointers
    const uint8_t* in_ptr = input.data();
    uint8_t* out_ptr = output.data();

    uint16_t flags = 0;
    int flag_bits = 0;

    while (dst_idx < uncompressed_size && src_idx < src_len) {
        // Refill 8-bit flags
        if (flag_bits == 0) {
            // flags = compressed_data[src_idx] | 0xFF00;
            // The 0xFF00 bit acts as a sentinel so we know when 8 bits are used up
            // simply by shifting right until the 0x100 bit drops off? 
            flags = in_ptr[src_idx++];
            flag_bits = 8;
        }

        // Check LSB
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
            // Reference
            if (src_idx + 1 >= src_len) break;
            uint8_t b1 = in_ptr[src_idx++];
            uint8_t b2 = in_ptr[src_idx++];

            // Offset: (b1) | (b2 upper 4 bits) << 4
            uint32_t offset = b1 | ((b2 & 0xF0) << 4);
            // Length: (b2 lower 4 bits) + 3
            uint32_t length = (b2 & 0x0F) + 3;

            for (uint32_t i = 0; i < length; ++i) {
                // Bounds check for output safety (optional for speed if confident in data)
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

struct Header {
    uint32_t magic; // Should be 1
    uint32_t uncompressed_size;
    uint32_t crc;
    uint8_t seed;
};

std::vector<uint8_t> ProcessFile(const std::string& filename, int version, const std::vector<uint8_t>& password) {
    if (!fs::exists(filename)) {
        // std::cout << "Skipping " << filename << " (Not found)" << std::endl;
        return {};
    }

    std::cout << "Processing: " << filename << "... ";
    std::vector<uint8_t> raw = ReadFile(filename);

    if (raw.size() < 13) {
        std::cout << "Error: File too small." << std::endl;
        return {};
    }

    // Parse Header
    // Magic check: 01 00 00 00
    uint32_t* pMagic = (uint32_t*)raw.data();
    if (*pMagic != 1) {
        std::cout << "Invalid Header Magic." << std::endl;
        return {};
    }

    // Extract metadata
    // Format: Magic(4) + Size(4) + CRC(4) + Seed(1) + Payload...
    uint32_t uncompressed_size = *(uint32_t*)(raw.data() + 4);
    // uint32_t crc = *(uint32_t*)(raw.data() + 8);
    uint8_t seed = raw[12];
    
    // Payload starts at 13
    std::vector<uint8_t> payload(raw.begin() + 13, raw.end());
    
    // 1. Decrypt (In-Place)
    Decrypt(payload, seed, password, version);

    // 2. Decompress
    try {
        std::vector<uint8_t> final_data = DecompressLZSS(payload, uncompressed_size);
        
        // Check integrity (rough check based on expected size)
        if (final_data.size() != uncompressed_size) {
            std::cout << "Warning: Output size mismatch." << std::endl;
        }

		std::string out_name;

		if (filename == "HD") {
			out_name = filename + ".hdi";
		} 
		else if (filename == "FONT" || filename == "SOUND" || filename == "BIOS") {
			out_name = filename + ".ROM";
		} 
		else {
			out_name = filename + ".bin";
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

    while (offset + 0x2B1 < total_len) {
        // Read size at offset + 0x1C
        if (offset + 0x20 > total_len) break;
        
        uint32_t chunk_size = *(uint32_t*)(data.data() + offset + 0x1C);

        if (chunk_size == 0 || offset + chunk_size > total_len) break;

        // Extract chunk
        std::vector<uint8_t> chunk(data.begin() + offset, data.begin() + offset + chunk_size);
        
        // Create filename: disk_001.d88
        std::ostringstream oss;
        oss << folder << "/disk_" << std::setw(3) << std::setfill('0') << count << ".d88";
        
        WriteFile(oss.str(), chunk);

        offset += chunk_size;
        count++;
    }
}

// ============================================================================
// MAIN
// ============================================================================

int main() {
    int version = 1;
    std::vector<uint8_t> product_id;

    // --- Step 1: Detect Version ---
    if (fs::exists("CFG")) {
        std::ifstream f("CFG", std::ios::binary);
        f.seekg(4);
        uint32_t cfg_size = 0;
        f.read((char*)&cfg_size, 4);

        if (cfg_size == 0x9E || cfg_size == 0x9F) {
            version = 2;
        }
        std::cout << "Detected Version: " << version << std::endl;

        // --- Step 2: Unpack CFG ---
        // CFG password is NULL (empty vector)
        std::vector<uint8_t> cfg_data = ProcessFile("CFG", version, {});
        
		// --- Determine Offset ---
        // Default V1 = 0x44, Default V2 = 0x04.
        // If V1 game has an HD file, the ID is usually at 0x04.
        size_t id_offset = (version == 2) ? 0x04 : 0x44;
        
        if (version == 1 && fs::exists("HD")) {
            id_offset = 0x04;
        }
        
        if (cfg_data.size() > id_offset + 64) {
            // The password is the raw bytes up to the first null, OR 64 bytes max.
            // Python's split(b'\x00')[0] stops at null.
            const uint8_t* start = cfg_data.data() + id_offset;
            size_t len = 0;
            while (len < 64 && start[len] != 0) {
                len++;
            }
            product_id.assign(start, start + len);
            
            // std::cout << "  -> Product ID (Hex): ";
            for(auto b : product_id) std::cout << std::hex << (int)b;
            std::cout << std::dec << std::endl;
        }
    } else {
        std::cout << "CFG missing, assuming Version 1 default." << std::endl;
    }

    // --- Step 3: Process FD ---
    std::vector<uint8_t> fd_data = ProcessFile("FD", version, product_id);
    ExtractFD(fd_data, "FD_Extracted");

    // --- Step 4: Process HD ---
    ProcessFile("HD", version, product_id);

    // --- Step 5: Process Optional Files ---
    // These use their own filename as the password
    const char* optionals[] = { "FONT", "SOUND", "BIOS", "HH", "TOP", "SD", "BD", "TOM", "RIM" };
    for (const char* name : optionals) {
        std::string s(name);
        std::vector<uint8_t> pw(s.begin(), s.end());
        ProcessFile(name, version, pw);
    }

    std::cout << "\nDone." << std::endl;
    return 0;
}