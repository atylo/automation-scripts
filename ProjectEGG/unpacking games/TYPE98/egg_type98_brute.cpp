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
#include <span>

namespace fs = std::filesystem;

// ============================================================================
// UTILITIES
// ============================================================================

// Update WriteFile to accept std::filesystem::path so Windows opens native UTF-16 paths
void WriteFile(const fs::path& filepath, const uint8_t* data, size_t size) {
    std::ofstream file(filepath, std::ios::binary);
    if (file) {
        // Write the data buffer to disk
        file.write(reinterpret_cast<const char*>(data), size);

        // Convert wide path to UTF-8 for console output
        std::wstring wpath = filepath.wstring();
        int ulen = WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), (int)wpath.length(), NULL, 0, NULL, NULL);
        std::string utf8_path(ulen, 0);
        WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), (int)wpath.length(), &utf8_path[0], ulen, NULL, NULL);

        std::cout << "  -> Saved " << utf8_path << " (" << size << " bytes)" << std::endl;
    }
}

void WriteFile(const fs::path& filepath, const std::vector<uint8_t>& data) {
    WriteFile(filepath, data.data(), data.size());
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

uint8_t CalcHash(std::span<const uint8_t> password) {
    if (password.empty()) return 0;
    uint8_t val = 0xFF;
    for (uint8_t b : password) {
        val ^= b;
    }
    return val;
}

void Decrypt(uint8_t* ptr, size_t len, uint8_t seed, std::span<const uint8_t> password, int version) {
    uint8_t key_hash = CalcHash(password);
    uint8_t combined_key;
    uint8_t shift_init;
    uint8_t mask;
    uint8_t shift_r;
	
	// std::cout << "key_hash: 0x" << std::hex << static_cast<unsigned int>(key_hash) << std::dec << "\n";

    if (version == 1) {
        combined_key = (key_hash ^ seed) & 0xFF;
		// std::cout << "combined_key: 0x" << std::hex << static_cast<unsigned int>(combined_key) << std::dec << "\n";
        shift_init = (combined_key >> 3) & 7;
        mask = 0x38;
        shift_r = 3;
    } else {
        combined_key = (~(key_hash ^ seed)) & 0xFF;
		// std::cout << "combined_key: 0x" << std::hex << static_cast<unsigned int>(combined_key) << std::dec << "\n";
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

bool DecompressLZSS(const uint8_t* in_ptr, size_t src_len, uint32_t uncompressed_size, std::vector<uint8_t>& output) {
    output.clear();
    output.reserve(uncompressed_size);

    uint8_t history[4096] = {0};
    uint32_t hist_pos = 0xFEE;

    size_t src_idx = 0;
    uint16_t flags = 0;
    int flag_bits = 0;

    while (output.size() < uncompressed_size && src_idx < src_len) {
        if (flag_bits == 0) {
            flags = in_ptr[src_idx++];
            flag_bits = 8;
        }

        bool is_literal = (flags & 1);
        flags >>= 1;
        flag_bits--;

        if (is_literal) {
            if (src_idx >= src_len) return false;
            uint8_t val = in_ptr[src_idx++];
            output.push_back(val);
            history[hist_pos] = val;
            hist_pos = (hist_pos + 1) & 0xFFF;
        } 
        else {
            if (src_idx + 1 >= src_len) return false;
            uint8_t b1 = in_ptr[src_idx++];
            uint8_t b2 = in_ptr[src_idx++];

            uint32_t offset = b1 | ((b2 & 0xF0) << 4);
            uint32_t length = (b2 & 0x0F) + 3;

            for (uint32_t i = 0; i < length; ++i) {
                if (output.size() >= uncompressed_size) break;
                uint8_t val = history[(offset + i) & 0xFFF];
                output.push_back(val);
                history[hist_pos] = val;
                hist_pos = (hist_pos + 1) & 0xFFF;
            }
        }
    }

    // Garbage keys will diverge and hit EOF early or have remaining bytes
    return (output.size() == uncompressed_size) && (src_idx == src_len);
}

// ============================================================================
// PROCESSING
// ============================================================================

std::vector<uint8_t> ProcessData(std::vector<uint8_t>& raw, const std::string& name, const fs::path& outFolder) {
    if (raw.size() < 13) return {};

    uint32_t uncompressed_size = 0;
    std::memcpy(&uncompressed_size, raw.data() + 4, sizeof(uint32_t));
    uint8_t seed = raw[12];

    std::cout << "Brute-forcing: " << name << "... " << std::flush;

    for (int test_version = 1; test_version <= 2; ++test_version) {
        for (int attempt = 0; attempt < 256; ++attempt) {
            std::vector<uint8_t> test_password = { static_cast<uint8_t>(attempt) };
            std::vector<uint8_t> payload_copy(raw.begin() + 13, raw.end());
            
            Decrypt(payload_copy.data(), payload_copy.size(), seed, test_password, test_version);

            std::vector<uint8_t> final_data;
            if (!DecompressLZSS(payload_copy.data(), payload_copy.size(), uncompressed_size, final_data)) {
                continue; 
            }

            if (name == "FD") {
                if (final_data.size() < 0x20) continue;
                uint32_t first_chunk_size = *reinterpret_cast<uint32_t*>(final_data.data() + 0x1C);
                if (first_chunk_size == 0 || first_chunk_size > final_data.size()) {
                    continue; 
                }
            }

            std::cout << "Success! (Version: " << test_version 
                      << ", Key Byte: 0x" << std::hex << attempt << std::dec << ")\n";
            
            std::string out_name;
            if (name == "HD") out_name = name + ".hdi";
            else if (name == "FONT" || name == "SOUND" || name == "BIOS" || name == "HH" || name == "TOP" || name == "SD") out_name = name + ".ROM";
            else out_name = name + ".bin";

            fs::path full_path = outFolder / out_name;
            WriteFile(full_path, final_data);
            return final_data;
        }
    }

    std::cout << "Failed." << std::endl;
    return {};
}

// Decodes CP932 directly into a native Windows std::wstring (UTF-16)
std::wstring GetD88Name(const uint8_t* header) {
    char raw_name[26] = {0}; 
    std::memcpy(raw_name, header, 25); // Apparently the disk title can be more than 16 bytes?
    
    std::string s(raw_name);
    
    // Remove trailing spaces and nulls
    size_t last_char = s.find_last_not_of(" \0");
    if (last_char == std::string::npos) {
        return L"";
    }
    s.erase(last_char + 1);

    // Convert Shift-JIS (CP932) directly to std::wstring
    int wlen = MultiByteToWideChar(932, 0, s.c_str(), (int)s.length(), NULL, 0);
    if (wlen <= 0) return L"";

    std::wstring wstr(wlen, 0);
    MultiByteToWideChar(932, 0, s.c_str(), (int)s.length(), &wstr[0], wlen);

    // Sanitize illegal Windows filename characters
    const wchar_t* invalid_chars = L"\\/:*?\"<>|";
    for (wchar_t& c : wstr) {
        if (wcschr(invalid_chars, c)) {
            c = L'_';
        }
    }

    return wstr;
}

void ExtractFD(const std::vector<uint8_t>& data, const fs::path& outFolder) {
    if (data.empty()) return;

    size_t offset = 0;
    int count = 1;
    size_t total_len = data.size();

    std::cout << "  -> Splitting FD Archive..." << std::endl;

    const uint8_t* raw_ptr = data.data();

    while (offset + 0x2B1 < total_len) {
        if (offset + 0x20 > total_len) break;
        
        uint32_t chunk_size = *(uint32_t*)(raw_ptr + offset + 0x1C);

        if (chunk_size == 0 || offset + chunk_size > total_len) break;

        std::wstring disk_name = GetD88Name(raw_ptr + offset);
        fs::path file_path;
        
        if (disk_name.empty()) {
            std::wostringstream woss;
            woss << L"disk_" << std::setw(1) << std::setfill(L'0') << count << L".d88";
            file_path = outFolder / woss.str();
        } else {
            file_path = outFolder / (disk_name + L".d88");
        }

        // Prevent overwriting if multiple disks share the exact same internal name
        if (fs::exists(file_path)) {
            std::wostringstream fallback_woss;
            fallback_woss << disk_name << L"_" << count << L".d88";
            file_path = outFolder / fallback_woss.str();
        }

        WriteFile(file_path, raw_ptr + offset, chunk_size);

        offset += chunk_size;
        count++;
    }
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char* argv[]) {
	// Force terminal to output UTF-8 for Japanese text rendering
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
	
    std::cout << "ProjectEGG TYPE98 brute extractor 0.2" << std::endl;

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <executable>" << std::endl;
        return 1;
    }
	
    std::string targetExe = argv[1];
    
    // Extract filename without extension (e.g., "ESAC0019.EXE" -> "ESAC0019")
    std::string outFolder = fs::path(targetExe).stem().string();
    
    std::cout << "Target: " << targetExe << std::endl;

    // Create the output directory if it doesn't exist
    if (!fs::exists(outFolder)) {
        fs::create_directory(outFolder);
    }

    HMODULE hLib = LoadLibraryExA(targetExe.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hLib) {
        std::cout << "Failed to load executable resources." << std::endl;
        return 1;
    }

    // --- Step 1: Process FD ---
    std::vector<uint8_t> fd_raw = LoadResource(hLib, "FD", "BIN");
    if (!fd_raw.empty()) {
        std::vector<uint8_t> fd_data = ProcessData(fd_raw, "FD", outFolder);
        ExtractFD(fd_data, outFolder); // Pass the same folder so D88s drop next to FD.bin
    }

    // --- Step 2: Process HD ---
    std::vector<uint8_t> hd_raw = LoadResource(hLib, "HD", "BIN");
    if (!hd_raw.empty()) {
        ProcessData(hd_raw, "HD", outFolder);
    }

    // --- Step 3: Process Optional Files ---
    const char* optionals[] = { "FONT", "SOUND", "BIOS", "HH", "TOP", "SD", "BD", "TOM", "RIM" };
    for (const char* name : optionals) {
        std::vector<uint8_t> raw = LoadResource(hLib, name, "BIN");
        if (!raw.empty()) {
            ProcessData(raw, name, outFolder);
        }
    }

    FreeLibrary(hLib);

    std::cout << "\nDone." << std::endl;
    return 0;
}