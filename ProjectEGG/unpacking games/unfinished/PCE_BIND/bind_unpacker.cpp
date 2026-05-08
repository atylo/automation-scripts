#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <filesystem>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <sstream>

namespace fs = std::filesystem;

// --- CONFIGURATION ---
// Set to true to force debug output via code, though it can now be passed as a flag.
const bool DEFAULT_DEBUG_MODE = false;

// --- BITWISE HELPERS ---
inline uint32_t ror32(uint32_t val, uint32_t n) {
    n %= 32;
    if (n == 0) return val;
    return (val >> n) | (val << (32 - n));
}

inline uint32_t rol32(uint32_t val, uint32_t n) {
    n %= 32;
    if (n == 0) return val;
    return (val << n) | (val >> (32 - n));
}

class BindArchive {
private:
    std::string file_path;
    bool debug;
    std::vector<uint8_t> raw;
    uint32_t session_key = 0;
	bool header_ready = false;

    struct Header {
        uint32_t table_off;
        uint32_t table_sz;
        uint32_t meta_off;
        uint32_t meta_sz;
        uint32_t data_off;
    } header{};

    uint32_t get_factor(uint32_t a2) {
        return ror32(session_key, (a2 + 17) % 32);
    }

    std::string to_hex_string(const std::vector<uint8_t>& data, size_t limit = 0) {
        std::stringstream ss;
        size_t len = limit > 0 ? std::min(data.size(), limit) : data.size();
        for (size_t i = 0; i < len; ++i) {
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
            if (limit == 0 && i < len - 1) ss << " "; 
        }
        return ss.str();
    }

public:
    BindArchive(const std::string& path, bool dbg) : file_path(path), debug(dbg) {
        std::ifstream file(file_path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file: " + file_path);
        }
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        raw.resize(size);
        if (!file.read(reinterpret_cast<char*>(raw.data()), size)) {
            throw std::runtime_error("Failed to read file completely.");
        }
    }

    void derive_header() {
        if (raw.size() < 40) throw std::runtime_error("File too small to contain valid header.");

        // 1. Project ID & Session Key
        std::string project_id = "";
        for (int i = 0; i < 8; ++i) {
            project_id += static_cast<char>(((raw[8 + i] + 119) ^ (51 * i)) & 0xFF);
        }
        
        uint32_t v2 = 0, v3 = 0;
        for (char c : project_id) {
            uint32_t val = static_cast<uint8_t>(c);
            v2 = val + 16 * v2;
            v3 += val;
        }
        session_key = ror32(v2 - 2083412177, (v3 + 61) % 32);

        // 2. Decrypt the 6 Table Integers
		// raw_hdr[5] is read to maintain correct struct size (6 x uint32 = 24 bytes)
		// but is reserved/checksum, who knows
        uint32_t raw_hdr[6];
        std::memcpy(raw_hdr, &raw[16], 6 * sizeof(uint32_t));

        header.table_off = rol32(raw_hdr[0], 7)  - get_factor(11) + 0x4CBD70AA;
        header.table_sz  = rol32(raw_hdr[1], 15) - get_factor(13) + 0x68CC8AEE;
        header.meta_off  = rol32(raw_hdr[2], 9)  - get_factor(15) - 0x7F61DB27;
        header.meta_sz   = rol32(raw_hdr[3], 19) - get_factor(17) + 0x12BDD8CF;
        header.data_off  = rol32(raw_hdr[4], 27) - get_factor(19) + 0x56E54C39;

        if (debug) {
            std::cout << std::string(60, '=') << "\n";
            std::cout << "DEBUG: HEADER INFO\n";
            std::cout << std::string(60, '=') << "\n";
            std::cout << "Project ID:      " << project_id << "\n";
            std::cout << "Session Key:     0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << session_key << std::dec << "\n";
            std::cout << "Table Offset:    " << header.table_off << " (0x" << std::hex << std::uppercase << header.table_off << std::dec << ")\n";
            std::cout << "Table Size:      " << header.table_sz << " bytes (0x" << std::hex << std::uppercase << header.table_sz << std::dec << ")\n";
            std::cout << "Metadata Offset: " << header.meta_off << " (0x" << std::hex << std::uppercase << header.meta_off << std::dec << ")\n";
            std::cout << "Data Offset:     " << header.data_off << " (0x" << std::hex << std::uppercase << header.data_off << std::dec << ")\n";
            std::cout << std::string(60, '=') << "\n\n";
        }
		header_ready = true;
    }

    std::pair<std::vector<uint8_t>, std::string> decrypt_metadata(const std::vector<uint8_t>& raw_bytes) {
        std::vector<uint8_t> dec_bytes;
        std::string name = "";
        
        for (size_t i = 0; i < raw_bytes.size(); ++i) {
            uint8_t b = raw_bytes[i];
            uint32_t rot_amt = (i + 3) % 8;
            
            // Safe 8-bit rotation
            uint8_t rotated = (rot_amt == 0) ? b : static_cast<uint8_t>((b << rot_amt) | (b >> (8 - rot_amt)));
            
            // CRITICAL FIX: Use raw ror32 here, NOT get_factor (which adds 17)
            uint8_t subkey = static_cast<uint8_t>(ror32(session_key, (i + 34) % 32) & 0xFF);
            
            uint8_t res = (rotated - subkey) & 0xFF;
            dec_bytes.push_back(res);
            
            if (res != 0) {
                name += static_cast<char>(res);
            }
        }
        return {dec_bytes, name};
    }

    std::vector<uint8_t> descramble_data(const uint8_t* data, uint32_t file_size) {
        std::vector<uint8_t> decrypted(file_size);
        uint32_t param_2 = file_size;
        uint32_t iVar5 = param_2 + 0x61;
        
        for (size_t i = 0; i < file_size; ++i) {
            uint8_t b = data[i];
            // Data descrambling DOES use get_factor
            uint8_t subkey = static_cast<uint8_t>(get_factor(iVar5 - 0x4a) & 0xFF);
            uint8_t b_sub = (b - subkey) & 0xFF;
            
            uint32_t shift = iVar5 % 8;
            uint8_t rotated = (shift == 0) ? b_sub : static_cast<uint8_t>((b_sub << shift) | (b_sub >> (8 - shift)));
            
            // Use long math to ensure overflow matches & 0xFF in orig code
            decrypted[i] = static_cast<uint8_t>((rotated + param_2 - 0x23) & 0xFF);
            
            param_2--;
            iVar5--;
			//intentional unsigned uint32_t wraparound, maybe
        }
        return decrypted;
    }

    void unpack(const std::string& output_dir = "extracted") {
		if (!header_ready)
            throw std::runtime_error("derive_header() must be called before unpack()");
			
        fs::create_directories(output_dir);
        uint32_t num_files = header.table_sz / 16;
        
        for (uint32_t i = 0; i < num_files; ++i) {
            // 1. File Table Entry
            uint32_t t_pos = header.table_off + (i * 16);
            if (t_pos + 16 > raw.size()) continue;

            
			// d[3] is the 4th field of the 16-byte file table record — reserved or unknown
            uint32_t d[4];
            std::memcpy(d, &raw[t_pos], 16);
            uint32_t idx = i * 4;
            
            uint32_t m_ptr = rol32(d[0], (idx + 73) % 32) + idx - get_factor(idx) + 0x660BCDDB;
            uint32_t f_off = rol32(d[1], (idx + 1 + 85) % 32) + (idx + 1) - get_factor(idx + 1) + 0x48219C77;
            uint32_t f_sz  = rol32(d[2], (idx + 2 + 19) % 32) + (idx + 2) - get_factor(idx + 2) + 0x357712D9;
			//uint32_t unk   = rol32(d[3], (idx + 3 + 35) % 32) + (idx + 3) - get_factor(idx + 3) - 0x73FB64DA;
            
            // 2. Metadata Entry
            uint32_t m_pos = header.meta_off + m_ptr;
            // Ensure we don't read past the buffer
            if (m_pos + 12 > raw.size()) continue; 
            if (m_ptr + 12 > header.meta_sz) continue;
			
            std::vector<uint8_t> raw_m(raw.begin() + m_pos, raw.begin() + m_pos + 12);
            auto [dec_m, fname] = decrypt_metadata(raw_m);
            
            // --- THE FIX: Truncate extension to 3 symbols ---
            size_t dot_pos = fname.find_last_of('.');
            if (dot_pos != std::string::npos) {
                // If there's a dot, keep only the dot + 3 characters (e.g., .bmp)
                if (fname.length() > dot_pos + 4) {
                    fname = fname.substr(0, dot_pos + 4);
                }
            }
            
            // 3. Data Extraction
            uint32_t d_pos = header.data_off + f_off;
            std::vector<uint8_t> clean_data;
            if (f_sz > 0 && d_pos + f_sz <= raw.size()) {
                clean_data = descramble_data(&raw[d_pos], f_sz);
            }
            std::string peek = clean_data.empty() ? "00000000" : to_hex_string(clean_data, 4);

            // --- OUTPUT ---
            if (debug) {
                std::cout << "FILE " << std::setw(3) << std::setfill('0') << i << ": " << fname << "\n";
                std::cout << "  [FileTable Entry @ " << t_pos << " (0x" << std::hex << std::uppercase << t_pos << std::dec << ")]\n";
				std::vector<uint8_t> raw_t(&raw[t_pos], &raw[t_pos + 16]);
                std::cout << "    Raw Hex: " << to_hex_string(raw_t) << "\n";
                std::cout << "    Dec Hex: " << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << m_ptr << " " 
                          << f_off << " " << f_sz << " " << d[3] << std::dec << "\n";
                std::cout << "  [Metadata Entry @ " << m_pos << " (0x" << std::hex << std::uppercase << m_pos << std::dec << ")]\n";
                std::cout << "    Raw Hex: " << to_hex_string(raw_m) << "\n";
                std::cout << "    Dec Hex: " << to_hex_string(dec_m) << "\n";
                std::cout << "  [Data Block]\n";
                std::cout << "    Absolute Offset: " << d_pos << " (0x" << std::hex << std::uppercase << d_pos << std::dec << ")\n";
                std::cout << "    File Size:       " << f_sz << " bytes (0x" << std::hex << std::uppercase << f_sz << std::dec << ")\n";
                std::cout << "    Header Peek:     0x" << peek << "\n";
                std::cout << std::string(60, '-') << "\n";
            } else {
                std::cout << "Saved: " << std::left << std::setw(20) << fname << "\n"
                          << "Size: " << std::right << f_sz << "\n";
            }

            // Save File
            std::string safe_name = "";
            for (char c : fname) {
                if (std::isalnum(c) || c == '.' || c == '_' || c == '-' || c == ' ') {
                    safe_name += c;
                }
            }
            if (safe_name.empty()) safe_name = "file_" + std::to_string(i) + ".bin";

            fs::path out_file = fs::path(output_dir) / fs::path(safe_name).filename();
            std::ofstream out(out_file, std::ios::binary);
            if (out.is_open() && !clean_data.empty()) {
                out.write(reinterpret_cast<const char*>(clean_data.data()), clean_data.size());
            }
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <archive.bnd/etc> [--debug]\n";
        return 1;
    }

    std::string filepath = argv[1];
    bool debug_mode = DEFAULT_DEBUG_MODE;

    // Check for --debug flag
    if (argc >= 3 && std::string(argv[2]) == "--debug") {
        debug_mode = true;
    }

    try {
        BindArchive archive(filepath, debug_mode);
        archive.derive_header();
        archive.unpack("extracted");
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}