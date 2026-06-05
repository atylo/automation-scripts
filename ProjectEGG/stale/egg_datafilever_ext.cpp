#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <filesystem>

namespace fs = std::filesystem;

// --- PE & Memory Tools ---

struct Section {
    std::string name;
    uint32_t start;
    uint32_t end;
    uint32_t raw_ptr;
};

uint32_t read_u32(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 4 > data.size()) return 0;
    return data[offset] | (data[offset+1] << 8) | (data[offset+2] << 16) | (data[offset+3] << 24);
}

uint16_t read_u16(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 2 > data.size()) return 0;
    return data[offset] | (data[offset+1] << 8);
}

bool get_pe_sections(const std::vector<uint8_t>& data, uint32_t& image_base, std::vector<Section>& sections) {
    if (data.size() < 0x40) return false;

    uint32_t e_lfanew = read_u32(data, 0x3C);
    if (e_lfanew + 52 + 4 > data.size()) return false;

    image_base = read_u32(data, e_lfanew + 52);
    uint16_t num_sections = read_u16(data, e_lfanew + 6);
    uint16_t opt_size = read_u16(data, e_lfanew + 20);
    uint32_t sec_table = e_lfanew + 24 + opt_size;

    sections.clear();
    for (int i = 0; i < num_sections; i++) {
        uint32_t sec_off = sec_table + (i * 40);
        if (sec_off + 40 > data.size()) break;

        Section sec;
        sec.name = std::string(reinterpret_cast<const char*>(&data[sec_off]), 8);
        sec.name.erase(std::find(sec.name.begin(), sec.name.end(), '\0'), sec.name.end());

        uint32_t virt_addr = read_u32(data, sec_off + 12);
        uint32_t raw_size = read_u32(data, sec_off + 16);
        sec.raw_ptr = read_u32(data, sec_off + 20);
        sec.start = image_base + virt_addr;
        sec.end = image_base + virt_addr + raw_size;

        sections.push_back(sec);
    }
    return true;
}

uint32_t find_nested_pe(const std::vector<uint8_t>& data) {
    for (size_t idx = 1; idx < data.size() - 0x100; idx++) {
        if (data[idx] == 'M' && data[idx+1] == 'Z') {
            if (idx + 0x40 < data.size()) {
                uint32_t e_lfanew = read_u32(data, idx + 0x3C);
                if (e_lfanew >= 0x40 && e_lfanew < 0x400 && idx + e_lfanew + 4 < data.size()) {
                    if (data[idx + e_lfanew] == 'P' && data[idx + e_lfanew + 1] == 'E' &&
                        data[idx + e_lfanew + 2] == 0 && data[idx + e_lfanew + 3] == 0) {
                        return idx;
                    }
                }
            }
        }
    }
    return 0;
}

// --- Decryption & Decompression ---

std::vector<uint8_t> decrypt_blob(const std::vector<uint8_t>& blob, uint8_t key) {
    std::vector<uint8_t> out(blob.size());

    // Pass 1: Rotation
    uint8_t curr = key;
    for (size_t i = 0; i < blob.size(); i++) {
        uint8_t b = blob[i];
        int rot = (curr >> 3) & 0x7;
        out[i] = ((b << rot) | (b >> (8 - rot))) & 0xFF;
        curr = b;
    }

    // Pass 2: XOR
    std::vector<uint8_t> final(out.size());
    uint8_t xor_k = key;
    for (size_t i = 0; i < out.size(); i++) {
        final[i] = out[i] ^ xor_k;
        xor_k = out[i];
    }

    return final;
}

std::vector<uint8_t> decompress_lzss(const std::vector<uint8_t>& data, uint32_t output_size) {
    std::vector<uint8_t> output;
    output.reserve(output_size);

    std::vector<uint8_t> text_buf(4096, 0);
    int r = 0xFEE;
    size_t src_idx = 0;
    int flags = 0;

    while (src_idx < data.size() && output.size() < output_size) {
        flags >>= 1;
        if ((flags & 0x100) == 0) {
            if (src_idx >= data.size()) break;
            uint8_t c = data[src_idx++];
            flags = c | 0xFF00;
        }

        if (flags & 1) {
            if (src_idx >= data.size()) break;
            uint8_t c = data[src_idx++];
            output.push_back(c);
            text_buf[r] = c;
            r = (r + 1) & 0xFFF;
        } else {
            if (src_idx + 1 >= data.size()) break;
            uint8_t i = data[src_idx++];
            uint8_t j = data[src_idx++];

            int offset = i | ((j & 0xF0) << 4);
            int count = (j & 0x0F) + 3;

            for (int k = 0; k < count; k++) {
                uint8_t c = text_buf[(offset + k) & 0xFFF];
                output.push_back(c);
                text_buf[r] = c;
                r = (r + 1) & 0xFFF;
            }
        }
    }

    return output;
}

// --- Disk Entry ---

struct DiskEntry {
    uint32_t decomp;
    uint32_t va;
    uint32_t blob_off;
    uint32_t comp;
    uint8_t key;
};

// --- Type 1 Detection ---

bool is_valid_entry_13(uint32_t decomp, uint32_t va, uint32_t comp, size_t data_len, uint32_t image_base) {
    if (decomp <= 100000 || decomp >= 5000000) return false;
    if (va <= image_base || va >= image_base + 0x1000000) return false;
    if (comp <= 10000 || comp >= 5000000) return false;
    uint32_t file_off = va - image_base;
    if (file_off == 0 || file_off >= data_len) return false;
    if (file_off + comp > data_len) return false;
    return true;
}

std::vector<DiskEntry> parse_type1_entries(const std::vector<uint8_t>& data, size_t start_offset, uint32_t image_base) {
    std::vector<DiskEntry> entries;
    size_t offset = start_offset;

    if (offset + 13 > data.size()) return entries;

    // Detect format: 13-byte or 17-byte
    uint32_t decomp = read_u32(data, offset);
    uint32_t field2 = read_u32(data, offset + 4);
    uint32_t field3 = read_u32(data, offset + 8);

    int entry_data_size;
    int va_offset;

    if (is_valid_entry_13(decomp, field2, field3, data.size(), image_base)) {
        entry_data_size = 13;
        va_offset = 4;
    } else if (offset + 17 <= data.size()) {
        uint32_t va = read_u32(data, offset + 8);
        uint32_t comp = read_u32(data, offset + 12);
        if (is_valid_entry_13(decomp, va, comp, data.size(), image_base)) {
            entry_data_size = 17;
            va_offset = 8;
        } else {
            return entries;
        }
    } else {
        return entries;
    }

    // Parse entries
    while (offset + entry_data_size <= data.size()) {
        decomp = read_u32(data, offset);
        uint32_t va = read_u32(data, offset + va_offset);
        uint32_t comp = read_u32(data, offset + va_offset + 4);
        uint8_t key = data[offset + entry_data_size - 1];

        uint32_t file_off = va - image_base;
        if (file_off == 0 || file_off >= data.size() || file_off + comp > data.size()) break;

        DiskEntry entry;
        entry.decomp = decomp;
        entry.va = va;
        entry.blob_off = file_off;
        entry.comp = comp;
        entry.key = key;
        entries.push_back(entry);

        offset += entry_data_size;

        // Skip zeros
        while (offset < data.size() && data[offset] == 0x00) offset++;

        // Check for 93 6F terminator
        if (offset + 1 < data.size() && data[offset] == 0x93 && data[offset+1] == 0x6F) break;

        // Check next decomp
        if (offset + 4 <= data.size()) {
            uint32_t next_decomp = read_u32(data, offset);
            if (next_decomp <= 100000 || next_decomp >= 5000000) break;
        }
    }

    return entries;
}

std::vector<DiskEntry> find_type1_metadata(const std::vector<uint8_t>& data, uint32_t image_base) {
    std::vector<DiskEntry> entries;

    // Search for 93 6F terminator
    size_t search_start = data.size() / 2;

    for (size_t idx = search_start; idx < data.size() - 2; idx++) {
        if (data[idx] == 0x93 && data[idx+1] == 0x6F) {
            // Look backwards for FF padding
            for (size_t back = 0x10; back < 0x200 && back < idx; back++) {
                size_t check_pos = idx - back;

                if (data[check_pos] == 0xFF && data[check_pos+1] == 0xFF &&
                    data[check_pos+2] == 0xFF && data[check_pos+3] == 0xFF) {

                    size_t j = check_pos + 4;
                    while (j < idx && data[j] == 0x00) j++;

                    size_t zero_count = j - (check_pos + 4);
                    if (zero_count >= 4 && j < idx) {
                        auto test_entries = parse_type1_entries(data, j, image_base);
                        if (test_entries.size() > entries.size()) {
                            entries = test_entries;
                        }
                    }
                }
            }
            if (!entries.empty()) break;
        }
    }

    // Fallback: scan for FF padding
    if (entries.empty()) {
        for (size_t i = search_start; i < data.size() - 24; i++) {
            if (data[i] == 0xFF && data[i+1] == 0xFF && data[i+2] == 0xFF && data[i+3] == 0xFF) {
                size_t j = i + 4;
                while (j < data.size() && data[j] == 0x00) j++;

                if (j - (i + 4) >= 4 && j + 16 <= data.size()) {
                    auto test_entries = parse_type1_entries(data, j, image_base);
                    if (test_entries.size() > entries.size()) {
                        entries = test_entries;
                    }
                }
            }
        }
    }

    return entries;
}

// --- Type 2/3/4 Detection ---

uint32_t va_to_offset(uint32_t va, const std::vector<Section>& sections) {
    for (const auto& sec : sections) {
        if (va >= sec.start && va < sec.end) {
            return sec.raw_ptr + (va - sec.start);
        }
    }
    return 0;
}

bool is_valid_va(uint32_t va, const std::vector<Section>& sections) {
    for (const auto& sec : sections) {
        if (va >= sec.start && va < sec.end) return true;
    }
    return false;
}

std::vector<DiskEntry> find_type234_metadata(const std::vector<uint8_t>& data, uint32_t image_base,
                                              const std::vector<Section>& sections) {
    std::vector<DiskEntry> entries;

    // Find .data section
    const Section* data_sec = nullptr;
    for (const auto& sec : sections) {
        if (sec.name.find(".data") != std::string::npos) {
            data_sec = &sec;
            break;
        }
    }
    if (!data_sec && sections.size() >= 2) {
        data_sec = &sections[sections.size() - 2];
    }
    if (!data_sec) return entries;

    uint32_t ptr_loc = data_sec->raw_ptr + 4;
    if (ptr_loc + 4 > data.size()) return entries;

    uint32_t init_func_va = read_u32(data, ptr_loc);
    uint32_t init_offset = va_to_offset(init_func_va, sections);
    if (init_offset == 0) return entries;

    // Search for E9 0B 00 00 00 signature
    const uint8_t sig[] = {0xE9, 0x0B, 0x00, 0x00, 0x00};
    size_t sig_idx = 0;
    for (size_t i = init_offset; i < init_offset + 5000 && i + 5 <= data.size(); i++) {
        if (memcmp(&data[i], sig, 5) == 0) {
            sig_idx = i;
            break;
        }
    }
    if (sig_idx == 0) return entries;

    size_t code_start = sig_idx + 5;

    // Scrape MOV instructions (search up to 15000 bytes for files with many disks)
    std::vector<uint32_t> found_values;
    size_t cursor = code_start;
    size_t limit = cursor + 15000;

    while (cursor < limit && cursor + 10 <= data.size()) {
        if (data[cursor] == 0xC7 && data[cursor+1] == 0x05) {
            uint32_t val = read_u32(data, cursor + 6);
            found_values.push_back(val);
            cursor += 10;
        } else {
            cursor++;
        }
    }

    // Process found values
    for (size_t i = 0; i + 1 < found_values.size(); i++) {
        uint32_t blob_va = found_values[i];
        uint32_t comp_size = found_values[i+1];

        if (is_valid_va(blob_va, sections) && comp_size > 100 && comp_size < 50000000) {
            uint32_t blob_offset = va_to_offset(blob_va, sections);

            if (blob_offset && blob_offset >= 8) {
                uint8_t key = data[blob_offset - 4];
                uint32_t decomp_size = read_u32(data, blob_offset - 8);

                // Check decomp_size is reasonable (100KB - 50MB, typical D88 is ~1.2MB)
                // Note: LZSS can expand data, so comp_size may be larger than decomp_size
                if (decomp_size > 100000 && decomp_size < 50000000) {
                    DiskEntry entry;
                    entry.decomp = decomp_size;
                    entry.va = blob_va;
                    entry.blob_off = blob_offset;
                    entry.comp = comp_size;
                    entry.key = key;
                    entries.push_back(entry);
                    i++;
                }
            }
        }
    }

    return entries;
}

// --- D88 Validation ---

bool validate_d88(const std::vector<uint8_t>& data, std::string& name) {
    if (data.size() < 0x2B0) return false;

    // Get disk name (16 bytes)
    name.clear();
    for (int i = 0; i < 16 && data[i] != 0; i++) {
        if (data[i] >= 0x20 && data[i] < 0x7F) {
            name += (char)data[i];
        } else {
            name += '?';
        }
    }

    // Check comment terminator
    if (data[0x10] != 0x00) return false;

    // Check reserved bytes
    for (int i = 0x11; i < 0x1A; i++) {
        if (data[i] != 0x00) return false;
    }

    // Check media type
    uint8_t media_type = data[0x1B];
    if (media_type != 0x00 && media_type != 0x10 && media_type != 0x20 &&
        media_type != 0x30 && media_type != 0x40) return false;

    // Check disk size
    uint32_t disk_size = read_u32(data, 0x1C);
    if (disk_size != data.size()) return false;

    // Check first track offset
    uint32_t first_track = read_u32(data, 0x20);
    if (first_track != 0 && first_track < 0x2B0) return false;

    return true;
}

// --- Main Extraction ---

int extract_disks(const std::string& exe_path, const std::string& output_dir) {
    std::cout << "=== Extracting from " << fs::path(exe_path).filename().string() << " ===" << std::endl;

    // Read file
    std::ifstream file(exe_path, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not open file" << std::endl;
        return 0;
    }

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    std::cout << "File size: " << data.size() << " bytes" << std::endl;

    // Parse PE
    uint32_t image_base;
    std::vector<Section> sections;
    if (!get_pe_sections(data, image_base, sections)) {
        std::cerr << "Error: Could not parse PE header" << std::endl;
        return 0;
    }

    std::cout << "Image base: 0x" << std::hex << image_base << std::dec << std::endl;

    // Check for nested PE
    uint32_t nested_pe_offset = find_nested_pe(data);
    if (nested_pe_offset) {
        std::cout << "Nested PE at: 0x" << std::hex << nested_pe_offset << std::dec << std::endl;
    }

    // Find metadata
    std::vector<DiskEntry> entries = find_type234_metadata(data, image_base, sections);
    std::string detected_type = "2/3/4";

    if (entries.empty()) {
        entries = find_type1_metadata(data, image_base);
        detected_type = "1";
    }

    if (entries.empty()) {
        std::cerr << "Error: Could not find disk metadata" << std::endl;
        return 0;
    }

    std::cout << "Detected as Type " << detected_type << std::endl;
    std::cout << "Found " << entries.size() << " disk entries" << std::endl << std::endl;

    // Get base name
    std::string base_name = fs::path(exe_path).stem().string();
    std::string out_dir = output_dir.empty() ? fs::path(exe_path).parent_path().string() : output_dir;
    if (out_dir.empty()) out_dir = ".";

    // Extract each disk
    int extracted = 0;
    for (size_t idx = 0; idx < entries.size(); idx++) {
        const auto& e = entries[idx];

        std::cout << "Disk " << (idx + 1) << ":" << std::endl;
        std::cout << "  Decomp: " << e.decomp << ", Comp: " << e.comp
                  << ", Key: 0x" << std::hex << (int)e.key << std::dec << std::endl;

        uint32_t blob_off = e.blob_off;

        // Adjust for nested PE
        if (detected_type == "1" && nested_pe_offset) {
            blob_off = nested_pe_offset + e.blob_off;
            std::cout << "  Blob offset: 0x" << std::hex << e.blob_off << " -> 0x" << blob_off
                      << std::dec << " (nested PE adjusted)" << std::endl;
        } else {
            std::cout << "  Blob offset: 0x" << std::hex << blob_off << std::dec << std::endl;
        }

        if (blob_off + e.comp > data.size()) {
            std::cerr << "  ERROR: Blob extends beyond file!" << std::endl;
            continue;
        }

        // Extract blob
        std::vector<uint8_t> blob(data.begin() + blob_off, data.begin() + blob_off + e.comp);

        std::cout << "  Decrypting..." << std::endl;
        auto decrypted = decrypt_blob(blob, e.key);

        std::cout << "  Decompressing..." << std::endl;
        auto decompressed = decompress_lzss(decrypted, e.decomp);

        std::cout << "  Result: " << decompressed.size() << " bytes" << std::endl;

        // Validate D88
        std::string header_name;
        bool valid = validate_d88(decompressed, header_name);
        if (valid) {
            std::cout << "  Header name: \"" << header_name << "\" (valid D88)" << std::endl;
        } else {
            std::cout << "  WARNING: Invalid D88 header!" << std::endl;
            if (!header_name.empty()) {
                std::cout << "  Header name: \"" << header_name << "\"" << std::endl;
            }
        }

        // Save
        std::string out_name = out_dir + "/" + base_name + "_disk_" + std::to_string(idx + 1) + ".d88";
        std::ofstream out(out_name, std::ios::binary);
        if (out) {
            out.write(reinterpret_cast<const char*>(decompressed.data()), decompressed.size());
            out.close();
            std::cout << "  Saved to " << out_name << std::endl;
            extracted++;
        } else {
            std::cerr << "  ERROR: Could not save file!" << std::endl;
        }

        std::cout << std::endl;
    }

    std::cout << "Extraction complete. " << extracted << "/" << entries.size() << " disks extracted." << std::endl;
    return extracted;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "EGG DataFileVer extractor" << std::endl;
        std::cout << "Usage: " << argv[0] << " <game.exe> [output_dir]" << std::endl;
        std::cout << std::endl;
        std::cout << "Supports Type 1 (93 6F terminator) and Type 2/3/4 (E9 0B signature)" << std::endl;
        return 1;
    }

    std::string exe_path = argv[1];
    std::string output_dir = argc > 2 ? argv[2] : "";

    if (!fs::exists(exe_path)) {
        std::cerr << "Error: File not found: " << exe_path << std::endl;
        return 1;
    }

    extract_disks(exe_path, output_dir);
    return 0;
}
