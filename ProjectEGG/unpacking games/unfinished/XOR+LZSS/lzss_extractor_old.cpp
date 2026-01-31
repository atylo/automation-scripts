#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

// LZSS decompression with inline inversion (data is NOT pre-XOR'd)
// This matches the EGG format where all bytes are inverted (~byte & 0xFF)
std::vector<uint8_t> decompress_lzss_inverted(const uint8_t* data, size_t size, size_t expected_output_size) {
    std::vector<uint8_t> output;
    output.reserve(expected_output_size > 0 ? expected_output_size : size * 4);

    uint8_t history[4096];
    memset(history, 0, sizeof(history));
    int history_ptr = 0xFEE;

    size_t src = 0;
    unsigned int flags = 0;

    while (src < size && (expected_output_size == 0 || output.size() < expected_output_size)) {
        flags >>= 1;
        if ((flags & 0x100) == 0) {
            if (src >= size) break;
            // Invert flag byte
            flags = 0xFF00 | ((~data[src++]) & 0xFF);
        }

        if (flags & 1) {
            // Literal - invert the byte
            if (src >= size) break;
            uint8_t val = (~data[src++]) & 0xFF;
            output.push_back(val);
            history[history_ptr] = val;
            history_ptr = (history_ptr + 1) & 0xFFF;
        } else {
            // Back reference - invert both bytes
            if (src + 1 >= size) break;
            uint8_t b1 = (~data[src++]) & 0xFF;
            uint8_t b2 = (~data[src++]) & 0xFF;
            int offset = ((b2 & 0xF0) << 4) | b1;
            int length = (b2 & 0x0F) + 3;

            for (int k = 0; k < length; k++) {
                uint8_t val = history[(offset + k) & 0xFFF];
                output.push_back(val);
                history[history_ptr] = val;
                history_ptr = (history_ptr + 1) & 0xFFF;

                if (expected_output_size > 0 && output.size() >= expected_output_size) break;
            }
        }
    }

    return output;
}

// Read 32-bit little-endian value
uint32_t read_u32(const uint8_t* data) {
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

// Detect disk format and return extension
struct DiskInfo {
    std::string extension;
    std::string name;
    std::string format;
    size_t truncate_to;  // Truncate output to this size (0 = no truncation)
};

DiskInfo detect_disk_format(const std::vector<uint8_t>& data) {
    DiskInfo info = {".bin", "", "Unknown", 0};

    if (data.size() < 0x20) return info;

    // Check for BMP image first (to avoid false 2D detection)
    if (data[0] == 'B' && data[1] == 'M') {
        info.extension = ".bmp";
        info.format = "BMP image";
        return info;
    }

    // Check for HDS format (SCSI hard disk) - "X68SCSI1" at offset 0
    if (data.size() > 16 && memcmp(&data[0], "X68SCSI1", 8) == 0) {
        info.extension = ".hds";
        info.format = "HDS (X68000 SCSI hard disk)";
        return info;
    }

    // Check for D88 format (size field at 0x1C)
    // D88 header: name (17 bytes), reserved (9 bytes), media type (1 byte), size (4 bytes)
    uint32_t d88_size = read_u32(&data[0x1C]);
    if (d88_size > 0x2B0 && d88_size <= data.size() && d88_size <= 4 * 1024 * 1024) {
        // Validate: check if track table at 0x20 looks reasonable (first track offset should be 0x2B0)
        uint32_t first_track = read_u32(&data[0x20]);
        if (first_track == 0x2B0 || first_track == 0) {
            info.extension = ".d88";
            info.format = "D88";

            // Extract name (Shift-JIS, up to 17 bytes)
            char name[18] = {0};
            for (int i = 0; i < 17 && data[i] != 0; i++) {
                name[i] = data[i];
            }
            info.name = name;

            // Media type
            uint8_t media = data[0x1B];
            if (media == 0x00) info.format += " (2D)";
            else if (media == 0x10) info.format += " (2DD)";
            else if (media == 0x20) info.format += " (2HD)";

            // Truncate to D88 size if we have trailing garbage
            if (data.size() > d88_size) {
                info.format += " (truncated)";
                info.truncate_to = d88_size;
            }

            return info;
        }
    }

    // Check for X68000 HDF (hard disk) - "X68K" at offset 0x400
    if (data.size() > 0x420 && memcmp(&data[0x400], "X68K", 4) == 0) {
        info.extension = ".hdf";
        info.format = "HDF (X68000 hard disk)";
        return info;
    }

    // Check for DIM format (256-byte header + XDF data)
    // "DIFC HEADER" signature at offset 0xAB, size 1,261,824 bytes
    if (data.size() == 1261824 && data.size() > 0xB8) {
        if (memcmp(&data[0xAB], "DIFC HEADER", 11) == 0) {
            info.extension = ".dim";
            info.format = "DIM (X68000 floppy with header)";
            return info;
        }
    }

    // Check for XDF format (exactly 1,261,568 bytes)
    if (data.size() == 1261568) {
        info.extension = ".xdf";
        info.format = "XDF (X68000 floppy)";
        return info;
    }

    // Check for XDF with extra trailing bytes (from over-decompression without exact size)
    // Truncate to exact XDF size
    if (data.size() > 1261568 && data.size() <= 1261568 + 100) {
        info.extension = ".xdf";
        info.format = "XDF (X68000, truncated)";
        info.truncate_to = 1261568;
        return info;
    }

    // Check for X68000 IPLROM (exactly 131,072 bytes = 128KB)
    // IPLROM starts with 68000 code: 2F 08 41 F9 00 00 10 00
    if (data.size() == 131072) {
        info.extension = ".dat";
        info.name = "iplrom";
        info.format = "X68000 IPLROM";
        return info;
    }

    // Check for IPLROM with trailing garbage - detect by signature and truncate to 128KB
    // IPLROM signature: starts with 2F 08 41 F9 00 00 10 00 (68000 code)
    if (data.size() > 131072 && data.size() >= 8) {
        const uint8_t iplrom_sig[] = {0x2F, 0x08, 0x41, 0xF9, 0x00, 0x00, 0x10, 0x00};
        if (memcmp(&data[0], iplrom_sig, 8) == 0) {
            info.extension = ".dat";
            info.name = "iplrom";
            info.format = "X68000 IPLROM (truncated)";
            info.truncate_to = 131072;
            return info;
        }
    }

    return info;
}

// Sanitize filename
std::string sanitize_filename(const std::string& name) {
    std::string result;
    for (char c : name) {
        if (c == ' ' || c == '/' || c == '\\' || c == ':' ||
            c == '*' || c == '?' || c == '"' || c == '<' ||
            c == '>' || c == '|') {
            result += '_';
        } else if (c >= 32 && c < 127) {
            result += c;
        }
    }
    // Trim trailing underscores/spaces
    while (!result.empty() && (result.back() == '_' || result.back() == ' ')) {
        result.pop_back();
    }
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "LZSS Blob Extractor for EGG emulator EXEs\n";
        std::cout << "Extracts disk images from b3a5acac-type blobs\n\n";
        std::cout << "Usage: " << argv[0] << " <game.exe>\n";
        return 1;
    }

    std::string exe_path = argv[1];
    std::cout << "=== Extracting from " << fs::path(exe_path).filename().string() << " ===\n";

    // Read EXE file
    std::ifstream file(exe_path, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open file\n";
        return 1;
    }

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(file_size);
    file.read(reinterpret_cast<char*>(data.data()), file_size);
    file.close();

    std::cout << "File size: " << file_size << " bytes\n";

    // Find all blob signatures (b3 a5 ac ac = "LZSS" XOR 0xFF)
    std::vector<size_t> blob_offsets;
    const uint8_t signature[] = {0xB3, 0xA5, 0xAC, 0xAC};

    for (size_t i = 0; i + 4 < file_size; i++) {
        if (memcmp(&data[i], signature, 4) == 0) {
            blob_offsets.push_back(i);
        }
    }

    if (blob_offsets.empty()) {
        std::cerr << "Error: No LZSS blobs found (signature b3 a5 ac ac)\n";
        return 1;
    }

    std::cout << "Found " << blob_offsets.size() << " blobs\n\n";

    // Create output directory
    std::string base_name = fs::path(exe_path).stem().string();
    std::string out_dir = fs::path(exe_path).parent_path().string();
    if (out_dir.empty()) out_dir = ".";
    out_dir += "/" + base_name + "_extracted";

    fs::create_directories(out_dir);

    // Process each blob
    int disk_count = 0;

    for (size_t idx = 0; idx < blob_offsets.size(); idx++) {
        size_t offset = blob_offsets[idx];

        // Calculate blob size (gap to next blob or end of file)
        size_t blob_size;
        if (idx + 1 < blob_offsets.size()) {
            blob_size = blob_offsets[idx + 1] - offset;
        } else {
            blob_size = file_size - offset;
        }

        // Sanity check - skip tiny blobs
        if (blob_size < 1000) continue;

        std::cout << "Blob " << (idx + 1) << ":\n";
        std::cout << "  Offset: 0x" << std::hex << offset << std::dec << "\n";
        std::cout << "  Compressed size: " << blob_size << " bytes\n";

        // Verify LZSS header (inverted: "LZSS" = B3 A5 AC AC when inverted)
        // We already found by signature, but double-check
        const uint8_t* blob_ptr = &data[offset];
        char sig_check[5] = {0};
        for (int i = 0; i < 4; i++) {
            sig_check[i] = (~blob_ptr[i]) & 0xFF;
        }
        if (memcmp(sig_check, "LZSS", 4) != 0) {
            std::cout << "  Skipping: Not LZSS signature\n\n";
            continue;
        }

        // Skip 6-byte header (LZSS\x00 + type byte), decompress with inline inversion
        // Pass 0 for expected_output_size since we don't have TOC info
        std::vector<uint8_t> decompressed = decompress_lzss_inverted(blob_ptr + 6, blob_size - 6, 0);

        std::cout << "  Decompressed size: " << decompressed.size() << " bytes\n";

        // Detect format
        DiskInfo info = detect_disk_format(decompressed);

        std::cout << "  Format: " << info.format << "\n";

        // Truncate to exact size if needed (removes trailing garbage from over-decompression)
        if (info.truncate_to > 0 && decompressed.size() > info.truncate_to) {
            std::cout << "  Truncating to " << info.truncate_to << " bytes (removing "
                      << (decompressed.size() - info.truncate_to) << " trailing bytes)\n";
            decompressed.resize(info.truncate_to);
        }

        // Determine output filename
        std::string out_name;
        if (!info.name.empty()) {
            out_name = sanitize_filename(info.name) + info.extension;
            std::cout << "  Disk name: \"" << info.name << "\"\n";
        } else if (info.extension == ".xdf" || info.extension == ".d88" ||
                   info.extension == ".hdf" || info.extension == ".dim" ||
                   info.extension == ".hds") {
            disk_count++;
            if (blob_offsets.size() <= 2 ||
                (info.extension == ".hdf") || (info.extension == ".hds")) {
                out_name = "disk" + info.extension;
            } else {
                out_name = "disk_" + std::to_string(disk_count) + info.extension;
            }
        } else {
            out_name = "blob_" + std::to_string(idx + 1) + info.extension;
        }

        // Save
        std::string out_path = out_dir + "/" + out_name;
        std::ofstream out(out_path, std::ios::binary);
        out.write(reinterpret_cast<char*>(decompressed.data()), decompressed.size());
        out.close();

        std::cout << "  Saved: " << out_name << "\n\n";
    }

    std::cout << "Extraction complete. Output: " << out_dir << "\n";
    return 0;
}
