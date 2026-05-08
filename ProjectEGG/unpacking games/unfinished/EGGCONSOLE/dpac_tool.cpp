#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <stdexcept>

// DPAC Decryptor for Steam archived games

class BinaryReader {
public:
    BinaryReader(const std::vector<uint8_t>& data)
        : buffer(data), pos(0) {}

    size_t position() const {
        return pos;
    }

    void seek(size_t newPos) {
        if (newPos > buffer.size())
            throw std::runtime_error("Seek out of bounds");

        pos = newPos;
    }

    template<typename T>
    T read() {
        if (pos + sizeof(T) > buffer.size())
            throw std::runtime_error("Unexpected EOF");

        T value;

        std::memcpy(
            &value,
            buffer.data() + pos,
            sizeof(T)
        );

        pos += sizeof(T);

        return value;
    }

    std::string read_string(size_t len) {
        if (pos + len > buffer.size())
            throw std::runtime_error("String out of bounds");

        std::string str(
            reinterpret_cast<const char*>(buffer.data() + pos),
            len
        );

        pos += len;

        return str;
    }

private:
    const std::vector<uint8_t>& buffer;
    size_t pos;
};

void decrypt_buffer(std::vector<uint8_t>& buffer) {
    // Initial seed found in Ghidra: 0x7F23BBE38FA12345
    uint64_t state = 0x7F23BBE38FA12345;

    for (size_t i = 0; i < buffer.size(); ++i) {
        // Xorshift64 Algorithm sequence: 12, 25, 27
        state ^= (state >> 12);
        state ^= (state << 25);
        state ^= (state >> 27);

        // XOR the ciphertext byte with the lowest 8 bits of the current state
        buffer[i] ^= static_cast<uint8_t>(state & 0xFF);
    }
}

// Extract all files from a decrypted DPAC buffer.
//
// Format (after the 8-byte magic + version header):
//   uint32_t  fileCount
//   for each file:
//     uint16_t  nameLen
//     char[]    filename  (nameLen bytes, no null terminator)
//     uint64_t  offset    (byte offset into this buffer)
//     uint64_t  size      (byte count)
//     uint8_t[4] padding/reserved
void extract_files(const std::vector<uint8_t>& buffer) {
    BinaryReader br(buffer);
	
	// Skip 8-byte header (magic "DPAC" + 4-byte version/flags)
    br.seek(8);

    uint32_t fileCount = br.read<uint32_t>();
	if (fileCount > 10000)
		throw std::runtime_error("Suspicious file count");

    std::cout << "Found " << fileCount << " files\n";

    const std::filesystem::path baseDir = "extracted";
    std::filesystem::create_directories(baseDir);

    // Canonical base used for path-traversal checks below.
    // weakly_canonical resolves ".." without requiring the path to exist yet.
    const std::filesystem::path canonBase =
        std::filesystem::weakly_canonical(baseDir);

    for (uint32_t i = 0; i < fileCount; ++i) {
        uint16_t nameLen = br.read<uint16_t>();

        if (nameLen == 0 || nameLen > 1024)
            throw std::runtime_error(
                "Suspicious filename length: " + std::to_string(nameLen)
            );

        std::string filename = br.read_string(nameLen);

        uint64_t offset = br.read<uint64_t>();
        uint64_t size   = br.read<uint64_t>();

        // Skip 4 reserved/padding bytes
        br.seek(br.position() + 4);


        // --- Validate data bounds ---
        if (offset + size > buffer.size() || offset + size < offset)
            throw std::runtime_error(
                "Invalid file bounds for: " + filename
            );

        // --- Path-traversal check ---
        // Build the intended output path and verify it still sits
        // inside canonBase. Using filesystem::relative() is more robust
        // than a raw string-prefix check, which can produce false passes
        // when directory names share a common prefix (e.g. /out vs /output).
        std::filesystem::path outPath =
            std::filesystem::weakly_canonical(baseDir / filename);

        auto rel = std::filesystem::relative(outPath, canonBase);
        if (rel.string().rfind("..", 0) == 0)
            throw std::runtime_error(
                "Path traversal detected for: " + filename
            );

        // --- Write file ---
        std::filesystem::create_directories(outPath.parent_path());

        std::ofstream outFile(outPath, std::ios::binary);
        if (!outFile)
            throw std::runtime_error(
                "Failed to create output file: " + outPath.string()
            );

        outFile.write(
            reinterpret_cast<const char*>(buffer.data() + offset),
            static_cast<std::streamsize>(size)
        );

        if (!outFile)
            throw std::runtime_error(
                "Write failed for: " + outPath.string()
            );

        std::cout << "Extracted: " << filename
                  << " (" << size << " bytes)\n";
    }
}

int main(int argc, char* argv[]) {

    try {
        if (argc < 2) {
            std::cout << "Usage: dpac_tool <input_file>\n";
            return 1;
        }

        const std::string inputPath = argv[1];

        // 1. Open file
        std::ifstream inFile(inputPath, std::ios::binary | std::ios::ate);
        if (!inFile) {
            std::cerr << "Error: Could not open input file: "
                      << inputPath << "\n";
            return 1;
        }

        // 2. Read size — explicit cast avoids implicit narrowing on 32-bit
        //    platforms where std::streampos is 64-bit but size_t is 32-bit.
        const auto rawSize = inFile.tellg();
        if (rawSize <= 0)
            throw std::runtime_error("Invalid or empty file");

        const auto fileSize = static_cast<std::size_t>(rawSize);
        inFile.seekg(0, std::ios::beg);

        // 3. Load into memory
        std::vector<uint8_t> buffer(fileSize);
        if (!inFile.read(reinterpret_cast<char*>(buffer.data()),
                         static_cast<std::streamsize>(fileSize))) {
            std::cerr << "Error: Could not read file data.\n";
            return 1;
        }
        inFile.close();

        std::cout << "Processing " << fileSize << " bytes...\n";

        // 4. Decrypt
        decrypt_buffer(buffer);

        // 5. Verify header
        if (std::memcmp(buffer.data(), "DPAC", 4) != 0) {
            std::cerr << "Error: DPAC header not found after decryption.\n";
            std::cerr << "First 4 bytes: " << std::hex
                      << static_cast<int>(buffer[0]) << " "
                      << static_cast<int>(buffer[1]) << " "
                      << static_cast<int>(buffer[2]) << " "
                      << static_cast<int>(buffer[3]) << std::dec << "\n";
            return 1;
        }

        std::cout << "Valid DPAC header confirmed.\n";

        // 6. Extract
        extract_files(buffer);

    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
