#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <cstdint>
#include <filesystem>

namespace fs = std::filesystem;

// GMA File structure:
// - Header: "GMAD" (4 bytes)
// - Version: 1 byte
// - SteamID: 8 bytes (uint64)
// - Timestamp: 8 bytes (uint64)
// - Required content (null-terminated string, repeated until empty string)
// - Addon name (null-terminated string)
// - Addon description (null-terminated string)
// - Addon author (null-terminated string)
// - Addon version: 4 bytes (int32)
// - File entries (until filenum == 0):
//   - Filenum: 4 bytes (uint32)
//   - Filename: null-terminated string
//   - File size: 8 bytes (int64)
//   - CRC: 4 bytes (uint32)
// - File content (concatenated)

struct GMAFileEntry {
    std::string filename;
    int64_t size;
    int64_t offset;
    uint32_t crc;
};

struct GMAInfo {
    std::string name;
    std::string description;
    std::string author;
    uint64_t steamId;
    uint64_t timestamp;
    int32_t version;
    std::vector<GMAFileEntry> files;
    bool valid;
};

class GMAReader {
public:
    static GMAInfo ReadGMAInfo(const fs::path& gmaPath) {
        GMAInfo info;
        info.valid = false;

        std::ifstream file(gmaPath, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open GMA file: " << gmaPath.string() << std::endl;
            return info;
        }

        // Read and verify header
        char header[4];
        file.read(header, 4);
        if (std::string(header, 4) != "GMAD") {
            std::cerr << "Error: Invalid GMA header in: " << gmaPath.string() << std::endl;
            return info;
        }

        // Read version
        uint8_t version;
        file.read(reinterpret_cast<char*>(&version), 1);
        if (version > 3) {
            std::cerr << "Warning: Unknown GMA version " << static_cast<int>(version) << " in: " << gmaPath.string() << std::endl;
        }

        // Read SteamID and timestamp
        file.read(reinterpret_cast<char*>(&info.steamId), 8);
        file.read(reinterpret_cast<char*>(&info.timestamp), 8);

        // Skip required content (read null-terminated strings until empty)
        std::string requiredContent;
        while (true) {
            std::getline(file, requiredContent, '\0');
            if (requiredContent.empty()) break;
        }

        // Read addon info
        std::getline(file, info.name, '\0');
        std::getline(file, info.description, '\0');
        std::getline(file, info.author, '\0');
        file.read(reinterpret_cast<char*>(&info.version), 4);

        // Read file entries
        int64_t contentOffset = 0;
        while (true) {
            uint32_t fileNum;
            file.read(reinterpret_cast<char*>(&fileNum), 4);
            if (fileNum == 0) break;

            GMAFileEntry entry;
            std::getline(file, entry.filename, '\0');
            file.read(reinterpret_cast<char*>(&entry.size), 8);
            file.read(reinterpret_cast<char*>(&entry.crc), 4);
            entry.offset = contentOffset;
            contentOffset += entry.size;

            info.files.push_back(entry);
        }

        // Store the position where file content starts
        // (This is needed if we want to extract files later)

        info.valid = true;
        return info;
    }

    // Extract a specific file's content from GMA
    static std::string ExtractFileContent(const fs::path& gmaPath, const GMAFileEntry& entry, int64_t contentStartOffset) {
        std::ifstream file(gmaPath, std::ios::binary);
        if (!file.is_open()) return "";

        file.seekg(contentStartOffset + entry.offset);
        
        std::string content;
        content.resize(static_cast<size_t>(entry.size));
        file.read(&content[0], entry.size);
        
        return content;
    }

    // Get content start offset (after all headers and file entries)
    static int64_t GetContentStartOffset(const fs::path& gmaPath) {
        std::ifstream file(gmaPath, std::ios::binary);
        if (!file.is_open()) return -1;

        // Skip header
        file.seekg(4); // "GMAD"
        
        uint8_t version;
        file.read(reinterpret_cast<char*>(&version), 1);
        
        file.seekg(8 + 8, std::ios::cur); // SteamID + Timestamp

        // Skip required content
        std::string temp;
        while (true) {
            std::getline(file, temp, '\0');
            if (temp.empty()) break;
        }

        // Skip addon info
        std::getline(file, temp, '\0'); // name
        std::getline(file, temp, '\0'); // description
        std::getline(file, temp, '\0'); // author
        file.seekg(4, std::ios::cur);   // version

        // Skip file entries
        while (true) {
            uint32_t fileNum;
            file.read(reinterpret_cast<char*>(&fileNum), 4);
            if (fileNum == 0) break;

            std::getline(file, temp, '\0'); // filename
            file.seekg(8 + 4, std::ios::cur); // size + crc
        }

        return file.tellg();
    }

    // Check if a file in GMA is scannable (lua, vmt, vtf, ttf)
    static bool IsScannableFile(const std::string& filename) {
        std::string ext = filename;
        size_t dotPos = ext.rfind('.');
        if (dotPos == std::string::npos) return false;
        
        ext = ext.substr(dotPos);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        
        return ext == ".lua" || ext == ".vmt" || ext == ".vtf" || ext == ".ttf";
    }

    // Get file extension
    static std::string GetExtension(const std::string& filename) {
        size_t dotPos = filename.rfind('.');
        if (dotPos == std::string::npos) return "";
        
        std::string ext = filename.substr(dotPos);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        return ext;
    }
};
