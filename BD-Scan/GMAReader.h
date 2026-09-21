#pragma once
#include <cctype>
#include <string>
#include <vector>
#include <fstream>
#include <cstdint>
#include <algorithm>
#include <filesystem>

#include "CleanString.h"

namespace fs = std::filesystem;

struct GMAFileEntry {
    std::string filename;
    int64_t size = 0;
    int64_t offset = 0;
    uint32_t crc = 0;
};

struct GMAInfo {
    std::string name;
    std::string description;
    std::string author;
    uint64_t steamId = 0;
    uint64_t timestamp = 0;
    int32_t version = 0;
    int64_t contentOffset = -1;
    std::vector<GMAFileEntry> files;
    bool valid = false;
    std::string error;
};

class GMAReader {
public:
    // Garry's Mod puts a JSON blob in the description; entry names stay tight.
    static constexpr size_t kMaxStringLength = 4096;
    static constexpr size_t kMaxMetadataLength = 1024 * 1024;
    static constexpr size_t kMaxFileEntries = 100000;

    static GMAInfo ReadGMAInfo(const fs::path& gmaPath) {
        std::error_code ec;
        const uintmax_t rawSize = fs::file_size(gmaPath, ec);
        if (ec) {
            GMAInfo info;
            info.error = "could not stat file";
            return info;
        }

        std::ifstream file(gmaPath, std::ios::binary);
        if (!file.is_open()) {
            GMAInfo info;
            info.error = "could not open file";
            return info;
        }
        return ReadGMAInfo(file, static_cast<int64_t>(rawSize));
    }

    static GMAInfo ReadGMAInfo(std::istream& file, int64_t fileSize) {
        GMAInfo info;

        file.clear();
        file.seekg(0);

        char header[4] = {};
        if (!file.read(header, 4)) {
            info.error = "file too small";
            return info;
        }
        if (std::string(header, 4) != "GMAD") {
            info.error = "invalid GMA header";
            return info;
        }

        uint8_t version = 0;
        if (!ReadRaw(file, version)) {
            info.error = "truncated header";
            return info;
        }
        if (!ReadRaw(file, info.steamId) || !ReadRaw(file, info.timestamp)) {
            info.error = "truncated header";
            return info;
        }

        std::string required;
        while (true) {
            if (!ReadCString(file, required)) {
                info.error = "truncated required-content list";
                return info;
            }
            if (required.empty()) break;
        }

        if (!ReadCString(file, info.name, kMaxMetadataLength) ||
            !ReadCString(file, info.description, kMaxMetadataLength) ||
            !ReadCString(file, info.author, kMaxMetadataLength) ||
            !ReadRaw(file, info.version)) {
            info.error = "truncated addon metadata";
            return info;
        }

        int64_t contentTotal = 0;
        while (true) {
            uint32_t fileNum = 0;
            if (!ReadRaw(file, fileNum)) {
                info.error = "truncated file index";
                return info;
            }
            if (fileNum == 0) break;

            if (info.files.size() >= kMaxFileEntries) {
                info.error = "file index exceeds sane limit";
                return info;
            }

            GMAFileEntry entry;
            if (!ReadCString(file, entry.filename) ||
                !ReadRaw(file, entry.size) ||
                !ReadRaw(file, entry.crc)) {
                info.error = "truncated file entry";
                return info;
            }

            if (entry.size < 0 || entry.size > fileSize) {
                info.error = "file entry size out of range";
                return info;
            }
            entry.offset = contentTotal;
            contentTotal += entry.size;
            if (contentTotal > fileSize) {
                info.error = "declared content exceeds archive size";
                return info;
            }

            info.files.push_back(std::move(entry));
        }

        const std::streamoff pos = file.tellg();
        if (pos < 0 || static_cast<int64_t>(pos) + contentTotal > fileSize) {
            info.error = "content block does not fit in archive";
            return info;
        }

        info.contentOffset = static_cast<int64_t>(pos);
        info.valid = true;
        return info;
    }

    static std::string ExtractFileContent(std::istream& in, const GMAFileEntry& entry, int64_t contentOffset, int64_t maxBytes) {
        if (entry.size <= 0 || entry.size > maxBytes) return "";

        in.clear();
        in.seekg(static_cast<std::streamoff>(contentOffset + entry.offset));
        if (!in) return "";

        std::string content;
        content.resize(static_cast<size_t>(entry.size));
        if (!in.read(&content[0], static_cast<std::streamsize>(entry.size))) return "";

        return content;
    }

    static constexpr int kSanitizePasses = 8;

    static std::string SanitizeEntryName(const std::string& rawName, bool& altered) {
        altered = false;
        std::string name = rawName;
        for (int pass = 0; pass < kSanitizePasses; ++pass) {
            bool changed = false;
            const std::string next = SanitizeEntryNameOnce(name, changed);
            if (changed) altered = true;
            if (next == name) return next;
            name = next;
        }
        return name;
    }

    static std::string SanitizeEntryNameOnce(const std::string& rawName, bool& altered) {
        const std::string filename = SanitizeUtf8(rawName);
        std::string working = filename;
        for (char& c : working) {
            if (c == '\\') c = '/';
        }

        altered = working != filename || filename != rawName;

        while (true) {
            if (working.size() >= 2 && working[1] == ':' &&
                std::isalpha(static_cast<unsigned char>(working[0]))) {
                working.erase(0, 2);
                altered = true;
                continue;
            }
            if (!working.empty() && working.front() == '/') {
                working.erase(0, 1);
                altered = true;
                continue;
            }
            break;
        }

        std::vector<std::string> parts;
        std::string segment;
        bool absolute = false;
        size_t index = 0;
        while (index <= working.size()) {
            const bool end = index == working.size();
            const char c = end ? '/' : working[index];
            if (c == '/') {
                while (segment.size() >= 2 && segment[1] == ':' &&
                       std::isalpha(static_cast<unsigned char>(segment[0]))) {
                    segment.erase(0, 2);
                    altered = true;
                }
                if (segment.empty()) {
                    if (index == 0) absolute = true;
                    else if (!end || !parts.empty()) altered = true;
                }
                else if (segment == ".") {
                    altered = true;
                }
                else if (segment == "..") {
                    altered = true;
                    if (!parts.empty()) parts.pop_back();
                }
                else {
                    parts.push_back(segment);
                }
                segment.clear();
            }
            else {
                segment += c;
            }
            index++;
        }

        if (absolute) altered = true;

        std::string result;
        for (const std::string& part : parts) {
            if (!result.empty()) result += '/';
            result += part;
        }
        if (result.empty()) {
            result = "unnamed";
            altered = true;
        }
        return result;
    }

    static bool IsArchiveFile(const std::string& filename) {
        return GetExtension(filename) == ".gma";
    }

    static bool IsBinaryModuleName(const std::string& filename) {
        const std::string ext = GetExtension(filename);
        if (ext != ".dll" && ext != ".so") return false;

        std::string lowered = filename;
        for (char& c : lowered) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        const size_t slash = lowered.find_last_of('/');
        const std::string base = slash == std::string::npos ? lowered : lowered.substr(slash + 1);
        if (base.rfind("gmsv_", 0) == 0 || base.rfind("gmcl_", 0) == 0) return true;

        return lowered.find("lua/bin/") != std::string::npos;
    }

    static bool IsNativeBinaryName(const std::string& filename) {
        const std::string ext = GetExtension(filename);
        return ext == ".dll" || ext == ".so" || ext == ".dylib";
    }

    static bool IsRuntimeDataPath(const std::string& filename) {
        std::string lowered = filename;
        for (char& c : lowered) {
            if (c == '\\') c = '/';
            else c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        static const char* const folders[] = { "data", "cache", "download", "downloads", "lua_temp" };
        for (const char* folder : folders) {
            const std::string prefix = std::string(folder) + "/";
            if (lowered.rfind(prefix, 0) == 0) return true;
            if (lowered.find("/" + prefix) != std::string::npos) return true;
        }
        return false;
    }

    static bool IsRuntimeDataFile(const std::string& filename) {
        const std::string ext = GetExtension(filename);
        if (ext != ".txt" && ext != ".dat" && ext != ".json") return false;
        return IsRuntimeDataPath(filename);
    }

    static bool IsScannableFile(const std::string& filename) {
        const std::string ext = GetExtension(filename);
        if (ext == ".lua" || ext == ".vmt" || ext == ".vtf" || ext == ".ttf") return true;
        if (IsNativeBinaryName(filename)) return true;
        return IsRuntimeDataFile(filename);
    }

    static std::string GetExtension(const std::string& filename) {
        const size_t dotPos = filename.rfind('.');
        if (dotPos == std::string::npos) return "";

        std::string ext = filename.substr(dotPos);
        std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) {
            return static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
        });
        return ext;
    }

private:
    template <typename T>
    static bool ReadRaw(std::istream& in, T& value) {
        return static_cast<bool>(in.read(reinterpret_cast<char*>(&value), sizeof(T)));
    }

    static bool ReadCString(std::istream& in, std::string& out, size_t limit = kMaxStringLength) {
        out.clear();
        char c = 0;
        while (out.size() < limit) {
            if (!in.get(c)) return false;
            if (c == '\0') return true;
            out += c;
        }
        return false;
    }
};
