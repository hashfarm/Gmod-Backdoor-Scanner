#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <regex>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <future>
#include <algorithm>
#include <nlohmann/json.hpp>

#include "CheckDefs.h"
#include "CleanString.h"

namespace fs = std::filesystem;
using json = nlohmann::json;

// Definition of global vectors
std::vector<std::string> LuaCheckPatterns, LuaCheckDefs;
std::vector<std::regex> LuaCheckRegex;
std::vector<std::string> VMTRegexPatterns, VMTRegexDefs;
std::vector<std::regex> VMTRegexPatternsRegex;
std::vector<std::string> VTFRegexPatterns, VTFRegexDefs;
std::vector<std::regex> VTFRegexPatternsRegex;
std::vector<std::string> TTFRegexPatterns, TTFRegexDefs;
std::vector<std::regex> TTFRegexPatternsRegex;

// String hash function for file type comparison
constexpr unsigned int str2int(const char* str, int h = 0) {
    return !str[h] ? 5381 : (str2int(str, h + 1) * 33) ^ str[h];
}

// Centralized logging function
void Log(const std::string& message, std::ofstream& logFile, json& logJson, const std::string& filePath = "", const std::string& detection = "", int lineNum = 0, const std::string& lineText = "") {
    std::cout << message;
    logFile << message;
    if (!filePath.empty() && !detection.empty()) {
        json entry;
        entry["file"] = filePath;
        entry["detection"] = detection;
        entry["line_number"] = lineNum;
        entry["line_text"] = lineText;
        logJson["detections"].push_back(entry);
    }
}

// Decode and log char codes
void DecodeCharCode(const std::string& LineSubject, const std::regex& CheckRegex, std::ofstream& logFile, json& logJson, const std::string& FilePath, int LineNum) {
    std::stringstream ss;
    ss << "Decoded Char Code: ";
    std::smatch Match;
    std::string remaining = LineSubject;
    try {
        while (std::regex_search(remaining, Match, CheckRegex)) {
            int value = std::stoi(Match.str(0));
            if (value >= 0 && value <= 255) {
                ss << static_cast<char>(value);
            }
            else {
                ss << "[Invalid CharCode: " << Match.str(0) << "]";
            }
            remaining = Match.suffix().str();
        }
        ss << std::endl;
        Log(ss.str(), logFile, logJson, FilePath, "CharCode", LineNum, trimExtraWhiteSpaces(LineSubject));
    }
    catch (const std::exception& e) {
        ss << "[Error decoding CharCode: " << e.what() << "]" << std::endl;
        Log(ss.str(), logFile, logJson, FilePath, "CharCode Error", LineNum, trimExtraWhiteSpaces(LineSubject));
    }
}

// Check a single line for patterns
void CheckLine(const std::string& Line, int LineNum, const std::string& FilePath, const std::string& FileType, std::ofstream& logFile, json& logJson) {
    auto performCheck = [&](const std::vector<std::regex>& regexes, const std::vector<std::string>& defs, const std::string& fileTypeLabel) {
        for (size_t i = 0; i < regexes.size(); ++i) {
            if (std::regex_search(Line, regexes[i])) {
                std::stringstream ss;
                ss << FilePath << " | " << defs[i] << " in a " << fileTypeLabel << " @ Line #" << LineNum << " | " << trimExtraWhiteSpaces(Line) << std::endl;
                if (defs[i] == "CharCode" || defs[i] == "Code Obfuscation (Decimal)") {
                    ss << "Converted value: ";
                    Log(ss.str(), logFile, logJson, FilePath, defs[i], LineNum, trimExtraWhiteSpaces(Line));
                    DecodeCharCode(Line, regexes[i], logFile, logJson, FilePath, LineNum);
                }
                else {
                    Log(ss.str(), logFile, logJson, FilePath, defs[i], LineNum, trimExtraWhiteSpaces(Line));
                }
            }
        }
        };

    // Check patterns based on file type
    if (FileType == ".lua") {
        performCheck(LuaCheckRegex, LuaCheckDefs, "LUA");
    }
    else if (FileType == ".vmt") {
        performCheck(VMTRegexPatternsRegex, VMTRegexDefs, "VMT");
    }
    else if (FileType == ".vtf") {
        performCheck(VTFRegexPatternsRegex, VTFRegexDefs, "VTF");
    }
    else if (FileType == ".ttf") {
        performCheck(TTFRegexPatternsRegex, TTFRegexDefs, "TTF");
    }
}

// Process a single file
void ProcessFile(const fs::path& filePath, std::ofstream& logFile, json& logJson, int& filesProcessed, int& detections) {
    if (fs::file_size(filePath) == 0) return;

    std::ifstream inFile(filePath);
    if (!inFile.is_open()) {
        Log("Error: Could not open file: " + filePath.string() + "\n", logFile, logJson);
        return;
    }

    int LineNum = 0;
    std::string FileText;
    std::string NormalPath = filePath.string();
    std::replace(NormalPath.begin(), NormalPath.end(), '\\', '/');
    std::string extension = filePath.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

    while (std::getline(inFile, FileText)) {
        LineNum++;
        CheckLine(FileText, LineNum, NormalPath, extension, logFile, logJson);
        // Count only actual detections
        const auto& regexes = (extension == ".lua" ? LuaCheckRegex :
            extension == ".vmt" ? VMTRegexPatternsRegex :
            extension == ".vtf" ? VTFRegexPatternsRegex : TTFRegexPatternsRegex);
        for (const auto& regex : regexes) {
            if (std::regex_search(FileText, regex)) {
                detections++;
                break;
            }
        }
    }
    inFile.close();
    filesProcessed++;
}

int main(int argc, char* argv[]) {
    std::cout << "Gmod Backdoor Scanner started!" << std::endl;

    // Load patterns
    if (!LoadAllPatterns()) {
        std::cerr << "Critical error: Patterns could not be loaded. Please ensure the .txt files are present." << std::endl;
        std::cout << "Press Enter to continue...";
        std::cin.get();
        return 1;
    }
    std::cout << "Patterns loaded successfully." << std::endl;

    // Handle input directory
    std::wstring InputDirectory;
    if (argc > 2 && std::string(argv[1]) == "-d") {
        InputDirectory = std::wstring(argv[2], argv[2] + strlen(argv[2]));
    }
    else {
        std::wcout << L"Please enter a path: ";
        std::getline(std::wcin, InputDirectory);
    }

    // Remove quotation marks if present
    if (!InputDirectory.empty() && InputDirectory.front() == L'"' && InputDirectory.back() == L'"') {
        InputDirectory = InputDirectory.substr(1, InputDirectory.length() - 2);
    }

    // Validate directory
    try {
        fs::path dir(InputDirectory);
        if (!fs::exists(dir) || !fs::is_directory(dir)) {
            std::wcerr << L"Error: Invalid or inaccessible directory." << std::endl;
            std::cout << "Press Enter to continue...";
            std::cin.get();
            return 1;
        }
        std::wcout << L"Selected directory: " << InputDirectory << std::endl << std::endl;
    }
    catch (const fs::filesystem_error& e) {
        std::cerr << "Error: Filesystem error: " << e.what() << std::endl;
        std::cout << "Press Enter to continue...";
        std::cin.get();
        return 1;
    }

    // Open log file
    std::ofstream logFile("scan_log.json");
    if (!logFile.is_open()) {
        std::cerr << "Error: Could not create log file." << std::endl;
        std::cout << "Press Enter to continue...";
        std::cin.get();
        return 1;
    }

    // Initialize JSON object explicitly
    json logJson = json::object();
    logJson["detections"] = json::array();
    logJson["start_time"] = std::chrono::system_clock::now().time_since_epoch().count();

    // Scan files
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::future<void>> futures;
    std::string CheckFileTypes[] = { ".lua", ".vmt", ".vtf", ".ttf" };
    int filesProcessed = 0;
    int detections = 0;

    for (const auto& entry : fs::recursive_directory_iterator(InputDirectory)) {
        if (entry.is_regular_file() && entry.path().has_extension()) {
            std::string extension = entry.path().extension().string();
            std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
            if (std::find(std::begin(CheckFileTypes), std::end(CheckFileTypes), extension) != std::end(CheckFileTypes)) {
                futures.push_back(std::async(std::launch::async, ProcessFile, entry.path(), std::ref(logFile), std::ref(logJson), std::ref(filesProcessed), std::ref(detections)));
            }
        }
    }

    for (auto& future : futures) {
        future.wait();
    }

    // Finalize logging
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;

    logJson["end_time"] = std::chrono::system_clock::now().time_since_epoch().count();
    logJson["files_processed"] = filesProcessed;
    logJson["detections_found"] = detections;
    logFile << logJson.dump(4) << std::endl;

    std::cout << std::endl << "Scan complete!" << std::endl;
    std::cout << "Total duration: " << std::fixed << std::setprecision(2) << duration.count() << " seconds." << std::endl;
    std::cout << "Files processed: " << filesProcessed << std::endl;
    std::cout << "Detections found: " << detections << std::endl;
    std::cout << "Results have been saved to 'scan_log.json'." << std::endl;
    std::cout << "Press Enter to continue...";
    std::cin.get();

    logFile.close();
    return 0;
}