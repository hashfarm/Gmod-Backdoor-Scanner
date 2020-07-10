#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <regex>
#include "CheckDefs.h"
#include "CleanString.h"
namespace fs = std::filesystem;

std::ifstream inFile;

std::string CheckFileTypes[] = {".lua", ".vmt", ".vtf", ".ttf"};

constexpr unsigned int str2int(const char* str, int h = 0)
{
    return !str[h] ? 5381 : (str2int(str, h + 1) * 33) ^ str[h];
}

void DecodeCharCode(std::string LineSubject, std::regex CheckRegex) {
    std::cout << "Converted Char Code : ";
    std::smatch Match;
    while (std::regex_search(LineSubject, Match, CheckRegex)) {

        std::cout << static_cast<char>(std::stoi(Match.str(0)));
        LineSubject = Match.suffix().str();
    }
    std::cout << std::endl;
}

void CheckLine(const std::string &Line, int LineNum, const std::string &FilePath, const std::string &FileType) {
    int DefVal = 0;

    switch (str2int(FileType.c_str()))
    {
        case str2int(".lua"):
            for (std::string RegexPattern : LuaCheckPatterns) {
                std::regex CheckRegex(RegexPattern); // Convert to actual regex

                std::ptrdiff_t number_of_matches = std::distance(std::sregex_iterator(Line.begin(), Line.end(), CheckRegex), std::sregex_iterator());

                if (number_of_matches > 0) {
                    std::cout << FilePath << " | " << LuaCheckDefs[DefVal] << " @ Line #" << LineNum << " | " << trimExtraWhiteSpaces(Line) << std::endl;
                    std::cout << std::endl;
                }

                DefVal++;
            }
            break;
        case str2int(".vmt"):
            for (std::string RegexPattern : VMTRegexPatterns) {
                std::regex CheckRegex(RegexPattern); // Convert to actual regex

                std::ptrdiff_t number_of_matches = std::distance(std::sregex_iterator(Line.begin(), Line.end(), CheckRegex), std::sregex_iterator());

                if (number_of_matches > 0) {
                    std::cout << FilePath << " | " << VMTRegexDefs[DefVal] << " in a VMT @ Line #" << LineNum << " | " << trimExtraWhiteSpaces(Line) << std::endl;
                    if (VMTRegexDefs[DefVal] == "CharCode")
                        DecodeCharCode(Line, CheckRegex);
                    std::cout << std::endl;
                }
                DefVal++;
            }
            break;
        case str2int(".vtf"):
            for (std::string RegexPattern : VTFRegexPatterns) {
                std::regex CheckRegex(RegexPattern); // Convert to actual regex

                std::ptrdiff_t number_of_matches = std::distance(std::sregex_iterator(Line.begin(), Line.end(), CheckRegex), std::sregex_iterator());

                if (number_of_matches > 0) {
                    std::cout << FilePath << " | " << VTFRegexDefs[DefVal] << " in a VTF @ Line #" << LineNum << " | " << trimExtraWhiteSpaces(Line) << std::endl;
                    if (VTFRegexDefs[DefVal] == "CharCode")
                        DecodeCharCode(Line, CheckRegex);
                    std::cout << std::endl;
                }
                DefVal++;
            }
            break;
        case str2int(".ttf"):
            for (std::string RegexPattern : TTFRegexPatterns) {
                std::regex CheckRegex(RegexPattern); // Convert to actual regex

                std::ptrdiff_t number_of_matches = std::distance(std::sregex_iterator(Line.begin(), Line.end(), CheckRegex), std::sregex_iterator());

                if (number_of_matches > 0) {
                    std::cout << FilePath << " | " << TTFRegexDefs[DefVal] << " in a TTF @ Line #" << LineNum << " | " << trimExtraWhiteSpaces(Line) << std::endl;
                    if (TTFRegexDefs[DefVal] == "Code Obfuscation (Decimal)") {
                        std::cout << "Converted Decimal : ";
                        DecodeCharCode(Line, CheckRegex);
                    }
                    std::cout << std::endl;
                }
                DefVal++;
            }
            break;
    }
}

void ShowFiles(const std::string& Path) {

    for (const auto& entry : fs::recursive_directory_iterator(Path)) {
        if (entry.path().has_extension()) {
            if (std::find(std::begin(CheckFileTypes), std::end(CheckFileTypes), entry.path().extension()) != std::end(CheckFileTypes)) {
                int LineNum = 0;
                std::string NormalPath = entry.path().u8string();
                std::string NormalEx = entry.path().extension().u8string();
                std::string FileText;

                std::replace(NormalPath.begin(), NormalPath.end(), '\\', '/');
                //std::cout << NormalPath << std::endl;

                inFile.open(NormalPath);
                while (inFile.good())
                {
                    getline(inFile, FileText);
                    LineNum++;
                    CheckLine(FileText, LineNum, NormalPath, NormalEx);
                }
                inFile.close();
            }
        }
    }
        
}

int main() {
    std::string InputDirectory{};
    std::cout << "Started!\n";
    std::cout << "Enter a path: ";
    std::getline(std::cin, InputDirectory);
    std::cout << "Selected Directory: " << toRawString(InputDirectory) << std::endl << std::endl;
    ShowFiles(toRawString(InputDirectory));
    std::cout << std::endl << "Scan Complete!" << std::endl;
    system("pause");
}
