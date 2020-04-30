#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <regex>
#include "CheckDefs.h"
#include "CleanString.h"
namespace fs = std::filesystem;

std::ifstream inFile;

void CheckLine(std::string Line, int LineNum, std::string FilePath, std::string FileType) {
    int DefVal = 0;
    if (FileType == ".lua") {
        for (std::string RegexPattern : LuaCheckPatterns) {
            std::regex CheckRegex(RegexPattern); // Convert to actual regex

            std::ptrdiff_t number_of_matches = std::distance(std::sregex_iterator(Line.begin(), Line.end(), CheckRegex), std::sregex_iterator());

            if (number_of_matches > 0) {
                std::cout << FilePath << " | " << LuaCheckDefs[DefVal] << " @ Line #" << LineNum << " | " << trimExtraWhiteSpaces(Line) << std::endl;
                std::cout << std::endl;
            }
            
            DefVal++;
        }
    }

    if (FileType == ".vmt") {
        for (std::string RegexPattern : VMTRegexPatterns) {
            std::regex CheckRegex(RegexPattern); // Convert to actual regex

            std::ptrdiff_t number_of_matches = std::distance(std::sregex_iterator(Line.begin(), Line.end(), CheckRegex), std::sregex_iterator());

            if (number_of_matches > 0) {
                std::cout << FilePath << " | " << VMTRegexDefs[DefVal] << " in a VMT @ Line #" << LineNum << " | " << trimExtraWhiteSpaces(Line) << std::endl;
                if (VMTRegexDefs[DefVal] == "CharCode") {
                    std::cout << "Converted Char Code : ";
                    std::string LineSubject = Line;
                    std::smatch Match;
                    while (std::regex_search(LineSubject, Match, CheckRegex)) {
                       
                        std::cout << static_cast<char>(std::stoi(Match.str(0)));
                        LineSubject = Match.suffix().str();
                    }
                    std::cout << std::endl;
                }
                std::cout << std::endl;
            }
            DefVal++;
        }
       
    }
}

void ShowFiles(std::string Path) {

    for (const auto& entry : fs::recursive_directory_iterator(Path)) {
        if (entry.path().has_extension()) {
            if (entry.path().extension() == ".lua" || entry.path().extension() == ".vmt") {
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