# Gmod Backdoor Scanner

## Overview
The Gmod Backdoor Scanner project is a C++ application developed to scan directories for potential backdoors in Garry's Mod (Gmod) related files. It supports scanning `.lua`, `.vmt`, `.vtf`, and `.ttf` files for suspicious patterns, such as obfuscated code or malicious function calls, using regular expressions defined in pattern files. The scanner generates a JSON-formatted log file (`scan_log.json`) with detailed detection results.

This project is not guaranteed to find everything, and will most likely include a few false positives with every scan. Use your own intuition alongside this tool for the best results.

## Features
- Scans directories recursively for `.lua`, `.vmt`, `.vtf`, and `.ttf` files.
- Supports detection of patterns like `RunString`, `http.Fetch`, and CharCode obfuscation.
- Parallel file processing using `std::async` for improved performance.
- Unicode support for file paths using `std::wstring`.
- Command-line argument support (`-d <directory>`) for automation.
- JSON-formatted logging for easy parsing of results.
- Robust error handling for file operations, regex compilation, and path validation.

## Requirements
- **C++17 Compiler**: Visual Studio 2019 or later (with `v143` toolset).
- **nlohmann/json**: JSON for Modern C++ library (available at https://github.com/nlohmann/json).
- **Operating System**: Windows (with plans for cross-platform support in future versions).
- **Pattern Files**: `lua_patterns.txt`, `vmt_patterns.txt`, `vtf_patterns.txt`, and `ttf_patterns.txt` must be present in the working directory.

## Installation
1. **Clone or Download the Project**:
   - Download the project files or clone the repository.
2. **Install nlohmann/json**:
   - Download `json.hpp` from https://github.com/nlohmann/json and place it in the project directory.
   - Ensure the project directory is included in the include path (configured in `BD-Scan.vcxproj`).
3. **Open in Visual Studio**:
   - Open `BD-Scan.sln` in Visual Studio (2019 or later).
   - Ensure the C++17 standard is enabled (`/std:c++17`).
4. **Build the Project**:
   - Build for Debug or Release (Win32 or x64).
   - The executable `BD-Scan.exe` will be generated in the output directory.

## Usage
1. **Run the Scanner**:
   - **Interactive Mode**: Run `BD-Scan.exe` and enter the directory path when prompted.
   - **Command-Line Mode**: Use `BD-Scan.exe -d "C:\Path\To\Directory"` to specify the directory directly.
2. **Check Output**:
   - Results are logged to `scan_log.json` in the working directory.
   - Console output displays scan progress, duration, and summary statistics.
3. **Example**:
   ```bash
   BD-Scan.exe -d "D:\TestDir"
   ```
   - Scans `D:\TestDir` for `.lua`, `.vmt`, `.vtf`, and `.ttf` files.
   - Outputs detections to `scan_log.json` and the console.

## Example Log Output
An example `scan_log.json` might look like this:
```json
{
    "detections": [
        {
            "file": "D:/TestDir/test.lua",
            "detection": "Code Execution (RunString)",
            "line_number": 1,
            "line_text": "RunString(\"print('Hello')\")"
        },
        {
            "file": "D:/TestDir/test.lua",
            "detection": "http.Fetch",
            "line_number": 2,
            "line_text": "http.Fetch(\"http://example.com\")"
        },
        {
            "file": "D:/TestDir/test.vmt",
            "detection": "CharCode",
            "line_number": 1,
            "line_text": "97,98,99"
        },
        {
            "file": "D:/TestDir/test.vmt",
            "detection": "CharCode",
            "line_number": 1,
            "line_text": "Decoded Char Code: abc"
        }
    ],
    "start_time": 1234567890,
    "end_time": 1234567895,
    "files_processed": 2,
    "detections_found": 4
}
```

## Testing
To test the scanner:
1. Create a test directory with sample files, e.g.:
   ```lua
   // test.lua
   RunString("print('Hello')")
   http.Fetch("http://example.com")
   ```
   ```vmt
   // test.vmt
   97,98,99
   ```
2. Run the scanner:
   ```bash
   BD-Scan.exe -d "D:\TestDir"
   ```
3. Verify the output in `scan_log.json` and the console.

## Troubleshooting
- **Linker Errors**: Ensure all global vectors are defined in `BD-Scan.cpp` and that `nlohmann/json.hpp` is correctly included.
- **Compiler Warnings**: If warnings about JSON initialization persist, consider adjusting the warning level (e.g., `/W3` instead of `/W4`) or suppressing specific warnings with `#pragma warning(disable:26495)`.
- **Missing Pattern Files**: Ensure `lua_patterns.txt`, `vmt_patterns.txt`, `vtf_patterns.txt`, and `ttf_patterns.txt` are in the working directory.
- **File Access Issues**: Verify that the specified directory is accessible and contains valid files.

## Contributors
- **hashfarm**: Original developer and creator of the Gmod Backdoor Scanner project.
- **Hungryy2K**: Implemented major improvements in July 2025, including linker fixes, JSON logging, parallel processing, and Unicode support.

## Recent Changes
The following improvements were implemented by **Hungryy2K** in July 2025:
- **Fixed Linker Errors**: Defined global vectors (`LuaCheckPatterns`, `LuaCheckDefs`, etc.) in `BD-Scan.cpp` to resolve unresolved external symbol errors.
- **Resolved Switch-Case Warnings**: Replaced `switch` with `if-else` in `CheckLine` to eliminate `fallthrough` warnings, ensuring compatibility with stricter compiler settings.
- **Improved JSON Initialization**: Explicitly initialized `logJson` as `json::object()` to suppress static analyzer warnings about uninitialized members.
- **Enhanced Detections Counter**: Refined logic in `ProcessFile` to count only actual pattern matches, improving accuracy of the `detections_found` metric.
- **Added Unicode Support**: Used `std::wstring` for directory input to handle non-ASCII paths.
- **Command-Line Support**: Added support for `-d <directory>` argument to specify the scan directory directly.
- **JSON Logging**: Implemented structured JSON output in `scan_log.json` with details on detected patterns, file paths, and scan statistics.
- **Performance Optimization**: Introduced parallel processing with `std::async` for faster scanning of large directories.
- **Error Handling**: Added robust checks for empty files, invalid paths, and regex compilation errors.
- **Pattern Refinement**: Updated `vmt_patterns.txt` and `ttf_patterns.txt` to improve CharCode detection with the regex `[0-9]{2,3}(,[0-9]{2,3})*`.

## NEW Features (December 2025)
The following features were added in this version:

### New Capabilities
- **GMA Archive Support**: Scan inside `.gma` addon files without extraction
- **Severity Levels**: All detections now classified as CRITICAL, HIGH, MEDIUM, or LOW
- **Base64 Decoding**: Automatic decoding and display of Base64 obfuscated content
- **HTML Reports**: Generate styled HTML reports with `--html` flag
- **78+ Lua Patterns**: Expanded detection patterns for better coverage

### New Command Line Options
- `-s <severity>`: Filter by minimum severity level (low, medium, high, critical)
- `-q, --quiet`: Quiet mode - suppress console output, show only summary
- `--html`: Generate HTML report (`scan_report.html`)
- `--diff`: Show only NEW detections since last scan
- `-h, --help`: Show help message

### Interactive Mode
When running without arguments, you can enter path and options together:
```
Enter path [options]: C:/gmod/addons --html --diff
```

### New Files
- `known_hashes.txt`: Database of known backdoor file hashes (auto-loaded)
- `last_scan.json`: Previous scan results for diff mode comparison

### Technical Improvements
- **Thread Safety**: Fixed race conditions in concurrent logging
- **Improved Pattern Files**: All patterns now include severity tags
- **Better CharCode Detection**: Enhanced decoding for obfuscated numeric sequences

## Future Improvements
- Cross-platform support (Linux/macOS)
- Whitelist system for false positive management
- Custom pattern file support
- Export to CSV format

For issues or feature requests, please contact the developer or open an issue in the **hashfarm** project repository.
