#pragma once
#include <string>

std::string LuaCheckPatterns[] = { "RunString", "CompileString", ".vmt", "http.Fetch", "http.Post", "STEAM_[0-9]+:[0-9]+:[0-9]+", "0[xX][0-9a-fA-F]+", "\\\\[0-9]+\\\\[0-9]+", ":SetUserGroup(.superadmin.|.admin.)", "file.Read", "file.Delete", "game.ConsoleCommand", "getfenv", "_G[.](.)" };
std::string LuaCheckDefs[] = { "Code Execution (RunString)", "Code Execution (CompileString)",  "VMT File Referenced", "http.Fetch", "http.Post", "Steam ID Referenced", "Obfuscated / Encrypted code", "Obfuscated / Encrypted code", "Setting User Group to Admin/SuperAdmin", "Reading File", "Deleting File", "Console Command", "Call to getfenv()", "References Global Table" };

std::string VMTRegexPatterns[] = { "[0-9]{2,3},", "[0-9]{2,3}\\\\", "RunString", "CompileString" };
std::string VMTRegexDefs[] = { "CharCode", "CharCode","Code Execution (RunString)", "Code Execution (CompileString)" };