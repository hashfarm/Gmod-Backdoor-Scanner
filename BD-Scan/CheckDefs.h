#pragma once
#include <string>

std::string LuaCheckPatterns[] = { "RunString", "CompileString", ".vmt", "http.Fetch", "http.Post", "STEAM_[0-9]+:[0-9]+:[0-9]+", "0[xX][0-9a-fA-F]+", "\\\\[xX][0-9a-fA-F]+", "\\\\[0-9]+\\\\[0-9]+", ":SetUserGroup(.superadmin.|.admin.)", "file.Read", "file.Delete", "game.ConsoleCommand", "getfenv", "_G[.](.)" };
std::string LuaCheckDefs[] = { "Code Execution (RunString)", "Code Execution (CompileString)",  "VMT File Referenced", "http.Fetch", "http.Post", "Steam ID Referenced", "Obfuscated / Encrypted Code", "Obfuscated / Encrypted Code [Hex Code]", "Obfuscated / Encrypted Code", "Setting User Group to Admin/SuperAdmin", "Reading File", "Deleting File", "Console Command", "Call to getfenv()", "References Global Table" };

std::string VMTRegexPatterns[] = { "[0-9]{2,3},", "[0-9]{2,3}\\\\", "\\\\[xX][0-9a-fA-F]+", "RunString", "CompileString", "timer.Simple", "http.Fetch", "http.Post" };
std::string VMTRegexDefs[] = { "CharCode", "CharCode", "Obfuscated Code [Hex]","Code Execution (RunString)", "Code Execution (CompileString)", "Timer", "http.Fetch", "http.Post" };

std::string VTFRegexPatterns[] = { "[0-9]{2,3},", "[0-9]{2,3}\\\\", "\\\\[xX][0-9a-fA-F]+", "RunString", "CompileString", "timer.Simple", "http.Fetch", "http.Post" };
std::string VTFRegexDefs[] = { "CharCode", "CharCode", "Obfuscated Code [Hex]","Code Execution (RunString)", "Code Execution (CompileString)", "Timer", "http.Fetch", "http.Post" };