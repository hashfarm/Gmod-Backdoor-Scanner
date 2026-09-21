local env = getfenv(1)
setfenv(1, setmetatable({}, {__index = _G}))
local key = _G[toolName]
local handlers = {}
_G["TOOL_" .. toolName] = function() return handlers end
util.AddNetworkString("ToolSync")
file.Delete("mytool_cache.txt")
file.Write("mytool_config.txt", util.TableToJSON(cfg))
local parts = {}
for i = 1, 5 do parts[i] = string.char(65 + i) end
local name = table.concat(parts)
