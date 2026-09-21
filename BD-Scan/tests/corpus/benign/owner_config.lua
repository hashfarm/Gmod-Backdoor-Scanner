MyAddon = MyAddon or {}
MyAddon.Owners = {
    ["STEAM_0:1:12345678"] = true,
    ["STEAM_0:0:87654321"] = true,
}
function MyAddon:IsOwner(ply) return self.Owners[ply:SteamID()] == true end
local c = Color(255, 128, 0)
local mask = 0xFF00FF00
