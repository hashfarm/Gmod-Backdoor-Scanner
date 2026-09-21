local meta = FindMetaTable("Player")
function meta:CanAfford(amount) return self:getDarkRPVar("money") >= amount end
function meta:IsSuperAdmin() return self:GetUserGroup() == "superadmin" end

hook.Add("PlayerInitialSpawn", "DarkRPLoad", function(ply)
    local _R = debug.getregistry()
    timer.Simple(1, function()
        if not IsValid(ply) then return end
        ply:SetDarkRPVar("money", 500)
    end)
end)

net.Receive("DarkRP_Money", function(len, ply)
    local amt = net.ReadInt(32)
    RunConsoleCommand("darkrp", "setmoney", ply:UserID(), amt)
end)

concommand.Add("darkrp_reload", function(ply)
    if not ply:IsSuperAdmin() then return end
    game.ConsoleCommand("changelevel " .. game.GetMap() .. "\n")
end)
