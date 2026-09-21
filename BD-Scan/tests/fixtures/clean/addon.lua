-- Synthetic sample for the CI smoke test. Ordinary addon code, must produce no detections.

local PLUGIN = {}

hook.Add("PlayerSpawn", "example_spawn", function(ply)
    ply:SetHealth(100)
    ply:SetArmor(0)
end)

net.Receive("example_message", function(len, ply)
    local text = net.ReadString()
    print(ply:Nick() .. " says " .. text)
end)

concommand.Add("example_hello", function(ply, cmd, args)
    ply:ChatPrint("Hello, " .. ply:Nick())
end)

return PLUGIN
