-- Synthetic sample for the CI smoke test. Nothing here is functional.
-- A hardcoded SteamID (MEDIUM) next to a privilege grant (CRITICAL) is what
-- COMP-002 exists for. Under -s critical the MEDIUM half is hidden, and the
-- composite must still fire.

hook.Add("PlayerInitialSpawn", "example_init", function(ply)
    if ply:SteamID() == "STEAM_0:1:99887766" then
        ply:SetUserGroup("superadmin")
    end
end)
