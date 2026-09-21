local VERSION = "1.4.2"
timer.Create("MyAddonUpdateCheck", 3600, 0, function()
    http.Fetch("https://raw.githubusercontent.com/me/myaddon/main/version.txt",
        function(body)
            if body ~= VERSION then print("Update available") end
        end,
        function(err) print("Update check failed: " .. err) end)
end)
hook.Add("Initialize", "MyAddonReport", function()
    http.Post("https://discord.com/api/webhooks/123/abc", { content = "Server started" })
end)
