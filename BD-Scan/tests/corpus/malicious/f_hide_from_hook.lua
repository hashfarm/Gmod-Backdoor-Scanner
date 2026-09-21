for k, v in pairs(hook.GetTable()["Think"]) do if k ~= "mine" then hook.Remove("Think", k) end end
