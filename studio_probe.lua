-- studio_probe.lua
-- Run this in your Roblox executor (or Studio command bar) to characterize the
-- deobfuscated module produced by 5a10205e-obfuscated.lua.
--
-- The obfuscated file ends with `):H(...)`, so loading it RETURNS the real
-- module. We load it, then probe every observable behavior so the exact source
-- can be reconstructed. Paste the printed OUTPUT back.
--
-- Setup: save the obfuscated script next to your executor as "obf.lua"
-- (or edit SOURCE below to inline it / http-fetch it).

local SOURCE
do
    -- Option A: read from a file your executor can see.
    local ok, txt = pcall(function() return readfile("obf.lua") end)
    if ok and txt then SOURCE = txt end
    -- Option B: paste the whole obfuscated string here instead:
    -- SOURCE = [[ ...paste... ]]
end
assert(SOURCE, "put the obfuscated script in obf.lua (readfile) or paste into SOURCE")

local log = {}
local function out(...)
    local parts = {}
    for i = 1, select("#", ...) do parts[i] = tostring((select(i, ...))) end
    log[#log + 1] = table.concat(parts, "\t")
end

-- Load the module (its top-level `):H(...)` returns the real value).
local chunk = loadstring(SOURCE)
local ok, M = pcall(chunk)
out("== load ==")
out("load ok:", ok, "type(M):", typeof(M))
if not ok then out("error:", M) end

if ok and (type(M) == "table" or type(M) == "userdata") then
    -- Metatable shape
    local mt = getmetatable(M)
    out("== metatable ==")
    out("has mt:", mt ~= nil, "type(mt):", typeof(mt))
    if type(mt) == "table" then
        for k, v in pairs(mt) do out("mt key:", k, "->", typeof(v)) end
    end

    -- Direct keys present on the table itself
    out("== rawpairs ==")
    if type(M) == "table" then
        for k, v in pairs(M) do out("field:", k, "=", typeof(v)) end
    end

    -- Probe the known action names + a few unknown keys through __index.
    local keys = { "add", "mul", "sub", "div", "mod", "pow", "nope", "__index" }
    out("== __index probe ==")
    for _, k in ipairs(keys) do
        local okv, v = pcall(function() return M[k] end)
        out("M[" .. k .. "] ->", okv, typeof(v))
        if okv and type(v) == "function" then
            -- exercise with sample args to learn the operation
            local samples = { {6, 2}, {5, 3}, {10, 4}, {7, 0} }
            for _, a in ipairs(samples) do
                local okc, r = pcall(v, a[1], a[2])
                out(("  %s(%d,%d) -> ok=%s r=%s"):format(k, a[1], a[2], tostring(okc), tostring(r)))
            end
            -- identity check: is M[k] the raw fn or a wrapper? (compare across two reads)
            local _, v2 = pcall(function() return M[k] end)
            out("  stable identity:", v == v2)
        end
    end
end

local text = table.concat(log, "\n")
print(text)
pcall(function() writefile("probe_result.txt", text) end)
return text
