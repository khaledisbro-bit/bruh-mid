-- studio_probe.lua  (v3)
-- Probes 5a10205e-obfuscated.lua LIVE: at the moment the program calls
-- setmetatable(M, mt), the VM state is still alive, so we call mt.__index right
-- then with the action names and exercise whatever it returns. This works even
-- though the chunk's own return value comes back nil.
--
-- Save the obfuscated script as "obf.lua" next to your executor (or paste it
-- into SOURCE). Run this, then paste the printed OUTPUT back.

local SOURCE
do
    local ok, txt = pcall(function() return readfile("obf.lua") end)
    if ok and txt then SOURCE = txt end
    -- SOURCE = [[ ...paste whole obfuscated script here... ]]
end
assert(SOURCE, "put the obfuscated script in obf.lua (readfile) or paste into SOURCE")

local log = {}
local function out(...)
    local parts = {}
    for i = 1, select("#", ...) do parts[i] = tostring((select(i, ...))) end
    log[#log + 1] = table.concat(parts, "\t")
end

local keys = { "add", "mul", "sub", "div", "mod", "pow", "nope" }
local samples = { {6, 2}, {5, 3}, {10, 4}, {7, 0} }

local function exercise(tag, mt, tbl)
    out(tag .. "  __index type: " .. typeof(mt.__index))
    if type(mt.__index) ~= "function" then return end
    for _, k in ipairs(keys) do
        -- call the metamethod directly, live
        local okv, v = pcall(mt.__index, tbl, k)
        out(("  __index(_, %q) -> ok=%s type=%s"):format(k, tostring(okv), typeof(v)))
        if okv and type(v) == "function" then
            for _, a in ipairs(samples) do
                local okc, r = pcall(v, a[1], a[2])
                out(("    (%d,%d) -> ok=%s r=%s"):format(a[1], a[2], tostring(okc), tostring(r)))
            end
            local _, v2 = pcall(mt.__index, tbl, k)
            out("    same-object across two reads: " .. tostring(v == v2))
        end
    end
end

local real_setmetatable = setmetatable
local seen = 0
local function hooked_setmetatable(t, mt)
    seen = seen + 1
    if type(mt) == "table" and type(mt.__index) == "function" then
        out(("== live setmetatable #%d (has __index fn) =="):format(seen))
        pcall(exercise, ("cap#%d"):format(seen), mt, t)
    end
    return real_setmetatable(t, mt)
end

local realenv = getfenv()
realenv.setmetatable = hooked_setmetatable

local chunk = loadstring(SOURCE)
local proxy = real_setmetatable({ setmetatable = hooked_setmetatable },
    { __index = realenv, __newindex = realenv })
pcall(function() setfenv(chunk, proxy) end)

out("== load ==")
local ok, ret = pcall(chunk)
out("run ok: " .. tostring(ok) .. "  return type: " .. typeof(ret))
if not ok then out("error: " .. tostring(ret)) end
out("total setmetatable calls: " .. tostring(seen))

realenv.setmetatable = real_setmetatable

local text = table.concat(log, "\n")
print(text)
pcall(function() writefile("probe_result.txt", text) end)
return text
