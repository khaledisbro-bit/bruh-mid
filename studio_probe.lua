-- studio_probe.lua  (v2)
-- Runs 5a10205e-obfuscated.lua and captures the real module even when the
-- chunk's return value comes back nil. It hooks setmetatable so the module
-- table `M` is grabbed at the moment the program builds it, then probes it.
--
-- Save the obfuscated script as "obf.lua" where your executor can readfile it,
-- OR paste it into SOURCE below. Run this, then paste the printed OUTPUT back.

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

-- ---- hook setmetatable to capture every table + metatable the program sets
local real_setmetatable = setmetatable
local captured = {}          -- list of { tbl = ..., mt = ... }
local function hooked_setmetatable(t, mt)
    captured[#captured + 1] = { tbl = t, mt = mt }
    return real_setmetatable(t, mt)
end

-- Install the hook where the VM will see it. The VM reads globals via
-- getfenv(), so replacing the global entry is enough. We also setfenv the
-- chunk onto a proxy env that forwards to the real globals but overrides
-- setmetatable, in case the executor sandboxes the global table.
local realenv = getfenv()
realenv.setmetatable = hooked_setmetatable

local chunk = loadstring(SOURCE)
local proxy = setmetatable({ setmetatable = hooked_setmetatable },
    { __index = realenv, __newindex = realenv })
pcall(function() setfenv(chunk, proxy) end)

out("== load ==")
local ok, ret = pcall(chunk)
out("run ok:", ok, "return type:", typeof(ret))
if not ok then out("error:", ret) end
out("setmetatable calls captured:", #captured)

-- restore
realenv.setmetatable = real_setmetatable

-- ---- pick the module: prefer the return value, else a captured table whose
-- metatable has an __index function.
local function looks_like_module(entry)
    return type(entry.mt) == "table" and type(entry.mt.__index) == "function"
end

local candidates = {}
if type(ret) == "table" then candidates[#candidates + 1] = { tbl = ret, mt = getmetatable(ret) } end
for _, e in ipairs(captured) do
    if looks_like_module(e) then candidates[#candidates + 1] = e end
end

out("== candidate modules:", #candidates, "==")
local keys = { "add", "mul", "sub", "div", "mod", "pow", "nope" }
local samples = { {6, 2}, {5, 3}, {10, 4}, {7, 0} }

for ci, e in ipairs(candidates) do
    local M = e.tbl
    out(("-- candidate #%d  mt=%s __index=%s"):format(
        ci, typeof(e.mt), e.mt and typeof(e.mt.__index) or "nil"))
    for _, k in ipairs(keys) do
        local okv, v = pcall(function() return M[k] end)
        out(("  M[%s] -> ok=%s type=%s"):format(k, tostring(okv), typeof(v)))
        if okv and type(v) == "function" then
            for _, a in ipairs(samples) do
                local okc, r = pcall(v, a[1], a[2])
                out(("    %s(%d,%d) -> ok=%s r=%s"):format(k, a[1], a[2], tostring(okc), tostring(r)))
            end
            local _, v2 = pcall(function() return M[k] end)
            out("    same-object across two reads:", v == v2)
        end
    end
end

if #candidates == 0 then
    out("no module captured -- the VM may have bailed. Dumping captured mts:")
    for i, e in ipairs(captured) do
        out(("  cap#%d tbl=%s mt=%s"):format(i, typeof(e.tbl), typeof(e.mt)))
    end
end

local text = table.concat(log, "\n")
print(text)
pcall(function() writefile("probe_result.txt", text) end)
return text
