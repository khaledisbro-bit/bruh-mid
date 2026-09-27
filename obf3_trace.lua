--!nocheck
-- obf3_trace.lua  --  self-contained Layer-2 trace for the Obscura-family build
-- (obf3.lua / 5a10205e). No server, no big files: it unwraps the script at
-- runtime (EncodingService is real in Studio), auto-patches the constant
-- resolver, runs the inner VM under an executor-sim env, taint-tracks arithmetic
-- on embedded numeric constants, captures the returned module, and probes each
-- action with tracked arguments so add/mul/sub are logged symbolically.
--
-- HOW TO RUN
--   1. Save the obfuscated script next to your executor as "obf.lua".
--   2. Run this file in your executor (or Studio command bar).
--   3. Read the printed report (also written to obf3_trace_result.txt).

local SOURCE
do
    local ok, txt = pcall(function() return readfile("obf.lua") end)
    if ok and txt then SOURCE = txt end
    -- SOURCE = [[ ...paste the whole obfuscated script here... ]]
end
assert(SOURCE, "put the obfuscated script in obf.lua (readfile) or paste into SOURCE")

local floor = math.floor
local byte, sub, char = string.byte, string.sub, string.char

------------------------------------------------------------------ report
local report = {}
local function say(...)
    local p = {}
    for i = 1, select("#", ...) do p[i] = tostring((select(i, ...))) end
    report[#report + 1] = table.concat(p, "\t")
end

------------------------------------------------------------- Layer 1 unwrap
-- Pull the base85 alphabet and payload straight out of the wrapper text, then
-- reproduce base85 -> EncodingService Zstd -> header split.
local alphabet = SOURCE:match("for BI=1,85 do BM%[Zd%(%[%[(.-)%]%],BI,BI%)%]=BI%-1 end")
assert(alphabet and #alphabet == 85, "could not find base85 alphabet")
local BM = {}
for i = 1, 85 do BM[sub(alphabet, i, i)] = i - 1 end

local payloadKey = SOURCE:match("%[(%d+)%]=%[%[") -- first [NNN]=[[ blob key
local blob = SOURCE:match("%[" .. payloadKey .. "%]=%[%[(.-)%]%]")
assert(blob, "could not find payload blob")

local function b85(F)
    local out, v, n = {}, 0, 0
    for i = 1, #F do
        local d = BM[sub(F, i, i)]
        if d == nil then return nil end
        v = v * 85 + d; n = n + 1
        if n == 5 then
            out[#out + 1] = char(floor(v / 16777216) % 256, floor(v / 65536) % 256, floor(v / 256) % 256, v % 256)
            v, n = 0, 0
        end
    end
    if n > 1 then
        for _ = 1, 5 - n do v = v * 85 + 84 end
        out[#out + 1] = sub(char(floor(v / 16777216) % 256, floor(v / 65536) % 256, floor(v / 256) % 256, v % 256), 1, n - 1)
    end
    return table.concat(out)
end

local ES_svc = game:GetService("EncodingService")
local J = buffer.tostring(ES_svc:DecompressBuffer(buffer.fromstring(b85(blob)), Enum.CompressionAlgorithm.Zstd))
local ZD = (byte(J, 1) + byte(J, 2) * 256 + byte(J, 3) * 65536 + byte(J, 4) * 16777216 - 2152627013) % 4294967296
local Zc = (byte(J, 5) + byte(J, 6) * 256 + byte(J, 7) * 65536 + byte(J, 8) * 16777216 - 2369095519) % 4294967296
local ZA = sub(J, 9, 9 + ZD - 1)          -- inner VM source
local Zh = sub(J, 9 + ZD, 9 + ZD + Zc - 1) -- inner VM data
say("unwrap: inner source=" .. #ZA .. "  inner data=" .. #Zc)

------------------------------------------------------- auto-patch resolver
-- resolver form: local function NAME(ARG)if ARG<0 then ARG=-ARG-GC end;return DEC(TBL[ARG])end
local rname, rarg, rgc, rdec, rtbl =
    ZA:match("local function (%w+)%((%w+)%)if %2<0 then %2=%-%2%-(%w+) end;return (%w+)%((%w+)%[%2%]%)end")
assert(rname, "could not locate constant resolver to patch")
local orig = ("local function %s(%s)if %s<0 then %s=-%s-%s end;return %s(%s[%s])end")
    :format(rname, rarg, rarg, rarg, rarg, rgc, rdec, rtbl, rarg)
local patched = ("local function %s(%s)if %s<0 then %s=-%s-%s end;local _r=%s(%s[%s]);if __SL then local _w=__SL(_r,%s) if _w~=nil then _r=_w end end;return _r end;if __CAP then __CAP(%s,%s)end")
    :format(rname, rarg, rarg, rarg, rarg, rgc, rdec, rtbl, rarg, rarg, rdec, rtbl)
local newZA, nrep = ZA:gsub(orig:gsub("[%-%[%]%(%)%.%+%*%?%^%$%%]", "%%%0"), patched, 1)
assert(nrep == 1, "resolver patch did not apply")
say("patched resolver: " .. rname .. " (decoder=" .. rdec .. " table=" .. rtbl .. ")")

--------------------------------------------------------------- executor env
local realenv = getfenv()
local genv = {}
local ES = {
    identifyexecutor = function() return "Synapse X", "2.0" end, getexecutorname = function() return "Synapse X" end,
    getgenv = function() return genv end, getrenv = function() return realenv end, getreg = function() return {} end, getgc = function() return {} end,
    getrawmetatable = function(o) local ok, m = pcall(getmetatable, o); return ok and m or nil end, setrawmetatable = function(o) return o end,
    setreadonly = function() end, isreadonly = function() return false end, make_writeable = function() end, make_readonly = function() end,
    hookfunction = function(a) return a end, replaceclosure = function(a) return a end, hookmetamethod = function() return function() end end,
    newcclosure = function(f) return f end, clonefunction = function(f) return f end, checkcaller = function() return true end,
    islclosure = function() return true end, iscclosure = function() return false end, getnamecallmethod = function() return "" end, setnamecallmethod = function() end,
    getcallingscript = function() return nil end, getscriptclosure = function() return function() end end, getscripthash = function() return "" end,
    request = function() return { StatusCode = 200, Body = "", Success = true } end, getconnections = function() return {} end,
    getinstances = function() return {} end, getnilinstances = function() return {} end, cloneref = function(x) return x end,
    compareinstances = function(a, b) return a == b end, setclipboard = function() end, isnetworkowner = function() return true end,
    getthreadidentity = function() return 8 end, setthreadidentity = function() end, checkclosure = function() return true end,
    isourclosure = function() return true end, isexecutorclosure = function() return true end,
}

------------------------------------------------------------ taint tracking
local ops = {}
local PMT = {}
local function uw(x) if type(x) == "table" and rawget(x, "__taint") then return x.__v end return x end
local function pv(x) if type(x) == "table" and rawget(x, "__taint") then return x.__e end return tostring(x) end
local function mk(v, e) return setmetatable({ __taint = true, __v = v, __e = e }, PMT) end
local function binop(sym, name)
    return function(a, b)
        local av, bv = uw(a), uw(b)
        local r = ({ ADD = function() return av + bv end, SUB = function() return av - bv end,
            MUL = function() return av * bv end, DIV = function() return av / bv end,
            MOD = function() return av % bv end, POW = function() return av ^ bv end })[name]()
        ops[#ops + 1] = ("%s(%s , %s) = %s"):format(name, pv(a), pv(b), tostring(r))
        return mk(r, "(" .. pv(a) .. sym .. pv(b) .. ")")
    end
end
PMT.__add = binop("+", "ADD"); PMT.__sub = binop("-", "SUB"); PMT.__mul = binop("*", "MUL")
PMT.__div = binop("/", "DIV"); PMT.__mod = binop("%", "MOD"); PMT.__pow = binop("^", "POW")
PMT.__unm = function(a) ops[#ops + 1] = "UNM(" .. pv(a) .. ")"; return mk(-uw(a), "(-" .. pv(a) .. ")") end
PMT.__eq = function(a, b) return uw(a) == uw(b) end
PMT.__lt = function(a, b) return uw(a) < uw(b) end
PMT.__le = function(a, b) return uw(a) <= uw(b) end
PMT.__concat = function(a, b) return pv(a) .. pv(b) end
PMT.__tostring = function(a) return tostring(uw(a)) end

------------------------------------------------------------ env + hooks
local behavior, stream = {}, {}
local captured = {}          -- module tables built during the run
local real_smt = setmetatable

local env = setmetatable({}, { __index = function(_, k)
    local rv = realenv[k]; if rv ~= nil then return rv end
    return ES[k]
end })

env.__SL = function(r, idx)
    local n = #stream
    if n < 200000 then
        stream[n + 1] = (type(r) == "string" and "S:" .. r) or ("N:" .. tostring(r))
    end
    return nil   -- no constant taint by default; module probe supplies tracked args
end
env.__CAP = function() end
env.print = function(...) local p = {}; for i = 1, select("#", ...) do p[i] = pv((select(i, ...))) end; behavior[#behavior + 1] = "PRINT: " .. table.concat(p, ", ") end
env.warn = function(...) behavior[#behavior + 1] = "WARN" end
env.getgenv = ES.getgenv
env.setmetatable = function(t, mt)
    if type(mt) == "table" and type(mt.__index) == "function" then
        captured[#captured + 1] = { tbl = t, mt = mt }
    end
    return real_smt(t, mt)
end
env.loadstring = function(src, ...) local f = loadstring(src, ...); if f then pcall(setfenv, f, env) end return f end
local RI = realenv.Instance
env.Instance = setmetatable({}, { __index = function(_, k)
    if k == "new" then return function(cls, ...) behavior[#behavior + 1] = "Instance.new: " .. tostring(cls); return RI.new(cls, ...) end end
    return RI[k]
end })
local rtask = realenv.task; local wN = 0
env.wait = function() wN = wN + 1; if wN > 3 then error("WAIT_BUDGET") end return 0 end
env.task = setmetatable({}, { __index = function(_, k) if k == "wait" then return env.wait end return rtask[k] end })

----------------------------------------------------------------- run it
local f = loadstring(newZA); setfenv(f, env)
local ok, ret = pcall(f, Zh)
say("run ok: " .. tostring(ok) .. "  return type: " .. typeof(ret))
if not ok then say("error: " .. tostring(ret)) end
say("setmetatable-captured module tables: " .. #captured)

-------------------------------------------------- probe module with taint args
local function probe(tag, M)
    local keys = { "add", "mul", "sub", "div", "mod", "pow", "nope" }
    for _, k in ipairs(keys) do
        local okv, v = pcall(function() return M[k] end)
        if okv and type(v) == "function" then
            local before = #ops
            local okc, r = pcall(v, mk(6, "a"), mk(2, "b"))
            local sym = (#ops > before) and ops[#ops] or ("-> " .. tostring(okc and pv(r) or r))
            say(("%s.%s(a,b) => %s"):format(tag, k, sym))
        else
            say(("%s.%s -> %s"):format(tag, k, typeof(v)))
        end
    end
end
if type(ret) == "table" then probe("return", ret) end
for i, e in ipairs(captured) do probe("cap#" .. i, e.tbl) end

------------------------------------------------------------------ output
say("---- ARITHMETIC OPS (execution + probe order) ----")
for _, o in ipairs(ops) do say(o) end
say("---- BEHAVIOR ----")
for _, l in ipairs(behavior) do say(l) end
say("resolution stream length: " .. #stream)

local text = table.concat(report, "\n")
print(text)
pcall(function() writefile("obf3_trace_result.txt", text) end)
return text
