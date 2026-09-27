--!nocheck
-- universal.lua  --  obfuscator-agnostic dynamic trace.
-- Runs ANY obfuscated Lua under an instrumented environment and reports what it
-- actually does: prints, service/API calls, remote fires, loadstring bodies,
-- created instances, and the chunk's return value. No unwrap and no per-build
-- knobs, so it works on families VmSmart has no static plugin for. It cannot
-- always rebuild exact source (virtualized VMs need a lifter), but it recovers
-- real behavior, which is the state-of-the-art universal approach.

local SOURCE
do
    local ok, txt = pcall(function() return readfile("obf.lua") end)
    if ok and txt then SOURCE = txt end
    -- SOURCE = [[ ...embedded by deob.py... ]]
end
assert(SOURCE, "no source")

local R = {}
local function say(...) local p = {}; for i = 1, select("#", ...) do p[i] = tostring((select(i, ...))) end; R[#R+1] = table.concat(p, "\t") end

local behavior, prints, loads = {}, {}, {}
local realenv = getfenv()
local realLoad = loadstring
local RI = realenv.Instance
local rtask = realenv.task

-- ===== CONSTANT DUMPER (standard technique) ==============================
-- VMs rebuild their string constants with string.char / sub / table.concat.
-- Hook those so every constant the VM unpacks is captured. This surfaces the
-- real hidden strings (keys, field names, defaults) the behavior trace misses.
local consts, seenC, capN = {}, {}, 0
local function capture(s)
    if type(s) ~= "string" then return end
    local n = #s
    if n < 2 or n > 120 or seenC[s] or capN > 6000 then return end
    for i = 1, n do local b = s:byte(i); if b < 9 or (b > 13 and b < 32) or b > 126 then return end end
    seenC[s] = true; capN = capN + 1; consts[capN] = s
end
local rstring, rtable = realenv.string, realenv.table
local wrapString = setmetatable({}, { __index = function(_, k)
    local f = rstring[k]
    if k == "char" or k == "sub" or k == "format" or k == "rep" or k == "reverse" then
        return function(...) local r = f(...); capture(r); return r end
    end
    return f
end })
local wrapTable = setmetatable({}, { __index = function(_, k)
    local f = rtable[k]
    if k == "concat" then return function(...) local r = f(...); capture(r); return r end end
    return f
end })
-- ========================================================================

-- executor-sim stubs so executor scripts run in Studio too
local genv = {}
local ES = {
    identifyexecutor=function() return "Synapse X","2.0" end, getexecutorname=function() return "Synapse X" end,
    getgenv=function() return genv end, getrenv=function() return realenv end, getreg=function() return {} end, getgc=function() return {} end,
    getrawmetatable=function(o) local ok,m=pcall(getmetatable,o); return ok and m or nil end, setrawmetatable=function(o) return o end,
    setreadonly=function() end, isreadonly=function() return false end, hookfunction=function(a) return a end, hookmetamethod=function() return function() end end,
    newcclosure=function(f) return f end, clonefunction=function(f) return f end, checkcaller=function() return true end,
    islclosure=function() return true end, iscclosure=function() return false end, getnamecallmethod=function() return "" end, setnamecallmethod=function() end,
    request=function(o) behavior[#behavior+1]="request: "..tostring(type(o)=="table" and o.Url or o); return {StatusCode=200,Body="",Success=true} end,
    getconnections=function() return {} end, getinstances=function() return {} end, cloneref=function(x) return x end,
    isnetworkowner=function() return true end, getthreadidentity=function() return 8 end, setthreadidentity=function() end,
    isexecutorclosure=function() return true end, isourclosure=function() return true end,
}

local env
env = setmetatable({}, { __index = function(_, k)
    if k == "string" then return wrapString end
    if k == "table" then return wrapTable end
    local rv = realenv[k]; if rv ~= nil then return rv end
    return ES[k]
end })
env.print = function(...) local p={}; for i=1,select("#",...) do p[i]=tostring((select(i,...))) end local s=table.concat(p, ", "); prints[#prints+1]=s; behavior[#behavior+1]="print: "..s end
env.warn  = function(...) local p={}; for i=1,select("#",...) do p[i]=tostring((select(i,...))) end behavior[#behavior+1]="warn: "..table.concat(p, ", ") end
env.getgenv = ES.getgenv
-- loadstring hook: log size, detect nested obfuscation layers, and setfenv the
-- inner chunk so its behavior is traced too (recursive unwrap).
local function detectLayer(s)
    s = tostring(s or "")
    local head = s:sub(1, 200)
    if head:find("MoonVeil", 1, true) then return "MoonVeil" end
    if head:find("Luraph", 1, true) then return "Luraph" end
    if head:find("Moonsec", 1, true) or head:find("MoonSec", 1, true) then return "MoonSec" end
    if head:find("DecompressBuffer", 1, true) or head:find("CompressionAlgorithm", 1, true) then return "base85+Zstd" end
    if head:find("return{", 1, true) or head:find("return({", 1, true) then return "wrapper-table VM" end
    if s:byte(1) == 27 then return "raw Luau bytecode" end  -- \27 = precompiled
    return "plain/unknown"
end
env.loadstring = function(src, ...)
    local n = #tostring(src or "")
    loads[#loads+1] = n
    local layer = detectLayer(src)
    behavior[#behavior+1] = "loadstring #" .. n .. "  (inner layer: " .. layer .. ")"
    -- save the first inner chunk so it can be re-analyzed by the pipeline
    if n > 200 and #loads <= 3 then
        pcall(function() writefile("inner_chunk_" .. #loads .. ".txt", tostring(src)) end)
    end
    local f = realLoad(src, ...)
    if f then pcall(setfenv, f, env) end
    return f
end
env.Instance = setmetatable({}, { __index=function(_,k) if k=="new" then return function(c,...) behavior[#behavior+1]="Instance.new: "..tostring(c); return RI.new(c,...) end end return RI[k] end })

-- Server-only services throw on a client executor and stop the trace. Proxy
-- `game` so GetService returns LOGGING PROXIES: every method call and its
-- arguments are recorded (e.g. GetDataStore("PlayerStats_V2"),
-- SetAsync(key, {...})), which recovers real names/keys/values, much closer to
-- source than bare service names. typeof(game) ~= "DataModel" here, an accepted
-- limit of universal mode.
local function preview(v, depth)
  depth = depth or 0
  local t = typeof(v)
  if t == "string" then return string.format("%q", #v > 60 and v:sub(1,60).."..." or v)
  elseif t == "number" or t == "boolean" then return tostring(v)
  elseif t == "nil" then return "nil"
  elseif t == "table" then
    if depth > 2 then return "{...}" end
    local parts = {}
    for k, vv in pairs(v) do
      if #parts >= 8 then parts[#parts+1] = "..."; break end
      parts[#parts+1] = tostring(k).."="..preview(vv, depth+1)
    end
    return "{"..table.concat(parts, ", ").."}"
  else return t end
end
local function argstr(...)
  local n = select("#", ...); local p = {}
  for i = 1, n do p[i] = preview((select(i, ...))) end
  return table.concat(p, ", ")
end
-- a proxy whose every method logs "ns:method(args)" and returns another proxy
local function logProxy(ns)
  return setmetatable({}, { __index = function(_, method)
    return function(_, ...)
      behavior[#behavior + 1] = ns .. ":" .. tostring(method) .. "(" .. argstr(...) .. ")"
      return logProxy(ns .. "." .. tostring(method))
    end
  end })
end
do
  local realGame = realenv.game
  if realGame then
    local serverStubs = {
      DataStoreService = "DataStoreService",
      MessagingService = "MessagingService",
      MarketplaceService = "MarketplaceService",
    }
    env.game = setmetatable({}, {
      __index = function(_, k)
        if k == "GetService" or k == "FindService" or k == "service" then
          return function(_, name)
            behavior[#behavior + 1] = "GetService: " .. tostring(name)
            if serverStubs[name] then return logProxy(name) end
            local ok, svc = pcall(function() return realGame:GetService(name) end)
            return ok and svc or logProxy(name)
          end
        end
        local v = realGame[k]
        if type(v) == "function" then return function(_, ...) return v(realGame, ...) end end
        return v
      end
    })
    env.Game = env.game
  end
end
local wN = 0
env.wait = function() wN = wN + 1; if wN > 5 then error("WAIT_BUDGET") end return 0 end
env.task = setmetatable({}, { __index=function(_,k) if k=="wait" then return env.wait end return rtask[k] end })

-- run
local f = realLoad(SOURCE)
say("loaded: "..tostring(f ~= nil))
local ret
if f then
  pcall(setfenv, f, env)
  local ok, r = pcall(f)
  ret = r
  say("run_ok: "..tostring(ok).."  return_type: "..typeof(r))
  if not ok then say("error: "..tostring(r)) end
  -- BFS: exercise functions the chunk returned, to surface nested behavior
  local function tryCall(fn) local okc = pcall(fn); return okc end
  if type(ret) == "function" then tryCall(ret) end
  if type(ret) == "table" then
    for k, v in pairs(ret) do if type(v) == "function" then behavior[#behavior+1]="module fn: "..tostring(k); pcall(v) end end
  end
else
  say("run_ok: false  return_type: nil"); say("error: loadstring failed")
end

say("counts: prints="..#prints.." loads="..#loads.." behavior="..#behavior.." consts="..capN)
say("mode: universal")
say("---PRINTS---"); for i=1,math.min(#prints,80) do say("PRINT: "..prints[i]) end
say("---BEHAVIOR---"); for i=1,math.min(#behavior,80) do say(behavior[i]) end
-- captured constant pool (full set to a side file, a sample to the console)
say("---CONSTANTS---"); for i=1,math.min(capN,120) do say("K: "..consts[i]) end
pcall(function() local t={}; for i=1,capN do t[i]=consts[i] end; writefile("constants_full.txt", table.concat(t,"\n")) end)

local body = "BEGIN_UNOBF_RESULT\n"..table.concat(R, "\n").."\nEND_UNOBF_RESULT"
print(body)
pcall(function() writefile("unobf_result.txt", body) end)
return body
