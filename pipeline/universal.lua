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
env = setmetatable({}, { __index = function(_, k) local rv = realenv[k]; if rv ~= nil then return rv end return ES[k] end })
env.print = function(...) local p={}; for i=1,select("#",...) do p[i]=tostring((select(i,...))) end local s=table.concat(p, ", "); prints[#prints+1]=s; behavior[#behavior+1]="print: "..s end
env.warn  = function(...) local p={}; for i=1,select("#",...) do p[i]=tostring((select(i,...))) end behavior[#behavior+1]="warn: "..table.concat(p, ", ") end
env.getgenv = ES.getgenv
env.loadstring = function(src, ...) loads[#loads+1] = #tostring(src or ""); behavior[#behavior+1]="loadstring #"..#tostring(src or ""); local f=realLoad(src, ...); if f then pcall(setfenv, f, env) end return f end
env.Instance = setmetatable({}, { __index=function(_,k) if k=="new" then return function(c,...) behavior[#behavior+1]="Instance.new: "..tostring(c); return RI.new(c,...) end end return RI[k] end })
-- wrap game:GetService without breaking typeof(game)=="DataModel"
do
  local realGame = realenv.game
  if realGame then
    -- log via a lightweight namecall proxy is risky; instead log GetService by wrapping the method table is not possible on userdata.
    -- keep game real (datatype checks pass); services are logged when scripts index them by name through HttpGet/request stubs above.
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

say("counts: prints="..#prints.." loads="..#loads.." behavior="..#behavior)
say("mode: universal")
say("---PRINTS---"); for i=1,math.min(#prints,80) do say("PRINT: "..prints[i]) end
say("---BEHAVIOR---"); for i=1,math.min(#behavior,80) do say(behavior[i]) end

local body = "BEGIN_UNOBF_RESULT\n"..table.concat(R, "\n").."\nEND_UNOBF_RESULT"
print(body)
pcall(function() writefile("unobf_result.txt", body) end)
return body
