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

-- Constant capture note: hooking string.char/table.concat globally floods the
-- log with the VM's per-byte intermediates AND can break the interpreter (it
-- rebuilds opcodes the same way). Instead we capture constants where they are
-- HIGH SIGNAL: the real arguments passed to API calls (logProxy / logForward
-- below). Those are the program's genuine strings/numbers, e.g.
-- GetDataStore("PlayerStats_V2") and captured argument tables.

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
-- Deep constant recovery: nested chunks in this family carry a constant
-- resolver of the form
--   local function R(x) if x<0 then x=-x-GC end; return DEC(TBL[x]) end
-- We patch that resolver so every constant it returns is logged. When the outer
-- program later drives the inner VM, this dumps the REAL program constants
-- (keys, field names, numbers). All guarded by pcall so it can never break the
-- run: if the patch does not apply, the original chunk is loaded unchanged.
local resolved, seenR = {}, {}
env.__SL = function(r)
    if #resolved > 4000 then return end
    if type(r) == "string" then
        if #r >= 2 and #r <= 120 and not seenR["S"..r] then
            local ok = true
            for i = 1, #r do local b = r:byte(i); if b < 9 or (b > 13 and b < 32) or b > 126 then ok = false break end end
            if ok then seenR["S"..r] = true; resolved[#resolved+1] = "S:" .. r end
        end
    elseif type(r) == "number" and not seenR["N"..tostring(r)] then
        seenR["N"..tostring(r)] = true; resolved[#resolved+1] = "N:" .. tostring(r)
    end
end
env.__CAP = function() end

-- Devirtualization trace. The inner VM's dispatch loop looks like
--   while true do local NO = ARR[PC]  ...
--     local NU = ((PC-1)*<num>+<h>) % 2147483647
--     local NL = (NQ+NU) % 2147483647     -- opcode = (NL-NU) % 0x7fffffff
--   ... nested if-tree on (NL-NU)%0x7fffffff picks the handler
-- We inject a log call right after NL is computed, so every executed
-- instruction (program counter, opcode, operand row) is recorded. This turns
-- the running VM into a disassembler of the paths that actually execute. All
-- guarded: if the shape does not match, the trace is simply skipped.
local ops, opn = {}, 0
env.__OP = function(pc, oc, NO, sp)
    opn = opn + 1
    if opn > 15000 then return end
    local a = {}
    if type(NO) == "table" then
        for i = 2, 8 do local v = NO[i]; if v ~= nil then a[#a+1] = tostring(v) end end
    end
    -- format: pc;opcode;operands;stackpointer  (sp lets the lifter measure the
    -- real push/pop effect of each opcode from execution, not from guesses)
    ops[#ops+1] = tostring(pc) .. ";" .. tostring(oc) .. ";" .. table.concat(a, ",")
                  .. ";" .. tostring(sp)
end

local function patchDispatch(s)
    -- first (NL-NU)%0x7fffffff expression = the dispatch opcode
    local nl, nu = s:match("%(%((%w+)%-(%w+)%)%%0[xX]%x+")
    if not nl then return nil end
    -- program counter from NU's own assignment: local NU=((PC-1)*<digits>...
    local pc = s:match("local " .. nu .. "=%(%((%w+)%-1%)%*%d+")
    if not pc then return nil end
    -- instruction row NO from the loop top: local NO = ARR[PC];
    local no = s:match("local (%w+)=%w+%[" .. pc .. "%];")
    if not no then return nil end
    -- stack pointer from the register-write-buffer flush the handlers share:
    --   if n>=2 then YL[Ym-1]=NN end  -> capture Ym
    local sp = s:match("if %w+>=2 then %w+%[(%w+)%-1%]=") or "0"
    -- inject the logger right after the NL assignment `local NL=...;`
    local mark = "local " .. nl .. "="
    local i = s:find(mark, 1, true); if not i then return nil end
    local j = s:find(";", i + #mark, true); if not j then return nil end
    local inject = ";if __OP then __OP(" .. pc .. ",(" .. nl .. "-" .. nu .. ")%2147483647," .. no .. "," .. sp .. ")end"
    return s:sub(1, j - 1) .. inject .. s:sub(j), (nl .. "/" .. nu .. "/" .. pc .. " sp=" .. sp)
end

local function patchResolver(s)
    local rn, ra, rg, rd, rt = s:match("local function (%w+)%((%w+)%)if %2<0 then %2=%-%2%-(%w+) end;return (%w+)%((%w+)%[%2%]%)end")
    if not rn then return nil end
    local orig = ("local function %s(%s)if %s<0 then %s=-%s-%s end;return %s(%s[%s])end"):format(rn, ra, ra, ra, ra, rg, rd, rt, ra)
    local patched = ("local function %s(%s)if %s<0 then %s=-%s-%s end;local _r=%s(%s[%s]);if __SL then __SL(_r) end;return _r end;if __CAP then __CAP(%s,%s)end"):format(rn, ra, ra, ra, ra, rg, rd, rt, ra, rd, rt)
    local out, nrep = s:gsub(orig:gsub("[%-%[%]%(%)%.%+%*%?%^%$%%]", "%%%0"), patched, 1)
    if nrep == 1 then return out, rn end
    return nil
end

env.loadstring = function(src, ...)
    local n = #tostring(src or "")
    loads[#loads+1] = n
    local layer = detectLayer(src)
    behavior[#behavior+1] = "loadstring #" .. n .. "  (inner layer: " .. layer .. ")"
    if n > 200 and #loads <= 3 then
        pcall(function() writefile("inner_chunk_" .. #loads .. ".txt", tostring(src)) end)
    end
    -- try to patch the inner resolver so it dumps real constants (guarded)
    local use = src
    local ok, patched, rn = pcall(patchResolver, src)
    if ok and patched then
        use = patched
        behavior[#behavior+1] = "  [patched resolver " .. tostring(rn) .. " -> dumping constants]"
    end
    -- on top of that, try to patch the dispatch loop so it traces opcodes
    local useD = use
    local okD, patchedD, dn = pcall(patchDispatch, use)
    if okD and patchedD then
        useD = patchedD
        behavior[#behavior+1] = "  [patched dispatch " .. tostring(dn) .. " -> tracing opcodes]"
    end
    -- compile, degrading gracefully: full (resolver+dispatch) -> resolver-only
    -- -> original. A broken dispatch patch never costs us the constant dump.
    local f = realLoad(useD, ...)
    if not f and useD ~= use then f = realLoad(use, ...) end
    if not f then f = realLoad(src, ...) end
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
-- like logProxy but forwards to the REAL service so results stay valid (used for
-- (Real client services like HttpService are left untouched: proxying them
-- returns a function for every field, which the VM's integrity ops break on.)
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
            -- everything else stays REAL (client services like HttpService work
            -- fine and must not be proxied, or the VM's integrity ops break).
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
-- Let loops run more iterations (so loop-gated behavior is captured) but still
-- bound it so an infinite while-wait cannot hang the trace.
local wN = 0
env.wait = function() wN = wN + 1; if wN > 40 then error("WAIT_BUDGET") end return 0 end
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
say("---BEHAVIOR---"); for i=1,math.min(#behavior,120) do say(behavior[i]) end
-- real constants dumped from the inner VM resolver (the deep recovery)
say("resolved="..#resolved)
say("---RESOLVED---"); for i=1,math.min(#resolved,400) do say(resolved[i]) end
pcall(function() local t={}; for i=1,#resolved do t[i]=resolved[i] end; writefile("resolved_constants.txt", table.concat(t,"\n")) end)
-- devirtualization: the executed instruction stream (pc;opcode;operands)
say("opcodes="..#ops.."  (logged, cap 15000; total executed may be higher)")
say("---OPCODES---"); for i=1,math.min(#ops,3000) do say(ops[i]) end
pcall(function() writefile("opcode_trace.txt", table.concat(ops,"\n")) end)

local body = "BEGIN_UNOBF_RESULT\n"..table.concat(R, "\n").."\nEND_UNOBF_RESULT"
print(body)
pcall(function() writefile("unobf_result.txt", body) end)
return body
