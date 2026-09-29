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
-- the real receiver, method and argument values of every call made.

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

-- ---------------------------------------------------------------- shields
-- Tracing changes two things a protected script can measure about itself, and
-- both of them are measurable without naming anything: how long it takes, and
-- what its own source looks like. Neither shield recognises a script or a
-- protection - they answer two questions consistently for every caller.
--
-- 1) Time. Logging every instruction makes the run hundreds of times slower.
--    A script that checks elapsed time sees a number that could not happen on
--    a real machine and can take a different path. Freezing the clock is not
--    the answer either: a clock that never moves is as wrong as one that
--    jumps, and code that waits for it to advance would hang. So the clock is
--    virtual - it starts where the real one did and advances by a small,
--    steady amount per reading, which is what an untraced run looks like.
local T0 = (realenv.os and realenv.os.clock and realenv.os.clock()) or 0
local vt, VSTEP = 0, 0.0000006
local function vclock() vt = vt + VSTEP; return T0 + vt end
local realTime = (realenv.os and realenv.os.time) or function() return 0 end
local TT0 = realTime()
local function vtime() return TT0 + math.floor(vt) end

-- 2) Its own source. The harness injects the trace callback into the
--    interpreter's text, which moves every line after the injection point and
--    changes how big each function is. debug.info and debug.traceback report
--    exactly that. The shield answers from the source as it was BEFORE the
--    injection, so what the script reads about itself matches what it shipped.
--    ORIGINAL_LINES is set when the patcher runs; until then the shield has
--    nothing to correct and passes everything through untouched.
local ORIGINAL_LINES, PATCH_AT, PATCH_ADDED = nil, nil, 0
local realdebug = realenv.debug or {}

local function fixline(n)
    if type(n) ~= "number" or not PATCH_AT then return n end
    if n > PATCH_AT then
        local back = n - PATCH_ADDED
        if back >= PATCH_AT then return back end
        return PATCH_AT
    end
    return n
end

local DBG = {}
DBG.info = function(a, b, c)
    if not realdebug.info then return nil end
    local r = { pcall(realdebug.info, a, b, c) }
    if not r[1] then return nil end
    local out = {}
    for i = 2, #r do out[i - 1] = r[i] end
    -- the line fields come back in the order the "what" string asked for; any
    -- number that looks like a line in the patched file is corrected
    local what = (type(b) == "string" and b) or (type(a) == "string" and a) or ""
    local j = 1
    for k = 1, #what do
        local ch = what:sub(k, k)
        if ch == "l" then out[j] = fixline(out[j]) end
        if ch == "s" and ORIGINAL_LINES and type(out[j]) == "string" then
            out[j] = out[j]
        end
        j = j + 1
    end
    return table.unpack and table.unpack(out) or unpack(out)
end
DBG.getinfo = function(...)
    if not realdebug.getinfo then return nil end
    local ok, t = pcall(realdebug.getinfo, ...)
    if not ok or type(t) ~= "table" then return ok and t or nil end
    t.currentline = fixline(t.currentline)
    t.linedefined = fixline(t.linedefined)
    t.lastlinedefined = fixline(t.lastlinedefined)
    return t
end
DBG.traceback = function(...)
    if not realdebug.traceback then return "" end
    local ok, s2 = pcall(realdebug.traceback, ...)
    if not ok or type(s2) ~= "string" then return "" end
    -- rewrite the ":<line>:" markers the same way
    return (s2:gsub(":(%d+):", function(n)
        return ":" .. tostring(fixline(tonumber(n))) .. ":"
    end))
end
setmetatable(DBG, { __index = realdebug })

local env
-- The tracer's own hooks live HERE, not on env. They used to be plain fields
-- on the environment, which means any script that walks its own globals
--
--     for k in pairs(getfenv()) do ... end
--
-- saw __OP, __CODE, __SL and __CAP sitting there. Four names that exist in no
-- Roblox environment are a far more direct giveaway than timing or line
-- numbers, and cost nothing to look for.
--
-- Served through __index instead, they still resolve when the injected code
-- reads them as globals, because a global read is exactly an __index lookup.
-- What changes is that pairs() does not walk a metamethod, and rawget on the
-- environment returns nil for them. Ordinary globals - print, game, warn -
-- stay real fields, because a real environment has those and hiding them would
-- be its own tell.
local HID = {}
env = setmetatable({}, { __index = function(_, k)
    local h = HID[k]; if h ~= nil then return h end
    local rv = realenv[k]; if rv ~= nil then return rv end
    return ES[k]
end })
env.debug = DBG
env.os = setmetatable({ clock = vclock, time = vtime },
                      { __index = realenv.os })
env.tick = vclock
env.time = vclock
env.elapsedTime = vclock
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
HID.__SL = function(r)
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
HID.__CAP = function() end

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
-- compact, safe preview of a runtime value on the VM stack (for value-flow).
local function vprev(v)
    local ok, t = pcall(type, v)
    if not ok then return "?" end
    if t == "string" then
        if #v > 28 then v = v:sub(1, 28) .. ".." end
        return "\"" .. v:gsub("[\r\n\t;]", " ") .. "\""
    elseif t == "number" or t == "boolean" then
        return tostring(v)
    elseif t == "nil" then
        return "nil"
    elseif t == "table" then
        return "{}"
    end
    return t   -- function / userdata / thread
end

local codeRows = nil
-- Dump the instruction array once. Every row is one instruction: its operands
-- as the interpreter stores them. Rows the run never reached are exactly what
-- makes this worth having, so nothing is filtered.
HID.__CODE = function(arr)
    if codeRows ~= nil or type(arr) ~= "table" then return end
    codeRows = {}
    local n = 0
    for pc = 1, 200000 do
        local row = arr[pc]
        if row == nil then
            if pc > 8 then break end
        else
            n = n + 1
            local a = {}
            if type(row) == "table" then
                for i = 1, 12 do
                    local v = row[i]
                    a[#a+1] = (v == nil) and "" or tostring(v)
                end
            end
            codeRows[#codeRows+1] = tostring(pc) .. ":" .. table.concat(a, ",")
        end
        if n > 100000 then break end
    end
    pcall(function()
        writefile("code_array.txt", table.concat(codeRows, "\n"))
    end)
end

HID.__OP = function(pc, oc, NO, sp, top)
    opn = opn + 1
    if opn > 40000 then return end
    local a = {}
    if type(NO) == "table" then
        for i = 2, 8 do local v = NO[i]; if v ~= nil then a[#a+1] = tostring(v) end end
    end
    -- format: pc;opcode;operands;stackpointer;topvalue
    -- topvalue is the real value the VM just produced (the pending write slot),
    -- so the lifter sees actual strings/numbers flowing between opcodes.
    ops[#ops+1] = tostring(pc) .. ";" .. tostring(oc) .. ";" .. table.concat(a, ",")
                  .. ";" .. tostring(sp) .. ";" .. vprev(top)
end

-- SAFE MODE: when false, the opcode-dispatch trace is not applied at all, so
-- the VM's self-integrity check is never disturbed and the run finishes clean
-- (constants + behavior only). deob.py --safe sets this to false.
local TRACE_OPCODES = true
-- WHICH nested interpreter to trace. Patching two at once is what tripped the
-- VM's self-integrity check and ended the run early, so exactly one is traced
-- per run and this says which. Run once per chunk and merge the captures: the
-- later chunks are where the program's tail runs, and a capture that only ever
-- traces the first one cannot account for it.
local TRACE_CHUNK = 1
local patchable = 0          -- how many interpreters we have been able to patch
local dispatchDone = false   -- harness-local gate (executors may sandbox _G)
local function patchDispatch(s)
    -- first (NL-NU)%0x7fffffff expression = the dispatch opcode
    local nl, nu = s:match("%(%((%w+)%-(%w+)%)%%0[xX]%x+")
    if not nl then return nil end
    -- program counter from NU's own assignment: local NU=((PC-1)*<digits>...
    local pc = s:match("local " .. nu .. "=%(%((%w+)%-1%)%*%d+")
    if not pc then return nil end
    -- instruction row NO from the loop top: local NO = CODE[PC];
    local no, code = s:match("local (%w+)=(%w+)%[" .. pc .. "%];")
    if not no then return nil end
    -- register array + stack pointer from the register-write-buffer flush the
    -- handlers share:  if n>=2 then YL[Ym-1]=NN end  -> capture YL and Ym
    local arr, sp = s:match("if %w+>=2 then (%w+)%[(%w+)%-1%]=")
    sp = sp or "0"
    -- This VM DEFERS register writes: a handler leaves its produced value in a
    -- pending slot (NY) and the NEXT handler flushes it to YL[Ym]. So YL[Ym] is
    -- stale at the loop top (nil most of the time); the freshly produced value
    -- lives in NY. Capture NY and log THAT as the value flowing.
    local ny = s:match("if %w+>=1 then %w+%[%w+%]=(%w+) end")
    local topexpr = ny or ((arr and sp ~= "0") and (arr .. "[" .. sp .. "]")) or "nil"
    -- inject the logger right after the NL assignment `local NL=...;`
    local mark = "local " .. nl .. "="
    local i = s:find(mark, 1, true); if not i then return nil end
    local j = s:find(";", i + #mark, true); if not j then return nil end
    -- The trace only shows instructions that RAN. The array they are read
    -- from holds every instruction the program has, including the ones this
    -- run never reached, and reachability, branch targets and real coverage
    -- cannot be judged without it. It is handed over once, from inside the
    -- dispatch loop, where it is certain to be fully built.
    local dump = code and (";if __CODE then __CODE(" .. code .. ")end") or ""
    local inject = ";if __OP then __OP(" .. pc .. ",(" .. nl .. "-" .. nu .. ")%2147483647," .. no .. "," .. sp .. "," .. topexpr .. ")end" .. dump
    -- Tell the debug shield what this injection did to the file's line
    -- numbering, measured rather than assumed: where it went in, and how many
    -- lines it added. Today it adds none - the whole logger is written on one
    -- line on purpose, so debug.info keeps reporting the lines the script
    -- shipped with. If that ever stops being true, the shield corrects for it
    -- instead of quietly reporting lines that moved.
    local before = select(2, s:sub(1, j - 1):gsub("\n", ""))
    local added = select(2, inject:gsub("\n", ""))
    PATCH_AT, PATCH_ADDED = before + 1, added
    ORIGINAL_LINES = select(2, s:gsub("\n", "")) + 1
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
    -- on top of that, trace the dispatch loop of ONE interpreter: the one this
    -- run was asked for. Patching two at once trips the VM's self-integrity
    -- check and ends the run, so each chunk gets its own run and the captures
    -- are merged afterwards.
    local useD = use
    if TRACE_OPCODES and not dispatchDone then
        local canPatch = select(2, pcall(patchDispatch, use))
        if canPatch then
            patchable = patchable + 1
            if patchable == TRACE_CHUNK then
                local okD, patchedD, dn = pcall(patchDispatch, use)
                if okD and patchedD then
                    useD = patchedD
                    dispatchDone = true
                    behavior[#behavior+1] = "  [patched dispatch " .. tostring(dn)
                        .. " -> tracing interpreter #" .. patchable .. "]"
                end
            else
                behavior[#behavior+1] = "  [interpreter #" .. patchable
                    .. " left untraced; this run traces #" .. TRACE_CHUNK .. "]"
            end
        end
    else
        behavior[#behavior+1] = "  [dispatch trace already placed for this run]"
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
-- arguments are recorded exactly as the program passed them,
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
-- A function handed to task.spawn, task.delay or task.defer runs on its own
-- thread. The pcall around the payload does not reach that thread, so when one
-- of them raises, the error surfaces as an engine message and never reaches the
-- capture: the trace looks clean while something in the script is failing, and
-- there is no way to tell from the files afterwards.
--
-- Wrapping the callback puts the error where it can be read. The error is not
-- swallowed - it is written into the behaviour log and re-raised nowhere, so
-- the thread ends exactly as it would have, and the capture now says why.
local function watched(fn, what)
    if type(fn) ~= "function" then return fn end
    return function(...)
        local packed = { pcall(fn, ...) }
        if not packed[1] then
            behavior[#behavior+1] = "error in " .. what .. ": " ..
                                    tostring(packed[2])
        end
        return select(2, unpack and unpack(packed) or table.unpack(packed))
    end
end
env.task = setmetatable({}, { __index = function(_, k)
    if k == "wait" then return env.wait end
    local real = rtask[k]
    if (k == "spawn" or k == "delay" or k == "defer") and type(real) == "function" then
        return function(a, b, ...)
            -- task.spawn(fn, ...) and task.delay(t, fn, ...) put the callback
            -- in different places, so the one that is a function is the one
            -- that gets watched.
            if type(a) == "function" then
                return real(watched(a, "task." .. k), b, ...)
            end
            return real(a, watched(b, "task." .. k), ...)
        end
    end
    return real
end })

-- ----------------------------------------------------------------- probe
-- Everything above is a shield. A shield nobody tested is a hope, so this
-- interrogates the environment the harness just built, the same way a
-- protected script would, and writes down whatever it can still tell.
--
-- It matches no names and knows nothing about any obfuscator. It asks
-- questions any script can ask about itself, and reports the answers. A clean
-- result is not proof that nothing is detectable. A dirty one is proof that
-- something is.
local probe = {}
local function pnote(tag, detail) probe[#probe+1] = tag .. "\t" .. tostring(detail) end

-- Each check runs in its own pcall. They all used to share one, so the first
-- that raised took every later one down with it and the section came back
-- empty with nothing to say why. A check that fails now says so and the rest
-- still run: a missing answer is information, an absent section is not.
local function pcheck(tag, fn)
    local ok, a, b = pcall(fn)
    if ok then
        pnote(tag, b == nil and a or (tostring(a) .. ": " .. tostring(b)))
    else
        pnote(tag, "check_failed: " .. tostring(a))
    end
end

-- 1) Globals that exist here and do not exist in the real environment. The
--    cheapest check a script can run, and the one that found the tracer's own
--    hooks sitting in plain sight.
pcheck("globals_not_in_real_env", function()
    local extra, n = {}, 0
    for k in pairs(env) do
        if type(k) == "string" and realenv[k] == nil then
            n = n + 1
            if n <= 12 then extra[#extra+1] = k end
        end
    end
    if n == 0 then return 0 end
    return n, table.concat(extra, ",")
end)

-- 2) Can the tracer's hooks be reached by name, and can they be seen?
--    Reachable is required - the injected logger calls them. Visible is the
--    leak.
pcheck("hooks_reachable", function()
    local n = 0
    for _, k in ipairs({"__OP", "__CODE", "__SL", "__CAP"}) do
        if env[k] ~= nil then n = n + 1 end
    end
    return n
end)
pcheck("hooks_visible_to_rawget", function()
    local n = 0
    for _, k in ipairs({"__OP", "__CODE", "__SL", "__CAP"}) do
        if rawget(env, k) ~= nil then n = n + 1 end
    end
    return n
end)

-- 3) Does the environment carry a metatable? A plain one does not, and this
--    harness's does. Reported rather than hidden: removing it would mean
--    giving up the fallback to the real globals.
pcheck("env_has_metatable", function()
    return getmetatable(env) ~= nil
end)

-- 4) Identity. A hooked function is not the function it replaced, and
--    rawequal says so without needing a name.
pcheck("functions_not_identical_to_real", function()
    local n = 0
    for _, k in ipairs({"print", "warn", "loadstring", "require"}) do
        local mine, real = env[k], realenv[k]
        if mine ~= nil and real ~= nil and not rawequal(mine, real) then
            n = n + 1
        end
    end
    return n
end)

-- 5) Time. The shield's whole job is that a traced run does not look
--    impossibly slow. Measure what a script measuring itself would get.
pcheck("virtual_seconds_for_200k_adds", function()
    local c0 = env.os.clock()
    local acc = 0
    for i = 1, 200000 do acc = acc + i end
    return string.format("%.6f", env.os.clock() - c0)
end)
pcheck("clock_is_monotonic", function()
    local a = env.os.clock()
    local b = env.os.clock()
    return b >= a
end)

-- 6) What the script can learn about its own source position.
pcheck("debug_info_line", function()
    if not (env.debug and env.debug.info) then return "no debug.info" end
    local l = env.debug.info(1, "l")
    return l == nil and "unavailable" or tostring(l)
end)

say("---PROBE---")
for i = 1, #probe do say(probe[i]) end

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
say("traced_chunk: "..TRACE_CHUNK.."  patchable_interpreters: "..patchable)
say("mode: universal")
say("---PRINTS---"); for i=1,math.min(#prints,80) do say("PRINT: "..prints[i]) end
say("---BEHAVIOR---"); for i=1,math.min(#behavior,120) do say(behavior[i]) end
-- real constants dumped from the inner VM resolver (the deep recovery)
say("resolved="..#resolved)
say("---RESOLVED---"); for i=1,math.min(#resolved,400) do say(resolved[i]) end
pcall(function() local t={}; for i=1,#resolved do t[i]=resolved[i] end; writefile("resolved_constants.txt", table.concat(t,"\n")) end)
-- devirtualization: the executed instruction stream (pc;opcode;operands)
say("opcodes="..#ops.."  (logged, cap 40000; total executed may be higher)")
if codeRows then
    say("code_rows="..#codeRows)
    say("---CODE---")
    for i=1,math.min(#codeRows,2000) do say(codeRows[i]) end
end
say("---OPCODES---"); for i=1,math.min(#ops,3000) do say(ops[i]) end
pcall(function() writefile("opcode_trace.txt", table.concat(ops,"\n")) end)

local body = "BEGIN_UNOBF_RESULT\n"..table.concat(R, "\n").."\nEND_UNOBF_RESULT"
print(body)
pcall(function() writefile("unobf_result.txt", body) end)
return body
