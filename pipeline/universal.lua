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
-- A standalone harness carries no script and reads obf.lua from the executor's
-- own folder. Saying so beats "no source", which names nothing a person can act
-- on and was the only message this could give.
if not SOURCE then
    local msg = "VmSmart: no script to run.\n"
        .. "This harness reads obf.lua from your executor's workspace folder.\n"
        .. "Save your obfuscated script there, named exactly obf.lua, and run "
        .. "this file again.\n"
        .. "(The harness with the script already inside it is harness.lua; this "
        .. "one is the standalone copy.)"
    print(msg)
    error(msg, 0)
end

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
-- Hooks served through __index are invisible to `pairs` and `rawget`, which
-- is what keeps a script from spotting the tracer by walking its own globals.
-- It costs one thing: a VM that COPIES its environment - `for k,v in
-- pairs(getfenv()) do E[k]=v end` - copies real fields and not metamethod
-- answers, so the hooks would not follow it and nothing would be logged.
--
-- No build has been shown to do that. But "no instructions were recorded" and
-- "the hook was unreachable" look identical from the files, so the choice is
-- a switch rather than a belief: deob.py can emit a harness with the hooks as
-- plain fields, and if that one records what the hidden one did not, the copy
-- is what happened.
local HIDE_HOOKS = true
local HID = {}
-- Every global the payload read that this environment did not have. The report
-- kept ending at "the program, or something this environment does not give it"
-- and then had nothing to say about which - because the one place that knows is
-- this lookup, and it was throwing the answer away. A nil read is not an error:
-- a script testing `if getgenv then` reads nil on purpose. This is a list of
-- names the environment did not carry, for a reader to judge.
local missing, missingSeen, missingN = {}, {}, 0
env = setmetatable({}, { __index = function(_, k)
    local h = HID[k]; if h ~= nil then return h end
    local rv = realenv[k]; if rv ~= nil then return rv end
    local sv = ES[k]
    if sv == nil and missingN < 400 and type(k) == "string"
       and not missingSeen[k] then
        missingSeen[k] = true
        missingN = missingN + 1
        missing[#missing+1] = k
    end
    return sv
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
-- Raw count of constants the resolver handed back, counted before the
-- de-duplication and before the cap. The de-duplicated list cannot say how far
-- a SECOND round got: every constant it resolves is already in the list, so the
-- round reads as having got nowhere when it got exactly as far as the first.
local constSeen = 0
HID.__SL = function(r)
    constSeen = constSeen + 1
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
-- Which instruction arrays the run has handed over, and in what order. A build
-- of this class does not have ONE instruction array: every function the program
-- defines is its own prototype with its own array, and the dispatch loop runs
-- whichever one the current call holds.
--
-- This used to dump the first array it was given and stop, and the report then
-- called that array "every instruction the program has". It is one function's
-- instructions. The give-away was a capture whose traced rows at a given number
-- carried no operands while the dumped array had a full row at that same number
-- - two different arrays, read as one.
local codeArrays, codeArrayN = {}, 0
local codeMap = {}
local codeRefs = {}          -- the arrays themselves, to read again at the end
local function arrayId(arr)
    local k = tostring(arr)
    if codeArrays[k] == nil then
        codeArrayN = codeArrayN + 1
        codeArrays[k] = codeArrayN
    end
    return codeArrays[k]
end
-- Dump an instruction array. Every row is one instruction: its operands as the
-- interpreter stores them. Rows the run never reached are exactly what makes
-- this worth having, so nothing is filtered.
local codeOrdered = {}
local function orderRows(byPc)
    local pcs = {}
    for pc in pairs(byPc) do pcs[#pcs+1] = pc end
    table.sort(pcs)
    local out = {}
    for i = 1, #pcs do out[i] = byPc[pcs[i]] end
    return out
end

local function readArray(arr)
    local rows, n = {}, 0
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
            rows[pc] = tostring(pc) .. ":" .. table.concat(a, ",")
        end
        if n > 100000 then break end
    end
    return rows
end

HID.__CODE = function(arr)
    if type(arr) ~= "table" then return end
    local id = arrayId(arr)
    codeRefs[id] = arr
    if codeMap[id] ~= nil then return end      -- this one is already written
    local byPc = readArray(arr)
    codeMap[id] = byPc
    local rows = orderRows(byPc)
    -- The first array keeps the name the reader already knows; the rest get
    -- their own files rather than overwriting it.
    if id == 1 then codeRows = rows end
    codeOrdered[id] = rows
    pcall(function()
        writefile(id == 1 and "code_array.txt"
                  or ("code_array_" .. id .. ".txt"),
                  table.concat(rows, "\n"))
    end)
end

HID.__OP = function(pc, oc, NO, sp, top, arr)
    opn = opn + 1
    if opn > 40000 then return end
    -- WHICH value is the instruction row.
    --
    -- This used to log the variable the dispatch loop assigns it to, found by
    -- matching `local NO = ARR[PC];` in the source. That variable was nil on six
    -- of nine traced instructions, and the capture reported "the interpreter read
    -- something that was not an instruction row" - which was then read, for
    -- several rounds of this work, as the build failing.
    --
    -- It was not. The same capture also recorded that ARR[PC] held a full row at
    -- those very numbers. So the variable is not ARR[PC] at the point the logger
    -- reads it: the name is matched from one place in a one-line megabyte source
    -- and the call is injected at another, and nothing guarantees the two are the
    -- same scope, or that the counter has not moved on in between.
    --
    -- The array and the counter are what the interpreter itself indexes, so the
    -- row is read from THEM. The variable is still recorded, as a cross-check,
    -- and a disagreement is written down as a fault in this hook rather than as a
    -- fact about the program.
    local row, fromArray = NO, false
    if type(arr) == "table" then
        local n = tonumber(pc)
        if n ~= nil then
            local direct = rawget(arr, n)
            if direct ~= nil then
                row, fromArray = direct, true
            end
        end
    end
    local a = {}
    local note = ""
    if type(row) == "table" then
        for i = 2, 8 do local v = row[i]; if v ~= nil then a[#a+1] = tostring(v) end end
    else
        note = "row=" .. vprev(row)
        note = note .. "|pctype=" .. type(pc)
        if type(arr) == "table" then
            local n = tonumber(pc)
            if n ~= nil and n ~= math.floor(n) then
                note = note .. "|pc_not_integral"
            end
            local ok, len = pcall(function() return #arr end)
            if ok then note = note .. "|arrlen=" .. tostring(len) end
        end
    end
    -- The row's own first field, the encoded opcode. It is pc-dependent by
    -- design, so two rows sharing a decoded opcode SHOULD differ here and a
    -- difference proves nothing on its own. It is recorded because a decode can
    -- only ever be established from it, and guessing at one from the decoded
    -- value alone is how this tool has gone wrong before.
    if type(row) == "table" and type(rawget(row, 1)) == "number" then
        note = (note ~= "" and (note .. "|") or "") .. "rawop=" .. tostring(row[1])
    end
    if fromArray then
        -- The row came from the array. Say so, and say whether the loop's own
        -- variable agreed: when it did not, the reading below is the array's and
        -- the mismatch is this hook's placement, not the build's behaviour.
        note = (note ~= "" and (note .. "|") or "") .. "src=array"
        if NO ~= row then
            note = note .. "|hook_var_disagrees=" .. vprev(NO)
        end
    elseif type(row) == "table" then
        note = (note ~= "" and (note .. "|") or "") .. "src=loopvar"
    end
    if arr ~= nil then
        local id = arrayId(arr)
        note = (note ~= "" and (note .. "|") or "") .. "arr=" .. id
    end
    -- format: pc;opcode;operands;stackpointer;topvalue;note
    -- topvalue is the real value the VM just produced (the pending write slot),
    -- so the lifter sees actual strings/numbers flowing between opcodes. The
    -- note says where the row was read from and what it was when it was not one.
    ops[#ops+1] = tostring(pc) .. ";" .. tostring(oc) .. ";" .. table.concat(a, ",")
                  .. ";" .. tostring(sp) .. ";" .. vprev(top)
                  .. ";" .. note
end

-- SAFE MODE: when false, the opcode-dispatch trace is not applied at all, so
-- the VM's self-integrity check is never disturbed and the run finishes clean
-- (constants + behavior only). deob.py --safe sets this to false.
-- Which build of this package wrote this harness. deob.py stamps it in. Three
-- captures in a row were read as evidence about the CURRENT code when they came
-- from the harness the user already had on disk, which is the normal case: the
-- new one arrives after they have run the old one. A capture that says which
-- build made it removes that inference, and the report can then say what a
-- fresh capture would add instead of drawing a conclusion the capture cannot
-- support.
local HARNESS_ENGINE = 0
local TRACE_OPCODES = true
-- WHICH nested interpreter to trace. Patching two at once is what tripped the
-- VM's self-integrity check and ended the run early, so exactly one is traced
-- per run and this says which. Run once per chunk and merge the captures: the
-- later chunks are where the program's tail runs, and a capture that only ever
-- traces the first one cannot account for it.
local TRACE_CHUNK = 1
-- The harness makes TWO edits to the inner chunk, not one: it rewrites the
-- constant resolver so constants are dumped, and it injects a logger into the
-- dispatch loop. Turning off "the trace" only ever took the second one back
-- out, so a payload that raised both ways was reported as raising "without the
-- patch" while the resolver rewrite was still in the file. That is a wrong fact
-- reached by the machinery built to avoid wrong facts.
--
-- So the edits are a LEVEL, and the harness removes them one at a time:
--   2 = resolver rewritten AND dispatch loop traced
--   1 = resolver rewritten only
--   0 = nothing touched
--   3 = prototype makers hooked, resolver rewritten AND dispatch loop traced
local PATCH_LEVEL = TRACE_OPCODES and 3 or 1
local LEVEL_NAME = { [3] = "watched+traced", [2] = "traced",
                     [1] = "resolver-only", [0] = "unpatched" }
local patchable = 0          -- how many interpreters we have been able to patch
local dispatchDone = false   -- harness-local gate (executors may sandbox _G)
local resolverDone = false   -- whether the resolver rewrite went in this round
local protosDone = false     -- whether the prototype-maker hook went in
-- The slice watch is a DIFFERENT edit from the prototype hook and needs its own
-- flag. Sharing one made the capture say protos_hooked: true on a run whose
-- behaviour log said, three lines up, that no prototype maker matched.
local slicesDone = false
-- The last match of a pattern that starts at or before `limit`. Anchoring
-- matters more than it looks: a dispatch loop's names must all come from the
-- SAME loop, and this source is one line of a megabyte with several interpreters
-- in it, so "the first match in the file" is a different loop nearly every time.
local function lastBefore(s, pat, limit)
    local at, a, b, c
    local from = 1
    while true do
        local i, j, x, y = s:find(pat, from)
        if not i or i > limit then break end
        at, a, b, c = i, x, y, j
        from = i + 1
    end
    return at, a, b, c
end

local function patchDispatch(s)
    -- The dispatch opcode expression, (NL-NU)%0x7fffffff. Everything else is
    -- found by walking BACK from here, so every name belongs to this one loop.
    --
    -- Each name used to be taken with its own s:match, which returns the first
    -- occurrence in the whole file. On the real sample that produced a row
    -- variable from one interpreter and an injection point in another: the
    -- logger then read a name that was not in scope, saw nil, and the capture
    -- reported the interpreter reading a missing instruction. It was reading the
    -- wrong variable. This is that bug's root, and the fix is the shape the
    -- Luraph v15 devirtualizer's find_dispatchers already has - it takes op, arr
    -- and pc from a single statement in a single scope, which is the whole point.
    -- find returns start, END, then the captures. Reading it as start, cap1,
    -- cap2 put a byte offset where a variable name belongs.
    local opAt, _opEnd, nl, nu = s:find("%(%((%w+)%-(%w+)%)%%0[xX]%x+")
    if not nl then return nil end
    -- program counter from NU's own assignment: local NU=((PC-1)*<digits>...
    local _, pc = lastBefore(s, "local " .. nu .. "=%(%((%w+)%-1%)%*%d+", opAt)
    if not pc then return nil end
    -- instruction row NO from the loop top: local NO = CODE[PC];
    local rowAt, no, code = lastBefore(s, "local (%w+)=(%w+)%[" .. pc .. "%];",
                                       opAt)
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
    -- The value flowing is read either from the pending slot or straight out of
    -- the register array. Reading the array MUST NOT be written as a bare
    -- index: on the first instruction the array can still be nil, and
    -- `arr[sp]` then raises "attempt to index nil with number" from inside the
    -- interpreter - the trace ends after a handful of instructions and the
    -- error looks like the script's own, because it is reported at line 1 of
    -- the chunk the injection went into.
    --
    -- Guarding it costs one `and`. The logger may never be the thing that ends
    -- the run it is there to observe.
    local topexpr = ny or ((arr and sp ~= "0")
                           and ("(" .. arr .. " and " .. arr .. "[" .. sp .. "])"))
                       or "nil"
    -- inject the logger right after THIS loop's NL assignment. Taking the first
    -- `local NL=` in the file put the call in another interpreter entirely,
    -- where the row variable this patch names does not exist.
    local mark = "local " .. nl .. "="
    local i = lastBefore(s, mark:gsub("[%-%[%]%(%)%.%+%*%?%^%$%%]", "%%%0"),
                         opAt)
    if not i then return nil end
    local j = s:find(";", i + #mark, true); if not j then return nil end
    -- The row must be read BEFORE the logger runs, or the name is not in scope
    -- yet and Lua resolves it to a nil global - which is exactly what happened.
    if rowAt > j then return nil end
    -- The trace only shows instructions that RAN. The array they are read
    -- from holds every instruction the program has, including the ones this
    -- run never reached, and reachability, branch targets and real coverage
    -- cannot be judged without it. It is handed over once, from inside the
    -- dispatch loop, where it is certain to be fully built.
    local dump = code and (";if __CODE then __CODE(" .. code .. ")end") or ""
    -- The array the row was read FROM goes in too. A build of this class runs a
    -- prototype per function, each with its own array, and without this a row
    -- logged at number N cannot be told from a row logged at N in another
    -- array - which is how a dumped array with a full row at N sat beside a
    -- traced row at N with no operands, and the two were read as one thing.
    local whicharr = code and ("," .. code) or ",nil"
    local inject = ";if __OP then __OP(" .. pc .. ",(" .. nl .. "-" .. nu .. ")%2147483647," .. no .. "," .. sp .. "," .. topexpr .. whicharr .. ")end" .. dump
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

-- Every prototype, not only the ones the run entered.
--
-- The dispatch trace can only ever show instructions that EXECUTED, and the
-- array it hands over is the one the current call holds. A build of this class
-- keeps a prototype per function, so a program's untaken branches and unused
-- functions have arrays that no trace and no single dump can reach. Coverage
-- measured against one array is coverage of one function.
--
-- The way in is the place where each closure is BUILT rather than run: a maker
-- function that takes the prototype and returns the interpreter closure for it.
-- Hooking there sees every prototype the program defines, including the ones it
-- never calls.
--
-- Finding that function without knowing any of its names is the part worth
-- having, and the discriminator comes from the Luraph v15 devirtualizer
-- (caomod2077/Deobfuscator-Luraph-V15, MIT), whose vmmap._maker_params picks the
-- prototype parameter as "the parameter indexed through itself (P[P[k]]: its
-- fields are keyed by its own entries)". That is a behavioural signature, so it
-- survives renaming, and it is the same kind of test the rest of this package
-- uses. Their implementation reads a real Luau AST; this one is a text pattern,
-- because this harness runs inside the executor with no parser. Nothing
-- build-specific is carried over: their loop_names() returns literal variable
-- names for known builds, and that is exactly the lookup this project refuses.
local protoSeen, protoN = {}, 0
HID.__PROTO = function(p)
    if type(p) ~= "table" then return end
    local k = tostring(p)
    if protoSeen[k] then return end
    protoSeen[k] = true
    protoN = protoN + 1
    if protoN > 400 then return end
    -- A prototype holds its instruction array as one of its fields. Which field
    -- is not known and is not guessed: every field that LOOKS like an
    -- instruction array is handed to the array dump, which records what it
    -- actually found. A field that is not one produces a short dump and says so.
    for _, v in pairs(p) do
        if type(v) == "table" and type(rawget(v, 1)) ~= "nil" then
            pcall(function() HID.__CODE(v) end)
        end
    end
    pcall(function() HID.__CODE(p) end)
end

-- The accessor that hands out slices, and the request that kills the run.
--
-- This family deserialises its payload into a table of (length, offset) pairs
-- and hands out a small descriptor per index through a one-parameter closure:
--
--   local function S(i) local m = TBL[i]; if not m then return nil end
--                       return {DATA, m[2], m[1]} end
--
-- The `return nil` is the interesting part. A caller that asks for an index the
-- data does not carry gets nil and then indexes it - S(4)[1] - and the engine
-- says "attempt to index nil with number" from line 1 of the chunk. That is the
-- shape of the error this build dies with, and nothing in the capture could say
-- WHICH index was asked for, because nothing was watching the accessor.
--
-- The pattern is the accessor's SHAPE, not its names: a local function of one
-- parameter whose body indexes a captured table by that parameter and returns
-- nil when the entry is absent. Lua back-references tie the three uses of the
-- parameter together, so no name appears here either.
local slices, sliceN = {}, 0
HID.__SLICE = function(name, idx, present, count)
    sliceN = sliceN + 1
    if sliceN > 2000 then return end
    slices[#slices+1] = tostring(name) .. ":" .. tostring(idx) .. ":"
                        .. (present and "ok" or "MISSING") .. ":"
                        .. tostring(count)
end

local function patchSlices(s)
    local hits = 0
    local out = s:gsub(
        "local function (%w+)%((%w+)%)local (%w+)=(%w+)%[%2%];if not %3 then return nil end",
        function(fn, arg, v, tbl)
            hits = hits + 1
            return ("local function %s(%s)local %s=%s[%s];"
                    .. "if __SLICE then __SLICE(%q,%s,%s~=nil,#%s)end;"
                    .. "if not %s then return nil end"):format(
                fn, arg, v, tbl, arg, fn, arg, v, tbl, v)
        end)
    if hits == 0 then return nil end
    return out, hits .. " accessor(s)"
end

local function patchProtos(s)
    -- The self-indexed variable: X[X[...]]. Lua patterns carry back-references,
    -- so this is one match and no name appears in it.
    local names, order = {}, {}
    for nm in s:gmatch("([%a_][%w_]*)%[%1%[") do
        if not names[nm] then names[nm] = true; order[#order+1] = nm end
    end
    if #order == 0 then return nil end
    local hits = 0
    local out = s
    for i = 1, #order do
        local nm = order[i]
        -- The ENCLOSING function header, found by walking forward and keeping
        -- the last one that both declares this name AND starts before the place
        -- the name is used that way. Keeping the last match anywhere in the file
        -- instead picked a function further down that happens to share the
        -- parameter name, which on a one-line megabyte source is every time.
        local at = out:find(nm .. "%[" .. nm .. "%[")
        local best
        local from = 1
        while true do
            -- `function(...)` and `function name(...)` and `function a.b:c(...)`
            -- all declare parameters. Matching only the anonymous form found no
            -- maker at all in a source that names its functions.
            local a, b, params = out:find("function[%s]*[%w_.:]*[%s]*%(([^)]*)%)",
                                          from)
            if not a then break end
            if at and a > at then break end
            local found = false
            for tok in params:gmatch("[%a_][%w_]*") do
                if tok == nm then found = true break end
            end
            if found then best = b end
            from = b + 1
        end
        if best then
            local inject = ";if __PROTO then __PROTO(" .. nm .. ")end"
            out = out:sub(1, best) .. inject .. out:sub(best + 1)
            hits = hits + 1
        end
    end
    if hits == 0 then return nil end
    return out, hits .. " maker(s) on " .. #order .. " self-indexed name(s)"
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
    -- The outermost edit: hook where prototypes are built, so the arrays of
    -- functions this run never calls are seen too.
    local src0 = src
    if PATCH_LEVEL >= 3 then
        local okS, patchedS, sn = pcall(patchSlices, src)
        if okS and patchedS then
            src = patchedS
            slicesDone = true
            behavior[#behavior+1] = "  [watching slice accessor -> " .. tostring(sn) .. "]"
        else
            behavior[#behavior+1] = "  [no slice accessor matched]"
        end
        local okP, patchedP, pn = pcall(patchProtos, src)
        if okP and patchedP then
            src = patchedP
            protosDone = true
            behavior[#behavior+1] = "  [hooked prototype makers -> " .. tostring(pn) .. "]"
        else
            behavior[#behavior+1] = "  [no prototype maker matched; nothing hooked]"
        end
    else
        behavior[#behavior+1] = "  [prototype makers left alone at this patch level]"
    end
    -- try to patch the inner resolver so it dumps real constants (guarded)
    local use = src
    if PATCH_LEVEL >= 1 then
        local ok, patched, rn = pcall(patchResolver, src)
        if ok and patched then
            use = patched
            resolverDone = true
            behavior[#behavior+1] = "  [patched resolver " .. tostring(rn) .. " -> dumping constants]"
        end
    else
        behavior[#behavior+1] = "  [resolver left alone at this patch level]"
    end
    -- on top of that, trace the dispatch loop of ONE interpreter: the one this
    -- run was asked for. Patching two at once trips the VM's self-integrity
    -- check and ends the run, so each chunk gets its own run and the captures
    -- are merged afterwards.
    local useD = use
    if PATCH_LEVEL >= 2 and not dispatchDone then
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
    elseif PATCH_LEVEL >= 2 then
        behavior[#behavior+1] = "  [dispatch trace already placed for this run]"
    else
        -- "already placed" was printed here for a round where the trace was
        -- deliberately taken OUT, which reads as the opposite of what happened.
        behavior[#behavior+1] = "  [dispatch loop left alone at this patch level]"
    end
    -- compile, degrading gracefully: full (resolver+dispatch) -> resolver-only
    -- -> original. A broken dispatch patch never costs us the constant dump.
    local f = realLoad(useD, ...)
    if not f and useD ~= use then f = realLoad(use, ...) end
    if not f and use ~= src then f = realLoad(src, ...) end
    if not f then f = realLoad(src0, ...) end
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
            if serverStubs[name] then
              behavior[#behavior + 1] = "GetService: " .. tostring(name)
                                        .. "  -> logging proxy (server-only)"
              return logProxy(name)
            end
            -- everything else stays REAL (client services like HttpService work
            -- fine and must not be proxied, or the VM's integrity ops break).
            local ok, svc = pcall(function() return realGame:GetService(name) end)
            -- WHICH of the two was handed back matters and was not recorded. A
            -- proxy answers every field with a function, so a program that asked
            -- for a service this engine does not have gets something shaped
            -- nothing like what it expected, and the report could not tell that
            -- from a service that resolved.
            behavior[#behavior + 1] = "GetService: " .. tostring(name) .. "  -> "
                .. ((ok and svc ~= nil) and "real service"
                    or "logging proxy (this engine has no such service)")
            return (ok and svc ~= nil) and svc or logProxy(name)
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
        -- `unpack and unpack(packed)` truncates to one value inside an
        -- and/or, so this used to hand back nothing at all. Unpack the
        -- results explicitly, from index 2, which is where they start.
        local un = table.unpack or unpack
        return un(packed, 2, #packed)
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

-- With hiding off, the hooks become ordinary globals. Placed here, after every
-- one of them is defined, so the copy carries all four.
if not HIDE_HOOKS then
    for k, v in pairs(HID) do rawset(env, k, v) end
end

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

-- ------------------------------------------------------------------- the run
-- The harness EDITS the inner chunk to observe it: it rewrites the constant
-- resolver, and it injects a logger into the dispatch loop. Either edit is
-- something a program can react to, and a program that raises under them looks
-- the same as one that raises on its own.
--
-- Telling those apart means running the SAME payload again with an edit taken
-- back out. That used to be a second file to run by hand, and choosing between
-- files went wrong twice; a capture from the wrong file looks exactly like the
-- right one, so the wrong conclusion got drawn with nothing to contradict it.
--
-- So the harness does it, and does it all the way down: on a run that raises it
-- removes ONE edit and runs again, until either the payload finishes or there is
-- no edit left to remove. Removing only the dispatch logger was not enough - the
-- resolver rewrite was still in the file, and a run that raised at that level
-- was being reported as raising "without the patch".
--
-- The step condition is what was observed: the edit at this level actually went
-- in, and the run raised. Not a count of instructions, not what the error text
-- looks like. Either of those would be guessing at the build.
-- The run's own headers need a section of their own. Without this marker they
-- land inside ---PROBE---, because that is the last section opened before the
-- payload runs and nothing closed it. A reader that looks for scalar headers at
-- the top of a capture then finds none of them, and "run_ok was not stated"
-- reads the same as "run_ok: false".
say("---RUN---")
local attempts = {}
local function runPayload()
    dispatchDone = false
    resolverDone = false
    protosDone = false
    slicesDone = false
    patchable = 0
    -- The line shield corrects for an injection. On a round where the injection
    -- is not going in, leaving it set would answer the payload's questions about
    -- its own source as if it were.
    ORIGINAL_LINES, PATCH_AT, PATCH_ADDED = nil, nil, 0
    local rec = { level = PATCH_LEVEL, mode = "unpatched",
                  ok = false, rtype = "nil", loaded = false, err = nil,
                  rows0 = #ops, const0 = constSeen }
    local f = realLoad(SOURCE)
    rec.loaded = (f ~= nil)
    if not f then
        rec.err = "loadstring failed"
    else
        pcall(setfenv, f, env)
        local ok, r = pcall(f)
        rec.ok = ok
        -- Only a run that finished HAS a return value. On a failed run the
        -- second pcall result is the error, and calling its type the chunk's
        -- return type puts a wrong fact in a header.
        rec.rtype = ok and tostring(typeof(r)) or "nil"
        if not ok then
            rec.err = tostring(r)
        else
            -- BFS: exercise functions the chunk returned, to surface nested
            -- behavior.
            if type(r) == "function" then pcall(r) end
            if type(r) == "table" then
                for k, v in pairs(r) do
                    if type(v) == "function" then
                        behavior[#behavior+1] = "module fn: " .. tostring(k)
                        pcall(v)
                    end
                end
            end
        end
    end
    rec.rows_added = #ops - rec.rows0
    -- Constants are counted RAW here, not from the de-duplicated list: a second
    -- round resolving the same constants adds nothing to that list, and
    -- "constants=0" then reads as "this round got nowhere" when it got exactly
    -- as far as the one before.
    rec.const_added = constSeen - rec.const0
    rec.applied_dispatch = dispatchDone
    rec.applied_resolver = resolverDone
    rec.applied_protos = protosDone
    rec.applied_slices = slicesDone
    rec.patchable = patchable
    -- The round's name comes from what was APPLIED, not from what was asked for.
    -- A level-2 round whose dispatch hook never matched this build is a
    -- resolver-only round, and calling it "traced" would put an edit in the
    -- record that is not in the chunk.
    rec.mode = ((protosDone or slicesDone) and LEVEL_NAME[3])
               or (dispatchDone and LEVEL_NAME[2])
               or (resolverDone and LEVEL_NAME[1])
               or LEVEL_NAME[0]
    attempts[#attempts+1] = rec
    return rec
end

local last = runPayload()
local first = last
while not last.ok do
    -- Which edit is there to remove? Only one that actually went in: dropping a
    -- level that changed nothing would repeat the same run and read as evidence.
    -- Go to the level that actually removes the named edit, not one level
    -- down. Stepping 2 -> 1 to remove the RESOLVER leaves the resolver in, so
    -- the next round repeats this one and reads as evidence that it is not the
    -- patches.
    local step
    if last.applied_protos or last.applied_slices then
        -- Name what was actually in the chunk, not the level's label. Both of
        -- these live at level 3 and either can be the only one that went in.
        local parts = {}
        if last.applied_slices then parts[#parts+1] = "the slice watch" end
        if last.applied_protos then parts[#parts+1] = "the prototype-maker hook" end
        step = table.concat(parts, " and ")
        PATCH_LEVEL = 2
    elseif last.applied_dispatch then
        step = "the dispatch logger"
        PATCH_LEVEL = 1
    elseif last.applied_resolver then
        step = "the resolver rewrite"
        PATCH_LEVEL = 0
    else
        break
    end
    say("retry_reason: the run raised with " .. step .. " in the chunk, so the "
        .. "same payload is run again with it taken out (patch level "
        .. PATCH_LEVEL .. ", " .. tostring(LEVEL_NAME[PATCH_LEVEL]) .. ")")
    behavior[#behavior+1] = "  [retry: same payload, " .. step .. " removed]"
    last = runPayload()
end

-- Which harness produced this capture, said by the harness instead of guessed
-- from its side effects. A capture from one mode used to be distinguishable from
-- another only by reading the behaviour log sideways, which is exactly the
-- inference that went wrong.
local best = first
for i = 1, #attempts do
    if attempts[i].ok then best = attempts[i] break end
end
local chain = {}
for i = 1, #attempts do chain[i] = attempts[i].mode end
local hid
if not first.loaded then
    -- Nothing was traced because nothing compiled. Saying "the hook did not
    -- match" here would send the reader after the wrong thing.
    hid = "untested (the payload did not compile)"
elseif #attempts > 1 then
    hid = table.concat(chain, "->")
elseif first.level >= 2 and not first.applied_dispatch
       and not first.applied_protos and not first.applied_slices then
    hid = "trace_requested_but_unpatched"
else
    hid = first.mode
end
say("harness: universal")
say("harness_engine: " .. tostring(HARNESS_ENGINE))
-- Whether the hooks were hidden behind the environment's metatable this run.
-- With them visible on purpose, two of the exposure checks come back EXPOSED by
-- design, and a report that cannot tell that apart from a leak reads the
-- requested mode as a defect.
say("hooks_hidden: " .. tostring(HIDE_HOOKS))
say("harness_id: " .. hid)
say("dispatch_patched: " .. tostring(first.applied_dispatch))
say("resolver_patched: " .. tostring(first.applied_resolver))
say("protos_hooked: " .. tostring(first.applied_protos))
say("slices_hooked: " .. tostring(first.applied_slices))
say("protos_seen: " .. protoN)
say("slice_requests: " .. sliceN)
say("attempts: " .. #attempts)
for i = 1, #attempts do
    local a = attempts[i]
    say(("attempt%d: mode=%s level=%d loaded=%s run_ok=%s return_type=%s "
         .. "instructions=%d constants=%d resolver=%s dispatch=%s protos=%s "
         .. "slices=%s"):format(
        i, tostring(a.mode), a.level, tostring(a.loaded), tostring(a.ok),
        tostring(a.rtype), a.rows_added, a.const_added,
        tostring(a.applied_resolver), tostring(a.applied_dispatch),
        tostring(a.applied_protos), tostring(a.applied_slices)))
    if a.err then say("attempt" .. i .. "_error: " .. tostring(a.err)) end
end
-- The headline outcome is the best attempt, so a capture whose later round
-- finished is not read as a failed run. The per-attempt lines above keep both.
say("loaded: " .. tostring(best.loaded))
say("run_ok: " .. tostring(best.ok) .. "  return_type: " .. tostring(best.rtype))
if not best.ok then
    say("error: " .. tostring(best.err or "the run did not finish"))
end
-- The comparison the rounds exist to make, stated only as what was seen.
if #attempts > 1 then
    if best.ok then
        -- The edit removed on the way into the round that finished is the one
        -- the payload objected to.
        local prev = attempts[1]
        for i = 2, #attempts do
            if attempts[i] == best then prev = attempts[i - 1] break end
        end
        local edit = (prev.applied_slices and "the slice watch")
                     or (prev.applied_protos and "the prototype-maker hook")
                     or (prev.applied_dispatch and "the dispatch logger")
                     or "the resolver rewrite"
        say("trace_verdict: patch_caught -- the payload raised at patch level "
            .. prev.level .. " (" .. tostring(prev.mode) .. ") and finished at "
            .. best.level .. " (" .. tostring(best.mode) .. "), same session, "
            .. "same payload. " .. edit .. " is what it reacted to.")
    else
        local deepest = attempts[#attempts]
        say("trace_verdict: not_the_patches -- the payload raised at every "
            .. "patch level the harness could take back: "
            .. table.concat(chain, ", ") .. ". At level " .. deepest.level
            .. " the chunk was not edited"
            .. ((deepest.level == 0) and " at all" or " beyond that level")
            .. ", so the failure is not the instrumentation. It is the program, "
            .. "or something this environment does not give it.")
        local same = true
        for i = 2, #attempts do
            if tostring(attempts[i].err) ~= tostring(attempts[1].err) then
                same = false
            end
        end
        say("trace_verdict_note: the error was "
            .. (same and "identical at every level, which is what an "
                         .. "environment fault looks like"
                     or "not the same at every level, so the edits are not "
                        .. "irrelevant either"))
    end
end

say("counts: prints="..#prints.." loads="..#loads.." behavior="..#behavior)
say("traced_chunk: "..TRACE_CHUNK.."  patchable_interpreters: "..first.patchable)
say("mode: universal")
say("---PRINTS---"); for i=1,math.min(#prints,80) do say("PRINT: "..prints[i]) end
say("---BEHAVIOR---"); for i=1,math.min(#behavior,120) do say(behavior[i]) end
-- real constants dumped from the inner VM resolver (the deep recovery)
say("resolved="..#resolved)
say("---RESOLVED---"); for i=1,math.min(#resolved,400) do say(resolved[i]) end
pcall(function() local t={}; for i=1,#resolved do t[i]=resolved[i] end; writefile("resolved_constants.txt", table.concat(t,"\n")) end)
-- devirtualization: the executed instruction stream (pc;opcode;operands)
say("opcodes="..#ops.."  (logged, cap 40000; total executed may be higher)")
-- How many instruction arrays the run handed over, and what became of them.
--
-- A build of this class holds a prototype per function, each with its own
-- instruction array, and some of them decrypt their rows AS THEY RUN: a row is
-- nil until an earlier instruction writes it. Both of those make a single dump
-- taken at one moment a description of that moment, not of the program - and the
-- report was calling it "every instruction the program has".
--
-- So each array is read again at the end and compared with what it held when it
-- was first seen. A row that appeared, or changed, is the array rewriting itself
-- while it runs, which is a fact about the build and not a guess about it.
say("code_arrays=" .. codeArrayN)
for id = 1, codeArrayN do
    local before = codeMap[id]
    local arr = codeRefs[id]
    if before and arr then
        local okr, after = pcall(readArray, arr)
        if okr and after then
            local same, changed, appeared, vanished, now = 0, 0, 0, 0, 0
            for pc, line in pairs(after) do
                now = now + 1
                if before[pc] == nil then appeared = appeared + 1
                elseif before[pc] == line then same = same + 1
                else changed = changed + 1 end
            end
            local was = 0
            for pc in pairs(before) do
                was = was + 1
                if after[pc] == nil then vanished = vanished + 1 end
            end
            say(("code_recheck: arr=%d rows_first=%d rows_last=%d same=%d "
                 .. "changed=%d appeared=%d vanished=%d"):format(
                id, was, now, same, changed, appeared, vanished))
            if changed > 0 or appeared > 0 then
                pcall(function()
                    writefile("code_array_" .. id .. "_final.txt",
                              table.concat(orderRows(after), "\n"))
                end)
            end
        else
            say("code_recheck: arr=" .. id .. " could not be read again")
        end
    end
end
-- Names the payload read that this environment did not carry. Not errors: a
-- script testing for a feature reads nil on purpose. But when a run dies
-- indexing nil, this is the shortest list of candidates there is, and it was
-- not being written down at all.
say("env_missing=" .. #missing)
if #missing > 0 then
    say("---ENVMISSING---")
    for i = 1, math.min(#missing, 400) do say(missing[i]) end
end
if codeRows then
    say("code_rows="..#codeRows)
    say("---CODE---")
    -- The cap used to cut the dump at the first 2000 rows, and a run that jumps
    -- past that point leaves a capture that cannot say where it went: the rows
    -- the trace actually visited were the ones missing. So every pc the trace
    -- reached is dumped whatever its number, on top of the first 2000.
    local want = {}
    for i = 1, #ops do
        local pc = tostring(ops[i]):match("^(%-?%d+);")
        if pc then want[tonumber(pc)] = true end
    end
    local said = 0
    for i = 1, #codeRows do
        local pc = tonumber(tostring(codeRows[i]):match("^(%d+):"))
        if i <= 2000 or (pc and want[pc]) then
            say(codeRows[i])
            said = said + 1
        end
    end
    say("code_rows_written=" .. said)
end
-- Every slice the payload asked the accessor for, and whether it was there.
-- This is a LIST, so it goes down here with the other lists. Opening its section
-- up among the run headers meant every header after it - the attempt lines, the
-- error, the verdict - landed inside it and was never read as a header at all.
-- The probe section had done exactly this once before.
if #slices > 0 then
    say("---SLICES---")
    for i = 1, math.min(#slices, 600) do say(slices[i]) end
end
say("---OPCODES---"); for i=1,math.min(#ops,3000) do say(ops[i]) end
pcall(function() writefile("opcode_trace.txt", table.concat(ops,"\n")) end)

local body = "BEGIN_UNOBF_RESULT\n"..table.concat(R, "\n").."\nEND_UNOBF_RESULT"
print(body)
pcall(function() writefile("unobf_result.txt", body) end)
return body
