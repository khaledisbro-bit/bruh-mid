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
-- How many instruction rows a capture carries. The run is not stopped at this
-- number - only the log is - and whether it was reached changes how every count
-- below it should be read, so the capture says which.
local OP_LOG_CAP = 200000
local OP_LOG_TRUNCATED = false
-- The counter the instruction logger last saw. The other watches used to take
-- the loop's counter variable by name, which only exists inside the interpreter
-- function - a watch that fired anywhere else read it as a nil global, and the
-- stand-in then reported being asked for a host datatype called `Ne`. The logger
-- passes through every instruction, so it is the one place that knows the
-- counter, and the rest read it from here.
local LAST_PC = nil
-- The row at which the stand-in's answers first entered the program's own
-- arithmetic, or nil if they never did.
local FICTION_AT_ROW = nil
local FICTION_AT_BEHAVIOR = nil
-- Whether to take this build's self-destruct out of the chunk.
--
-- Only against a stand-in, and only at the top patch level. In a real host the
-- checks behind it pass and it never fires, so removing it there would be an
-- edit with nothing to gain; offline they cannot pass, and without removing it
-- no offline run reaches the program at all.
local NEUTRALISE_TAMPER = false
local TAMPER_TAKEN = 0
-- Declared up here on purpose: the instruction logger is defined further down
-- but ABOVE where this used to be, so the name resolved to a nil global, the
-- comparison against it raised inside the hook, and the capture came back with
-- zero instructions and a stand-in that had been asked for a datatype called
-- OP_LOG_CAP. Four separate watches have now been written with this mistake.
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
DBG.info = function(...)
    if not realdebug.info then return nil end
    -- The ARITY is forwarded, not just the values. debug.info is a C function
    -- with two shapes - (level, options) and (function, options) - and some
    -- hosts also take (thread, level, options). A C function counts its
    -- arguments with the stack top, and an explicit nil counts, so calling it
    -- with a third nil picked the three-argument shape and it answered with one
    -- value instead of three. The script asked about three things, checked the
    -- type of each, found two of them nil, and marked itself as tampered with.
    local argc = select("#", ...)
    local a, b, c = ...
    -- A numeric first argument is a STACK LEVEL, counted from the caller of
    -- debug.info. This wrapper is a frame the script does not know it has, so
    -- the level has to be raised by one or the script is told about the wrapper
    -- instead of about itself.
    --
    -- And no pcall in between. A pcall is another frame, and with both of them
    -- level 1 landed on pcall - a C function, whose line is -1. So every script
    -- that asked which line it was on got -1, at every patch level, in every
    -- capture this project has taken. A build that checks its own line numbers
    -- sees that as tampering, which is exactly what the harness is trying not to
    -- look like. If the arguments are wrong, the real debug.info raises, and
    -- raising is what the script would have got without the harness.
    if type(a) == "number" then a = a + 1 end
    local pack = table.pack or function(...) return { n = select("#", ...), ... } end
    local r
    if argc <= 1 then r = pack(realdebug.info(a))
    elseif argc == 2 then r = pack(realdebug.info(a, b))
    else r = pack(realdebug.info(a, b, c)) end
    local out = { n = r.n or #r }
    for i = 1, out.n do out[i] = r[i] end
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
    -- WITH the count. `table.unpack(out)` stops at the array's border, and a
    -- debug.info result is full of holes: ask for three things about a function
    -- and the second can be nil, at which point the border is 1 and the other
    -- two are dropped. This build asks for three and checks the types of all
    -- three, so dropping two made it mark itself as tampered with at its second
    -- instruction - and the refusal that ends the run, thousands of counters
    -- later, is that mark. The harness was the tamper it was detecting.
    local n = out.n or #out
    -- A call inside an `and`/`or` is truncated to ONE value, so
    -- `return table.unpack and table.unpack(out, 1, n) or ...` returned the
    -- first result and dropped the rest, however correct the count was. The
    -- function is chosen first, then called in a return of its own.
    local unpackf = table.unpack or unpack
    return unpackf(out, 1, n)
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
-- `type` AS THE HOST ANSWERS IT, for the payload and nothing else. In Roblox an
-- Instance and a datatype are userdata; here they are tables, because a table is
-- all this can build. A build that asks reads the difference in one call. The
-- stand-in publishes the host-faithful answer under its own name rather than
-- replacing the global, so this harness and the stand-in itself keep seeing Lua's
-- own kinds - replacing it for everybody stopped parenting from working, because
-- the code that links a child to its parent asks whether the parent is a table.
if VMSMART_HOST_TYPE ~= nil then env.type = VMSMART_HOST_TYPE end
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
local PROTO_LEVELS = {}
-- WHICH ROUND a record belongs to. The ladder runs the same payload again with
-- one edit taken out each time it raises, so a capture holds several rounds of
-- the same program. Without this they read as one long run: the instruction
-- count is several copies of itself, and the calls the program made come out
-- multiplied by the number of rounds - which is why the reconstruction, which
-- runs once, could never account for more than a fraction of them.
VMSMART_ROUND = 1
-- The name matters. The stand-in answers an unknown capitalised global with a
-- stub, because that is how a host datatype it has never heard of is served -
-- so a global of this kind reads as "not nil" before anything is put in it,
-- the test below never fires, and what gets written out is the stub's own name
-- instead of a megabyte of interpreter. A VMSMART name is one the stand-in
-- never answers for, and `false` is a value rather than an absence.
VMSMART_INNER_SRC = false
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
                -- From index ZERO. This interpreter keeps the opcode at [0] and
                -- its operands from [2] up:
                --     local OP = ROW and ROW[0] or 0
                -- Reading from 1 meant the opcode field was never in the dump at
                -- all - not for the instructions that ran and not for the two
                -- thousand that did not. Every number this package reported per
                -- opcode was derived from arithmetic in the dispatch loop instead
                -- of from the field the interpreter actually reads.
                for i = 0, 12 do
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

HID.__OP = function(pc, oc, NO, sp, top, arr, trustRow, pending)
    LAST_PC = pc
    opn = opn + 1
    -- Which row the run is on, published for the stand-in. A call the stand-in
    -- answers can then be tied to the instruction that made it by POSITION,
    -- which is a stronger anchor than looking for the method's name in the value
    -- graph - and most recorded calls could not be matched that way.
    if VMSMART_STANDIN then VMSMART_ROW = opn end
    -- WHERE the stand-in's invented values entered the program's own
    -- arithmetic, measured in rows rather than described in prose. The report
    -- says the rows after that point describe the stand-in; without the row
    -- number, nothing downstream can act on that, and the analysis would go on
    -- reconstructing from rows the same report had just disowned. Read once per
    -- instruction until it happens, then never again.
    if FICTION_AT_ROW == nil and VMSMART_STANDIN then
        local n = rawget(realenv, "VMSMART_ARITH_COUNT")
        if type(n) == "number" and n > 0 then
            FICTION_AT_ROW = opn
            -- the behaviour log cannot be split by row number, so the count of
            -- entries at this moment is kept: everything logged after it was
            -- logged by a program already computing with invented values.
            FICTION_AT_BEHAVIOR = #behavior
        end
    end
    if opn > OP_LOG_CAP then
        OP_LOG_TRUNCATED = true
        return
    end
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
    -- WHICH of the two is believed.
    --
    -- From the loop top, the row variable is the row: the interpreter has just
    -- read its opcode out of it and is about to dispatch on that. The array
    -- named there is not necessarily the one it came from - this family
    -- re-fetches the row from a second array variable in between - so reading
    -- arr[pc] instead would reintroduce the very mismatch that reading the array
    -- was meant to fix.
    --
    -- From anywhere else, the row variable cannot be trusted and the array can.
    local row, fromArray = NO, false
    if trustRow and NO ~= nil then
        row, fromArray = NO, false
    elseif type(arr) == "table" then
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
    if type(row) == "table" then
        -- The opcode as the interpreter reads it: index 0. rawop used to carry
        -- index 1, which is not the opcode - it is a per-instruction number the
        -- handlers never read as one, and calling it the opcode put a wrong fact
        -- in every row of every capture.
        local op0 = rawget(row, 0)
        if op0 ~= nil then
            note = (note ~= "" and (note .. "|") or "") .. "rowop=" .. tostring(op0)
        else
            note = (note ~= "" and (note .. "|") or "") .. "rowop=absent"
        end
        if type(rawget(row, 1)) == "number" then
            note = note .. "|field1=" .. tostring(row[1])
        end
    end
    if fromArray then
        -- The row came from the array. Say so, and say whether the loop's own
        -- variable agreed: when it did not, the reading below is the array's and
        -- the mismatch is this hook's placement, not the build's behaviour.
        note = (note ~= "" and (note .. "|") or "") .. "src=array"
        if NO ~= row then
            note = note .. "|hook_var_disagrees=" .. vprev(NO)
        end
    elseif trustRow then
        -- Taken at the loop top, where the interpreter had just read its opcode
        -- from this very value. Whether the named array agrees is worth knowing
        -- and is not a reason to prefer it.
        note = (note ~= "" and (note .. "|") or "") .. "src=looptop"
        if type(arr) == "table" then
            local n = tonumber(pc)
            local alt = (n ~= nil) and rawget(arr, n) or nil
            if alt ~= nil and alt ~= row then
                note = note .. "|named_array_differs"
            end
        end
    elseif type(row) == "table" then
        note = (note ~= "" and (note .. "|") or "") .. "src=loopvar"
    end
    if arr ~= nil then
        local id = arrayId(arr)
        note = (note ~= "" and (note .. "|") or "") .. "arr=" .. id
    end
    -- which round of the ladder this row belongs to, so several runs of the
    -- same payload are not read as one long program
    note = (note ~= "" and (note .. "|") or "") .. "round="
           .. tostring(VMSMART_ROUND or 1)
    -- format: pc;opcode;operands;stackpointer;topvalue;note
    -- topvalue is the real value the VM just produced (the pending write slot),
    -- so the lifter sees actual strings/numbers flowing between opcodes. The
    -- note says where the row was read from and what it was when it was not one.
    -- the pending count goes in the note, so a reader that does not know about
    -- it still parses every field it did before
    if type(pending) == "number" then
        note = (note ~= "" and (note .. "|") or "") .. "pend=" .. tostring(pending)
    end
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
-- The ladder removes one edit per round, and between the dispatch logger and
-- the resolver rewrite there used to be nothing: taking the logger out took
-- the trace with it, so a build that objects to the RESOLVER could only be
-- told apart from one that objects to the LOGGER by losing the trace. This
-- flag is the missing rung - the trace stays in, the resolver comes out.
local RESOLVER_OFF = false
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

-- The loop top, where the interpreter reads its own opcode.
--
-- This family fetches the instruction row and then takes the opcode straight out
-- of it:
--     local ROW = ARR[PC]; ... local OP = ROW and ROW[0] or 0
-- and only then walks a chain of `elseif OP==N then <handler>` with a bit-tree
-- in the final else.
--
-- The logger used to go into that final else, because it was anchored on the
-- arithmetic there. So it only ever saw instructions whose opcode fell through
-- the WHOLE chain. Nine rows came back and were read as "the program ran nine
-- instructions and died" - they were nine instructions out of however many ran,
-- selected by which handler they missed. Every count, every jump, every gap in
-- this project's reports for this build came from that filtered subset.
--
-- Injecting after the opcode assignment sees every instruction, and takes the
-- opcode the interpreter itself uses rather than recomputing it. The shape is
-- the anchor: a row fetched by the counter, then a local assigned from that row
-- indexed by a constant with an `or 0` fallback. No name appears in it, and the
-- opcode's index is read from the source rather than assumed to be 1.
-- Forward declaration: patchDispatch calls this when the loop top does not
-- match, and without the declaration the call would resolve to a nil global.
local patchDispatchFallback
-- patchBlocks is defined with the other watches, below the hook it
-- records into, and patchDispatch calls it. Without this declaration that
-- call resolves to a nil global and the whole dispatch patch fails inside
-- a pcall, which reads downstream as a build whose loop never matched.
local patchBlocks
local patchChecks
local patchKeyTables
local patchFields
local patchSelfChecks
local patchResidue
local patchPoison
-- conditionAt lives with the block watch, further down, and three separate
-- watches have now been written to call one of these helpers before its
-- definition. A missing forward declaration resolves to a nil global, the call
-- raises inside the caller's pcall, and the capture then reports a patched
-- dispatch loop with no watches on it and no reason given.
local conditionAt

-- The row fetch, in the four shapes a dispatch loop writes it.
--
-- Two real builds of this class write it two different ways. One declares the
-- row:   local ROW = ARR[PC]
-- the other assigns an outer local and guards the array:
--        ROW = ARR and ARR[PC]
-- A matcher with `local` and no guard in it finds the first and reports the
-- second as a build with no interpreter in it. The spacing is the minifier's
-- too, so every token is separated by %s*, and the trailing semicolon the
-- sample happened to have is not required.
local ROWFETCH_SHAPES = {
    "local%s+([%a_][%w_]*)%s*=%s*([%a_][%w_]*)%s*%[%s*([%a_][%w_]*)%s*%]",
    "local%s+([%a_][%w_]*)%s*=%s*([%a_][%w_]*)%s+and%s+%2%s*%[%s*([%a_][%w_]*)%s*%]",
    "([%a_][%w_]*)%s*=%s*([%a_][%w_]*)%s+and%s+%2%s*%[%s*([%a_][%w_]*)%s*%]",
    "([%a_][%w_]*)%s*=%s*([%a_][%w_]*)%s*%[%s*([%a_][%w_]*)%s*%]",
}
local ROWFETCH = ROWFETCH_SHAPES[1]   -- the miss report counts this one

-- How far after the row fetch the loop top is. A dispatch loop reads its
-- opcode out of the row in the next statement or two; nothing useful is further
-- away. The first version allowed 4000 characters, which on a one-line chunk
-- reaches into unrelated handlers, and a handler variable compared against
-- small numbers was picked as the opcode.
local TOP_WINDOW = 500

-- The loop advances its program counter. This is what separates a dispatch loop
-- from the accessors that have the same shape - a constant reader also fetches
-- a row out of an array by a key, and it does not then step that key.
local function advances(window, pc)
    return window:find("%f[%w_]" .. pc .. "%f[^%w_]%s*=%s*" .. pc .. "%s*[%+%-]")
        or window:find("%f[%w_]" .. pc .. "%f[^%w_]%s*[%+%-]=")
end

-- Reads of the row at the loop top, guarded (`ROW and ROW[i] or n`) and bare
-- (`ROW[i]`). All of them, because a row carries more than its opcode: both
-- builds seen here also read a second field beside it, and taking the first
-- read found logged that field as the opcode.
local function rowReads(window, row)
    local list = {}
    local shapes = {
        { "guarded", "local%s+([%a_][%w_]*)%s*=%s*" .. row .. "%s+and%s+" .. row
                     .. "%s*%[%s*(%-?%d+)%s*%]%s*or%s*%-?%w+" },
        { "bare", "local%s+([%a_][%w_]*)%s*=%s*" .. row
                  .. "%s*%[%s*(%-?%d+)%s*%]" },
    }
    for _, sh in ipairs(shapes) do
        local from = 1
        while true do
            local a, b, v, idx = window:find(sh[2], from)
            if not a then break end
            list[#list+1] = { v = v, idx = tonumber(idx), at = b, shape = sh[1] }
            from = b + 1
        end
    end
    return list
end

-- Which of those reads is the opcode. The answer is in what the loop DOES with
-- it: the opcode is the value the dispatch compares against numbers, and the
-- other fields are carried. That is a behavioural test, so it survives renaming,
-- and the index comes out of it rather than going into it. Picking by the
-- fallback value instead - `or 0` is the opcode, `or -1` is not - held on one
-- build and is a property of that build's codegen, not of this class.
local function numberComparisons(window, v)
    local c = 0
    for _ in window:gmatch("%f[%w_]" .. v .. "%f[^%w_]%s*==%s*%-?%d+") do
        c = c + 1
    end
    for _ in window:gmatch("%-?%d+%s*==%s*%f[%w_]" .. v .. "%f[^%w_]") do
        c = c + 1
    end
    return c
end

local function findLoopTop(s)
    for shapeIndex, pat in ipairs(ROWFETCH_SHAPES) do
        local from = 1
        while true do
            local a, b, row, arr, pc = s:find(pat, from)
            if not a then break end
            local near = s:sub(b, math.min(#s, b + TOP_WINDOW))
            -- the comparisons that name the opcode are in the chain under the
            -- loop, which is long, so they are counted over a wide window while
            -- the reads themselves have to be at the top
            local wide = s:sub(b, math.min(#s, b + 40000))
            if advances(near, pc) then
                local best
                for _, c in ipairs(rowReads(near, row)) do
                    c.score = numberComparisons(wide, c.v)
                    if c.score > 0 and (not best or c.score > best.score
                                        or (c.score == best.score
                                            and c.at < best.at)) then
                        best = c
                    end
                end
                if best then
                    return { row = row, arr = arr, pc = pc, op = best.v,
                             opindex = best.idx, at = b + best.at - 1,
                             shape = best.shape, compared = best.score,
                             fetch = shapeIndex }
                end
            end
            from = b + 1
        end
    end
    return nil
end

-- What the chunk looked like when nothing matched.
--
-- "dispatch_patched: false" was the whole report, and it says nothing a person
-- or a later version of this file can act on. These are counts of the shapes
-- the matchers look for, measured on the chunk in front of it, plus the text
-- around the closest thing to a loop top. No build is named and nothing is
-- assumed: if the counts are all zero this is not a dispatch interpreter, and
-- if they are not, the numbers say which shape moved.
local function patchMissReport(s)
    local out = {}
    local function n(pat)
        local c = 0
        for _ in s:gmatch(pat) do c = c + 1 end
        return c
    end
    out[#out+1] = "chunk_bytes: " .. #s
    out[#out+1] = "chunk_lines: " .. (select(2, s:gsub("\n", "")) + 1)
    out[#out+1] = "row_fetches: " .. n(ROWFETCH)
    out[#out+1] = "guarded_opcode_reads: "
        .. n("local%s+[%a_][%w_]*%s*=%s*[%a_][%w_]*%s+and%s+[%a_][%w_]*%s*%[%s*%-?%d+%s*%]%s*or%s*%-?%d+")
    out[#out+1] = "numeric_elseif_arms: " .. n("elseif%s+[%a_][%w_]*%s*==%s*%-?%d+%s*then")
    out[#out+1] = "numeric_if_arms: " .. n("if%s+[%a_][%w_]*%s*==%s*%-?%d+%s*then")
    out[#out+1] = "while_true_loops: " .. n("while%s+true%s+do")
    out[#out+1] = "repeat_loops: " .. n("repeat[%s\n]")
    out[#out+1] = "goto_statements: " .. n("goto%s+[%a_][%w_]*")
    out[#out+1] = "masked_opcode_exprs: " .. n("%%%s*0[xX]%x+")
    -- the closest thing to a loop top, so the shape that moved can be read
    local a, b, row, arr, pc = s:find(ROWFETCH)
    if a then
        out[#out+1] = "first_row_fetch: " .. row .. "=" .. arr .. "[" .. pc .. "]"
        local after = s:sub(b + 1, math.min(#s, b + 220))
        out[#out+1] = "what_follows_it: " .. (after:gsub("[\r\n]", " "))
    else
        out[#out+1] = "first_row_fetch: none - no `local X = Y[Z]` anywhere"
    end
    return out
end

local function patchDispatch(s)
    -- Preferred: the loop top, which every instruction passes through.
    local top = findLoopTop(s)
    if top then
        local arr2, sp2 = s:match("if %w+>=2 then (%w+)%[(%w+)%-1%]=")
        sp2 = sp2 or "0"
        local ny2 = s:match("if %w+>=1 then %w+%[%w+%]=(%w+) end")
        local topexpr2 = ny2 or ((arr2 and sp2 ~= "0")
                                 and ("(" .. arr2 .. " and " .. arr2 .. "["
                                      .. sp2 .. "])")) or "nil"
        -- HOW MANY RESULTS ARE STILL PENDING.
        --
        -- This family defers its register writes: a handler leaves its results in
        -- one or two slots with a count, and the NEXT handler flushes them to the
        -- array. The logger runs at the loop top, before that flush, so the stack
        -- pointer it reports is one instruction behind - and every arity measured
        -- from the difference between consecutive pointers is off by whatever the
        -- previous instruction had pending. That is why a handler that visibly
        -- takes two values off the stack was measured as taking one, and why a
        -- hundred opcodes could not be named from their own handlers.
        --
        -- The count is the variable the flush tests, so it is read from the flush
        -- itself and logged beside the pointer. Nothing is corrected here; the
        -- reader adds it, and a capture that lacks it reads exactly as before.
        -- the OUTER variable, not the handler's local copy of it. `do local n=NG;
        -- if n>=2 then ...` names both: `n` lives inside the handler and is not in
        -- scope at the loop top, so logging it read a nil global and the count
        -- never reached the capture.
        local _, pend2 = s:match("do local (%w+)=(%w+);if %1>=2 then %w+%[%w+%-1%]=")
        if not pend2 then
            _, pend2 = s:match("local (%w+)=(%w+);if %1>=2 then")
        end
        local inject = ";if __OP then __OP(" .. top.pc .. "," .. top.op .. ","
            .. top.row .. "," .. sp2 .. "," .. topexpr2 .. "," .. top.arr
            .. ",true," .. (pend2 or "nil") .. ")end;if __CODE then __CODE("
            .. top.arr .. ")end"
        local before = select(2, s:sub(1, top.at):gsub("\n", ""))
        PATCH_AT, PATCH_ADDED = before + 1, select(2, inject:gsub("\n", ""))
        ORIGINAL_LINES = select(2, s:gsub("\n", "")) + 1
        local out = s:sub(1, top.at) .. inject .. s:sub(top.at + 1)
        -- The array the loop reads is rebuilt as the program runs on this
        -- build, so where it came from is part of reading a nil row. Watched at
        -- the top patch level only, like the other watches, so a round that
        -- objects to being watched still gets a plain traced round after it.
        local blockNote = ""
        -- PATCH_LEVEL is nil only when these functions are extracted on their
        -- own by a test, and there the watch is what is being tested.
        --
        -- ORDER MATTERS, and getting it wrong is silent. Two of these watches go
        -- in at a measured offset (the loop top) and two rewrite text wherever
        -- they find it. A rewrite anywhere before that offset moves it, so the
        -- offset-based ones go first, while the number still means what it meant
        -- when it was measured. Running them the other way round put the pc-table
        -- dump in the wrong place and lost the block watch entirely, while the
        -- capture still reported both as applied.
        if PATCH_LEVEL == nil or PATCH_LEVEL >= 3 then
            -- Each watch is applied under its own pcall, and a failure is
            -- written into the behaviour log. One watch calling a helper that
            -- was not declared yet used to take the whole patch down, and the
            -- capture then showed a traced round with no watches and nothing to
            -- say why. A broken watch now costs its own line and nothing else.
            local function apply(name, fn, ...)
                local ok, result, count, extra = pcall(fn, ...)
                -- the third return of the tamper patchers is how many blocks
                -- they took out, which is the number the capture reports
                if ok and type(extra) == "number" and NEUTRALISE_TAMPER then
                    TAMPER_TAKEN = TAMPER_TAKEN + extra
                end
                if not ok then
                    behavior[#behavior+1] = "  [watch " .. name
                        .. " could not be applied: " .. tostring(result) .. "]"
                    return nil
                end
                if not result or not count or count == 0 then return nil end
                blockNote = blockNote .. " " .. name .. "=" .. count
                -- the third return means different things: for the tamper
                -- patchers it is how many blocks were taken OUT, which is
                -- already reported as tamper_taken_out, and for the block watch
                -- it is how many assignments were left alone. Calling both
                -- "skipped" put "checks_watched_skipped=1538" in the capture for
                -- 1538 blocks that were removed, not skipped.
                if extra and extra > 0 and not NEUTRALISE_TAMPER then
                    blockNote = blockNote .. " " .. name .. "_skipped=" .. extra
                end
                return result
            end
            -- offset-based first, while the loop top's offset still means what
            -- it meant when it was measured
            out = apply("pc_tables", patchKeyTables, out, top.at, top.pc) or out
            out = apply("blocks_watched", patchBlocks, out, top.at, top.arr,
                        top.pc) or out
            -- then the whole-chunk rewrites, which may move anything
            -- The self-destruct: watched, or taken out. Taken out only against
            -- a stand-in, where the checks behind it cannot pass.
            local before = TAMPER_TAKEN
            out = apply("checks_watched", patchChecks, out, top.pc,
                        NEUTRALISE_TAMPER) or out
            out = apply("poison_sites", patchPoison, out, top.pc,
                        NEUTRALISE_TAMPER) or out
            if NEUTRALISE_TAMPER and TAMPER_TAKEN > before then
                blockNote = blockNote .. " tamper_taken_out=" .. (TAMPER_TAKEN - before)
            end
            out = apply("key_folds", patchResidue, out, top.pc) or out
            out = apply("self_checks", patchSelfChecks, out) or out
            out = apply("fields_watched", patchFields, out) or out
        end
        return out,
               ("loop top (" .. top.shape .. "): " .. top.op .. "="
                .. top.row .. "[" .. top.opindex .. "] pc=" .. top.pc
                .. " sp=" .. sp2 .. " compared_against_numbers="
                .. tostring(top.compared) .. " fetch_shape=" .. top.fetch
                .. blockNote)
    end
    return patchDispatchFallback(s)
end

function patchDispatchFallback(s)
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
-- THE PROGRAM'S FUNCTIONS, taken where the interpreter builds them.
--
-- The edit the analysis puts in the interpreter is one table write and nothing
-- else: `__VMPROTO[proto] = upvalues`. No call, no new local - a protected
-- build watches its own stack, and a hook that calls out changes what it sees.
--
-- The work happens here, in the metatable, where the build cannot look: the
-- write is caught and the proto's arrays are copied before anything has run
-- over them. A function the program never calls is copied on the same terms as
-- one it does, which is the whole point: what the checks route execution away
-- from is in hand anyway.
-- Bytes, as hex. A constant's value arrives as a string of arbitrary bytes and
-- a capture is a text file, so the only safe way across is hex. Long blobs are
-- cut and the cut is recorded, so a truncated value can never be mistaken for a
-- short one.
local HEXOF = function(sv)
    local n = #sv
    local cut = false
    if n > 8192 then sv = string.sub(sv, 1, 8192) cut = true end
    local out = string.gsub(sv, ".", function(ch)
        return string.format("%02x", string.byte(ch))
    end)
    if cut then return out .. ":cut" .. tostring(n) end
    return out
end
local protoCopies, protoCopyN = {}, 0
local protoResolver = nil
HID.__VMPROTO = setmetatable({}, {
    __index = function() return nil end,
    __newindex = function(t, proto, ups)
        rawset(t, proto, ups or true)
        -- THE PROGRAM'S OWN DECRYPTOR, handed over the same way the prototypes
        -- are: as a key of this table, one write and no call. It is kept and
        -- not used until the run is over, so asking it for a constant cannot
        -- change anything the build can see while the build is still watching.
        if type(proto) == "function" and ups == "resolver" then
            protoResolver = proto
            return
        end
        if type(proto) ~= "table" then return end
        if protoCopyN >= 2000 then return end
        protoCopyN = protoCopyN + 1
        local copy = { fields = {}, rows = {}, deep = {}, live = {},
                       shape = {}, n = protoCopyN }
        -- WHAT IS AND IS NOT THERE. The interpreter takes the length of some of
        -- a prototype's fields the moment a closure for it is called, so a
        -- prototype missing one of those does not fail later - it fails there,
        -- with "attempt to get length of a nil value" and nothing to say which
        -- field or which function. This records the type of every field, so the
        -- report can name the one that is absent.
        for k = 1, 24 do
            local v = rawget(proto, k)
            local t = type(v)
            if t == "table" then
                local okn, n = pcall(function() return #v end)
                copy.shape[k] = "table#" .. (okn and tostring(n) or "?")
            elseif t ~= "nil" then
                copy.shape[k] = t
            else
                copy.shape[k] = "nil"
            end
        end
        -- every field that is an array of numbers: the instruction arrays and
        -- the operand arrays live there, and which slot holds which is read
        -- from the interpreter later rather than assumed here
        for k, v in pairs(proto) do
            if type(v) == "table" then
                local nums, cnt = {}, 0
                local rows, rcnt = {}, 0
                for i = 1, 8192 do
                    local x = rawget(v, i)
                    if x == nil then break end
                    if type(x) == "number" then
                        cnt = cnt + 1
                        nums[cnt] = x
                    elseif type(x) == "table" then
                        -- THE INSTRUCTIONS. One row per instruction, each a
                        -- small array: the opcode and its operands. This is
                        -- the field the dispatch loop indexes by its program
                        -- counter, and copying only arrays of numbers walked
                        -- straight past it - which is why the first version of
                        -- this took sixty functions and not one instruction.
                        local row, rn = {}, 0
                        for j = 0, 16 do
                            local y = rawget(x, j)
                            if type(y) == "number" then
                                rn = rn + 1
                                row[rn] = j .. "=" .. tostring(y)
                            elseif type(y) == "string" and #y < 64 then
                                rn = rn + 1
                                row[rn] = j .. "=" .. string.format("%q", y)
                            end
                        end
                        if rn > 0 then
                            rcnt = rcnt + 1
                            rows[rcnt] = tostring(i) .. ":" ..
                                         table.concat(row, " ")
                        end
                    else
                        break
                    end
                end
                if cnt > 0 then copy.fields[tostring(k)] = nums end
                if rcnt > 0 then copy.rows[tostring(k)] = rows end
                -- ONE LEVEL DEEPER. The interpreter takes the tables it needs
                -- to decode a block out of a sub-table of the prototype: which
                -- block a counter is in, what each block's key material is,
                -- and the table that turns an unmasked number into an opcode.
                -- They are tables of tables, so the pass above walks past them.
                do
                    -- always, not only when the field looked like neither an
                    -- array nor rows: a sub-table whose keys are counters has
                    -- numbers at 1..16 too, so the row reader claims it and
                    -- the walk below never happened
                    for j, w in pairs(v) do
                        if type(w) == "table" then
                            -- the table itself, kept so the program's own
                            -- resolver can be asked for it after the run
                            copy.live[tostring(k) .. "." .. tostring(j)] = w
                            local sub, sn = {}, 0
                            for q, x in pairs(w) do
                                if type(q) == "number" and type(x) == "number"
                                        and sn < 4096 then
                                    sn = sn + 1
                                    sub[sn] = tostring(q) .. ">" .. tostring(x)
                                elseif type(q) == "number"
                                        and type(x) == "string"
                                        and sn < 4096 then
                                    -- THE BYTES THE NUMBERS POINT AT. A
                                    -- constant in this family is a small table
                                    -- holding a type tag, a seed, and the
                                    -- ciphertext of the value as a string. The
                                    -- pass above copied the tag and the seed
                                    -- and dropped the string, so every constant
                                    -- arrived as a pair of numbers with the
                                    -- value missing - which is why a function
                                    -- nothing called could be read as
                                    -- instructions and not as what it says.
                                    -- Written as hex: the bytes are arbitrary,
                                    -- and a capture is a text file read line by
                                    -- line.
                                    sn = sn + 1
                                    sub[sn] = tostring(q) .. "$" .. HEXOF(x)
                                end
                            end
                            if sn > 0 then
                                copy.deep[tostring(k) .. "." .. tostring(j)] =
                                    sub
                            else
                                -- ONE MORE LEVEL: the block descriptors. Each
                                -- block has a table of its own - where it
                                -- starts and ends, which key material decodes
                                -- it, and a per-predecessor entry - and that
                                -- is a table of tables, which the pass above
                                -- walks past.
                                for q, y in pairs(w) do
                                    if type(y) == "table" then
                                        local d3, dn = {}, 0
                                        for a, b in pairs(y) do
                                            if type(a) == "number"
                                                    and type(b) == "number"
                                                    and dn < 512 then
                                                dn = dn + 1
                                                d3[dn] = tostring(a) .. ">"
                                                         .. tostring(b)
                                            elseif type(a) == "number"
                                                    and type(b) == "string"
                                                    and dn < 512 then
                                                dn = dn + 1
                                                d3[dn] = tostring(a) .. "$"
                                                         .. HEXOF(b)
                                            end
                                        end
                                        if dn > 0 then
                                            copy.deep[tostring(k) .. "."
                                                .. tostring(j) .. "."
                                                .. tostring(q)] = d3
                                        end
                                    end
                                end
                            end
                        elseif type(w) == "number" then
                            copy.deep[tostring(k) .. ".#" .. tostring(j)] =
                                { tostring(w) }
                        end
                    end
                end
            elseif type(v) == "number" then
                copy.fields["#" .. tostring(k)] = { v }
            end
        end
        protoCopies[#protoCopies + 1] = copy
    end,
})

HID.__PROTO = function(level, p, ...)
    -- WHICH level was called, recorded whether or not its first argument is a
    -- prototype: that is how the maker is told from the functions around it.
    if type(level) == "number" then
        PROTO_LEVELS[level] = (PROTO_LEVELS[level] or 0) + 1
    else
        p, level = level, nil
    end
    if type(p) ~= "table" then
        -- the prototype may be any of the arguments, not the first
        local n = select("#", ...)
        for i = 1, n do
            local v = (select(i, ...))
            if type(v) == "table" then p = v break end
        end
    end
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
-- THE CHECK, AND WHETHER THIS ENVIRONMENT PASSED IT.
--
-- A build of this family decides whether to run the program by digesting values
-- the host gives it and comparing against digests it carries. That comparison is
-- the most useful thing in the file: it is a test whose answer the build already
-- knows, so watching it says - per value - whether this environment behaved like
-- a real client, and when it did not, exactly which value was wrong.
--
-- Only watched. Nothing here answers for the comparison or changes its result.
local hashes, hashN = {}, 0
HID.__HASH = function(result, ...)
    hashN = hashN + 1
    if hashN > 4000 then return end
    local parts = { "out=" .. tostring(result) }
    local n = select("#", ...)
    for i = 1, n do
        local v = (select(i, ...))
        local t = type(v)
        if t == "string" then
            parts[#parts + 1] = "in" .. i .. "=s$" .. HEXOF(v)
        elseif t == "number" or t == "boolean" then
            parts[#parts + 1] = "in" .. i .. "=" .. t:sub(1, 1) .. "="
                                .. tostring(v)
        elseif t == "nil" then
            parts[#parts + 1] = "in" .. i .. "=nil"
        else
            parts[#parts + 1] = "in" .. i .. "=" .. t
        end
    end
    hashes[#hashes + 1] = table.concat(parts, "|")
end

-- THE KEY THE PAYLOAD IS DECRYPTED WITH, and the numbers it was made of.
--
-- This build does not compare the host against anything. It MEASURES the host
-- and uses the measurements as the decryption key for its own program. So a
-- wrong answer anywhere does not fail a check - it produces a different key, and
-- the program comes out as noise that the deserialiser walks off the end of.
--
-- Written down here so fidelity is measurable rather than guessed at: run this
-- same harness in a real client and run it here, and the number that differs is
-- the thing to fix.
-- Every property the program read off a host object, and what it got. A value
-- answered out of this environment's own table is answered silently, so a wrong
-- one leaves no trace - and these builds fold what they read into the key their
-- payload is decrypted with, so a reader needs to see each one.
local reads, readN = {}, 0
local readSeen = {}
VMSMART_READ = function(what, value)
    readN = readN + 1
    if readN > 20000 then return end
    local t = type(value)
    local shown
    if t == "string" then
        shown = string.format("%q", #value < 48 and value
                              or (string.sub(value, 1, 48) .. "..."))
    elseif t == "number" or t == "boolean" then
        shown = tostring(value)
    else
        shown = t .. (typeof ~= nil and ("/" .. tostring(typeof(value))) or "")
    end
    local line = what .. " -> " .. shown
    if readSeen[line] then
        readSeen[line] = readSeen[line] + 1
        return
    end
    readSeen[line] = 1
    reads[#reads + 1] = line
end

local keyLog = {}
-- AND WHETHER THE DECRYPTION PRODUCED A PROGRAM. Between the key and the call
-- comes the decryption and the deserialising, and when the key is wrong the
-- deserialiser raises in the middle of them. So this not being recorded is the
-- answer as much as its contents are.
HID.__GATE = function(prog)
    local what = type(prog)
    if what == "table" then
        local n = 0
        for _ in pairs(prog) do n = n + 1 end
        local rows = rawget(prog, 2)
        local nrows = 0
        if type(rows) == "table" then
            for _ in pairs(rows) do nrows = nrows + 1 end
        end
        what = "table with " .. tostring(n) .. " field(s), "
               .. tostring(nrows) .. " instruction(s)"
    end
    keyLog[#keyLog + 1] = "gate: the payload decrypted to " .. what
end
HID.__KEY = function(key, ...)
    local parts = {}
    if type(key) == "table" then
        for i = 1, 8 do
            local v = rawget(key, i)
            if v == nil then break end
            parts[#parts + 1] = tostring(i) .. "=" .. tostring(v)
        end
    end
    -- and the numbers it was made of, which is what says WHERE this environment
    -- answered differently from a real client rather than only that it did
    local n = select("#", ...)
    local froms = {}
    for i = 1, n do
        froms[#froms + 1] = tostring((select(i, ...)))
    end
    keyLog[#keyLog + 1] = "key:" .. table.concat(parts, " ")
                          .. (n > 0 and ("  from:" .. table.concat(froms, ","))
                              or "")
end

local slices, sliceN = {}, 0
local sliceSwapUsed = nil
-- EVERY SLICE, not only the ones the run asked for. The accessor is handed its
-- own table, so the first request shows what else is in there: a slice the run
-- never reached is described on the same terms as one it did, and the analysis
-- can cut it out of the bytes it already holds. Same reason as the prototypes -
-- what the checks route execution away from is in hand anyway.
local sliceTable = {}
HID.__SLICE = function(name, idx, present, count, tbl)
    sliceN = sliceN + 1
    if sliceN > 2000 then return end
    slices[#slices+1] = tostring(name) .. ":" .. tostring(idx) .. ":"
                        .. (present and "ok" or "MISSING") .. ":"
                        .. tostring(count)
    if type(tbl) == "table" and not sliceTable[tostring(name)] then
        local rows = {}
        for i = 1, 256 do
            local m = rawget(tbl, i)
            if m == nil then break end
            if type(m) == "table" then
                local parts = {}
                for j = 1, 8 do
                    local x = rawget(m, j)
                    if type(x) == "number" then
                        parts[#parts+1] = tostring(j) .. "=" .. tostring(x)
                    elseif type(x) == "string" then
                        parts[#parts+1] = tostring(j) .. "=#" .. tostring(#x)
                    end
                end
                rows[#rows+1] = tostring(i) .. ":" .. table.concat(parts, " ")
            else
                rows[#rows+1] = tostring(i) .. ":" .. type(m)
            end
        end
        sliceTable[tostring(name)] = rows
    end
end

-- The redirect. Served only when VMSMART_SLICE_SWAP names one, so an ordinary
-- round has no __SLICEMAP in its environment and the accessor is unchanged.
if type(VMSMART_SLICE_SWAP) == "table" then
    HID.__SLICEMAP = function(i)
        local to = VMSMART_SLICE_SWAP[i] or VMSMART_SLICE_SWAP[tostring(i)]
        if to then
            sliceSwapUsed = tostring(i) .. "->" .. tostring(to)
            return to
        end
        return i
    end
end

local function patchSlices(s)
    local hits = 0
    local out = s:gsub(
        "local function (%w+)%((%w+)%)local (%w+)=(%w+)%[%2%];if not %3 then return nil end",
        function(fn, arg, v, tbl)
            hits = hits + 1
            return ("local function %s(%s)local %s=%s[%s];"
                    -- THE SLICE THE RUN NEVER ASKS FOR, as an added statement
                    -- rather than a rewritten one: the line above is the
                    -- build's own text, byte for byte, so what was there is
                    -- still readable from what is there now. `__SLICEMAP` is
                    -- absent on every ordinary round, so this does nothing. On a
                    -- round that sets it, the first request is answered with a
                    -- slice the run did not reach, and the prototype hook then
                    -- reports whatever the interpreter builds out of it - or
                    -- nothing, which is an answer too.
                    .. "if __SLICEMAP then local __m=__SLICEMAP(%s) "
                    .. "if __m~=%s then %s=%s[__m] or %s end end;"
                    -- `#tbl` runs __len, and these VMs put metatables on the
                    -- tables they hand slices out of. rawlen asks no metamethod;
                    -- where it does not exist the count is simply not reported.
                    .. "if __SLICE then __SLICE(%q,%s,%s~=nil,"
                    .. "(rawlen and rawlen(%s) or -1),%s)end;"
                    .. "if not %s then return nil end"):format(
                fn, arg, v, tbl, arg,
                arg, arg, v, tbl, v,
                fn, arg, v, tbl, tbl, v)
        end)
    if hits == 0 then return nil end
    return out, hits .. " accessor(s)"
end

-- The jump decoder, and whether its target was looked up or invented.
--
-- This family resolves a branch target through a table:
--     local function J(x,k,s,o) if k~=0 then x=D(x,k) end
--       local e = TBL[x] or {BASE+x,-1,-1,-1,-1,-1,-1}
--       ... return e[1]-ish
-- The `or {...}` is the part that matters. When TBL has no entry for the decoded
-- operand, the target is COMPUTED from a base instead of looked up, and a
-- computed target can land anywhere - including outside every block the
-- interpreter knows about, where the row fetch returns nil and the next opcode
-- read falls back to 0.
--
-- Matched by shape: a four-parameter local function whose body indexes a
-- captured table by its first parameter with an `or {` fallback. No name here.
local jumps, jumpN = {}, 0
HID.__JMP = function(fn, x, hit, target, from)
    jumpN = jumpN + 1
    if jumpN > 2000 then return end
    jumps[#jumps+1] = tostring(fn) .. ":" .. tostring(from) .. ":" .. tostring(x)
                      .. ":" .. (hit and "table" or "COMPUTED") .. ":"
                      .. tostring(target)
end

-- Every write to the value that decides whether this build keeps running.
--
-- The counter-bump blocks are the loud ones and they were the only ones watched.
-- There is a second, quieter family: the same stir statement on its own, with no
-- counter and no threshold, guarded by a check of its own - the first instruction
-- of this sample is one of those. Those writes are what make the build refuse
-- later, and nothing recorded them. The trace showed instructions running
-- normally and then, thousands of counters later, a refusal whose cause had
-- already happened.
--
-- So the stir itself is logged, wherever it appears, numbered in file order,
-- with the value it produced. The counter watch stays: it answers a different
-- question, which is when the build decides to stop rather than when it decides
-- it has been tampered with.
local poisons, poisonN = {}, 0
HID.__POISON = function(site, value, pc)
    pc = pc or LAST_PC
    poisonN = poisonN + 1
    if poisonN > 400 then return end
    poisons[#poisons+1] = "site" .. tostring(site) .. ":value_now="
                          .. tostring(value) .. ":pc=" .. tostring(pc)
end

function patchPoison(s, pc, neutralise)
    -- ACC = (ACC*k1 + PC*k2 + VAR*k3 + k4) % m, the stir this family uses to
    -- mark itself as tampered with. Walked rather than gsub'd, because the
    -- condition that led to each one is part of the finding and that needs the
    -- position.
    local pat = "([%a_][%w_]*)=%(%1%*%d+%+[%a_][%w_]*%*%d+%+[%a_][%w_]*%*%d+%+%d+%)%%%d+"
    local pieces, i, n, taken = {}, 1, 0, 0
    local pcArg = ",nil"
    while true do
        local a, b, acc = s:find(pat, i)
        if not a then break end
        n = n + 1
        local extra = ""
        -- the guard, over a wide window: these conditions carry long literals
        local text, names = conditionAt(s, a, 1600)
        if text then
            local args = {}
            for _, nm in ipairs(names) do
                args[#args+1] = string.format("%q", nm) .. "," .. nm
            end
            -- the text can be enormous; what matters is which check it is
            local shown = #text > 300 and (text:sub(1, 300) .. " ...") or text
            extra = ";if __COND then __COND(" .. (pc or "nil") .. "," .. n .. ","
                .. string.format("%q", shown)
                .. (#args > 0 and ("," .. table.concat(args, ",")) or "")
                .. ")end"
        end
        if neutralise then
            -- the statement is REPLACED by its own log. The value it would have
            -- stirred is the one this build uses to decide it has been tampered
            -- with, and in a real host it is never stirred, because the checks
            -- behind these statements pass there.
            pieces[#pieces+1] = s:sub(i, a - 1)
            pieces[#pieces+1] = "if __POISON then __POISON(" .. n .. ",0"
                .. pcArg .. ")end" .. extra
            taken = taken + 1
        else
            pieces[#pieces+1] = s:sub(i, b)
            pieces[#pieces+1] = ";if __POISON then __POISON(" .. n .. "," .. acc
                .. pcArg .. ")end" .. extra
        end
        i = b + 1
    end
    if n == 0 then return s, 0, 0 end
    pieces[#pieces+1] = s:sub(i)
    return table.concat(pieces), n, taken
end

-- The residue a chained key absorbs, and what it does to the key.
--
-- This family's branch decoder does not just look a target up. It computes a
-- verification residue from the jump's own record - where the jump came from,
-- what the instruction carried, what two running keys ought to be - and folds
-- that residue into a key:
--
--     KEY = (KEY * mult + residue) % mod
--
-- and then returns the decoded target PLUS that key. So a residue of zero keeps
-- the key at zero and the target is the decoded value; any non-zero residue
-- shifts every target after it and, in both samples here, makes the interpreter
-- refuse to produce instructions at all.
--
-- That makes the residue the most useful number in the run, and nothing else
-- reveals it: the target is observable, the residue is not. It is logged where
-- the key is folded, reading two locals that were just computed.
local resids, residN = {}, 0
HID.__RESID = function(name, residue, key, from)
    from = from or LAST_PC
    residN = residN + 1
    if residN > 400 then return end
    resids[#resids+1] = tostring(name) .. ": residue=" .. tostring(residue)
        .. " key_now=" .. tostring(key) .. " at=" .. tostring(from)
        .. ((residue ~= 0)
            and "  NON-ZERO, so this build's own verification did not match"
            or "")
end

function patchResidue(s, pc)
    local n = 0
    local pcArg = ",nil"
    -- KEY = (KEY * <digits> + NAME) % <digits>, where KEY is an index into a
    -- table of running keys. The log goes AFTER the statement, so the key it
    -- reports is the one the decoder goes on to use.
    local out = s:gsub("(([%a_][%w_]*%b[])=%(%2%*%d+%+([%a_][%w_]*)%)%%%d+)",
        function(whole, key, residue)
            n = n + 1
            return whole .. ";if __RESID then __RESID("
                .. string.format("%q", key) .. "," .. residue .. "," .. key
                .. pcArg .. ")end"
        end)
    if n == 0 then return s, 0 end
    return out, n
end

-- The checks a build makes about the environment it is running in.
--
-- One shape turns up at the first instruction of both samples here:
--
--     local t = {}; if not F(t, t) then <poison the accumulator> end
--
-- A function applied to one value twice, whose answer is known in advance. That
-- is not a computation, it is a question about F: a hooked or replaced F answers
-- differently, and the build then poisons the value that decides whether it will
-- go on running. Nothing in a trace shows it - the instruction looks like any
-- other, and the damage surfaces thousands of counters later as a refusal.
--
-- So the result is recorded where the build reads it, and the function it asked
-- about is identified by IDENTITY against the host's own functions. Identity,
-- not name: the build holds these functions in a table with a decrypting
-- __index, so the name it used is not in the chunk, and comparing the value to
-- the host's real `rawequal` is the only honest way to say which one it is.
local selfchecks, selfcheckN = {}, 0
local hostNames = nil

local function nameOfHostFunction(fn)
    if type(fn) ~= "function" then return type(fn) end
    if hostNames == nil then
        hostNames = {}
        local function note(tbl, prefix)
            if type(tbl) ~= "table" then return end
            for k, v in pairs(tbl) do
                if type(v) == "function" and type(k) == "string"
                   and hostNames[v] == nil then
                    hostNames[v] = prefix .. k
                end
            end
        end
        note(realenv, "")
        for _, lib in ipairs({ "string", "table", "math", "bit32", "buffer",
                               "os", "debug", "coroutine", "utf8" }) do
            note(realenv[lib], lib .. ".")
        end
    end
    return hostNames[fn] or "a function the host does not have"
end

HID.__SELFCHK = function(name, result, fn)
    selfcheckN = selfcheckN + 1
    if selfcheckN > 200 then return result end
    selfchecks[#selfchecks+1] = tostring(name) .. " -> " .. tostring(result)
        .. "  (" .. nameOfHostFunction(fn) .. ")"
        .. ((result == false or result == nil)
            and "  THIS ONE FAILED, and the build poisons itself when it does"
            or "")
    return result
end

function patchSelfChecks(s)
    local n = 0
    -- `if not F(x,x) then` - the same value twice, which is a question about F
    -- and not about x. The existing call is wrapped; F is never called again.
    local out = s:gsub("if not ([%a_][%w_]*)%(([%a_][%w_]*),%2%)%s*then",
        function(fn, arg)
            n = n + 1
            return "if not (function(__v)if __SELFCHK then __SELFCHK("
                .. string.format("%q", fn) .. ",__v," .. fn
                .. ")end;return __v end)(" .. fn .. "(" .. arg .. ","
                .. arg .. ")) then"
        end)
    if n == 0 then return s, 0 end
    return out, n
end

-- What the deserialiser actually handed the interpreter.
--
-- An interpreter of this class reads its optional parts as `local X = SRC[k] or
-- {}`: present, or an empty default. Both samples here run a few instructions
-- and then refuse to continue because one of those parts is empty, and from
-- inside the loop there is no way to tell an empty default from a part that was
-- deserialised as empty. One is a build that does not carry that part; the other
-- is a deserialiser that produced nothing for it, which is a different problem
-- with a different fix.
--
-- So the read is wrapped where it happens - the interpreter's own read, not an
-- extra one - and what came back is recorded before the default is applied.
local fields, fieldN = {}, 0
HID.__FIELD = function(name, expr, v)
    if fields[name] ~= nil then return end
    local kind = type(v)
    local count = ""
    if kind == "table" then
        local n = 0
        local ok, err = pcall(function()
            for _ in next, v do
                n = n + 1
                if n > 4000 then break end
            end
        end)
        -- the reason, not just the fact. "could not be counted" on a table that
        -- another watch counted a moment later is a fact with no use.
        count = ok and (", " .. n .. " entr" .. (n == 1 and "y" or "ies"))
                    or (", could not be counted - " .. tostring(err))
    end
    fieldN = fieldN + 1
    fields[name] = name .. " = " .. expr .. ": " .. kind .. count
    return v
end

function patchFields(s)
    local n = 0
    local function wrap(name, expr)
        n = n + 1
        return "local " .. name .. "=(function(__v)if __FIELD then __FIELD("
            .. string.format("%q", name) .. "," .. string.format("%q", expr)
            .. ",__v)end;return __v end)(" .. expr .. ") or {}"
    end
    -- %b[] matches a balanced bracket, so an index chain is taken whole. Two
    -- links then one, because a pattern cannot make the second optional and
    -- the longer match has to be tried first.
    local out = s:gsub("local%s+([%a_][%w_]*)%s*=%s*([%a_][%w_]*%b[]%b[])%s*or%s*{%s*}",
                       wrap)
    out = out:gsub("local%s+([%a_][%w_]*)%s*=%s*([%a_][%w_]*%b[])%s*or%s*{%s*}",
                   wrap)
    if n == 0 then return s, 0 end
    return out, n
end

-- Which counters this build has anything at all for.
--
-- The loop looks several tables up by its own counter: the block's metadata, the
-- end of the region it belongs to, the cache. A counter that none of them has an
-- entry for is not a counter the program was ever meant to reach, and that tells
-- a wrong branch target apart from a target the environment failed to prepare -
-- which a trace on its own cannot do.
--
-- Read raw, with `next`, so no __index runs. These tables decrypt on access in
-- this family, and a dump that decrypted them would advance the key and change
-- the run. Keys only; no value is read.
local keyTabs, keyTabN = {}, 0
HID.__KEYS = function(name, t)
    if keyTabs[name] ~= nil or type(t) ~= "table" then return end
    -- Under a pcall, and the failure is recorded rather than raised. A watch
    -- that ends the run it is there to observe has already been the cause of
    -- one wrong finding in this project; iterating a table the VM owns is
    -- exactly the kind of read that can be refused.
    local ok, err = pcall(function()
    local nums, other, total = {}, 0, 0
    for k in next, t do
        total = total + 1
        if type(k) == "number" then
            if #nums < 400 then nums[#nums+1] = k end
        else
            other = other + 1
        end
        if total > 4000 then break end
    end
    table.sort(nums)
    local shown = {}
    for i = 1, math.min(#nums, 60) do shown[i] = tostring(nums[i]) end
    keyTabN = keyTabN + 1
    keyTabs[name] = name .. ": " .. total .. " key(s), " .. other
        .. " not numbers, first " .. #shown .. " in order: "
        .. table.concat(shown, ",")
    end)
    if not ok then
        keyTabN = keyTabN + 1
        keyTabs[name] = name .. ": could not be read - " .. tostring(err)
    end
end

function patchKeyTables(s, at, pc)
    -- every table the loop indexes by the counter, named once each
    local from = math.max(1, at - 3000)
    local region = s:sub(from, at)
    local seen, calls = {}, {}
    local i = 1
    while true do
        local a, b, name = region:find("([%a_][%w_]*)%s*%[%s*" .. pc
                                       .. "%s*%]", i)
        if not a then break end
        if not seen[name] and name ~= pc then
            seen[name] = true
            calls[#calls+1] = "if __KEYS then __KEYS("
                              .. string.format("%q", name) .. "," .. name
                              .. ")end"
        end
        i = b + 1
    end
    if #calls == 0 then return s, 0 end
    -- No trailing semicolon, and the pieces are joined with one. Luau rejects an
    -- empty statement, so the `;;` this produced where the next injection began
    -- with its own semicolon was a syntax error - and the harness then silently
    -- fell back to the unpatched chunk, which reads downstream as a traced round
    -- that logged nothing. Lua 5.2 and later accept `;;`, so a test running
    -- under a plain Lua never saw it.
    return s:sub(1, at) .. ";" .. table.concat(calls, ";") .. s:sub(at + 1), #calls
end

-- The interpreter's own verdict on its integrity.
--
-- This build carries the same three-statement block in more than a thousand
-- places: a counter is bumped, a running value is stirred, and once the counter
-- passes a threshold the code reads an entry of a table that is not there. That
-- read is the crash this capture has been reporting as "attempt to index nil
-- with number" - the program ending itself on purpose, not a trace going wrong.
--
-- Matched by shape, and the shape is the point: a `do` block whose first
-- statement increments a counter and whose second stirs another variable from
-- itself by a multiplier. No name is written here, and nothing about which
-- check it belongs to is assumed. Numbering them in file order is enough to say
-- WHICH one fired first, which is the question a capture could not answer.
local viols, violN = {}, 0
HID.__VIOL = function(site, count, pc)
    pc = pc or LAST_PC
    violN = violN + 1
    if violN > 400 then return end
    viols[#viols+1] = "site" .. tostring(site) .. ":count=" .. tostring(count)
                      .. ":pc=" .. tostring(pc)
end

-- Watch the self-destruct, or take it out.
--
-- The block is `do COUNTER=COUNTER+1; STIR=(STIR*k+...)%m; if COUNTER>=LIMIT
-- then <read a row that is not there> end end`. Watching it says when the build
-- decided it had been tampered with. Taking it out says something different, and
-- it is the thing that makes an offline run worth having:
--
-- In a real host this build's checks PASS. The counter stays at zero, the stirred
-- value stays at zero, and the interpreter goes on producing instructions. Offline
-- they cannot pass - the build fingerprints host datatypes whose real numbers are
-- the host's - so the counter climbs and the interpreter refuses. Replacing the
-- block with a no-op does not invent a state the program never has; it restores
-- the state the program has everywhere it was meant to run. That is the opposite
-- of faking a result, and the capture says it was done on every round where it
-- was done.
--
-- It is still a patch, so it sits at the top patch level and the ladder takes it
-- out first if the payload objects to it.
function patchChecks(s, pc, neutralise)
    local n, taken = 0, 0
    local pcArg = ",nil"
    local pieces, i = {}, 1
    while true do
        -- the multiplier is captured, not consumed blindly: rebuilding the
        -- statement needs it, and reading it back from a position past the match
        -- read the wrong characters.
        local a, b, counter, stir, mult = s:find(
            "do ([%a_][%w_]*)=%1%+1;([%a_][%w_]*)=%(%2%*(%d+)", i)
        if not a then break end
        n = n + 1
        pieces[#pieces+1] = s:sub(i, a - 1)
        if neutralise then
            -- the whole block, up to the `end end` that closes the inner `if`
            -- and the `do`. The body between them is one statement in this
            -- family and carries no `end` of its own, so the first match is the
            -- right one; when it is not found the block is left as it was.
            local close = s:find("end end", b, true)
            if close then
                pieces[#pieces+1] = "do if __VIOL then __VIOL(" .. n .. ",0"
                    .. pcArg .. ")end end"
                i = close + 7
                taken = taken + 1
            else
                pieces[#pieces+1] = s:sub(a, b)
                i = b + 1
            end
        else
            pieces[#pieces+1] = "do if __VIOL then __VIOL(" .. n .. ","
                .. counter .. pcArg .. ")end;" .. counter .. "=" .. counter
                .. "+1;" .. stir .. "=(" .. stir .. "*" .. mult
            i = b + 1
        end
    end
    if n == 0 then return s, 0, 0 end
    pieces[#pieces+1] = s:sub(i)
    return table.concat(pieces), n, taken
end

-- Where the array the loop reads comes from.
--
-- This build does not keep one array per program. The loop reads its row out of
-- a table it rebuilds as it goes - a block - and the row for a given counter
-- exists only while the block holding it is the one in hand. So "the
-- interpreter read nil at pc N" has two different causes that look identical in
-- a trace: the branch went somewhere there is no code, or the block for that
-- counter was never built. Nothing in a dispatch trace separates them.
--
-- This logs what the block came back as, per counter, at every assignment to
-- the array variable in the loop's own text. It reads nothing through the VM's
-- tables: rawlen and rawget do not run a metatable, and these tables decrypt on
-- __index, so a probe that indexed them would change the run it is watching.
local blocks, blockN = {}, 0
HID.__BLOCK = function(pc, site, b)
    blockN = blockN + 1
    if blockN > 2000 then return b end
    local kind = type(b)
    local len, has = -1, "no"
    if kind == "table" then
        len = rawlen and rawlen(b) or -1
        has = (rawget(b, pc) ~= nil) and "yes" or "no"
    end
    -- the site number says WHICH assignment in the loop produced this. A loop
    -- that has more than one - a cache hit, a build, and the branches that give
    -- up and store nothing - is answering a different question at each of them,
    -- and "the array was nil" does not say which question was answered.
    blocks[#blocks+1] = tostring(pc) .. ":site" .. tostring(site) .. ":" .. kind
                        .. ":" .. tostring(len) .. ":row_at_pc=" .. has
    return b
end

-- When the loop gives up on its array, what it was testing.
--
-- A site that assigns nil is the interpreter deciding not to produce a block.
-- The decision has a condition behind it, and without the values that condition
-- was reading, "the array was nil at this counter" is the end of the trail. So
-- the enclosing condition's text is recorded with the values of the plain
-- locals in it.
--
-- Plain locals only. An index or a call inside the condition is NOT read again:
-- these VMs decrypt on __index and advance a key as they go, so re-reading one
-- would change the run. A table is reported as a table and never printed, for
-- the same reason - __tostring would be the VM's own code.
local conds, condN = {}, 0
HID.__COND = function(pc, site, text, ...)
    condN = condN + 1
    if condN > 400 then return end
    local parts = {}
    local n = select("#", ...)
    for i = 1, n, 2 do
        local name = select(i, ...)
        local v = select(i + 1, ...)
        local t = type(v)
        local shown
        if t == "number" or t == "boolean" or t == "nil" then
            shown = tostring(v)
        elseif t == "string" then
            -- the value, when it is short enough to be one. A build that checks
            -- its own chunk name holds that name in a local, and "string[64]"
            -- is the one thing about it that does not help.
            shown = (#v <= 160) and ("\"" .. v .. "\"")
                    or ("string[" .. #v .. "]")
        else
            shown = t
        end
        parts[#parts+1] = tostring(name) .. "=" .. shown
    end
    conds[#conds+1] = tostring(pc) .. ":site" .. tostring(site) .. ":"
                      .. tostring(text) .. " -> " .. table.concat(parts, " ")
end

-- The condition a site sits under, and the plain locals in it.
local LUA_WORDS = {
    ["if"]=true, ["then"]=true, ["elseif"]=true, ["else"]=true, ["end"]=true,
    ["and"]=true, ["or"]=true, ["not"]=true, ["nil"]=true, ["true"]=true,
    ["false"]=true, ["local"]=true, ["function"]=true, ["return"]=true,
    ["while"]=true, ["do"]=true, ["for"]=true, ["in"]=true, ["repeat"]=true,
    ["until"]=true, ["break"]=true, ["continue"]=true,
}
function conditionAt(region, pos, window)
    local best
    local from = math.max(1, pos - (window or 400))
    -- BOTH keywords, scanned separately and the later one kept. The single
    -- pattern this used to have was `els?e?if`, which matches elseif and never
    -- matches a plain `if` - so a poison guarded by an inner `if` was reported
    -- with the `elseif` that merely selected the opcode, and the values printed
    -- were that selector's, not the guard's. `%f[%w_]if` cannot match inside
    -- "elseif" either, since the character before is a word character.
    for _, kw in ipairs({ "if", "elseif" }) do
        local i = from
        while true do
            local a, b = region:find("%f[%w_]" .. kw .. "%f[^%w_]", i)
            if not a or a >= pos then break end
            if not best or b > best then best = b end
            i = b + 1
        end
    end
    if not best then return nil, nil end
    local t = region:find("%f[%w_]then%f[^%w_]", best)
    if not t or t >= pos then return nil, nil end
    local text = region:sub(best + 1, t - 1)
    -- Walked by position. A gmatch with a trailing `(.?)` capture eats the
    -- first character of the next token, so `not Yw` yielded `w` - and the
    -- injected code then read a global that does not exist and reported its nil
    -- as the local's value. A watch may not invent the thing it reports.
    local names, seen = {}, {}
    local i = 1
    while true do
        local a, b, name = text:find("([%a_][%w_]*)", i)
        if not a then break end
        local before = a > 1 and text:sub(a - 1, a - 1) or ""
        local after = text:sub(b + 1, b + 1)
        -- a name cannot start after a digit: `0X7FFFFFFF` was being read as an
        -- identifier called X7FFFFFFF, and the watch then reported that nil as
        -- though the build had asked about it.
        if not LUA_WORDS[name] and not seen[name]
           and not before:match("%d") and before ~= "." and before ~= ":"
           and after ~= "[" and after ~= "(" and after ~= "."
           and after ~= ":" then
            seen[name] = true
            names[#names+1] = name
            if #names >= 6 then break end
        end
        i = b + 1
    end
    return text, names
end

-- The assignments are found by walking back from the loop top, so every name
-- belongs to that loop, and the call's end is found by matching its parentheses
-- rather than by looking for the next one - an argument list that contains a
-- call of its own would otherwise be cut in half.
-- Where the right-hand side of one of those assignments ends.
--
-- Only the three forms this loop writes are handled, each with an end that can
-- be found exactly: a literal, a call (by matching its parentheses, so an
-- argument that is itself a call is not cut in half), and an index (by matching
-- its brackets). Anything else is left alone and counted, because a wrapper
-- around a guess would produce source that does not parse, and a watch may not
-- be the thing that ends the run it is there to observe.
local function blockRhsEnd(region, i)
    while region:sub(i, i):match("%s") do i = i + 1 end
    local lit = region:match("^nil%f[^%w_]", i) or region:match("^false%f[^%w_]", i)
                or region:match("^true%f[^%w_]", i)
    if lit then return i + #lit - 1 end
    local name = region:match("^[%a_][%w_]*", i)
    if not name then return nil end
    local j = i + #name
    while region:sub(j, j):match("%s") do j = j + 1 end
    local open = region:sub(j, j)
    local close = (open == "(" and ")") or (open == "[" and "]") or nil
    if not close then
        -- a plain name, which ends where the name ends
        return i + #name - 1
    end
    local depth = 1
    j = j + 1
    while j <= #region and depth > 0 do
        local c = region:sub(j, j)
        if c == open then depth = depth + 1
        elseif c == close then depth = depth - 1 end
        j = j + 1
    end
    if depth ~= 0 then return nil end
    -- an index may be followed by another index or a call: YY[2](x)[3]
    local k = j
    while true do
        while region:sub(k, k):match("%s") do k = k + 1 end
        local nxt = region:sub(k, k)
        local nclose = (nxt == "(" and ")") or (nxt == "[" and "]") or nil
        if not nclose then break end
        local d2 = 1
        k = k + 1
        while k <= #region and d2 > 0 do
            local c = region:sub(k, k)
            if c == nxt then d2 = d2 + 1
            elseif c == nclose then d2 = d2 - 1 end
            k = k + 1
        end
        if d2 ~= 0 then return nil end
        j = k
    end
    return j - 1
end

function patchBlocks(s, at, arr, pc)
    local from = math.max(1, at - 3000)
    local region = s:sub(from, at)
    local pieces, i, n, skipped = {}, 1, 0, 0
    while true do
        -- the pattern ends ON the `=`, so eq is its position. Letting it end
        -- after optional spaces put eq on a space or on the `=` depending on
        -- the spacing, and the comparison test below then read the wrong
        -- character and skipped every assignment in the loop.
        local a, eq = region:find("%f[%w_]" .. arr .. "%f[^%w_]%s*=", i)
        if not a then break end
        -- `==`, `~=`, `<=`, `>=` are comparisons, not assignments
        if region:sub(eq + 1, eq + 1) == "="
           or region:sub(eq - 1, eq - 1):match("[=~<>]") then
            i = eq + 2
        else
            local rhsEnd = blockRhsEnd(region, eq + 1)
            if rhsEnd then
                n = n + 1
                pieces[#pieces+1] = region:sub(i, eq)
                local rhs = region:sub(eq + 1, rhsEnd)
                -- a site that produces nothing is a decision, so record what
                -- the decision was reading
                local extra = ""
                if rhs:match("^%s*nil%s*$") or rhs:match("^%s*false%s*$") then
                    local text, names = conditionAt(region, a)
                    if text then
                        local args = {}
                        for _, nm in ipairs(names) do
                            args[#args+1] = string.format("%q", nm) .. "," .. nm
                        end
                        extra = ";if __COND then __COND(" .. pc .. "," .. n
                            .. "," .. string.format("%q", text)
                            .. (#args > 0 and ("," .. table.concat(args, ",")) or "")
                            .. ")end"
                    end
                end
                pieces[#pieces+1] = "(function(__b)if __BLOCK then __BLOCK("
                    .. pc .. "," .. n .. ",__b)end" .. extra
                    .. ";return __b end)(" .. rhs .. ")"
                i = rhsEnd + 1
            else
                skipped = skipped + 1
                i = eq + 1
            end
        end
    end
    if n == 0 then return s, 0, skipped end
    pieces[#pieces+1] = region:sub(i)
    return s:sub(1, from - 1) .. table.concat(pieces) .. s:sub(at + 1), n, skipped
end

local function patchJumps(s)
    local hits = 0
    -- Match the WHOLE lookup statement, up to the semicolon that ends it, so the
    -- probe goes AFTER it and the fallback table literal is left intact. An
    -- earlier version cut the statement at `or {` and spliced the log in there,
    -- which split the literal in half and produced source that would not parse.
    local out = s:gsub(
        "local function (%w+)%((%w+),(%w+),(%w+),(%w+)%)(.-)local (%w+)=(%w+)%[%2%] or ({[^}]*});",
        function(fn, x, k, sp, o, mid, e, tbl, fallback)
            if #mid > 200 then return nil end     -- not the same statement run
            hits = hits + 1
            -- The probe must not INDEX the program's own table. These VMs put a
            -- metatable on their lookup tables whose __index decrypts an entry
            -- and advances a running key, so an extra read is an extra step of
            -- that key and every later read comes out wrong. The first version
            -- read the table twice more and the traced round went from 12
            -- instructions to NONE - the watch destroyed the run it was there to
            -- observe. rawget sees no metamethod; `e` is the value the VM just
            -- computed, so reporting from it costs nothing.
            return ("local function %s(%s,%s,%s,%s)%slocal %s=%s[%s] or %s;"
                    .. "if __JMP then __JMP(%q,%s,rawget(%s,%s)~=nil,%s[1],%s)end;")
                   :format(fn, x, k, sp, o, mid, e, tbl, x, fallback,
                           fn, x, tbl, x, e, sp)
        end)
    if hits == 0 then return nil end
    return out, hits .. " jump decoder(s)"
end

-- THE FUNCTION THAT MAKES THE PROGRAM'S FUNCTIONS, found by where it sits
-- rather than by what it looks like.
--
-- This build runs an interpreter closure; the function that ENCLOSES that
-- closure is called once for every function of the program, and it is handed
-- that function's instruction array. Hooking it brings back every function's
-- instructions - including the ones this run never calls, which is where a
-- payload sits when a check sends execution past it.
--
-- The shape that finds it: the dispatch loop's position is already known, so
-- the enclosing function headers are the ones whose `end` falls after it. The
-- innermost is the interpreter itself; the next one out that takes arguments is
-- the maker.
local function enclosingFunctions(s, at, limit)
    -- ONE PASS, with a stack. The functions that enclose a point are the ones
    -- still open when the pass reaches it, and the only way to know that is to
    -- read the blocks in order: `function`, `do`, `if` and `repeat` open one,
    -- `end` and `until` close one. Looking at the headers nearest the point
    -- instead finds the helpers declared just before the loop, which enclose
    -- nothing - this build has eight of them in the two hundred characters
    -- before its dispatch loop.
    local stack = {}
    local i = 1
    local n = #s
    while i <= n do
        local a, b, word = s:find("([%a_][%w_]*)", i)
        if not a or a > at then break end
        if word == "function" then
            -- its parameter list, if the header is right here
            local _, pe, params = s:find("^[%s]*[%w_.:]*[%s]*%(([^)]*)%)", b + 1)
            stack[#stack + 1] = { a = a, b = pe or b, params = params or "" }
        elseif word == "do" or word == "if" or word == "repeat" then
            stack[#stack + 1] = false
        elseif word == "end" or word == "until" then
            if #stack > 0 then stack[#stack] = nil end
        end
        i = b + 1
    end
    -- innermost first
    local out = {}
    for k = #stack, 1, -1 do
        if stack[k] then
            out[#out + 1] = stack[k]
            if limit and #out >= limit then break end
        end
    end
    return out
end

local function patchProtosByLoop(s, at)
    if not at then return nil, 0 end
    local encl = enclosingFunctions(s, at, 40)
    -- the innermost enclosing function is the interpreter; the next one out
    -- that takes arguments is the one called once per program function
    -- WHICH of the enclosing functions is the maker is not guessed. Every
    -- enclosing function that takes arguments is hooked, each one saying which
    -- level it is, and the run reports which ones were actually called. One
    -- call per program function is the maker; the rest cost nothing.
    local picks = {}
    for i = 1, #encl do
        if encl[i].params and encl[i].params:match("[%a_]") then
            picks[#picks + 1] = { h = encl[i], level = i }
            if #picks >= 3 then break end
        end
    end
    if #picks == 0 then return nil, 0 end
    -- inject from the LAST position backwards, so earlier offsets stay valid
    table.sort(picks, function(x, y) return x.h.b > y.h.b end)
    local out = s
    for _, pick in ipairs(picks) do
        local args = {}
        for tok in pick.h.params:gmatch("[%a_][%w_]*") do
            args[#args + 1] = tok
        end
        if #args > 0 then
            local inject = ";if __PROTO then __PROTO(" .. tostring(pick.level)
                           .. "," .. table.concat(args, ",") .. ")end"
            out = out:sub(1, pick.h.b) .. inject .. out:sub(pick.h.b + 1)
        end
    end
    return out, #picks
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
    -- A chunk the analysis prepared, keyed by the bytes the program produced.
    -- The preparation needs the chunk, and the chunk only exists once the
    -- program has built it, so this is the second run's part: the first run
    -- hands the chunk over, the analysis edits it with a real reading of its
    -- structure, and this run uses that instead.
    if VMSMART_CHUNK_REPLACEMENT ~= nil and type(src) == "string" then
        local n0 = #src
        local key = tostring(n0) .. ":" .. string.sub(src, 1, 24)
        local sub = VMSMART_CHUNK_REPLACEMENT[key]
        if sub ~= nil then
            behavior[#behavior+1] = "  [using the prepared chunk for this "
                .. "loadstring: " .. tostring(n0) .. " bytes in, "
                .. tostring(#sub) .. " out]"
            src = sub
        end
    end
    local n = #tostring(src or "")
    loads[#loads+1] = n
    local layer = detectLayer(src)
    behavior[#behavior+1] = "loadstring #" .. n .. "  (inner layer: " .. layer .. ")"
    if n > 200 and #loads <= 3 then
        pcall(function() writefile("inner_chunk_" .. #loads .. ".txt", tostring(src)) end)
    end
    -- THE INTERPRETER'S OWN SOURCE, kept for the report. What each opcode does
    -- is read from its handler, and that is the single biggest thing this
    -- analysis has: on the first sample it took the share of instructions
    -- explained from about four in ten to nine. The source is recovered before
    -- the run only for a packing this tool recognises; here it is simply the
    -- string the program handed to loadstring, so it works whatever the build
    -- did to hide it.
    if VMSMART_INNER_SRC == false and n > 20000 then
        VMSMART_INNER_SRC = tostring(src)
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
        local okJ, patchedJ, jn = pcall(patchJumps, src)
        if okJ and patchedJ then
            src = patchedJ
            slicesDone = true
            behavior[#behavior+1] = "  [watching jump decoder -> " .. tostring(jn) .. "]"
        else
            behavior[#behavior+1] = "  [no jump decoder matched]"
        end
        -- EVERY EDIT IS COMPILED BEFORE IT IS BELIEVED. An edit that does not
        -- parse makes the loader fall back to the original, and the run then
        -- looks exactly like one where the edit matched and found nothing -
        -- which is what the prototype hook looked like for three rounds of
        -- this: "hooked prototype makers -> 3" and not one prototype seen,
        -- because the chunk it produced would not compile and was never used.
        local function compiles(text)
            local f = (loadstring or load)
            if not f then return true end
            local ok, fn = pcall(f, text)
            return ok and fn ~= nil
        end
        local okP, patchedP, pn = pcall(patchProtos, src)
        if okP and patchedP and not compiles(patchedP) then
            behavior[#behavior+1] = "  [the prototype hook's edit did not "
                .. "compile; it is not used, and nothing is hooked by it]"
            okP, patchedP = false, nil
        end
        if (not okP) or (not patchedP) then
            -- The shape-based match found nothing. Where the dispatch loop is
            -- is already known, and the function that encloses it is the one
            -- called once per program function, so the maker is found by its
            -- position instead. This is what brings back the instructions of
            -- functions this run never calls - which is where a payload sits
            -- when a check sends execution past it.
            local okT, topT = pcall(findLoopTop, src)
            if okT and topT and topT.at then
                local okL, patchedL, ln = pcall(patchProtosByLoop, src, topT.at)
                if okL and patchedL and not compiles(patchedL) then
                    behavior[#behavior+1] = "  [the prototype hook found "
                        .. tostring(ln) .. " enclosing function(s) by position, "
                        .. "but the edit did not compile - this source is one "
                        .. "line of a megabyte and the word `function` appears "
                        .. "inside its strings, so a reader that counts blocks "
                        .. "in the text cannot be trusted on it. Nothing is "
                        .. "hooked, and nothing is claimed]"
                    okL, patchedL = false, nil
                end
                if okL and patchedL then
                    okP, patchedP, pn = true, patchedL,
                                        tostring(ln) .. " (by position)"
                end
            end
        end
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
    if PATCH_LEVEL >= 1 and not RESOLVER_OFF then
        local ok, patched, rn = pcall(patchResolver, src)
        if ok and patched then
            use = patched
            resolverDone = true
            behavior[#behavior+1] = "  [patched resolver " .. tostring(rn) .. " -> dumping constants]"
        end
    elseif RESOLVER_OFF then
        behavior[#behavior+1] = "  [resolver left alone on purpose, to see "
            .. "whether its rewrite is what this build objects to]"
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
-- Every recorded action carries the row the run was on, the same way the
-- stand-in's own records do. Without it the report has an action the program
-- took and no way to say which instruction took it, and fourteen of this
-- build's first actions - the services it asked for, the objects it made -
-- could be listed but never placed.
local function atRow()
  if type(VMSMART_ROW) == "number" then return "  @row=" .. tostring(VMSMART_ROW) end
  return ""
end
-- The object a constructor or a service lookup hands back is given the same
-- number the stand-in gives every host object, and the record carries it. That
-- is what lets the analysis say later whether the program ever used what it
-- asked for, from the records rather than from the shape of a name.
local function gave(line, v)
    if VMSMART_ID == nil then return v end
    local id = VMSMART_ID(v, true)
    if id then behavior[line] = behavior[line] .. "  @gave=#" .. tostring(id) end
    return v
end
-- ONE `Instance.new`, not a new one per read. In the host, `Instance.new` is the
-- same function every time you read it, so `rawequal(Instance.new, Instance.new)`
-- is true. Building the logging wrapper inside __index made that false, and a
-- build that compares two reads of the same host function sees a stand-in in one
-- comparison. This one compares functions: `rawequal` is in its constant table.
local instanceNew = function(c, ...)
    behavior[#behavior+1] = "Instance.new: " .. tostring(c) .. atRow()
    return gave(#behavior, RI.new(c, ...))
end
env.Instance = setmetatable({}, { __index = function(_, k)
    if k == "new" then return instanceNew end
    return RI[k]
end })

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
    -- and the same `GetService`, for the same reason
    local getServiceFn = nil
    env.game = setmetatable({}, {
      __index = function(_, k)
        if k == "GetService" or k == "FindService" or k == "service" then
          if getServiceFn then return getServiceFn end
          getServiceFn = function(_, name)
            if serverStubs[name] then
              behavior[#behavior + 1] = "GetService: " .. tostring(name)
                                        .. "  -> logging proxy (server-only)"
                                        .. atRow()
              return logProxy(name)
            end
            -- everything else stays REAL (client services like HttpService work
            -- fine and must not be proxied, or the VM's integrity ops break).
            local ok, svc = pcall(function() return realGame:GetService(name) end)
            -- WHEN THE HOST REFUSES, the program has to see the refusal. A name
            -- that is not a service raises on a real client, and handing back a
            -- proxy instead answers a question the build asked on purpose: it
            -- names a service that cannot exist to find out whether anything is
            -- standing in for the host. Against the stand-in the raise is the
            -- host's own answer and it is passed through. On a real executor
            -- the proxy stays, because there the failure means a service this
            -- engine happens not to have.
            if (not ok) and VMSMART_STANDIN and VMSMART_STRICT_SERVICES then
                behavior[#behavior + 1] = "GetService: " .. tostring(name)
                    .. "  -> refused, as a real client refuses it" .. atRow()
                error(svc, 0)
            end
            -- WHICH of the two was handed back matters and was not recorded. A
            -- proxy answers every field with a function, so a program that asked
            -- for a service this engine does not have gets something shaped
            -- nothing like what it expected, and the report could not tell that
            -- from a service that resolved.
            behavior[#behavior + 1] = "GetService: " .. tostring(name) .. "  -> "
                .. ((ok and svc ~= nil) and "real service"
                    or "logging proxy (this engine has no such service)")
                .. atRow()
            return gave(#behavior,
                        (ok and svc ~= nil) and svc or logProxy(name))
          end
          return getServiceFn
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
-- Set only after a round proves the loadstring path found no interpreter. See
-- the retry below for why it is not on from the start.
local OUTER_TRY, outerDone = false, false
-- set by the ladder when it puts the self-destruct back
local TAMPER_OFF = false
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
    -- Decided per round, from the environment rather than from a guess: there
    -- is nothing to take out in a host where the checks pass.
    NEUTRALISE_TAMPER = (VMSMART_STANDIN ~= nil) and PATCH_LEVEL >= 3
                        and not TAMPER_OFF
    TAMPER_TAKEN = 0
    local rec = { level = PATCH_LEVEL, mode = "unpatched",
                  ok = false, rtype = "nil", loaded = false, err = nil,
                  rows0 = #ops, const0 = constSeen }
    -- The interpreter is not always a chunk the payload hands to loadstring.
    -- A build that keeps its dispatch loop in the file itself never calls
    -- loadstring at all, so the hook that patches what loadstring is given
    -- never sees an interpreter, and the round reports no trace and no
    -- instructions. The same patch works on the top-level chunk; it just has to
    -- be applied to it.
    local source = SOURCE
    outerDone = false
    if OUTER_TRY and PATCH_LEVEL >= 2 then
        local okD, patchedD, dn = pcall(patchDispatch, SOURCE)
        if okD and patchedD then
            -- a patch that does not compile is not a patch. Prove it loads
            -- before the run depends on it, or a text edit becomes a load
            -- failure reported as the script's own.
            if realLoad(patchedD) then
                source, outerDone, dispatchDone = patchedD, true, true
                behavior[#behavior+1] = "  [patched the top-level chunk itself ("
                    .. tostring(dn) .. ")]"
            else
                behavior[#behavior+1] = "  [the top-level patch did not compile; "
                    .. "the chunk was left alone]"
            end
        else
            behavior[#behavior+1] = "  [no dispatch loop in the top-level chunk]"
        end
    end
    local f = realLoad(source)
    rec.loaded = (f ~= nil)
    if not f then
        rec.err = "loadstring failed"
    else
        pcall(setfenv, f, env)
        -- WHERE IT STOPPED, not only that it stopped. Everything in these
        -- chunks is on line 1, so an error message names the chunk and nothing
        -- else, and "attempt to get length of a nil value" could be any of a
        -- hundred places. A traceback is taken while the stack is still
        -- standing, which is the only moment it exists.
        local trace = nil
        -- NOT ON THE MAIN THREAD. In Roblox a script body runs on a thread the
        -- engine made for it, so `coroutine.running()` reports a coroutine and
        -- "is main" is false. Calling the payload straight from here ran it on
        -- the main thread, where that answer is the other way round - and this
        -- build reads `coroutine.running`, which is in its own constant table.
        -- The traceback is still taken inside, where the stack is.
        local handler = function(e)
            local tb = nil
            if debug and debug.traceback then
                local okk, t = pcall(debug.traceback, tostring(e), 2)
                if okk then tb = t end
            end
            trace = tb
            return e
        end
        local ok, r
        if coroutine and coroutine.create and coroutine.resume then
            local co = coroutine.create(function(...)
                return xpcall(f, handler, ...)
            end)
            local alive, a, b = coroutine.resume(co)
            if alive then
                ok, r = a, b
            else
                -- the coroutine itself failed to run, which is this harness's
                -- problem and not the program's
                ok, r = false, a
            end
        else
            ok, r = xpcall(f, handler)
        end
        rec.trace = trace
        rec.ok = ok
        -- Only a run that finished HAS a return value. On a failed run the
        -- second pcall result is the error, and calling its type the chunk's
        -- return type puts a wrong fact in a header.
        rec.rtype = ok and tostring(typeof(r)) or "nil"
        if not ok then
            rec.err = tostring(r)
            if trace then
                behavior[#behavior+1] = "  [where it stopped]"
                for line in tostring(trace):gmatch("[^\n]+") do
                    behavior[#behavior+1] = "    " .. line:sub(1, 300)
                end
            end
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
    rec.outer = outerDone
    rec.tamper_taken = TAMPER_TAKEN
    rec.applied_resolver = resolverDone
    rec.applied_protos = protosDone
    rec.applied_slices = slicesDone
    rec.patchable = patchable
    -- The round's name comes from what was APPLIED, not from what was asked for.
    -- A level-2 round whose dispatch hook never matched this build is a
    -- resolver-only round, and calling it "traced" would put an edit in the
    -- record that is not in the chunk.
    -- A round that traced with the resolver deliberately left out is not the
    -- same round as one that traced with it in, and calling both "traced" hid
    -- the only comparison that tells the two causes apart.
    rec.mode = ((protosDone or slicesDone) and LEVEL_NAME[3])
               or (dispatchDone and not resolverDone and "traced-no-resolver")
               or (dispatchDone and LEVEL_NAME[2])
               or (resolverDone and LEVEL_NAME[1])
               or LEVEL_NAME[0]
    attempts[#attempts+1] = rec
    return rec
end

local last = runPayload()
local first = last
-- One retry, on evidence rather than on a guess about the build. The first
-- round has already said whether anything reached the loadstring hook; if
-- nothing did and no instruction was logged, the interpreter is either absent
-- or it is the file itself, and only the second of those is actionable here. A
-- build that does use loadstring never reaches this, so its behaviour is the
-- behaviour it had.
if PATCH_LEVEL >= 2 and first.loaded and not first.applied_dispatch
   and first.rows_added == 0 then
    -- Ask the patcher first, run second. A chunk with no dispatch loop in it
    -- gains nothing from a second run, and running the payload twice to find
    -- that out doubles everything the first run logged.
    local okD, patchedD = pcall(patchDispatch, SOURCE)
    if okD and patchedD then
        OUTER_TRY = true
        behavior[#behavior+1] = "  [no interpreter was reached through "
            .. "loadstring, and the top-level chunk has a dispatch loop; "
            .. "running it again with that patched]"
        local retry = runPayload()
        if retry.rows_added > 0 then
            last, first = retry, retry
        end
    else
        behavior[#behavior+1] = "  [no interpreter through loadstring, and no "
            .. "dispatch loop in the top-level chunk either]"
    end
end
while not last.ok do
    -- Which edit is there to remove? Only one that actually went in: dropping a
    -- level that changed nothing would repeat the same run and read as evidence.
    -- Go to the level that actually removes the named edit, not one level
    -- down. Stepping 2 -> 1 to remove the RESOLVER leaves the resolver in, so
    -- the next round repeats this one and reads as evidence that it is not the
    -- patches.
    local step
    if (last.tamper_taken or 0) > 0 and not TAMPER_OFF then
        -- The most invasive edit goes back first. If the payload objects to its
        -- self-destruct being absent, that is worth knowing before anything else
        -- is removed - and the round after this one is a plain watched round.
        step = "the removal of this build's self-destruct"
        TAMPER_OFF = true
    elseif last.applied_protos or last.applied_slices then
        -- Name what was actually in the chunk, not the level's label. Both of
        -- these live at level 3 and either can be the only one that went in.
        local parts = {}
        if last.applied_slices then parts[#parts+1] = "the slice watch" end
        if last.applied_protos then parts[#parts+1] = "the prototype-maker hook" end
        step = table.concat(parts, " and ")
        PATCH_LEVEL = 2
    elseif last.applied_dispatch and last.applied_resolver
           and not RESOLVER_OFF then
        -- Before giving up the trace, keep it and drop the resolver instead.
        -- The constants stop being dumped for this round, which is a real cost,
        -- and what it buys is the one comparison that separates "this build
        -- objects to being traced" from "this build objects to its constant
        -- resolver being rewritten" - and the second is the one that leaves the
        -- instructions readable.
        step = "the resolver rewrite, with the dispatch logger left in"
        RESOLVER_OFF = true
    elseif last.applied_dispatch then
        step = "the dispatch logger"
        PATCH_LEVEL = 1
        -- and the resolver comes back, because this rung removes the logger and
        -- nothing else. Leaving it off here made the next round an unpatched
        -- round wearing the resolver-only label, and the ladder then skipped the
        -- level it was supposed to test.
        RESOLVER_OFF = false
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
    VMSMART_ROUND = (VMSMART_ROUND or 1) + 1
    if VMSMART_CALLS then
        VMSMART_CALLS[#VMSMART_CALLS + 1] =
            "  [retry round " .. VMSMART_ROUND .. "]"
    end
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
-- Where this run happened. robloxenv.lua sets VMSMART_STANDIN when the harness
-- is run outside Roblox against a stand-in, and a capture taken there is weaker
-- evidence than one taken in a game: the services resolve but every field on
-- them is absent. Saying so here is what stops the two being read as the same.
say("environment: " .. (VMSMART_STANDIN and ("standin/" .. tostring(VMSMART_STANDIN)) or "host"))
say("harness_engine: " .. tostring(HARNESS_ENGINE))
-- Whether the hooks were hidden behind the environment's metatable this run.
-- With them visible on purpose, two of the exposure checks come back EXPOSED by
-- design, and a report that cannot tell that apart from a leak reads the
-- requested mode as a defect.
say("hooks_hidden: " .. tostring(HIDE_HOOKS))
say("harness_id: " .. hid)
say("dispatch_patched: " .. tostring(first.applied_dispatch))
say("outer_chunk_patched: " .. tostring(first.outer or false))
say("tamper_taken_out: " .. tostring(first.tamper_taken or 0))
say("resolver_patched: " .. tostring(first.applied_resolver))
say("protos_hooked: " .. tostring(first.applied_protos))
say("slices_hooked: " .. tostring(first.applied_slices))
say("protos_seen: " .. protoN)
say("slice_requests: " .. sliceN)
say("jump_decodes: " .. jumpN)
say("block_builds: " .. blockN)
if FICTION_AT_ROW ~= nil then
    say("derived_arithmetic_at_row: " .. FICTION_AT_ROW)
    say("derived_arithmetic_at_behavior: " .. tostring(FICTION_AT_BEHAVIOR))
end
say("block_conditions: " .. condN)
say("integrity_checks_fired: " .. violN)
say("environment_checks: " .. selfcheckN)
say("key_folds: " .. residN)
say("tamper_marks: " .. poisonN)
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
-- What the chunk looked like when no dispatch loop was found in it. Without
-- this the capture said only "dispatch_patched: false", which names the outcome
-- and none of the evidence.
if #poisons > 0 then
    say("---POISON---")
    for i = 1, math.min(#poisons, 200) do say(poisons[i]) end
end
if #resids > 0 then
    say("---KEYFOLDS---")
    for i = 1, math.min(#resids, 200) do say(resids[i]) end
end
if #selfchecks > 0 then
    say("---SELFCHECKS---")
    for i = 1, math.min(#selfchecks, 100) do say(selfchecks[i]) end
end
-- What the stand-in answered for, when the run happened against one. These are
-- the host's questions the stand-in made up an answer to, and a reader has to be
-- able to see every one of them: a capture that looks complete because the
-- environment never said no is worse than one that stopped.
if VMSMART_STANDIN then
    local asked = {}
    local types = rawget(realenv, "VMSMART_HOST_TYPES_ASKED")
    if type(types) == "table" then
        for i = 1, #types do asked[#asked+1] = "datatype answered: " .. tostring(types[i]) end
    end
    -- which types were answered by their real algebra, and which were not
    for label, name in pairs({ ["modelled type"] = "VMSMART_TYPES_MODELLED",
                               ["stubbed field"] = "VMSMART_TYPES_STUBBED" }) do
        local t = rawget(realenv, name)
        if type(t) == "table" then
            local keys = {}
            for k in pairs(t) do keys[#keys+1] = tostring(k) end
            table.sort(keys)
            for i = 1, math.min(#keys, 120) do
                asked[#asked+1] = label .. ": " .. keys[i]
            end
        end
    end
    for _, name in ipairs({ "VMSMART_HOST_FIELDS_ASKED",
                            "VMSMART_INSTANCE_FIELDS_ASKED" }) do
        local t = rawget(realenv, name)
        if type(t) == "table" then
            local keys = {}
            for k in pairs(t) do keys[#keys+1] = k end
            table.sort(keys)
            for i = 1, math.min(#keys, 300) do
                asked[#asked+1] = "field answered: " .. keys[i] .. " x"
                                  .. tostring(t[keys[i]])
            end
        end
    end
    if rawget(realenv, "VMSMART_ENUM_VALUES_ARE_DERIVED") then
        asked[#asked+1] = "enum values are derived here, not the host's"
    end
    -- the line past which the program is computing with values this harness
    -- invented. Everything after it is a reading of the stand-in, not of the
    -- program.
    local an = rawget(realenv, "VMSMART_ARITH_COUNT")
    if type(an) == "number" and an > 0 then
        asked[#asked+1] = "derived_arithmetic: " .. tostring(an)
            .. " operation(s) on values this stand-in invented, first at "
            .. tostring(rawget(realenv, "VMSMART_ARITH_FIRST"))
    end
    if rawget(realenv, "VMSMART_STUB_LIMIT_HIT") then
        asked[#asked+1] = "the stand-in stopped answering at its own limit, so "
                          .. "the run ended on this file rather than on the "
                          .. "program"
    end
    if #asked > 0 then
        say("---STANDIN---")
        for i = 1, #asked do say(asked[i]) end
    end
end
-- Bytes the program handed the stand-in to decompress, where no answer had
-- been prepared for them. Written out with the bytes, so the next run can be
-- given the answer. This is what lets a build that packs its payload some way
-- this tool has never seen be run anyway: the program itself produces the
-- bytes, and they are taken from its hands.
if VMSMART_DECOMPRESS_WANT and #VMSMART_DECOMPRESS_WANT > 0 then
    say("---WANTBYTES---")
    for i = 1, #VMSMART_DECOMPRESS_WANT do say(VMSMART_DECOMPRESS_WANT[i]) end
end
-- Names the program asked its environment for and did not get, because a real
-- client does not have them either. This is the list to work from when a run
-- stops for want of one: it says what the program wanted, in its own words.
-- which enclosing function the maker hook actually caught
do
    local parts = {}
    for lvl, n in pairs(PROTO_LEVELS) do
        parts[#parts + 1] = "level " .. tostring(lvl) .. " called "
                            .. tostring(n) .. " time(s)"
    end
    if #parts > 0 then
        table.sort(parts)
        say("proto_levels: " .. table.concat(parts, ", "))
    end
end
if VMSMART_NOT_A_HOST_NAME ~= nil then
    local names = {}
    for k, n in pairs(VMSMART_NOT_A_HOST_NAME) do
        names[#names + 1] = tostring(k) .. " x" .. tostring(n)
    end
    if #names > 0 then
        table.sort(names)
        say("---NOTAHOSTNAME---")
        for i = 1, #names do say(names[i]) end
    end
end
if #protoCopies > 0 then
    say("---PROTOS---")
    for i = 1, #protoCopies do
        local c = protoCopies[i]
        local keys = {}
        for k in pairs(c.fields) do keys[#keys + 1] = k end
        table.sort(keys)
        for _, k in ipairs(keys) do
            local arr = c.fields[k]
            local parts = {}
            for j = 1, math.min(#arr, 4096) do
                parts[j] = tostring(arr[j])
            end
            say("p" .. tostring(c.n) .. ":" .. k .. "=" ..
                table.concat(parts, ","))
        end
        if c.shape then
            local parts = {}
            for k = 1, 24 do
                parts[#parts + 1] = tostring(k) .. "=" ..
                                    tostring(c.shape[k] or "nil")
            end
            say("p" .. tostring(c.n) .. "$shape:" .. table.concat(parts, " "))
        end
        local dkeys = {}
        for k in pairs(c.deep) do dkeys[#dkeys + 1] = k end
        table.sort(dkeys)
        for _, k in ipairs(dkeys) do
            local sub = c.deep[k]
            local parts = {}
            for j = 1, math.min(#sub, 4096) do parts[j] = sub[j] end
            say("p" .. tostring(c.n) .. "~" .. k .. ":" ..
                table.concat(parts, ","))
        end
        local rkeys = {}
        for k in pairs(c.rows) do rkeys[#rkeys + 1] = k end
        table.sort(rkeys)
        for _, k in ipairs(rkeys) do
            local rows = c.rows[k]
            for j = 1, #rows do
                say("p" .. tostring(c.n) .. "@" .. k .. ":" .. rows[j])
            end
        end
        -- THE CONSTANTS, AS VALUES. An instruction carries an index into a
        -- table whose entries hold the value as ciphertext, so the shape of a
        -- function is readable long before any of its words are. The program's
        -- own resolver does the decrypting, here, after the run: asked for
        -- every entry of every table the prototype holds, and whatever comes
        -- back is written with its type. An entry that is not a constant gives
        -- back itself and is written as a table, which says so.
        if protoResolver then
            local lkeys = {}
            for k in pairs(c.live) do lkeys[#lkeys + 1] = k end
            table.sort(lkeys)
            for _, k in ipairs(lkeys) do
                local ok, val = pcall(protoResolver, c.live[k])
                if ok then
                    local tv = type(val)
                    local body
                    if tv == "string" then
                        body = "s$" .. HEXOF(val)
                    elseif tv == "number" or tv == "boolean" then
                        body = tv:sub(1, 1) .. "=" .. tostring(val)
                    elseif tv == "nil" then
                        body = "nil"
                    else
                        body = tv
                    end
                    say("p" .. tostring(c.n) .. "!" .. k .. "=" .. body)
                else
                    say("p" .. tostring(c.n) .. "!" .. k .. "=error")
                end
            end
        end
    end
    say("proto_copies: " .. tostring(#protoCopies))
    if protoResolver then
        say("proto_resolver: the interpreter's own")
    else
        say("proto_resolver: none, so the constants stayed as numbers")
    end
end
if type(VMSMART_INNER_SRC) == "string" then
    say("---INNERSRC---")
    say(VMSMART_INNER_SRC)
end
if fieldN > 0 then
    say("---FIELDS---")
    for _, line in pairs(fields) do say(line) end
end
if keyTabN > 0 then
    say("---PCTABLES---")
    for _, line in pairs(keyTabs) do say(line) end
end
if #viols > 0 then
    say("---CHECKS---")
    for i = 1, math.min(#viols, 200) do say(viols[i]) end
end
if #conds > 0 then
    say("---CONDS---")
    for i = 1, math.min(#conds, 200) do say(conds[i]) end
end
if #blocks > 0 then
    say("---BLOCKS---")
    for i = 1, math.min(#blocks, 400) do say(blocks[i]) end
end
if not first.applied_dispatch then
    say("---PATCHMISS---")
    local miss = patchMissReport(SOURCE)
    for i = 1, #miss do say(miss[i]) end
end
-- Calls the stand-in answered, folded into the behaviour log in the same shape
-- as the harness's own records, because they are the same kind of fact: a call
-- the program made, seen by whatever answered it.
-- Calls the stand-in answered, in a section of their own.
--
-- They were appended to the behaviour log first, and landed after the last retry
-- marker - which is where the reader looks for the SECOND run's records, so they
-- were counted as a retry's and left out of the analysis. They belong to the run
-- as a whole, so they get their own section and the reader merges them.
if VMSMART_STANDIN then
    local sc = rawget(realenv, "VMSMART_CALLS")
    if type(sc) == "table" and #sc > 0 then
        say("---HOSTCALLS---")
        for i = 1, math.min(#sc, 4000) do say(tostring(sc[i])) end
    end
end
say("---PRINTS---"); for i=1,math.min(#prints,80) do say("PRINT: "..prints[i]) end
-- The whole behaviour log. A cap of 120 lines was fine while the log held the
-- harness's own notes; it is not fine now that every call the environment
-- answered is in there, and dropping them means the analysis cannot see where a
-- value ended up.
say("---BEHAVIOR---")
for i = 1, math.min(#behavior, 4000) do say(behavior[i]) end
-- real constants dumped from the inner VM resolver (the deep recovery)
say("resolved="..#resolved)
say("---RESOLVED---"); for i=1,math.min(#resolved,400) do say(resolved[i]) end
pcall(function() local t={}; for i=1,#resolved do t[i]=resolved[i] end; writefile("resolved_constants.txt", table.concat(t,"\n")) end)
-- devirtualization: the executed instruction stream (pc;opcode;operands)
say("opcodes=" .. #ops .. "  (logged, cap " .. OP_LOG_CAP
    .. (OP_LOG_TRUNCATED and "; THE CAP WAS REACHED, so the program ran past "
        .. "the last row here" or "; the cap was not reached") .. ")")
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
if #jumps > 0 then
    say("---JUMPS---")
    for i = 1, math.min(#jumps, 600) do say(jumps[i]) end
end
if #slices > 0 then
    say("---SLICES---")
    for i = 1, math.min(#slices, 600) do say(slices[i]) end
    for nm, rows in pairs(sliceTable) do
        for i = 1, #rows do
            say("table:" .. nm .. ":" .. rows[i])
        end
    end
    if sliceSwapUsed then
        say("swap:" .. sliceSwapUsed)
    end
    for i = 1, #keyLog do say(keyLog[i]) end
end
-- Outside the slice section on purpose: a count of zero is a finding about this
-- harness, not about the program, and burying it inside a section that only
-- exists when something else happened is how it went unnoticed.
-- The class names this environment refused to create, as the host refuses them.
-- Written down because the list it judges by is partial: a real class missing
-- from it would be refused here and created there, and that is a difference a
-- reader has to be able to see.
if VMSMART_REFUSED_CLASSES ~= nil then
    local names = {}
    for n in pairs(VMSMART_REFUSED_CLASSES) do names[#names + 1] = n end
    table.sort(names)
    if #names > 0 then
        say("---REFUSEDCLASSES---")
        for i = 1, #names do say(names[i]) end
    end
end
say("---READS---")
say("reads_total: " .. tostring(readN))
for i = 1, math.min(#reads, 900) do
    say(reads[i] .. "  x" .. tostring(readSeen[reads[i]] or 1))
end
if #hashes > 0 then
    say("---HASHES---")
    for i = 1, #hashes do say(hashes[i]) end
    say("hash_calls: " .. tostring(hashN))
end
-- Every row that was logged, not the first three thousand of them. The logger's
-- cap is what limits a capture; printing fewer than it collected meant a run of
-- 200,000 instructions arrived for analysis as 3,000, and every coverage number
-- downstream was a number about the first one and a half per cent of the run.
say("---OPCODES---")
for i = 1, #ops do say(ops[i]) end
pcall(function() writefile("opcode_trace.txt", table.concat(ops,"\n")) end)

local body = "BEGIN_UNOBF_RESULT\n"..table.concat(R, "\n").."\nEND_UNOBF_RESULT"
print(body)
pcall(function() writefile("unobf_result.txt", body) end)
return body
