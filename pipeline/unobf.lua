--!nocheck
-- unobf.lua  --  Stage-2 dynamic oracle for the base85+Zstd VM family
-- (obf2 / obf3 / siblings). Runtime-keyed layers (ChaCha-ish decoder + per-pc
-- LCG) cannot be decoded statically, so this runs in a real executor / Studio
-- and reports what execution proves. It is sample-agnostic: it auto-detects the
-- base85 alphabet, header subtractors, and constant resolver from the file text.
--
-- HOW TO RUN
--   1. Save the obfuscated script next to your executor as "obf.lua".
--   2. Run this file. Read the report between BEGIN_UNOBF_RESULT / END markers
--      (also written to unobf_result.txt). Paste that block back for ai.py.

local SOURCE
do
    local ok, txt = pcall(function() return readfile("obf.lua") end)
    if ok and txt then SOURCE = txt end
    -- SOURCE = [[ ...paste whole obfuscated script here... ]]
end
assert(SOURCE, "put the obfuscated script in obf.lua (readfile) or paste into SOURCE")

local floor, byte, sub, char = math.floor, string.byte, string.sub, string.char
local R = {}
local function say(...) local p = {}; for i = 1, select("#", ...) do p[i] = tostring((select(i, ...))) end; R[#R + 1] = table.concat(p, "\t") end

------------------------------------------------------------ Layer 1 (auto)
-- prefer the [[..]] literal inside the `for i=1,85 do` alphabet loop; else any
-- long-bracket literal that is exactly 85 chars (matches unobf.py's approach).
local alphabet = SOURCE:match("1,85 do.-%[%[(.-)%]%]")
if not (alphabet and #alphabet == 85) then
    for cap in SOURCE:gmatch("%[%[(.-)%]%]") do
        if #cap == 85 then alphabet = cap break end
    end
end
assert(alphabet and #alphabet == 85, "base85 alphabet not found")
local BM = {}; for i = 1, 85 do BM[sub(alphabet, i, i)] = i - 1 end
local subA, subB = SOURCE:match("%-(%d%d%d%d%d%d+)%)%%4294967296.-%-(%d%d%d%d%d%d+)%)%%4294967296")
subA, subB = tonumber(subA), tonumber(subB)
local blob = SOURCE:match("%[%d+%]=%[%[(.-)%]%]")

local function b85(F)
    local out, v, n = {}, 0, 0
    for i = 1, #F do
        local d = BM[sub(F, i, i)]; if d == nil then return nil end
        v = v * 85 + d; n = n + 1
        if n == 5 then out[#out+1] = char(floor(v/16777216)%256, floor(v/65536)%256, floor(v/256)%256, v%256); v, n = 0, 0 end
    end
    if n > 1 then for _ = 1, 5 - n do v = v * 85 + 84 end
        out[#out+1] = sub(char(floor(v/16777216)%256, floor(v/65536)%256, floor(v/256)%256, v%256), 1, n - 1) end
    return table.concat(out)
end

local J = buffer.tostring(game:GetService("EncodingService")
    :DecompressBuffer(buffer.fromstring(b85(blob)), Enum.CompressionAlgorithm.Zstd))
local L1 = (byte(J,1)+byte(J,2)*256+byte(J,3)*65536+byte(J,4)*16777216 - subA) % 4294967296
local L2 = (byte(J,5)+byte(J,6)*256+byte(J,7)*65536+byte(J,8)*16777216 - subB) % 4294967296
local segA, segB = sub(J, 9, 9 + L1 - 1), sub(J, 9 + L1, 9 + L1 + L2 - 1)
local function isLua(s) local h = s:sub(1, 8):gsub("^%s+", ""); return h:sub(1,5) == "local" or h:sub(1,6) == "return" or h:sub(1,3) == "--!" end
local ZA, Zh = segA, segB
if not isLua(segA) and isLua(segB) then ZA, Zh = segB, segA end
say("layer1: inner_source=" .. #ZA .. " inner_data=" .. #Zh)

------------------------------------------------- auto-patch resolver
local rn, ra, rg, rd, rt = ZA:match("local function (%w+)%((%w+)%)if %2<0 then %2=%-%2%-(%w+) end;return (%w+)%((%w+)%[%2%]%)end")
assert(rn, "resolver not found (unsupported build)")
local orig = ("local function %s(%s)if %s<0 then %s=-%s-%s end;return %s(%s[%s])end"):format(rn, ra, ra, ra, ra, rg, rd, rt, ra)
local patched = ("local function %s(%s)if %s<0 then %s=-%s-%s end;local _r=%s(%s[%s]);if __SL then local _w=__SL(_r,%s) if _w~=nil then _r=_w end end;return _r end;if __CAP then __CAP(%s,%s)end"):format(rn, ra, ra, ra, ra, rg, rd, rt, ra, ra, rd, rt)
local newZA, n = ZA:gsub(orig:gsub("[%-%[%]%(%)%.%+%*%?%^%$%%]", "%%%0"), patched, 1)
assert(n == 1, "resolver patch failed")
say("resolver: " .. rn .. " decoder=" .. rd .. " table=" .. rt)

------------------------------------------------- executor-sim env
local realenv = getfenv(); local genv = {}
local ES = {
    identifyexecutor=function() return "Synapse X","2.0" end, getexecutorname=function() return "Synapse X" end,
    getgenv=function() return genv end, getrenv=function() return realenv end, getreg=function() return {} end, getgc=function() return {} end,
    getrawmetatable=function(o) local ok,m=pcall(getmetatable,o); return ok and m or nil end, setrawmetatable=function(o) return o end,
    setreadonly=function() end, isreadonly=function() return false end, make_writeable=function() end, make_readonly=function() end,
    hookfunction=function(a) return a end, replaceclosure=function(a) return a end, hookmetamethod=function() return function() end end,
    newcclosure=function(f) return f end, clonefunction=function(f) return f end, checkcaller=function() return true end,
    islclosure=function() return true end, iscclosure=function() return false end, getnamecallmethod=function() return "" end, setnamecallmethod=function() end,
    getcallingscript=function() return nil end, getscriptclosure=function() return function() end end, getscripthash=function() return "" end,
    request=function() return {StatusCode=200,Body="",Success=true} end, getconnections=function() return {} end,
    getinstances=function() return {} end, getnilinstances=function() return {} end, cloneref=function(x) return x end,
    compareinstances=function(a,b) return a==b end, setclipboard=function() end, isnetworkowner=function() return true end,
    getthreadidentity=function() return 8 end, setthreadidentity=function() end, checkclosure=function() return true end,
    isourclosure=function() return true end, isexecutorclosure=function() return true end,
}

------------------------------------------------- taint tracking
local ops, PMT = {}, {}
local function uw(x) if type(x)=="table" and rawget(x,"__taint") then return x.__v end return x end
local function pv(x) if type(x)=="table" and rawget(x,"__taint") then return x.__e end return tostring(x) end
local function mk(v,e) return setmetatable({__taint=true,__v=v,__e=e}, PMT) end
local function bo(sym,nm) return function(a,b) local av,bv=uw(a),uw(b)
    local r=({ADD=function() return av+bv end,SUB=function() return av-bv end,MUL=function() return av*bv end,
        DIV=function() return av/bv end,MOD=function() return av%bv end,POW=function() return av^bv end})[nm]()
    ops[#ops+1]=("%s(%s , %s) = %s"):format(nm,pv(a),pv(b),tostring(r)); return mk(r,"("..pv(a)..sym..pv(b)..")") end end
PMT.__add=bo("+","ADD");PMT.__sub=bo("-","SUB");PMT.__mul=bo("*","MUL");PMT.__div=bo("/","DIV");PMT.__mod=bo("%","MOD");PMT.__pow=bo("^","POW")
PMT.__unm=function(a) ops[#ops+1]="UNM("..pv(a)..")"; return mk(-uw(a),"(-"..pv(a)..")") end
PMT.__eq=function(a,b) return uw(a)==uw(b) end; PMT.__lt=function(a,b) return uw(a)<uw(b) end; PMT.__le=function(a,b) return uw(a)<=uw(b) end
PMT.__concat=function(a,b) return pv(a)..pv(b) end; PMT.__tostring=function(a) return tostring(uw(a)) end

------------------------------------------------- env + hooks
local behavior, stream, strings, captured = {}, {}, {}, {}
local real_smt = setmetatable
local env = setmetatable({}, { __index=function(_,k) local rv=realenv[k]; if rv~=nil then return rv end return ES[k] end })
env.__SL = function(r) local n=#stream; if n<200000 then stream[n+1]=(type(r)=="string" and "S:"..r) or ("N:"..tostring(r)) end
    if type(r)=="string" then
        local ok=#r>0; for j=1,#r do local b=r:byte(j); if b<9 or (b>13 and b<32) or b>126 then ok=false break end end
        if ok then strings[#strings+1]=r end
    end
    return nil end
env.__CAP = function() end
env.print = function(...) local p={}; for i=1,select("#",...) do p[i]=pv((select(i,...))) end behavior[#behavior+1]="PRINT: "..table.concat(p,", ") end
env.warn = function() behavior[#behavior+1]="WARN" end
env.getgenv = ES.getgenv
env.setmetatable = function(t,mt) if type(mt)=="table" and type(mt.__index)=="function" then captured[#captured+1]={tbl=t,mt=mt} end return real_smt(t,mt) end
env.loadstring = function(s,...) local f=loadstring(s,...); if f then pcall(setfenv,f,env) end return f end
local RI=realenv.Instance
env.Instance=setmetatable({},{__index=function(_,k) if k=="new" then return function(c,...) behavior[#behavior+1]="Instance.new: "..tostring(c); return RI.new(c,...) end end return RI[k] end})
local rtask=realenv.task; local wN=0
env.wait=function() wN=wN+1; if wN>3 then error("WAIT_BUDGET") end return 0 end
env.task=setmetatable({},{__index=function(_,k) if k=="wait" then return env.wait end return rtask[k] end})

------------------------------------------------- run
local f=loadstring(newZA); setfenv(f,env)
local ok, ret = pcall(f, Zh)
say("run_ok: "..tostring(ok).."  return_type: "..typeof(ret))
if not ok then say("error: "..tostring(ret)) end

-- probe any returned/captured module with tracked args
local function probe(tag, M)
    for _,k in ipairs({"add","mul","sub","div","mod","pow","nope"}) do
        local okv,v=pcall(function() return M[k] end)
        if okv and type(v)=="function" then
            local before=#ops; local okc,r=pcall(v, mk(6,"a"), mk(2,"b"))
            say(("MODULE %s.%s(a,b) => %s"):format(tag,k,(#ops>before) and ops[#ops] or ("-> "..tostring(okc and pv(r) or r))))
        end
    end
end
if type(ret)=="table" then probe("return",ret) end
for i,e in ipairs(captured) do probe("cap"..i, e.tbl) end

------------------------------------------------- structured result
-- Keep the PRINTED block small so executor/MCP consoles do not truncate it
-- (a truncated block loses END and breaks auto-capture). Full detail, including
-- every decoded string, is written to unobf_result_full.txt.
say("counts: strings="..#strings.." ops="..#ops.." behavior="..#behavior.." stream="..#stream)
say("---OPS---"); for _,o in ipairs(ops) do say(o) end
say("---BEHAVIOR---"); for i=1,math.min(#behavior,40) do say(behavior[i]) end
say("---STRINGS---"); for i=1,math.min(#strings,60) do say(strings[i]) end

local body = "BEGIN_UNOBF_RESULT\n"..table.concat(R,"\n").."\nEND_UNOBF_RESULT"
print(body)
-- full detail (all strings) to a side file, not to the console
local full = {}
for _,s in ipairs(strings) do full[#full+1]=s end
pcall(function() writefile("unobf_result.txt", body) end)
pcall(function() writefile("unobf_result_full.txt", table.concat(full,"\n")) end)
return body
