-- event_watch.lua
--
-- Put this ABOVE the script you want to watch, in the same place it runs, and it
-- writes down everything that script does to the game: every remote it fires,
-- every signal it connects, every connected function the moment it is called,
-- every instance it makes, every property it sets, and who asked.
--
-- It changes nothing. It wraps, records and hands the real answer straight back,
-- so the watched script behaves exactly as it would on its own.
--
-- It takes three routes to the same place and uses whichever the host allows:
--
--   1  the metatable route. If the host hands over the game metatable, one hook
--      on __namecall sees EVERY method call on every instance - FireServer,
--      Fire, Invoke, Connect, Destroy, anything - with no list of names needed.
--   2  the member route. If not, the known members are wrapped one by one on
--      the classes that carry them.
--   3  whatever is left. Instance.new, the globals, and any object handed to
--      WATCH() by name.
--
-- It prints as it goes, and REPORT() prints the whole list again at the end.
--
-- HOW TO USE IT
--
--   1  run this file first, in the same place the script runs. On an executor
--      with hookmetamethod it is already watching everything at that point and
--      there is nothing more to do.
--   2  in plain Roblox, with no executor, name what you want watched:
--
--         WATCH(game.ReplicatedStorage.Bridge)     -- a remote, by itself
--         WATCH(part.Touched, "part.Touched")      -- one signal
--         WATCHFUNCS(myModule, "myModule")         -- every function in a table
--
--      It also sweeps the tree on its own for RemoteEvent, RemoteFunction,
--      BindableEvent, BindableFunction and UnreliableRemoteEvent under the
--      usual services, so most remotes are watched without being named.
--   3  run the script you want to watch.
--   4  REPORT() prints everything, and VMSMART_EVENTS holds the same lines.
--
-- WHAT EACH LINE MEANS
--
--   fire      something was fired: FireServer, FireClient, FireAllClients,
--             InvokeServer, InvokeClient, Fire, Invoke - with its arguments and
--             the line that fired it
--   connect   a handler was attached to a signal
--   ran       an attached handler was CALLED - the event actually happened - with
--             what it was handed
--   call      any other method or watched function was called
--   gave      what a watched function gave back
--   made      Instance.new, with the class and the line
--   watching  this file started watching something

local EVENTS = {}
local MAX = 4000
local START = os.clock()

local function now()
    return string.format("%7.3f", os.clock() - START)
end

-- WHERE THE CALL CAME FROM. The first frame that is not one of this file's own
-- wrappers, found by identity rather than by the name of a file: the watcher and
-- the watched script can sit in the same chunk, and matching on the file name
-- then picks the wrong line every time.
local MINE = setmetatable({}, { __mode = "k" })

local HAVE_INFO = (type(debug) == "table" and type(debug.info) == "function")

local function whence()
    if not HAVE_INFO then return "?" end
    -- debug.info is called DIRECTLY, not through pcall: pcall puts a frame of its
    -- own on the stack and every level then counts from the wrong place, which is
    -- why the first version of this reported one line of this file for
    -- everything. Luau answers nil past the top of the stack, so the loop is safe.
    for level = 2, 16 do
        local fn = debug.info(level, "f")
        if fn == nil then break end
        if not MINE[fn] then
            local src, line = debug.info(level, "sl")
            if src ~= nil then
                return tostring(src) .. ":" .. tostring(line)
            end
            return "?"
        end
    end
    return "?"
end

local function short(v, depth)
    depth = depth or 0
    local t = typeof and typeof(v) or type(v)
    if t == "string" then
        if #v > 60 then return string.format("%q", string.sub(v, 1, 60) .. "...") end
        return string.format("%q", v)
    end
    if t == "number" or t == "boolean" or t == "nil" then return tostring(v) end
    if t == "Instance" then
        local ok, cls = pcall(function() return v.ClassName end)
        local ok2, nm = pcall(function() return v.Name end)
        return (ok and tostring(cls) or "Instance") .. "(" ..
               (ok2 and tostring(nm) or "?") .. ")"
    end
    if t == "table" then
        if depth > 0 then return "{...}" end
        local parts, n = {}, 0
        for k, vv in pairs(v) do
            n = n + 1
            if n > 6 then parts[#parts + 1] = "..." break end
            parts[#parts + 1] = tostring(k) .. "=" .. short(vv, depth + 1)
        end
        return "{" .. table.concat(parts, ", ") .. "}"
    end
    if t == "function" then return "function" end
    return t .. "(" .. tostring(v) .. ")"
end

local function args(...)
    local n = select("#", ...)
    local parts = {}
    for i = 1, n do parts[i] = short((select(i, ...))) end
    return table.concat(parts, ", ")
end

local function note(kind, text)
    if #EVENTS >= MAX then return end
    local line = now() .. "  " .. kind .. "  " .. text
    EVENTS[#EVENTS + 1] = line
    print("[watch] " .. line)
end

----------------------------------------------------------------------------
-- what counts as firing something
----------------------------------------------------------------------------

local FIRES = {
    FireServer = true, fireServer = true,
    FireClient = true, FireAllClients = true,
    InvokeServer = true, InvokeClient = true,
    Fire = true, Invoke = true,
    fireServer_ = true,
}

local CONNECTS = {
    Connect = true, connect = true, Once = true, once = true,
    ConnectParallel = true, Wait = true, wait = true,
}

----------------------------------------------------------------------------
-- a connected function, wrapped so its CALL is written down too
----------------------------------------------------------------------------

local function wrapCallback(where, fn)
    if type(fn) ~= "function" then return fn end
    local wrapped
    wrapped = function(...)
        note("ran", where .. " fired with (" .. args(...) .. ")")
        return fn(...)
    end
    MINE[wrapped] = true
    return wrapped
end

----------------------------------------------------------------------------
-- route 1: the metatable. One hook sees every method call there is.
----------------------------------------------------------------------------

local hooked = false

local function tryMetatable()
    local getraw = rawget(getfenv and getfenv() or _G, "getrawmetatable")
    local setro = rawget(getfenv and getfenv() or _G, "setreadonly")
    local hookmeta = rawget(getfenv and getfenv() or _G, "hookmetamethod")
    local newcc = rawget(getfenv and getfenv() or _G, "newcclosure")
                  or function(f) return f end

    if hookmeta then
        local old
        old = hookmeta(game, "__namecall", newcc(function(self, ...)
            local method = getnamecallmethod and getnamecallmethod() or "?"
            local text = short(self) .. ":" .. tostring(method)
            if FIRES[method] then
                note("fire", text .. "(" .. args(...) .. ")  from " .. whence())
            elseif CONNECTS[method] then
                note("connect", text .. "  from " .. whence())
                local a, b = ...
                if type(a) == "function" then
                    return old(self, wrapCallback(text, a), select(2, ...))
                end
            else
                note("call", text .. "(" .. args(...) .. ")")
            end
            return old(self, ...)
        end))
        hooked = true
        return "the game metatable, through hookmetamethod"
    end

    if getraw then
        local mt = getraw(game)
        if type(mt) == "table" then
            if setro then setro(mt, false) end
            local oldnc = mt.__namecall
            if type(oldnc) == "function" then
                mt.__namecall = newcc(function(self, ...)
                    local method = getnamecallmethod and getnamecallmethod() or "?"
                    local text = short(self) .. ":" .. tostring(method)
                    if FIRES[method] then
                        note("fire", text .. "(" .. args(...) .. ")  from " .. whence())
                    elseif CONNECTS[method] then
                        note("connect", text .. "  from " .. whence())
                    else
                        note("call", text .. "(" .. args(...) .. ")")
                    end
                    return oldnc(self, ...)
                end)
                hooked = true
                if setro then setro(mt, true) end
                return "the game metatable, through getrawmetatable"
            end
            if setro then setro(mt, true) end
        end
    end
    return nil
end

----------------------------------------------------------------------------
-- route 2: the members, one object at a time. Works with no host help at all.
----------------------------------------------------------------------------

local watched = setmetatable({}, { __mode = "k" })

local function wrapMember(obj, name, label)
    local ok, fn = pcall(function() return obj[name] end)
    if not ok or type(fn) ~= "function" then return false end
    local text = label .. ":" .. name
    local replaced
    replaced = function(self, ...)
        if FIRES[name] then
            note("fire", text .. "(" .. args(...) .. ")  from " .. whence())
        elseif CONNECTS[name] then
            note("connect", text .. "  from " .. whence())
            local a = ...
            if type(a) == "function" then
                return fn(self, wrapCallback(text, a), select(2, ...))
            end
        else
            note("call", text .. "(" .. args(...) .. ")")
        end
        return fn(self, ...)
    end
    MINE[replaced] = true
    local set = pcall(function() obj[name] = replaced end)
    return set
end

function WATCH(obj, label)
    if obj == nil or watched[obj] then return obj end
    watched[obj] = true
    label = label or short(obj)
    local any = false
    for name in pairs(FIRES) do
        if wrapMember(obj, name, label) then any = true end
    end
    for name in pairs(CONNECTS) do
        if wrapMember(obj, name, label) then any = true end
    end
    note("watching", label .. (any and " (members wrapped)" or " (nothing to wrap)"))
    return obj
end

-- ANY FUNCTION AT ALL. Hand it a table and every function in it is written down
-- when it is called, with its arguments and what it gave back. This is the one to
-- use for a module's own functions rather than the game's members.
function WATCHFUNCS(t, label)
    if type(t) ~= "table" then return t end
    label = label or "table"
    local n = 0
    for k, v in pairs(t) do
        if type(v) == "function" and not MINE[v] then
            local name = label .. "." .. tostring(k)
            local real = v
            local wrapped
            wrapped = function(...)
                note("call", name .. "(" .. args(...) .. ")  from " .. whence())
                local out = table.pack(real(...))
                if out.n > 0 then
                    note("gave", name .. " -> " .. args(table.unpack(out, 1, out.n)))
                end
                return table.unpack(out, 1, out.n)
            end
            MINE[wrapped] = true
            if pcall(function() t[k] = wrapped end) then n = n + 1 end
        end
    end
    note("watching", label .. ": " .. tostring(n) .. " function(s) wrapped")
    return t
end

----------------------------------------------------------------------------
-- route 3: what the script makes, and what it sets
----------------------------------------------------------------------------

local function watchInstanceNew()
    local realNew = Instance and Instance.new
    if type(realNew) ~= "function" then return false end
    local ok = pcall(function()
        Instance.new = function(class, parent, ...)
            local made = realNew(class, parent, ...)
            note("made", "Instance.new(" .. short(class) ..
                 (parent ~= nil and (", " .. short(parent)) or "") .. ")" ..
                 "  from " .. whence())
            if not hooked then pcall(WATCH, made, short(made)) end
            return made
        end
    end)
    return ok
end

----------------------------------------------------------------------------
-- the signals and remotes already sitting in the tree
----------------------------------------------------------------------------

local function sweep(root, label, depth)
    if depth > 3 or root == nil then return end
    local ok, kids = pcall(function() return root:GetChildren() end)
    if not ok then return end
    for _, kid in ipairs(kids) do
        local ok2, cls = pcall(function() return kid.ClassName end)
        if ok2 then
            cls = tostring(cls)
            if cls == "RemoteEvent" or cls == "RemoteFunction"
               or cls == "BindableEvent" or cls == "BindableFunction"
               or cls == "UnreliableRemoteEvent" then
                WATCH(kid, label .. "." .. tostring(kid.Name) .. "[" .. cls .. "]")
            end
        end
        sweep(kid, label .. "." .. tostring((pcall(function() return kid.Name end))
              and kid.Name or "?"), depth + 1)
    end
end

----------------------------------------------------------------------------
-- start
----------------------------------------------------------------------------

local route = nil
if game ~= nil then
    local ok, why = pcall(tryMetatable)
    if ok then route = why end
end

note("start", "watching. route: " .. tostring(route or "members only"))

if watchInstanceNew() then
    note("start", "Instance.new is watched")
end

if game ~= nil and not hooked then
    for _, name in ipairs({ "ReplicatedStorage", "ReplicatedFirst",
                            "Players", "Workspace", "Lighting" }) do
        local ok, svc = pcall(function() return game:GetService(name) end)
        if ok and svc ~= nil then pcall(sweep, svc, name, 1) end
    end
end

function REPORT()
    print("---EVENTS---")
    print("events: " .. tostring(#EVENTS))
    for i = 1, #EVENTS do print(EVENTS[i]) end
    print("---END---")
    return EVENTS
end

VMSMART_EVENTS = EVENTS
VMSMART_WATCH = WATCH
VMSMART_WATCHFUNCS = WATCHFUNCS
VMSMART_REPORT = REPORT

-- If nothing else prints it, print it when the script that loaded this ends.
if game ~= nil then
    local ok, run = pcall(function() return game:GetService("RunService") end)
    if ok and run ~= nil then
        pcall(function()
            local conn
            conn = run.Heartbeat:Connect(function()
                if #EVENTS > 0 and os.clock() - START > 5 then
                    conn:Disconnect()
                    REPORT()
                end
            end)
        end)
    end
end

return { events = EVENTS, watch = WATCH, watchfuncs = WATCHFUNCS,
         report = REPORT }
