--!nocheck
-- robloxenv.lua  --  the least Roblox the harness needs to run outside Roblox.
--
-- universal.lua builds its own environment for the payload. What it takes from
-- the HOST is small and specific: getfenv's table, and from it `game`,
-- `Instance`, `task`, `os`, `debug`, plus `typeof`, `loadstring` and the
-- executor's `readfile`/`writefile`. Under a bare `luau` binary none of those
-- Roblox ones exist, and the harness is written to notice: the service-proxy
-- block is wrapped in `if realGame then`, so with no `game` it is skipped and
-- the payload's `game:GetService(...)` indexes nil.
--
-- So this file supplies those roots and nothing else. It does NOT imitate
-- Roblox. Every field it does not carry stays absent, the payload's read of it
-- lands in the capture's ---ENVMISSING--- section, and a reader can see exactly
-- which names this stand-in could not answer for. Adding behaviour here would be
-- asserting something about Roblox that nothing observed, which is the one line
-- this project does not cross.
--
-- It also asserts, loudly, that it IS a stand-in: VMSMART_STANDIN is set so the
-- capture records where the run happened. A capture taken here is weaker
-- evidence than one taken in a game, and nothing downstream may mistake the two.

VMSMART_STANDIN = "robloxenv"

-- The stand-in's own records, created here because the blocks that write to them
-- run in file order and one of them is above their old declarations.
VMSMART_INSTANCE_FIELDS_ASKED = {}
VMSMART_HOST_FIELDS_ASKED = {}
VMSMART_STUB_COUNT = 0
-- weak, so a stub nobody holds can still be collected
VMSMART_STUB_PATH = setmetatable({}, { __mode = "k" })
VMSMART_STUB_LIMIT_HIT = false

-- A number derived from a path. Stable, and not the host's.
function VMSMART_DERIVE(seed)
    local v = 7
    for i = 1, #seed do
        v = (v * 131 + string.byte(seed, i)) % 2147483647
    end
    return v
end

-- The result of arithmetic on a stub is another stub, not a number.
--
-- A number was the obvious answer and it ended the run one step later: the build
-- indexes what the arithmetic produced. A stub can be indexed, called, compared,
-- concatenated, formatted (through the string wrapper) and used in further
-- arithmetic, so it survives whatever comes next, and its path records the whole
-- chain. tostring of it is still a stable number, so anything that wants a
-- numeric string gets one.
-- The boundary this crosses, and why it is counted rather than listed.
--
-- When the program does arithmetic on a value this file made up, the result is a
-- value this file made up, and from then on the program is computing with
-- fiction. That is a line worth crossing - it is what let the run get past the
-- host fingerprint this build takes - and it is not a line that may be crossed
-- quietly: every instruction after the first such operation describes a program
-- working on numbers the host never gave it.
--
-- So the first one is remembered and the rest are counted. Listing them all
-- flooded the capture with thousands of paths and said nothing the count does
-- not.
VMSMART_ARITH_COUNT = 0
VMSMART_ARITH_FIRST = nil

-- The PATH of a stub, not the number it prints as. A stub's tostring is a derived
-- number, so the first-arithmetic report named a number and left the gap it came
-- from unidentified.
function VMSMART_WHICH(v)
    if type(v) == "table" then
        local p = VMSMART_STUB_PATH and VMSMART_STUB_PATH[v]
        if p then return p end
        local t = VMSMART_TAGGED and VMSMART_TAGGED[v]
        if t then return t end
    end
    return tostring(v)
end

function VMSMART_ARITH(op, a, b)
    local key = op .. "(" .. VMSMART_WHICH(a) .. "," .. VMSMART_WHICH(b) .. ")"
    VMSMART_ARITH_COUNT = VMSMART_ARITH_COUNT + 1
    if VMSMART_ARITH_FIRST == nil then VMSMART_ARITH_FIRST = key end
    return VMSMART_STUB(VMSMART_ARITH_SINK, key, 0)
end

-- a sink, so these do not crowd out the paths that say what the build wanted
VMSMART_ARITH_SINK = {}

-- What a host object answers for a field this file does not implement.
--
-- Not nil. An absent field reads as nil, the build calls it, and the run ends on
-- this file's gap rather than on anything about the program. A recording stub
-- can be called, indexed and printed, answers nil to everything underneath, and
-- counts every name it was asked for, so the capture carries the list of what
-- the build wanted from the host instead of a stack trace.
--
-- This is the stand-in being a stand-in: it is not a claim that the host answers
-- this way, and the capture says where it ran.
-- Every call the stand-in answered, written the way the behaviour log writes a
-- call: `Receiver:Member(args)`. These are calls the program really made - the
-- stand-in is what answered them - and recording them is what lets the analysis
-- see where a value ended up. Without them a host interaction leaves no trace at
-- all, and every instruction feeding it reads as having no observable effect.
VMSMART_CALLS = {}

local function previewArg(v)
    local t = type(v)
    if t == "string" then
        if #v > 40 then return string.format("%q", v:sub(1, 40) .. "...") end
        return string.format("%q", v)
    end
    if t == "number" or t == "boolean" or t == "nil" then return tostring(v) end
    if t == "table" then
        local tag = VMSMART_TAGGED and VMSMART_TAGGED[v]
        if tag then return tag end
        local p = VMSMART_STUB_PATH and VMSMART_STUB_PATH[v]
        if p then return p end
        return "table"
    end
    return t
end

-- IDENTITY. What the host handed back, and whether the program ever used it.
--
-- A build that is measuring the machine it runs on asks a great many questions
-- and does nothing with the answers: whether this object is a Lighting, then a
-- Model, then a Workspace. A build doing its own work uses what it gets. The
-- difference is visible only if the answer can be recognised when it comes back
-- as an argument or a receiver later, so every host object this environment
-- hands out is given a number, and the records carry it.
--
-- The number says nothing about whether the object is real or a decoy. It is
-- there so the analysis can say "the program never used this answer" from the
-- records instead of guessing from a name.
VMSMART_IDS = setmetatable({}, { __mode = "k" })
VMSMART_ID_N = 0

function VMSMART_ID(v, assign)
    local t = type(v)
    if t ~= "table" and t ~= "userdata" and t ~= "function" then return nil end
    local id = VMSMART_IDS[v]
    if id == nil and assign then
        VMSMART_ID_N = VMSMART_ID_N + 1
        id = VMSMART_ID_N
        VMSMART_IDS[v] = id
    end
    return id
end

function VMSMART_RECORD_CALL(key, ...)
    if #VMSMART_CALLS >= 4000 then return end
    local parts = {}
    local n = select("#", ...)
    -- a method call passes the receiver as its first argument; it is already in
    -- the key, so it is not repeated among the arguments
    for i = 2, n do
        local a = (select(i, ...))
        local id = VMSMART_ID(a, false)
        parts[#parts + 1] = (id and ("#" .. tostring(id))
                             or previewArg(a))
    end
    local receiver, member = key:match("^(.-)[:%.]([%w_]+)$")
    if receiver == nil or receiver == "" then
        receiver, member = "host", key
    end
    -- the row the trace was on when this call happened, so the analysis can tie
    -- the two together by position
    local at = VMSMART_ROW
    local rid = VMSMART_ID((select(1, ...)), false)
    VMSMART_CALLS[#VMSMART_CALLS + 1] = receiver .. ":" .. member .. "("
        .. table.concat(parts, ", ") .. ")"
        .. (rid and ("  @on=#" .. tostring(rid)) or "")
        .. (type(at) == "number" and ("  @row=" .. tostring(at)) or "")
    return #VMSMART_CALLS
end

-- What the call answered with, written on the record the call left. Called
-- after the real method has run, so the answer is in hand.
function VMSMART_RECORD_ANSWER(slot, v)
    if type(slot) ~= "number" then return v end
    local line = VMSMART_CALLS[slot]
    if line == nil then return v end
    local id = VMSMART_ID(v, true)
    if id then
        VMSMART_CALLS[slot] = line .. "  @gave=#" .. tostring(id)
    end
    return v
end

function VMSMART_STUB(record, key, depth)
    depth = depth or 0
    record[key] = (record[key] or 0) + 1
    -- A stub that answers nil when it is CALLED, or when a field of it is read,
    -- ends the run one step later: this build calls a method on a host object and
    -- then uses what came back. So a stub answers with another stub, down to a
    -- fixed depth, and every step is recorded under its own path.
    --
    -- The cost is honest and worth stating: a stub is truthy, so a build that
    -- tests `if object.Something then` takes the branch it would take against a
    -- real host that HAS that thing. Where the real host would answer nil, this
    -- sends the program down the other branch. The ---STANDIN--- section lists
    -- every path answered this way so a reader can see which branches were taken
    -- on the stand-in's word rather than the host's.
    -- The chain has to be long enough for whatever the build does with it. A
    -- limit of 8 ended a run that had got 81,000 instructions in, with a nil
    -- being indexed - the nil was this limit, not the program. The bound is on
    -- the TOTAL number of stubs instead, so a runaway cannot eat the machine
    -- while an honest chain is never cut short.
    VMSMART_STUB_COUNT = (VMSMART_STUB_COUNT or 0) + 1
    if depth > 64 or VMSMART_STUB_COUNT > 400000 then
        VMSMART_STUB_LIMIT_HIT = true
        return nil
    end
    local v = setmetatable({}, {
        __call = function(_, ...)
            VMSMART_RECORD_CALL(key, ...)
            return VMSMART_STUB(record, key .. "()", depth + 1)
        end,
        __index = function(_, k)
            return VMSMART_STUB(record, key .. "." .. tostring(k), depth + 1)
        end,
        -- and it behaves as a number where one is wanted, for the same reason:
        -- this build adds what a host object gave it to something. The number is
        -- derived from the path, so it is stable across reads and across runs,
        -- and it is NOT the host's number.
        __tostring = function() return tostring(VMSMART_DERIVE(key)) end,
        __eq = function(a, b) return tostring(a) == tostring(b) end,
        __len = function() return 0 end,
        __concat = function(a, b) return tostring(a) .. tostring(b) end,
        __add = function(a, b) return VMSMART_ARITH("add", a, b) end,
        __sub = function(a, b) return VMSMART_ARITH("sub", a, b) end,
        __mul = function(a, b) return VMSMART_ARITH("mul", a, b) end,
        __div = function(a, b) return VMSMART_ARITH("div", a, b) end,
        __mod = function(a, b) return VMSMART_ARITH("mod", a, b) end,
        __pow = function(a, b) return VMSMART_ARITH("pow", a, b) end,
        __unm = function(a) return VMSMART_ARITH("unm", a, a) end,
        __lt = function(a, b) return tostring(a) < tostring(b) end,
        __le = function(a, b) return tostring(a) <= tostring(b) end,
    })
    VMSMART_STUB_PATH[v] = key
    return v
end

-- Luau's standalone binary has no loadstring. The harness captures it once as
-- `realLoad` and the whole nested-chunk path depends on it, so without this the
-- run ends before it starts. `load` is the same function under another name.
if loadstring == nil and load ~= nil then
    loadstring = function(src, chunkname)
        return load(src, chunkname or "=(load)")
    end
end

-- typeof is Luau's, and the standalone binary has it; this is only for a host
-- that does not.
if typeof == nil then typeof = type end

-- Files. The harness reads obf.lua and writes its captures beside it. Nothing
-- here invents a filesystem: a read that fails fails, and the harness already
-- treats a missing obf.lua as the thing to report.
if readfile == nil then
    readfile = function(path)
        local f = io.open(path, "rb")
        if not f then error("readfile: " .. tostring(path) .. " not found", 0) end
        local t = f:read("*a"); f:close(); return t
    end
end
if writefile == nil then
    writefile = function(path, text)
        local f = io.open(path, "wb")
        if not f then error("writefile: cannot open " .. tostring(path), 0) end
        f:write(text); f:close()
    end
end
if isfile == nil then
    isfile = function(path)
        local f = io.open(path, "rb"); if f then f:close(); return true end
        return false
    end
end

-- task. The harness wraps whatever it finds so errors on spawned threads reach
-- the capture; here the threads are ordinary coroutines, which is what they are.
if task == nil then
    task = {
        spawn = function(fn, ...) local co = coroutine.create(fn)
                                  coroutine.resume(co, ...) return co end,
        defer = function(fn, ...) local co = coroutine.create(fn)
                                  coroutine.resume(co, ...) return co end,
        delay = function(_, fn, ...) local co = coroutine.create(fn)
                                     coroutine.resume(co, ...) return co end,
        wait  = function() return 0 end,
        cancel = function() end,
    }
end
if wait == nil then wait = function() return 0 end end
if spawn == nil then spawn = function(fn, ...) return task.spawn(fn, ...) end end

-- Instance. A created instance is a plain table that remembers what it was asked
-- for. It is not a Roblox instance and does not pretend to be one: the harness
-- logs the class name and the arguments, which is the part that carries meaning.
-- Instances, with the one piece of the host's model this build depends on:
-- a tree. It creates an instance under a random name, parents it, and later
-- looks that name up - so an instance that forgets its children answers nil and
-- the run ends on a field whose name is random, which reads like a build doing
-- something clever and is really this file not keeping a tree.
--
-- Parenting, naming, lookup by name, GetChildren, FindFirstChild, WaitForChild,
-- Destroy and IsA are the host's documented behaviour and are implemented as
-- such. Anything else answers with a recording stub.
-- WHAT A CLASS IS, in the host's own terms. Only the parents each class
-- actually has; anything not named here is its own class and an Instance,
-- which is what the host says too.
VMSMART_PARENTS = {
    Part = {"FormFactorPart", "BasePart", "PVInstance", "Instance"},
    MeshPart = {"TriangleMeshPart", "BasePart", "PVInstance", "Instance"},
    WedgePart = {"FormFactorPart", "BasePart", "PVInstance", "Instance"},
    SpawnLocation = {"FormFactorPart", "BasePart", "PVInstance", "Instance"},
    Model = {"PVInstance", "Instance"},
    Folder = {"Instance"},
    Workspace = {"WorldRoot", "Model", "PVInstance", "Instance"},
    Players = {"Instance"},
    Player = {"Instance"},
    ReplicatedStorage = {"Instance"},
    ServerStorage = {"Instance"},
    ServerScriptService = {"Instance"},
    StarterGui = {"Instance"},
    Lighting = {"Instance"},
    RunService = {"Instance"},
    HttpService = {"Instance"},
    TweenService = {"Instance"},
    UserInputService = {"Instance"},
    CollectionService = {"Instance"},
    TeleportService = {"Instance"},
    MarketplaceService = {"Instance"},
    DataStoreService = {"Instance"},
    Script = {"BaseScript", "LuaSourceContainer", "Instance"},
    LocalScript = {"BaseScript", "LuaSourceContainer", "Instance"},
    ModuleScript = {"LuaSourceContainer", "Instance"},
    ScreenGui = {"LayerCollector", "GuiBase2d", "GuiBase", "Instance"},
    Frame = {"GuiObject", "GuiBase2d", "GuiBase", "Instance"},
    TextLabel = {"GuiLabel", "GuiObject", "GuiBase2d", "GuiBase", "Instance"},
    TextButton = {"GuiButton", "GuiObject", "GuiBase2d", "GuiBase", "Instance"},
    Humanoid = {"Instance"},
    Tool = {"BackpackItem", "Instance"},
    Sound = {"Instance"},
    Attachment = {"Instance"},
    Camera = {"Instance"},
}

function VMSMART_ISA(class, want)
    want = tostring(want)
    if class == want then return true end
    local up = VMSMART_PARENTS[class]
    if up then
        for i = 1, #up do
            if up[i] == want then return true end
        end
        return false
    end
    -- a class this file does not model is still an Instance, which is what the
    -- host answers for everything in its tree
    return want == "Instance"
end

-- THE SERVICES A ROBLOX CLIENT HAS. `game:GetService(name)` raises for a name
-- that is not one of them - "'X' is not a valid Service name" - and that is a
-- question a protected build asks on purpose: it names a service that cannot
-- exist and sees what comes back. A stand-in that hands one over has told the
-- build it is not on a real client, and the build then runs its checks instead
-- of its work. That is what this environment was doing: it answered
-- `GetService("EncodingService")` with a service, and there is no such service.
-- THE NAMES A ROBLOX CLIENT HAS. Datatypes, libraries and the few globals the
-- engine puts in every script's environment. It is what this file is willing to
-- answer for; everything else is nil, because that is what the host says.
--
-- A name missing from here that the host really has costs a run, and the report
-- names it, so the list grows from evidence rather than from guessing. A name
-- here that the host does not have costs much more: it tells a protected build
-- that nothing it is talking to is real.
VMSMART_NOT_A_HOST_NAME = {}
VMSMART_HOST_GLOBALS = {}
for _, n in ipairs({
    "Instance", "Enum", "EnumItem", "Vector3", "Vector2", "Vector3int16",
    "Vector2int16", "CFrame", "UDim", "UDim2", "Color3", "BrickColor",
    "Ray", "Region3", "Region3int16", "Rect", "NumberRange", "NumberSequence",
    "NumberSequenceKeypoint", "ColorSequence", "ColorSequenceKeypoint",
    "TweenInfo", "PhysicalProperties", "Faces", "Axes", "Random",
    "RaycastParams", "RaycastResult", "OverlapParams", "DateTime",
    "PathWaypoint", "Font", "CatalogSearchParams", "FloatCurveKey",
    "RotationCurveKey", "SharedTable", "Secret", "Content", "CFrameValue",
    "Workspace", "Game", "Players", "Lighting",
}) do VMSMART_HOST_GLOBALS[n] = true end

VMSMART_STRICT_SERVICES = false
VMSMART_SERVICES = {}
for _, n in ipairs({
    "Workspace", "Players", "Lighting", "ReplicatedStorage",
    "ReplicatedFirst", "ServerStorage", "ServerScriptService",
    "StarterGui", "StarterPack", "StarterPlayer", "SoundService",
    "Chat", "TextChatService", "Teams", "InsertService", "Debris",
    "RunService", "HttpService", "TweenService", "UserInputService",
    "ContextActionService", "CollectionService", "PathfindingService",
    "PhysicsService", "TeleportService", "MarketplaceService",
    "DataStoreService", "MessagingService", "MemoryStoreService",
    "BadgeService", "GamePassService", "PointsService", "AnalyticsService",
    "LocalizationService", "TextService", "ContentProvider",
    "GuiService", "CoreGui", "VirtualUser", "VirtualInputManager",
    "HapticService", "VRService", "GroupService", "FriendService",
    "SocialService", "PolicyService", "AvatarEditorService",
    "AssetService", "AnimationClipProvider", "KeyframeSequenceProvider",
    "TestService", "LogService", "ScriptContext", "Stats", "StarterPlayerScripts",
    "ProximityPromptService", "VoiceChatService", "NetworkClient",
    "NetworkServer", "Selection", "ChangeHistoryService", "Studio",
    "UserGameSettings", "TouchInputService", "CaptureService",
    "SerializationService", "ReflectionService", "ScriptService",
}) do VMSMART_SERVICES[n] = true end

if Instance == nil then
    -- Attributes and signals are state the host keeps for an instance, so this
    -- file keeps them: what the program writes it reads back, and what it never
    -- wrote reads as nil, which is what the host answers too. A signal answers
    -- Connect with a connection that can be disconnected, and fires nothing,
    -- because nothing here produces events.
    local function newSignal(name)
        local sig
        sig = setmetatable({}, {
            __index = function(_, k)
                if k == "Connect" or k == "ConnectParallel" or k == "Once" then
                    return function(_, fn)
                        return setmetatable({}, { __index = function(_, j)
                            if j == "Disconnect" or j == "disconnect" then
                                return function() end
                            end
                            if j == "Connected" then return true end
                            return nil
                        end })
                    end
                end
                if k == "Wait" then return function() return nil end end
                if k == "Fire" then return function() return nil end end
                return nil
            end,
            __tostring = function() return name end,
        })
        return sig
    end

    -- Wraps one of this file's methods so the call through it is recorded. The
    -- stub path records the calls it answers, and once the real methods existed
    -- almost nothing went through a stub any more - so the calls that matter
    -- most, the ones on objects the program built, were the ones not being seen.
    local function recorded(name, fn)
        return function(...)
            local slot = VMSMART_RECORD_CALL(name, ...)
            -- every return, not the first three: a method that hands back more
            -- than this reads for would be quietly truncated, and the program
            -- would carry on with values the host never gave it
            local r = table.pack(fn(...))
            VMSMART_RECORD_ANSWER(slot, r[1])
            return table.unpack(r, 1, r.n)
        end
    end

    local function newInstance(class)
        local children = {}
        local attributes = {}
        local signals = {}
        local self
        local function link(parent)
            if parent ~= nil and type(parent) == "table" then
                local add = rawget(parent, "VMSMART_ADD_CHILD")
                if add then add(self) end
            end
        end
        -- The method lookup is wrapped once, rather than each of the methods
        -- being wrapped one by one: whatever this instance answers with, if it is
        -- a function, the call through it is recorded. One place to get right,
        -- and it covers the methods added later too.
        local function answer(k, v)
            if type(v) ~= "function" then return v end
            return recorded(class .. ":" .. tostring(k), v)
        end
        self = setmetatable({ ClassName = class, Name = class, Parent = nil },
            { __index = function(_, k) return answer(k, (function()
                  if k == "GetChildren" or k == "GetDescendants" then
                      return function()
                          local list = {}
                          for _, v in pairs(children) do list[#list + 1] = v end
                          return list
                      end
                  elseif k == "FindFirstChild" or k == "WaitForChild"
                         or k == "FindFirstChildOfClass"
                         or k == "FindFirstChildWhichIsA" then
                      return function(_, n) return children[tostring(n)] end
                  elseif k == "Destroy" or k == "Remove" then
                      return function()
                          local p = rawget(self, "Parent")
                          if p ~= nil and type(p) == "table" then
                              local drop = rawget(p, "VMSMART_DROP_CHILD")
                              if drop then drop(self) end
                          end
                      end
                  elseif k == "Clone" then
                      return function() return newInstance(class) end
                  elseif k == "IsA" then
                      -- IsA walks the class tree in the host: a Folder IS an
                      -- Instance, a Part IS a BasePart and a PVInstance and an
                      -- Instance. Answering only on an exact name match made
                      -- this environment say no to `x:IsA("Instance")`, which
                      -- is true of every object there is - and a build that
                      -- asks that question is asking whether it is talking to
                      -- a real host at all.
                      return function(_, n) return VMSMART_ISA(class, n) end
                  elseif k == "SetAttribute" then
                      return function(_, n, v) attributes[tostring(n)] = v end
                  elseif k == "GetAttribute" then
                      return function(_, n) return attributes[tostring(n)] end
                  elseif k == "GetAttributes" then
                      return function()
                          local copy = {}
                          for n, v in pairs(attributes) do copy[n] = v end
                          return copy
                      end
                  elseif k == "GetAttributeChangedSignal"
                         or k == "GetPropertyChangedSignal" then
                      return function(_, n)
                          local key = tostring(n)
                          if signals[key] == nil then
                              signals[key] = newSignal(class .. "." .. key)
                          end
                          return signals[key]
                      end
                  elseif k == "Changed" or k == "AncestryChanged"
                         or k == "ChildAdded" or k == "ChildRemoved"
                         or k == "Destroying" then
                      if signals[k] == nil then
                          signals[k] = newSignal(class .. "." .. k)
                      end
                      return signals[k]
                  elseif k == "GetFullName" then
                      return function()
                          local parts, node = {}, self
                          while node ~= nil and type(node) == "table" do
                              table.insert(parts, 1,
                                           tostring(rawget(node, "Name")))
                              node = rawget(node, "Parent")
                          end
                          return table.concat(parts, ".")
                      end
                  elseif k == "IsDescendantOf" then
                      return function(_, other)
                          local node = rawget(self, "Parent")
                          while node ~= nil and type(node) == "table" do
                              if node == other then return true end
                              node = rawget(node, "Parent")
                          end
                          return false
                      end
                  elseif k == "ClearAllChildren" then
                      return function()
                          for n in pairs(children) do children[n] = nil end
                      end
                  elseif k == "VMSMART_ADD_CHILD" then
                      return function(child)
                          children[tostring(rawget(child, "Name"))] = child
                      end
                  elseif k == "VMSMART_DROP_CHILD" then
                      return function(child)
                          children[tostring(rawget(child, "Name"))] = nil
                      end
                  end
                  -- a child of this instance, by its own name, which is how the
                  -- host answers it too
                  local byName = children[tostring(k)]
                  if byName ~= nil then return byName end
                  return VMSMART_STUB(VMSMART_INSTANCE_FIELDS_ASKED,
                                      class .. ":" .. tostring(k))
              end)()) end,
              __newindex = function(t, k, v)
                  -- A property write is behaviour: the program setting Parent,
                  -- Name, a colour or a position is a thing it DID, and the
                  -- values it wrote are values with an observable effect. None
                  -- of them was recorded, so every instruction that computed one
                  -- read as having no consequence.
                  VMSMART_RECORD_CALL(class .. ":set_" .. tostring(k), t, v)
                  if k == "Parent" then
                      local old = rawget(t, "Parent")
                      if old ~= nil and type(old) == "table" then
                          local drop = rawget(old, "VMSMART_DROP_CHILD")
                          if drop then drop(t) end
                      end
                      rawset(t, "Parent", v)
                      link(v)
                      return
                  end
                  if k == "Name" then
                      -- renaming moves it in its parent's index, as it does in
                      -- the host
                      local p = rawget(t, "Parent")
                      if p ~= nil and type(p) == "table" then
                          local drop = rawget(p, "VMSMART_DROP_CHILD")
                          if drop then drop(t) end
                      end
                      rawset(t, "Name", v)
                      if p ~= nil then link(p) end
                      return
                  end
                  rawset(t, k, v)
              end,
              __tostring = function() return tostring(rawget(self, "Name")) end })
        return self
    end
    Instance = { new = function(class) return newInstance(tostring(class)) end }
    -- the service factory below builds its containers with this, so a service
    -- holds children the same way an instance does
    VMSMART_NEW_INSTANCE = newInstance
end

-- game. The one root that changes what the harness builds. A service here is an
-- empty object: asking for a service SUCCEEDS (so the harness's proxy path runs
-- and every call is logged), and every field on it is absent (so what the
-- payload wanted is recorded rather than answered). That split is deliberate -
-- answering would be inventing Roblox, and refusing the service would hide the
-- call the capture exists to record.
-- Enum, as the host's data model rather than as a placeholder.
--
-- The first version answered any path with a token, which is enough to stop
-- `Enum.X.Y` from being a nil index. It is not enough for a build that checks
-- the model: this one reads `Enum.Material.Plastic`, calls
-- `Enum.Material:FromName("Plastic")`, compares what comes back, and asks
-- `typeof` about it. A token has no FromName, and the read of it raised.
--
-- So the shape is implemented: a container of Enums, each Enum carrying its
-- items and the three methods the host documents, each item carrying Name,
-- Value and EnumType. Identity is stable, so FromName returns the same item the
-- field access returns, which is the comparison this build makes.
--
-- What is NOT the host's: the numeric Value. The real numbers are the host's
-- data and this file does not have them, so each item gets a stable number
-- derived from its own name. A build that compares a Value against the real
-- number fails here, and that is a limit of the stand-in rather than something
-- to paper over - VMSMART_ENUM_VALUES_ARE_DERIVED says so in the capture.
if Enum == nil then
    VMSMART_ENUM_VALUES_ARE_DERIVED = true
    local kinds = setmetatable({}, { __mode = "k" })

    local function derivedValue(name)
        local v = 0
        for i = 1, #name do
            v = (v * 31 + string.byte(name, i)) % 1000003
        end
        return v
    end

    local function makeEnum(enumName)
        local items, byValue, enum = {}, {}, nil
        local function item(itemName, forcedValue)
            if items[itemName] == nil then
                local value = forcedValue or derivedValue(itemName)
                local it = setmetatable(
                    { Name = itemName, Value = value },
                    { __index = function(_, k)
                          if k == "EnumType" then return enum end
                          return nil
                      end,
                      __tostring = function()
                          return "Enum." .. enumName .. "." .. itemName
                      end })
                kinds[it] = "EnumItem"
                items[itemName] = it
                byValue[value] = it
            end
            return items[itemName]
        end
        enum = setmetatable({}, {
            __index = function(_, k)
                k = tostring(k)
                if k == "GetEnumItems" then
                    return function()
                        local list = {}
                        for _, v in pairs(items) do list[#list + 1] = v end
                        return list
                    end
                end
                if k == "FromName" then
                    return function(_, n) return item(tostring(n)) end
                end
                if k == "FromValue" then
                    -- The host answers with the item that HAS that value, and a
                    -- value this stand-in has not seen before is still a value
                    -- the host would know. Returning nil made the build read a
                    -- field of nil one step later, which is this file's gap and
                    -- not the build's. The item it gets back carries the value
                    -- it asked for, so a round trip through FromValue agrees.
                    return function(_, v)
                        if byValue[v] ~= nil then return byValue[v] end
                        return item("FromValue_" .. tostring(v), v)
                    end
                end
                return item(k)
            end,
            __tostring = function() return "Enum." .. enumName end,
        })
        kinds[enum] = "Enum"
        return enum
    end

    local enums = {}
    Enum = setmetatable({}, {
        __index = function(_, k)
            k = tostring(k)
            if k == "GetEnums" then
                return function()
                    local list = {}
                    for _, v in pairs(enums) do list[#list + 1] = v end
                    return list
                end
            end
            if enums[k] == nil then enums[k] = makeEnum(k) end
            return enums[k]
        end,
        __tostring = function() return "Enums" end,
    })

    -- typeof has to agree, or every check of the model answers "table". The
    -- real one still answers for everything else.
    local realtypeof = typeof or type
    typeof = function(v)
        if type(v) == "table" then
            local k = kinds[v] or (VMSMART_TAGGED and VMSMART_TAGGED[v])
            if k then return k end
        end
        return realtypeof(v)
    end
    VMSMART_ENUM_KINDS = kinds
end

-- The host's datatypes, answered on demand and written down.
--
-- This build walks the host's own type system to decide whether it is running
-- somewhere real: it reads a datatype, calls a constructor on it, and asks
-- `typeof` what came back. There is no list of those types in this file on
-- purpose - a list is host data that would go stale, and the build chooses which
-- ones it asks about. The rule is structural instead: a global that is not
-- defined and whose name begins with a capital letter is answered with a
-- datatype root, whose fields are constructors, and whose products are tagged
-- values that report their own type name.
--
-- Everything answered this way is recorded in VMSMART_HOST_TYPES_ASKED and
-- printed in the capture, because answering a global is exactly the kind of
-- thing that must not happen quietly: without the record, a missing host type
-- would stop appearing in ---ENVMISSING--- and the capture would look like a run
-- that needed nothing.
--
-- A tagged value keeps the arguments it was built from and nothing else. Its
-- fields read as nil and each read is recorded, so what the build wanted from it
-- is in the capture rather than guessed at here.
local _type, _tostring, _setmetatable, _byte, _concat =
    type, tostring, setmetatable, string.byte, table.concat

VMSMART_HOST_TYPES_ASKED = {}
-- created before the function that writes to it
VMSMART_TAGGED = _setmetatable({}, { __mode = "k" })

-- A value a host constructor produced, and what a read of its fields answers.
--
-- The build reads a path into it - `UDim2.new(...).X.Offset` - and formats the
-- end of that path as a number. A field that answers nil ends the run at the
-- second step, so the shape is answered instead: one level of nesting, then a
-- number. That is the shape the host's own datatypes have, and it is as far as
-- a guess is allowed to go here.
--
-- The NUMBERS ARE NOT THE HOST'S. They are derived from the path and the
-- arguments, deterministically, so a run is repeatable and two reads of the same
-- path agree. A build that hashes these numbers and compares the hash against
-- one it carries gets a different answer than it would in a real host - which is
-- a limit of running offline, not something to be papered over. Every path read
-- is recorded in VMSMART_HOST_FIELDS_ASKED and printed in the capture.
local function derivedNumber(seed)
    local v = 7
    for i = 1, #seed do
        v = (v * 131 + _byte(seed, i)) % 2147483647
    end
    return v
end

-- Arithmetic on a constructed host value answers with another value of the same
-- kind, for the same reason the stubs do: a plain number ends the run as soon as
-- the build indexes what it got back.
local function arith(op, a2, b2)
    local key = "arith." .. op
    VMSMART_HOST_FIELDS_ASKED[key] = (VMSMART_HOST_FIELDS_ASKED[key] or 0) + 1
    return VMSMART_STUB(VMSMART_HOST_FIELDS_ASKED,
                        op .. "(" .. _tostring(a2) .. "," .. _tostring(b2) .. ")",
                        0)
end

local taggedValue
function taggedValue(typeName, args, n, depth)
    depth = depth or 0
    local shown = {}
    for i = 1, n do shown[i] = _tostring(args[i]) end
    local label = typeName .. "(" .. _concat(shown, ", ") .. ")"
    local v
    v = _setmetatable({}, {
        __index = function(_, k)
            local key = typeName .. "." .. _tostring(k)
            VMSMART_HOST_FIELDS_ASKED[key] =
                (VMSMART_HOST_FIELDS_ASKED[key] or 0) + 1
            -- Nesting is not depth-limited. A one-level rule answered
            -- `UDim2.new(...).X.Offset` and then broke on a path with three
            -- steps, because where the numbers start is the host's business and
            -- this file does not know it. So every field read answers with
            -- another value of this kind, and the value BEHAVES as a number
            -- wherever one is wanted: arithmetic through the metamethods below,
            -- and formatting through the wrappers further down.
            return taggedValue(key, args, n, depth + 1)
        end,
        -- Called as a function and used in arithmetic, because the build does
        -- both to these values: a method read off one of them is called, and the
        -- numbers that come out are added and compared. Every answer is derived
        -- from the path, deterministically, and every one is recorded.
        __call = function(_, ...)
            local key = typeName .. "()"
            VMSMART_HOST_FIELDS_ASKED[key] =
                (VMSMART_HOST_FIELDS_ASKED[key] or 0) + 1
            return taggedValue(key, { ... }, select("#", ...), depth)
        end,
        -- tostring answers with the derived NUMBER, as a decimal string, so
        -- the host's own string.format coerces it like any numeric string. The
        -- label is kept for the record, not for the program.
        __tostring = function() return _tostring(derivedNumber(label)) end,
        __eq = function(a2, b2) return _tostring(a2) == _tostring(b2) end,
        __len = function() return n end,
        __concat = function(a2, b2) return _tostring(a2) .. _tostring(b2) end,
        __add = function(a2, b2) return arith("add", a2, b2) end,
        __sub = function(a2, b2) return arith("sub", a2, b2) end,
        __mul = function(a2, b2) return arith("mul", a2, b2) end,
        __div = function(a2, b2) return arith("div", a2, b2) end,
        __mod = function(a2, b2) return arith("mod", a2, b2) end,
        __pow = function(a2, b2) return arith("pow", a2, b2) end,
        __unm = function(a2) return arith("unm", a2, a2) end,
        __lt = function(a2, b2) return _tostring(a2) < _tostring(b2) end,
        __le = function(a2, b2) return _tostring(a2) <= _tostring(b2) end,
    })
    VMSMART_TAGGED[v] = typeName
    return v
end

local function datatypeRoot(name)
    return _setmetatable({}, {
        __index = function(_, k)
            local key = name .. ":" .. _tostring(k)
            VMSMART_HOST_FIELDS_ASKED[key] =
                (VMSMART_HOST_FIELDS_ASKED[key] or 0) + 1
            return function(...)
                return taggedValue(name, { ... }, select("#", ...))
            end
        end,
        __tostring = function() return name end,
    })
end

-- Formatting and tonumber have to accept these values.
--
-- A tagged value is a table, and the host's string.format wants a number or a
-- string, so a build that formats one of them raises - and this build formats
-- with %.17g, which is how it turns the host's numbers into text to hash. The
-- host's own string table is frozen, so it is copied and the copy shadows the
-- global: format converts a tagged value with tostring first, which produces a
-- decimal string the real format then coerces. tonumber is wrapped the same way.
do
    local realstring = string
    if _type(realstring) == "table" then
        local copy = {}
        for k, v in pairs(realstring) do copy[k] = v end
        local realformat = realstring.format
        copy.format = function(fmt, ...)
            local argc = select("#", ...)
            local args = { ... }
            for i = 1, argc do
                if VMSMART_TAGGED[args[i]] ~= nil then
                    args[i] = _tostring(args[i])
                end
            end
            return realformat(fmt, table.unpack and table.unpack(args, 1, argc)
                              or unpack(args, 1, argc))
        end
        string = copy
    end
    local realtonumber = tonumber
    tonumber = function(v, base)
        if VMSMART_TAGGED[v] ~= nil then v = _tostring(v) end
        if base == nil then return realtonumber(v) end
        return realtonumber(v, base)
    end
end

do
    -- Captured above, and only locals are used inside __index: a global lookup
    -- in there would come straight back through this same metatable.
    --
    -- And the chain that was already there is kept. Luau's standalone binary
    -- hands a script an environment table whose metatable's __index points at
    -- the real globals, so replacing that metatable cut print, type and
    -- setmetatable off at the knees - this file stopped loading at its own
    -- `game = setmetatable(...)` line, with "attempt to call a nil value", and
    -- the nil was setmetatable itself. A host that protects its metatable
    -- (getmetatable answering with something that is not a table) gets nothing
    -- installed at all, and says so.
    local autos = {}
    local globals = getfenv and getfenv() or nil
    local previous = globals and getmetatable(globals) or nil
    if globals and (previous == nil or _type(previous) == "table") then
        local prev = previous and previous.__index or nil
        local prevIsFn = _type(prev) == "function"
        _setmetatable(globals, {
            __index = function(t, k)
                -- whatever the host had first, always
                local v
                if prevIsFn then v = prev(t, k)
                elseif prev ~= nil then v = prev[k] end
                if v ~= nil then return v end
                if _type(k) ~= "string" then return nil end
                local first = _byte(k, 1)
                if not first or first < 65 or first > 90 then return nil end
                -- never the stand-in's own bookkeeping. Those names are
                -- capitalised too, and answering one with a datatype root made
                -- this file's own counter read as a constructor - which failed
                -- as arithmetic on a function, inside the stand-in, during the
                -- payload's run.
                if k:sub(1, 7) == "VMSMART" then return nil end
                -- A NAME THE HOST DOES NOT HAVE IS NIL. This answered every
                -- capitalised name with something, and something is truthy: a
                -- build that asks `if SomeName then` to find out whether it is
                -- talking to a real client got yes, every time, for any name it
                -- cared to invent. The capture of this build says so in as many
                -- words - "a function the host does not have -> true" - and a
                -- build that learns it is being watched runs its checks and not
                -- its program, which is why a trace of it is all checks.
                --
                -- So only the names a Roblox client really has are answered.
                -- The rest are nil, which is what a real client answers, and
                -- each one is written down: what the program asked for and did
                -- not get is a fact worth having, and it is the list to work
                -- from if a run stops for want of one.
                if not VMSMART_HOST_GLOBALS[k] then
                    VMSMART_NOT_A_HOST_NAME[k] =
                        (VMSMART_NOT_A_HOST_NAME[k] or 0) + 1
                    return nil
                end
                if autos[k] == nil then
                    -- A type whose algebra robloxtypes.lua implements answers
                    -- with real numbers: the program reads back what it put in,
                    -- which is what it would get in a game. Only a type that
                    -- file does not model falls back to a structural root.
                    local modelled = VMSMART_TYPE_ROOT and VMSMART_TYPE_ROOT(k)
                    autos[k] = modelled or datatypeRoot(k)
                    VMSMART_HOST_TYPES_ASKED[#VMSMART_HOST_TYPES_ASKED + 1] =
                        k .. (modelled and " (modelled)" or " (structural)")
                end
                return autos[k]
            end,
            -- the rest of the host's metatable is carried over, so anything it
            -- did beyond __index keeps working
            __newindex = previous and previous.__newindex or nil,
            __call = previous and previous.__call or nil,
        })
    else
        VMSMART_HOST_TYPES_OFF = "the host protects its environment's metatable"
    end
end

-- The decompression the host does and this binary cannot. sidecar.py computes
-- it before the run from the script's own blobs, with a real Zstd decoder, and
-- leaves the answers in VMSMART_DECOMPRESS keyed by the bytes. A key that is
-- not there is a miss, and a miss raises with the key it looked for rather than
-- returning something that was never asked for.
VMSMART_DECOMPRESS_ASKED = {}

local function sideKey(s)
    local n = #s
    local function hex(part)
        local out = {}
        for i = 1, #part do
            out[i] = string.format("%02x", string.byte(part, i))
        end
        return table.concat(out)
    end
    local head = string.sub(s, 1, 8)
    local tail = n >= 8 and string.sub(s, n - 7, n) or s
    return n .. ":" .. hex(head) .. ":" .. hex(tail)
end

-- What was asked for and could not be answered, in full. The answers are
-- computed before the run from the blobs this tool can find in the script, and
-- a build that packs its bytes some other way - several frames in a table, its
-- own alphabet, a decoder of its own - produces bytes at RUN time that no
-- amount of looking at the file beforehand would have found.
--
-- Those bytes are in hand at exactly this moment: the program just passed
-- them. So the miss is written out with the bytes themselves, and the run that
-- follows is given the answer. It costs one more run of the payload and it
-- needs nothing to be known about how the build packs anything.
VMSMART_DECOMPRESS_WANT = {}

local function hexOf(s)
    local out = {}
    for i = 1, #s do out[i] = string.format("%02x", string.byte(s, i)) end
    return table.concat(out)
end

local function hostDecompress(bytes)
    local key = sideKey(bytes)
    VMSMART_DECOMPRESS_ASKED[#VMSMART_DECOMPRESS_ASKED + 1] = key
    local table_ = VMSMART_DECOMPRESS
    local got = table_ and table_[key]
    if got then return got end
    if #VMSMART_DECOMPRESS_WANT < 8 then
        VMSMART_DECOMPRESS_WANT[#VMSMART_DECOMPRESS_WANT + 1] =
            key .. " " .. hexOf(bytes)
    end
    error("this stand-in has no decompressed bytes for " .. key
          .. " (prepared: " .. tostring(table_ and #key or "none") .. ")", 0)
end

if game == nil then
    local services = {}
    -- What a stand-in service can answer. Everything not here stays absent, as
    -- the rest of this file does; this is the one capability the offline run
    -- cannot do without, because a payload that never gets its bytes back never
    -- reaches its own interpreter.
    local function capability(name, key)
        if key == "DecompressBuffer" or key == "DecompressString" then
            return function(_, data, _algorithm)
                local isBuffer = buffer ~= nil and type(data) ~= "string"
                local bytes = isBuffer and buffer.tostring(data) or data
                local plain = hostDecompress(bytes)
                if key == "DecompressBuffer" and buffer ~= nil then
                    return buffer.fromstring(plain)
                end
                return plain
            end
        end
        -- and nothing else. The stub belongs to the service wrapper below, which
        -- tries the instance's own fields FIRST: answering everything here meant
        -- `HttpService.ClassName` came back as a stub instead of the string the
        -- instance already had, and the program called :byte() on it.
        return nil
    end
    local function service(name)
        -- A name that is not a service raises on a real client, and this is a
        -- question builds ask deliberately. Answering it with a service is a
        -- plain statement that the host is not real, and from there a
        -- protected build runs its checks instead of its program - which is
        -- exactly what the first captures of this build contained.
        if not VMSMART_SERVICES[tostring(name)] then
            -- A name this file cannot place among the host's services. On a
            -- real client GetService raises for a name that is not a service,
            -- and a protected build asks for one on purpose to find out whether
            -- anything is standing in for the host.
            --
            -- Both answers are wrong in their own way, so neither is assumed.
            -- The list here is what this file knows, not what Roblox has, and
            -- refusing a name that is real would end a run that should have
            -- gone on. So the default is to answer and to RECORD that the
            -- answer is one a real client would not have given - which is a
            -- difference the build can see, and the report says so. The strict
            -- answer is run as its own attempt, and the two are compared.
            VMSMART_FAKE_SERVICE_ASKED = (VMSMART_FAKE_SERVICE_ASKED or 0) + 1
            if VMSMART_CALLS then
                VMSMART_CALLS[#VMSMART_CALLS + 1] =
                    "host:GetService_unknown(\"" .. tostring(name) .. "\")"
                    .. "  -- this file cannot place that name among the host's "
                    .. "services; a real client may raise here"
            end
            if VMSMART_STRICT_SERVICES then
                error("'" .. tostring(name) .. "' is not a valid Service name",
                      0)
            end
        end
        if services[name] == nil then
            -- A service is a container in the host's tree, and this build puts
            -- the instance it makes INSIDE one and looks it up again later. So a
            -- service is built as an instance, and the capabilities this file
            -- can actually perform are layered in front of it.
            local inst = VMSMART_NEW_INSTANCE and VMSMART_NEW_INSTANCE(name)
            if inst == nil then
                inst = setmetatable({ Name = name, ClassName = name }, {})
            end
            services[name] = setmetatable({}, {
                __index = function(_, k)
                    -- Real fields first - Name, ClassName, Parent, anything
                    -- written to it - read with rawget, because the instance's
                    -- own __index answers EVERYTHING with a stub and asking it
                    -- first meant the decompression this file can really do was
                    -- shadowed by a stub, and buffer.tostring got a table.
                    local own = rawget(inst, k)
                    if own ~= nil then return own end
                    local cap = capability(name, k)
                    if cap ~= nil then return cap end
                    -- then the instance's methods, its children, and its stub
                    return inst[k]
                end,
                __newindex = function(_, k, v)
                    VMSMART_RECORD_CALL(name .. ":set_" .. tostring(k), nil, v)
                    inst[k] = v
                end,
                __tostring = function() return name end,
            })
        end
        return services[name]
    end
    game = setmetatable({}, {
        __index = function(_, k)
            if k == "GetService" or k == "FindService" or k == "service" then
                return function(_, name) return service(tostring(name)) end
            end
            if k == "GetChildren" then return function() return {} end end
            if k == "Players" or k == "Workspace" then return service(k) end
            return nil
        end,
        __tostring = function() return "DataModel(standin)" end,
    })
    workspace = game:GetService("Workspace")
    -- `Game` is the host's own alias for `game`, and answering it with a datatype
    -- root made the program read a stub where it expected the data model.
    Game = game
    Workspace = workspace
end

return VMSMART_STANDIN
