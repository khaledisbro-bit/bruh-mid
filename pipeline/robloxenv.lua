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
function VMSMART_STUB(record, key)
    record[key] = (record[key] or 0) + 1
    return setmetatable({}, {
        __call = function() return nil end,
        __index = function() return nil end,
        __tostring = function() return key end,
    })
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
if Instance == nil then
    local function newInstance(class)
        local children = {}
        local self
        local function link(parent)
            if parent ~= nil and type(parent) == "table" then
                local add = rawget(parent, "VMSMART_ADD_CHILD")
                if add then add(self) end
            end
        end
        self = setmetatable({ ClassName = class, Name = class, Parent = nil },
            { __index = function(_, k)
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
                      return function(_, n) return n == class end
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
              end,
              __newindex = function(t, k, v)
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

local function arith(op, a2, b2)
    local key = "arith." .. op
    VMSMART_HOST_FIELDS_ASKED[key] = (VMSMART_HOST_FIELDS_ASKED[key] or 0) + 1
    return derivedNumber(op .. "|" .. _tostring(a2) .. "|" .. _tostring(b2))
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
                if autos[k] == nil then
                    autos[k] = datatypeRoot(k)
                    VMSMART_HOST_TYPES_ASKED[#VMSMART_HOST_TYPES_ASKED + 1] = k
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

local function hostDecompress(bytes)
    local key = sideKey(bytes)
    VMSMART_DECOMPRESS_ASKED[#VMSMART_DECOMPRESS_ASKED + 1] = key
    local table_ = VMSMART_DECOMPRESS
    local got = table_ and table_[key]
    if got then return got end
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
        -- everything else a service is asked for: recorded, callable, and not
        -- an answer about Roblox. A nil here ended runs that had got thousands
        -- of instructions in.
        return VMSMART_STUB(VMSMART_INSTANCE_FIELDS_ASKED,
                            name .. ":" .. tostring(key))
    end
    local function service(name)
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
                    local cap = capability(name, k)
                    if cap ~= nil then return cap end
                    return inst[k]
                end,
                __newindex = function(_, k, v) inst[k] = v end,
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
end

return VMSMART_STANDIN
