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
if Instance == nil then
    local function newInstance(class)
        local children = {}
        local self
        self = setmetatable({ ClassName = class, Name = class, Parent = nil },
            { __index = function(_, k)
                  if k == "GetChildren" then
                      return function() return children end
                  elseif k == "FindFirstChild" or k == "WaitForChild" then
                      return function(_, n) return children[n] end
                  elseif k == "Destroy" or k == "Remove" then
                      return function() end
                  elseif k == "Clone" then
                      return function() return newInstance(class) end
                  elseif k == "IsA" then
                      return function(_, n) return n == class end
                  end
                  return nil
              end,
              __newindex = function(t, k, v) rawset(t, k, v) end,
              __tostring = function() return class end })
        return self
    end
    Instance = { new = function(class) return newInstance(tostring(class)) end }
end

-- game. The one root that changes what the harness builds. A service here is an
-- empty object: asking for a service SUCCEEDS (so the harness's proxy path runs
-- and every call is logged), and every field on it is absent (so what the
-- payload wanted is recorded rather than answered). That split is deliberate -
-- answering would be inventing Roblox, and refusing the service would hide the
-- call the capture exists to record.
-- Enum. A root the payload indexes to name a constant, and the names it uses
-- are not knowable in advance, so this answers any of them with a token that
-- carries its own path and nothing else. A token is not a value this file
-- claims to know: it compares equal to itself, prints what it was asked for,
-- and every read of it lands in the record. What matters is that indexing Enum
-- stops being an error, because `Enum.Something.Other` as a nil index ends the
-- run before the payload has done anything worth watching.
if Enum == nil then
    local seen = {}
    local function token(path)
        if seen[path] == nil then
            seen[path] = setmetatable({ Name = path:match("[^.]+$"),
                                        Path = path, Value = 0 },
                { __tostring = function() return "Enum." .. path end,
                  __index = function() return nil end })
        end
        return seen[path]
    end
    local function level(path)
        return setmetatable({}, {
            __index = function(_, k)
                k = tostring(k)
                if path == "" then return level(k) end
                return token(path .. "." .. k)
            end,
            __tostring = function() return "Enum." .. path end,
        })
    end
    Enum = level("")
    VMSMART_ENUM_TOKENS = seen
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
        return nil
    end
    local function service(name)
        if services[name] == nil then
            services[name] = setmetatable({ Name = name, ClassName = name },
                { __index = function(_, k) return capability(name, k) end,
                  __tostring = function() return name end })
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
