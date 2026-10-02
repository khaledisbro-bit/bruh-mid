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
if game == nil then
    local services = {}
    local function service(name)
        if services[name] == nil then
            services[name] = setmetatable({ Name = name, ClassName = name },
                { __index = function() return nil end,
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
