--!nocheck
-- robloxtypes.lua  --  the host's datatypes, by their documented algebra.
--
-- The stand-in answered these structurally at first: a constructor produced a
-- tagged value, a field read produced another, and the numbers were derived from
-- the path. That is enough to keep a program running and not enough to be worth
-- much, because a build of this class READS those numbers back, formats them and
-- hashes them. Derived numbers make a derived hash, the build's comparison
-- fails, and from then on the program is computing with fiction.
--
-- Most of these types are pure functions of their own arguments:
-- UDim2.new(a, b, c, d).X.Offset is b, Color3.new(r, g, b).R is r,
-- Vector3.new(x, y, z).Magnitude is the length of that vector. Those are not
-- facts about any script - they are the host's algebra, documented and stable -
-- and implementing them means the program reads back what it put in, exactly as
-- it would in a game.
--
-- What is NOT here, and is marked rather than guessed:
--   * BrickColor's palette: a name-to-number table is the host's DATA, not its
--     algebra, and this file does not carry host data.
--   * Random: Roblox's generator is not a documented algorithm, so its numbers
--     cannot be reproduced.
--   * anything else a program asks for that is not listed below.
-- Those stay stubs, every one is recorded, and the capture says which types were
-- modelled and which were not.

VMSMART_TYPES_MODELLED = {}
VMSMART_TYPES_STUBBED = {}

local floor, sqrt, huge = math.floor, math.sqrt, math.huge

-- A value of a modelled type: a table of real fields, plus the methods the type
-- documents. Reads of anything else fall through to the stand-in's recorder.
-- `lazy` fields are computed on first read and then cached. Unit is one: a unit
-- vector is itself a vector, so building it eagerly builds its own unit, and
-- that recursion overflowed the stack 20,000 frames deep. Computed on demand it
-- stops at the first one nobody asks about.
-- THE REAL `type`. The stand-in replaces the global one so that an Instance and
-- a datatype answer "userdata", which is what the host answers and what a build
-- that asks has to see. Every check in THIS file is about Lua's own kinds - is
-- this argument a table I built, is that one a plain number - so it has to keep
-- asking the old question. Leaving them on the replaced global made
-- `UDim2.new(UDim, UDim)` stop recognising its arguments and every datatype
-- operator stop recognising its operands.
local rawtype = VMSMART_REAL_TYPE or type

-- WHERE A DATATYPE'S COMPONENTS LIVE.
--
-- Not in the value itself. In the host these are userdata and every component
-- read goes through the engine. Copying them into the table was close enough to
-- work and far enough to hide: a read served out of the table never reaches
-- __index, so it could not be recorded, and a component with a wrong value was
-- invisible. These builds fold the components they read into the key their
-- payload is decrypted with, so each read has to be visible.
VMSMART_FIELDS = VMSMART_FIELDS or {}

-- The separators and the shapes the host prints these with. Public behaviour,
-- checkable by printing one: a space for the sequence types, a comma and a space
-- for the vectors and colours, and a shape of its own for the two that are not a
-- flat list of numbers.
local TOSTRING_SEP = {
    NumberRange = " ",
    NumberSequenceKeypoint = " ",
    ColorSequenceKeypoint = " ",
    NumberSequence = " ",
    ColorSequence = " ",
}
local TOSTRING_SHAPE = {
    -- a UDim2 is two UDims, each in braces
    UDim2 = function(fields)
        local x, y = fields.X, fields.Y
        return "{" .. tostring(x) .. "}, {" .. tostring(y) .. "}"
    end,
    -- a Rect is its two corners' components, flat
    Rect = function(fields)
        local mn, mx = fields.Min, fields.Max
        return tostring(mn) .. ", " .. tostring(mx)
    end,
    -- a BrickColor prints its name and nothing else
    BrickColor = function(fields) return tostring(fields.Name) end,
    -- a sequence prints every keypoint in order, space separated
    NumberSequence = function(fields)
        local ks = fields.Keypoints or {}
        local parts = {}
        for i = 1, #ks do parts[#parts + 1] = tostring(ks[i]) end
        return table.concat(parts, " ")
    end,
    ColorSequence = function(fields)
        local ks = fields.Keypoints or {}
        local parts = {}
        for i = 1, #ks do parts[#parts + 1] = tostring(ks[i]) end
        return table.concat(parts, " ")
    end,
}

local function make(typeName, fields, methods, lazy, ops)
    local v = {}
    local wrapped = nil
    VMSMART_FIELDS[v] = fields
    local meta = {
        __index = function(t, k)
            local own = fields[k]
            if own ~= nil then
                if VMSMART_READ then
                    VMSMART_READ(typeName .. "." .. tostring(k), own)
                end
                return own
            end
            local l = lazy and lazy[k]
            if l then
                local value = l()
                fields[k] = value
                if VMSMART_READ then
                    VMSMART_READ(typeName .. "." .. tostring(k) .. " (computed)",
                                 value)
                end
                return value
            end
            local m = methods and methods[k]
            if m then
                -- A METHOD IS A HOST COMPUTATION, and those are the answers this
                -- file can be wrong about: a component read back is whatever the
                -- program passed in, but Cross, Dot and Lerp are arithmetic the
                -- host does. So the call and what it produced are recorded the
                -- same way a component read is.
                if VMSMART_READ == nil then return m end
                -- THE SAME FUNCTION EVERY TIME. In the host, reading a method
                -- twice gives the same function, and `rawequal(a.Lerp, a.Lerp)`
                -- is true. A wrapper built per read makes that false, which is a
                -- difference a build can read with one comparison - and this one
                -- compares functions.
                wrapped = wrapped or {}
                if wrapped[k] then return wrapped[k] end
                local w = function(...)
                    local r = m(...)
                    VMSMART_READ(typeName .. ":" .. tostring(k) .. "()", r)
                    return r
                end
                wrapped[k] = w
                return w
            end
            -- not part of this type: recorded, not invented
            return VMSMART_STUB(VMSMART_HOST_FIELDS_ASKED,
                                typeName .. "." .. tostring(k))
        end,
        -- HOW THE HOST PRINTS IT.
        --
        -- Not one format. Roblox prints a Vector3 as "1, 2, 3" and a
        -- NumberRange as "1 2" - a space, no comma - and a UDim2 as
        -- "{0, 1}, {0, 2}", braces and all. A BrickColor prints its name and a
        -- TweenInfo prints nothing but its type. Joining every type's components
        -- with ", " is right for about half of them.
        --
        -- It matters here because this build formats what the host gives it and
        -- folds the text: `string.format("%.17g", ...)` is one of its own
        -- functions. A separator in the wrong place changes every number after
        -- it.
        __tostring = function(t)
            local sep = TOSTRING_SEP[typeName] or ", "
            local shape = TOSTRING_SHAPE[typeName]
            if shape then return shape(fields, t) end
            local parts = {}
            for _, k in ipairs(fields.__order or {}) do
                parts[#parts + 1] = tostring(fields[k])
            end
            return #parts > 0 and table.concat(parts, sep) or typeName
        end,
        __eq = function(a, b) return tostring(a) == tostring(b) end,
    }
    -- The operators a type documents. A type with no arithmetic gets none, and
    -- Lua then raises where the program tried to do some - which is what the host
    -- does too, and is better than an invented answer.
    if ops then
        for k, fn in pairs(ops) do meta[k] = fn end
    end
    VMSMART_TAGGED[v] = typeName
    return setmetatable(v, meta)
end

local function num(x) return tonumber(x) or 0 end

-- A plain Lua array, as opposed to one of these types. Indexing a type answers
-- with a recording stub rather than nil, so `a[1] ~= nil` is true for every type
-- as well - which made ColorSequence.new(colour, colour) treat its first colour
-- as a list of keypoints.
local function isArray(v)
    return rawtype(v) == "table" and VMSMART_TAGGED[v] == nil and rawget(v, 1) ~= nil
end

local T = {}

T.UDim = function(scale, offset)
    local sc, off = num(scale), num(offset)
    return make("UDim", { Scale = sc, Offset = off,
                          __order = { "Scale", "Offset" } }, {
        Lerp = function(_, goal, alpha)
            alpha = num(alpha)
            return T.UDim(sc + (num(goal.Scale) - sc) * alpha,
                          off + (num(goal.Offset) - off) * alpha)
        end,
    }, nil, {
        __add = function(a, b)
            return T.UDim(num(a.Scale) + num(b.Scale),
                          num(a.Offset) + num(b.Offset))
        end,
        __sub = function(a, b)
            return T.UDim(num(a.Scale) - num(b.Scale),
                          num(a.Offset) - num(b.Offset))
        end,
        __unm = function(a) return T.UDim(-num(a.Scale), -num(a.Offset)) end,
    })
end

T.UDim2 = function(xs, xo, ys, yo)
    -- UDim2.new(UDim, UDim) is also documented
    if rawtype(xs) == "table" and VMSMART_TAGGED[xs] == "UDim" then
        local a, b = xs, xo
        return make("UDim2", { X = a, Y = b, Width = a, Height = b,
                               __order = { "X", "Y" } })
    end
    local x, y = T.UDim(xs, xo), T.UDim(ys, yo)
    return make("UDim2", { X = x, Y = y, Width = x, Height = y,
                           __order = { "X", "Y" } }, {
        Lerp = function(_, goal, alpha)
            alpha = num(alpha)
            local gx, gy = goal.X, goal.Y
            return T.UDim2(
                num(x.Scale) + (num(gx.Scale) - num(x.Scale)) * alpha,
                num(x.Offset) + (num(gx.Offset) - num(x.Offset)) * alpha,
                num(y.Scale) + (num(gy.Scale) - num(y.Scale)) * alpha,
                num(y.Offset) + (num(gy.Offset) - num(y.Offset)) * alpha)
        end,
    }, nil, {
        __add = function(a, b)
            return T.UDim2(num(a.X.Scale) + num(b.X.Scale),
                           num(a.X.Offset) + num(b.X.Offset),
                           num(a.Y.Scale) + num(b.Y.Scale),
                           num(a.Y.Offset) + num(b.Y.Offset))
        end,
        __sub = function(a, b)
            return T.UDim2(num(a.X.Scale) - num(b.X.Scale),
                           num(a.X.Offset) - num(b.X.Offset),
                           num(a.Y.Scale) - num(b.Y.Scale),
                           num(a.Y.Offset) - num(b.Y.Offset))
        end,
    })
end

T.Vector2 = function(x, y)
    x, y = num(x), num(y)
    local mag = sqrt(x * x + y * y)
    return make("Vector2", { X = x, Y = y, Magnitude = mag,
                             __order = { "X", "Y" } }, {
        Dot = function(_, o) return x * num(o.X) + y * num(o.Y) end,
    }, {
        Unit = function()
            if mag > 0 then return T.Vector2(x / mag, y / mag) end
            return T.Vector2(0, 0)
        end,
    }, {
        __add = function(a, b) return T.Vector2(num(a.X) + num(b.X),
                                                num(a.Y) + num(b.Y)) end,
        __sub = function(a, b) return T.Vector2(num(a.X) - num(b.X),
                                                num(a.Y) - num(b.Y)) end,
        __mul = function(a, b)
            if rawtype(b) == "number" then return T.Vector2(num(a.X) * b,
                                                         num(a.Y) * b) end
            if rawtype(a) == "number" then return T.Vector2(a * num(b.X),
                                                         a * num(b.Y)) end
            return T.Vector2(num(a.X) * num(b.X), num(a.Y) * num(b.Y))
        end,
        __unm = function(a) return T.Vector2(-num(a.X), -num(a.Y)) end,
    })
end

T.Vector3 = function(x, y, z)
    x, y, z = num(x), num(y), num(z)
    local mag = sqrt(x * x + y * y + z * z)
    local self = make("Vector3", { X = x, Y = y, Z = z, Magnitude = mag,
                                   __order = { "X", "Y", "Z" } }, {
        Dot = function(_, o) return x * num(o.X) + y * num(o.Y) + z * num(o.Z) end,
        Cross = function(_, o)
            return T.Vector3(y * num(o.Z) - z * num(o.Y),
                             z * num(o.X) - x * num(o.Z),
                             x * num(o.Y) - y * num(o.X))
        end,
        Lerp = function(_, o, t)
            t = num(t)
            return T.Vector3(x + (num(o.X) - x) * t,
                             y + (num(o.Y) - y) * t,
                             z + (num(o.Z) - z) * t)
        end,
    }, {
        Unit = function()
            if mag > 0 then return T.Vector3(x / mag, y / mag, z / mag) end
            return T.Vector3(0, 0, 0)
        end,
    }, {
        __add = function(a, b)
            return T.Vector3(num(a.X) + num(b.X), num(a.Y) + num(b.Y),
                             num(a.Z) + num(b.Z))
        end,
        __sub = function(a, b)
            return T.Vector3(num(a.X) - num(b.X), num(a.Y) - num(b.Y),
                             num(a.Z) - num(b.Z))
        end,
        __mul = function(a, b)
            if rawtype(b) == "number" then
                return T.Vector3(num(a.X) * b, num(a.Y) * b, num(a.Z) * b)
            end
            if rawtype(a) == "number" then
                return T.Vector3(a * num(b.X), a * num(b.Y), a * num(b.Z))
            end
            return T.Vector3(num(a.X) * num(b.X), num(a.Y) * num(b.Y),
                             num(a.Z) * num(b.Z))
        end,
        __div = function(a, b)
            if rawtype(b) == "number" then
                return T.Vector3(num(a.X) / b, num(a.Y) / b, num(a.Z) / b)
            end
            return T.Vector3(num(a.X) / num(b.X), num(a.Y) / num(b.Y),
                             num(a.Z) / num(b.Z))
        end,
        __unm = function(a) return T.Vector3(-num(a.X), -num(a.Y), -num(a.Z)) end,
    })
    return self
end

T.Color3 = function(r, g, b)
    r, g, b = num(r), num(g), num(b)
    return make("Color3", { R = r, G = g, B = b,
                            __order = { "R", "G", "B" } }, {
        Lerp = function(_, o, t)
            t = num(t)
            return T.Color3(r + (num(o.R) - r) * t,
                            g + (num(o.G) - g) * t,
                            b + (num(o.B) - b) * t)
        end,
        ToHex = function()
            return string.format("%02X%02X%02X", floor(r * 255 + 0.5),
                                 floor(g * 255 + 0.5), floor(b * 255 + 0.5))
        end,
    })
end

T.CFrame = function(a, b, c)
    local pos
    if rawtype(a) == "table" and VMSMART_TAGGED[a] == "Vector3" then
        pos = a
    else
        pos = T.Vector3(a, b, c)
    end
    return make("CFrame", { Position = pos, X = pos.X, Y = pos.Y, Z = pos.Z,
                            p = pos, __order = { "X", "Y", "Z" } })
end

T.NumberRange = function(a, b)
    a = num(a)
    if b == nil then b = a else b = num(b) end
    return make("NumberRange", { Min = a, Max = b, __order = { "Min", "Max" } })
end

T.NumberSequenceKeypoint = function(t, v, e)
    return make("NumberSequenceKeypoint",
                { Time = num(t), Value = num(v), Envelope = num(e),
                  __order = { "Time", "Value", "Envelope" } })
end

T.ColorSequenceKeypoint = function(t, c)
    return make("ColorSequenceKeypoint", { Time = num(t), Value = c,
                                           __order = { "Time", "Value" } })
end

T.ColorSequence = function(a, b)
    local keys
    if isArray(a) then
        keys = a
    elseif b ~= nil then
        keys = { T.ColorSequenceKeypoint(0, a), T.ColorSequenceKeypoint(1, b) }
    else
        keys = { T.ColorSequenceKeypoint(0, a), T.ColorSequenceKeypoint(1, a) }
    end
    return make("ColorSequence", { Keypoints = keys })
end

T.NumberSequence = function(a, b)
    local keys
    if isArray(a) then
        keys = a
    elseif b ~= nil then
        keys = { T.NumberSequenceKeypoint(0, a, 0),
                 T.NumberSequenceKeypoint(1, b, 0) }
    else
        keys = { T.NumberSequenceKeypoint(0, a, 0),
                 T.NumberSequenceKeypoint(1, a, 0) }
    end
    return make("NumberSequence", { Keypoints = keys })
end

T.Rect = function(a, b, c, d)
    local min, max
    if rawtype(a) == "table" then min, max = a, b
    else min, max = T.Vector2(a, b), T.Vector2(c, d) end  -- Rect.new takes either
    return make("Rect", { Min = min, Max = max,
                          Width = num(max.X) - num(min.X),
                          Height = num(max.Y) - num(min.Y) })
end

T.Ray = function(origin, direction)
    origin = origin or T.Vector3(0, 0, 0)
    direction = direction or T.Vector3(0, 0, 0)
    return make("Ray", { Origin = origin, Direction = direction }, nil, {
        Unit = function() return T.Ray(origin, direction.Unit) end,
    })
end

T.Region3 = function(min, max)
    return make("Region3", { CFrame = T.CFrame(0, 0, 0),
                             Size = T.Vector3(0, 0, 0), Min = min, Max = max })
end

local FACE_NAMES = { "Top", "Bottom", "Left", "Right", "Front", "Back" }
T.Faces = function(...)
    local set, fields = {}, {}
    for i = 1, select("#", ...) do
        local v = select(i, ...)
        local name = rawtype(v) == "table" and tostring(v.Name) or tostring(v)
        set[name] = true
    end
    for _, name in ipairs(FACE_NAMES) do fields[name] = set[name] or false end
    return make("Faces", fields)
end

T.Axes = function(...)
    local set, fields = {}, {}
    for i = 1, select("#", ...) do
        local v = select(i, ...)
        local name = rawtype(v) == "table" and tostring(v.Name) or tostring(v)
        set[name] = true
    end
    for _, name in ipairs({ "X", "Y", "Z" }) do fields[name] = set[name] or false end
    return make("Axes", fields)
end

T.TweenInfo = function(time, style, direction, reps, reverses, delay)
    return make("TweenInfo", { Time = num(time ~= nil and time or 1),
                               EasingStyle = style, EasingDirection = direction,
                               RepeatCount = num(reps),
                               Reverses = reverses and true or false,
                               DelayTime = num(delay) })
end

T.PhysicalProperties = function(d, f, e, fw, ew)
    return make("PhysicalProperties",
                { Density = num(d), Friction = num(f), Elasticity = num(e),
                  FrictionWeight = num(fw ~= nil and fw or 1),
                  ElasticityWeight = num(ew ~= nil and ew or 1) })
end

T.Vector3int16 = function(x, y, z)
    return make("Vector3int16", { X = floor(num(x)), Y = floor(num(y)),
                                  Z = floor(num(z)),
                                  __order = { "X", "Y", "Z" } })
end

T.Vector2int16 = function(x, y)
    return make("Vector2int16", { X = floor(num(x)), Y = floor(num(y)),
                                  __order = { "X", "Y" } })
end

-- RaycastParams is a settable record: whatever is written to it reads back, with
-- the host's documented defaults. No algebra to get wrong.
T.RaycastParams = function()
    local v = make("RaycastParams",
                   { FilterType = nil, FilterDescendantsInstances = {},
                     IgnoreWater = false, CollisionGroup = "Default",
                     RespectCanCollide = false, BruteForceAllSlow = false })
    return setmetatable(v, {
        __index = getmetatable(v).__index,
        __newindex = function(t, k, x) rawset(t, k, x) end,
        __tostring = function() return "RaycastParams" end,
    })
end

T.OverlapParams = T.RaycastParams

-- BrickColor: the NAME is what was asked for, and the number is not.
--
-- A name-to-number table is the host's data. This file carries algebra, not data,
-- so the name reads back faithfully, the number and the colour are derived, and
-- both are recorded as derived. A build that checks a BrickColor number against a
-- real one will not match here.
T.BrickColor = function(a, b, c)
    local name
    if rawtype(a) == "string" then name = a
    elseif b ~= nil then name = "Color3"
    else name = "BrickColor " .. tostring(a) end
    VMSMART_TYPES_STUBBED["BrickColor.Number"] = true
    VMSMART_TYPES_STUBBED["BrickColor.Color"] = true
    local derived = VMSMART_DERIVE("BrickColor|" .. name) % 1032 + 1
    return make("BrickColor", { Name = name, Number = derived,
                                Color = T.Color3(0, 0, 0),
                                r = 0, g = 0, b = 0 })
end

-- Random: deterministic here, and not the host's sequence.
--
-- Roblox's generator is not a documented algorithm, so no implementation can
-- reproduce its numbers. This one is a plain xorshift seeded the same way, so a
-- run is repeatable and a comparison against the host's sequence fails - which is
-- recorded rather than hidden.
T.Random = function(seed)
    VMSMART_TYPES_STUBBED["Random.sequence"] = true
    local state = (num(seed) ~= 0 and num(seed) or 88172645463325252) % 2147483647
    if state <= 0 then state = 1 end
    local function nextBits()
        state = (state * 48271) % 2147483647
        return state
    end
    return make("Random", {}, {
        NextNumber = function(_, lo, hi)
            local r = nextBits() / 2147483647
            if lo == nil then return r end
            if hi == nil then return r * num(lo) end
            return num(lo) + r * (num(hi) - num(lo))
        end,
        NextInteger = function(_, lo, hi)
            lo, hi = num(lo), num(hi)
            if hi < lo then hi = lo end
            return lo + (nextBits() % (hi - lo + 1))
        end,
        NextUnitVector = function()
            return T.Vector3(0, 1, 0)
        end,
        Clone = function() return T.Random(state) end,
    })
end

-- The constructor names each type documents, beyond `new`.
local EXTRA = {
    UDim2 = {
        fromScale = function(x, y) return T.UDim2(x, 0, y, 0) end,
        fromOffset = function(x, y) return T.UDim2(0, x, 0, y) end,
    },
    Color3 = {
        fromRGB = function(r, g, b)
            return T.Color3(num(r) / 255, num(g) / 255, num(b) / 255)
        end,
        fromHex = function(hex)
            hex = tostring(hex):gsub("#", "")
            local function part(i)
                return (tonumber(hex:sub(i, i + 1), 16) or 0) / 255
            end
            return T.Color3(part(1), part(3), part(5))
        end,
    },
    Vector3 = {
        FromNormalId = function() return T.Vector3(0, 1, 0) end,
        FromAxis = function() return T.Vector3(1, 0, 0) end,
    },
    CFrame = {
        Angles = function() return T.CFrame(0, 0, 0) end,
        fromEulerAnglesXYZ = function() return T.CFrame(0, 0, 0) end,
        lookAt = function(at) return T.CFrame(at) end,
    },
    Rect = {},
    UDim = {},
}

-- Constants the types document.
local CONSTANTS = {
    Vector3 = { zero = function() return T.Vector3(0, 0, 0) end,
                one = function() return T.Vector3(1, 1, 1) end,
                xAxis = function() return T.Vector3(1, 0, 0) end,
                yAxis = function() return T.Vector3(0, 1, 0) end,
                zAxis = function() return T.Vector3(0, 0, 1) end },
    Vector2 = { zero = function() return T.Vector2(0, 0) end,
                one = function() return T.Vector2(1, 1) end },
    CFrame = { identity = function() return T.CFrame(0, 0, 0) end },
}

-- The root a program sees for a modelled type. `new` and the documented
-- constructors answer with real values; anything else is recorded and stubbed.
function VMSMART_TYPE_ROOT(name)
    local ctor = T[name]
    if ctor == nil then return nil end
    VMSMART_TYPES_MODELLED[name] = true
    return setmetatable({}, {
        __index = function(_, k)
            k = tostring(k)
            if k == "new" then return function(...) return ctor(...) end end
            local extra = EXTRA[name] and EXTRA[name][k]
            if extra then return extra end
            local const = CONSTANTS[name] and CONSTANTS[name][k]
            if const then return const() end
            VMSMART_TYPES_STUBBED[name .. "." .. k] = true
            return VMSMART_STUB(VMSMART_HOST_FIELDS_ASKED, name .. ":" .. k)
        end,
        __tostring = function() return name end,
    })
end

return "robloxtypes"
