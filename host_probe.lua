-- host_probe.lua
--
-- The thirty-eight questions this build puts to the host, asked again on their
-- own, with the answers printed one per line.
--
-- Why it exists. The build's key is a hash over the host's answers, so it is
-- right only when every answer is right. The analysis knows WHICH answers are
-- folded - each was found by running the build twice and watching where the chain
-- parted - and it can see what its own stand-in answers. What it cannot see is
-- what a real client answers. This file asks the same questions in the same
-- order, so the two lists can be put side by side and the first line that
-- differs is the answer that was wrong.
--
-- It reads only. It builds a few values, reads them back, makes one folder and
-- one part under itself, and destroys them. Nothing is kept.
--
-- Run it anywhere Luau runs. On a real client it prints the client's answers; on
-- the stand-in it prints the stand-in's. Diff the two.

-- `type` AS THE PAYLOAD SEES IT. The stand-in publishes a host-faithful answer
-- under its own name rather than replacing the global, so a probe that used the
-- plain global would compare the stand-in's Lua against a client's Roblox and
-- call every datatype a table.
local type = (VMSMART_HOST_TYPE or type)

local OUT = {}

local function say(label, value)
    local t = typeof and typeof(value) or type(value)
    local shown
    if t == "string" then shown = string.format("%q", value)
    elseif t == "number" then shown = string.format("%.17g", value)
    elseif t == "boolean" or t == "nil" then shown = tostring(value)
    else shown = t .. ":" .. tostring(value) end
    OUT[#OUT + 1] = label .. " = " .. shown
end

local function try(label, fn)
    local ok, a = pcall(fn)
    if ok then say(label, a) else say(label .. " RAISED", tostring(a)) end
end

----------------------------------------------------------------------------
-- the type system: the words the host uses
----------------------------------------------------------------------------

try("type(Vector3)", function() return type(Vector3.new(1, 2, 3)) end)
try("typeof(Vector3)", function() return typeof(Vector3.new(1, 2, 3)) end)
try("type(Vector2)", function() return type(Vector2.new(1, 2)) end)
try("type(UDim)", function() return type(UDim.new(0, 1)) end)
try("type(Color3)", function() return type(Color3.new(0, 0, 0)) end)
try("type(Enum)", function() return type(Enum) end)
try("typeof(Enum)", function() return typeof(Enum) end)
try("typeof(Enum.PartType)", function() return typeof(Enum.PartType) end)
try("typeof(Enum.PartType.Ball)", function() return typeof(Enum.PartType.Ball) end)
try("type(Enum.PartType.Ball)", function() return type(Enum.PartType.Ball) end)
try("typeof(game)", function() return typeof(game) end)
try("type(game)", function() return type(game) end)
try("typeof(Instance.new('Folder'))", function() return typeof(Instance.new("Folder")) end)
try("typeof(newproxy())", function() return typeof(newproxy()) end)
try("typeof(coroutine.running())", function() return typeof((coroutine.running())) end)

----------------------------------------------------------------------------
-- the enums the build reads
----------------------------------------------------------------------------

try("Enum.PartType.Ball.Name", function() return Enum.PartType.Ball.Name end)
try("Enum.PartType.Ball.Value", function() return Enum.PartType.Ball.Value end)
try("#Enum.PartType:GetEnumItems()", function() return #Enum.PartType:GetEnumItems() end)
try("Enum.EasingStyle.Back.Value", function() return Enum.EasingStyle.Back.Value end)
try("Enum.EasingDirection.Out.Value", function() return Enum.EasingDirection.Out.Value end)

----------------------------------------------------------------------------
-- the components, read back after being written
----------------------------------------------------------------------------

try("UDim.new(0.03125,155).Scale", function() return UDim.new(0.03125, 155).Scale end)
try("UDim.new(0.03125,155).Offset", function() return UDim.new(0.03125, 155).Offset end)
try("UDim.new(0.5,1.7).Offset", function() return UDim.new(0.5, 1.7).Offset end)
try("Vector3.new(434,452,128).X", function() return Vector3.new(434, 452, 128).X end)
try("Vector3.new(19,10,20):Dot(Vector3.new(0,20,0))", function()
    return Vector3.new(19, 10, 20):Dot(Vector3.new(0, 20, 0))
end)
try("Color3.new(17/255,17/255,17/255).R", function()
    return Color3.new(17 / 255, 17 / 255, 17 / 255).R
end)
try("Vector2.new(89,154).X", function() return Vector2.new(89, 154).X end)
try("NumberRange.new(51,93).Min", function() return NumberRange.new(51, 93).Min end)
try("NumberRange.new(51,93).Max", function() return NumberRange.new(51, 93).Max end)
try("NumberSequenceKeypoint.new(0,0.65625,0.8125).Envelope", function()
    return NumberSequenceKeypoint.new(0, 0.65625, 0.8125).Envelope
end)
try("#NumberSequence.new(0.65625,0.5).Keypoints", function()
    return #NumberSequence.new(0.65625, 0.5).Keypoints
end)
try("TweenInfo RepeatCount", function()
    return TweenInfo.new(0.3125, Enum.EasingStyle.Back, Enum.EasingDirection.Out,
                         1, true, 0.5).RepeatCount
end)
try("TweenInfo Reverses", function()
    return TweenInfo.new(0.3125, Enum.EasingStyle.Back, Enum.EasingDirection.Out,
                         1, true, 0.5).Reverses
end)
try("TweenInfo Time", function()
    return TweenInfo.new(0.3125, Enum.EasingStyle.Back, Enum.EasingDirection.Out,
                         1, true, 0.5).Time
end)
try("Rect.new(V2(21,70),V2(89,154)).Max.X", function()
    return Rect.new(Vector2.new(21, 70), Vector2.new(89, 154)).Max.X
end)
try("Rect.new(V2(89,154),V2(21,70)).Max.X  (inside out)", function()
    return Rect.new(Vector2.new(89, 154), Vector2.new(21, 70)).Max.X
end)
try("Color3.new(0,0,0):Lerp(Color3.new(1,1,1),0.25).R", function()
    return Color3.new(0, 0, 0):Lerp(Color3.new(1, 1, 1), 0.25).R
end)
try("BrickColor.new('Really black').Number", function()
    return BrickColor.new("Really black").Number
end)
try("BrickColor.new('Really black').Color.R", function()
    return BrickColor.new("Really black").Color.R
end)

----------------------------------------------------------------------------
-- the instance tree: names, classes, attributes, lookup, destroy
----------------------------------------------------------------------------

local holder, part
try("Instance.new('Folder').Name", function()
    holder = Instance.new("Folder")
    return holder.Name
end)
try("Instance.new('Folder').ClassName", function() return holder.ClassName end)
try("Instance.new('Folder').Parent", function() return holder.Parent end)
try("Instance.new('Part').Name", function()
    part = Instance.new("Part")
    part.Parent = holder
    return part.Name
end)
try("Instance.new('Part').ClassName", function() return part.ClassName end)
try("Part.Size default X", function() return part.Size.X end)
try("Part.Size set to 19,10,20 reads back X", function()
    part.Size = Vector3.new(19, 10, 20)
    return part.Size.X
end)
try("SetAttribute then GetAttribute", function()
    holder:SetAttribute("4rI3AaoQ85", 579)
    return holder:GetAttribute("4rI3AaoQ85")
end)
try("GetAttributes count", function()
    local n = 0
    for _ in pairs(holder:GetAttributes()) do n = n + 1 end
    return n
end)
try("FindFirstChild('Part') is the part", function()
    return holder:FindFirstChild("Part") == part
end)
try("FindFirstChildOfClass('Part') is the part", function()
    return holder:FindFirstChildOfClass("Part") == part
end)
try("FindFirstChildWhichIsA('Instance') is the part", function()
    return holder:FindFirstChildWhichIsA("Instance") == part
end)
try("#GetChildren()", function() return #holder:GetChildren() end)
try("GetFullName of a loose folder", function() return holder:GetFullName() end)
try("ReplicatedStorage:IsA('Players')", function()
    return game:GetService("ReplicatedStorage"):IsA("Players")
end)
try("ReplicatedStorage:IsA('ServiceProvider')", function()
    return game:GetService("ReplicatedStorage"):IsA("ServiceProvider")
end)
try("ReplicatedStorage:IsA('Instance')", function()
    return game:GetService("ReplicatedStorage"):IsA("Instance")
end)
try("game.ClassName", function() return game.ClassName end)
try("game:IsA('ServiceProvider')", function() return game:IsA("ServiceProvider") end)
try("ReplicatedStorage:GetFullName()", function()
    return game:GetService("ReplicatedStorage"):GetFullName()
end)
try("Instance.new('part') refused", function() return Instance.new("part") end)
try("Destroy then Parent", function()
    part:Destroy()
    return part.Parent
end)
try("Destroy then set Parent", function()
    part.Parent = holder
    return "accepted"
end)

----------------------------------------------------------------------------
-- the guid's shape, which is all that can be folded about it
----------------------------------------------------------------------------

try("GenerateGUID(false) length", function()
    return #game:GetService("HttpService"):GenerateGUID(false)
end)
try("GenerateGUID(false) dashes at 9,14,19,24", function()
    local g = game:GetService("HttpService"):GenerateGUID(false)
    return string.sub(g, 9, 9) .. string.sub(g, 14, 14)
        .. string.sub(g, 19, 19) .. string.sub(g, 24, 24)
end)
try("GenerateGUID() first character", function()
    return string.sub(game:GetService("HttpService"):GenerateGUID(), 1, 1)
end)
try("GenerateGUID(false) is upper case hex", function()
    local g = game:GetService("HttpService"):GenerateGUID(false)
    return string.match(g, "^[0-9A-F%-]+$") ~= nil
end)

----------------------------------------------------------------------------
-- how a number comes out as text, which the build compares
----------------------------------------------------------------------------

try("format %.17g of 1/3", function() return string.format("%.17g", 1 / 3) end)
try("format %.17g of 17/255", function() return string.format("%.17g", 17 / 255) end)
try("the exponent gsub", function()
    local s = string.format("%.17g", 1e-20)
    return (string.gsub(s, "e([+-])0+(%d+)", "e%1%2"))
end)

if holder then pcall(function() holder:Destroy() end) end

print("---HOST ANSWERS---")
print("lines: " .. tostring(#OUT))
for i = 1, #OUT do print(OUT[i]) end
print("---END---")

return OUT
