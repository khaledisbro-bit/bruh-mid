--!nocheck
-- sample2_source.luau
-- Rebuilt from the run of 06f51c74-25ms_obf_2.lua, slice 3.
-- Every line below comes from what the program did under the offline host:
-- the values it built (MADE) and the calls it made (HOSTCALLS).
-- Slice 3 is the guard layer. It measures the host and builds the key.
-- The real script is slice 4. It stays locked until the key is right.

local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")

-- step 1: a run of UDim2 values, read back and folded into the key
local layout = {
    UDim2.new(0, 187, 0.5625, 199),
    UDim2.new(0, 301, 0.71875, 67),
    UDim2.new(0, 880, 0.625, 146),
    UDim2.new(0, 272, 0.53125, 107),
    UDim2.new(0, 764, 0.125, 111),
    UDim2.new(0, 736, 0.5, 103),
    UDim2.new(0, 394, 0.15625, 129),
}
-- It reads X.Offset, Y.Scale and Y.Offset of each one. The exact fold math
-- is not lifted yet, so the reads are listed and not combined here.
local reads = {}
for _, u in ipairs(layout) do
    table.insert(reads, { u.X.Offset, u.Y.Scale, u.Y.Offset })
end

-- step 2: a hidden test part, measured
local holder = Instance.new("Folder")
local part = Instance.new("Part")
part.Parent = holder
part.CanCollide = false
part.CanTouch = false
part.CanQuery = false
part.Transparency = 1
part.Size = Vector3.new(1.25, 3.5, 6.25)
-- the arguments of this call were not captured
part.CustomPhysicalProperties = PhysicalProperties.new(Enum.Material.Plastic)
part.CFrame = CFrame.new(41, 2330, 37)
holder.Parent = ReplicatedStorage

local accel = Vector3.new(0.75, -1, 1)
local pivot = Vector3.new(1.25, -0.25, 1.125)
local okTorque, torque = pcall(function()
    return part:AngularAccelerationToTorque(accel, pivot)
end)
local okBack = okTorque and pcall(function()
    return part:TorqueToAngularAcceleration(torque, pivot)
end)
local mass = part:GetMass()
local massCheck = part.AssemblyMass - 13.671875
local centreCheck = part.AssemblyCenterOfMass - part.Position

-- the same call, anchored and unanchored
part.Anchored = true
pcall(function() return part:AngularAccelerationToTorque(accel, pivot) end)
holder.Parent = nil
part.Anchored = false
pcall(function() return part:AngularAccelerationToTorque(accel, pivot) end)

-- the part's own axes, both directions
local cf = part.CFrame
local toObject = cf:VectorToObjectSpace(accel)
local toWorld = cf:VectorToWorldSpace(toObject)

holder:Destroy()
part:Destroy()

-- step 3: instance lookups on a scratch model
local model = Instance.new("Model")
local inner = Instance.new("Folder")
inner.Name = "Inner"
inner.Parent = model
local children = model:GetChildren()
local a = model:FindFirstChild("Folder")
local b = model:FindFirstChildOfClass("Folder")
local c = model:FindFirstChildWhichIsA("Instance")
local same = rawequal(b, c)
model:Destroy()
inner:Destroy()

-- step 4: enum and datatype checks
local plastic = Enum.Material:FromName("Plastic")
local ball = Enum.PartType:FromValue(0)
local faces = Faces.new(Enum.NormalId.Top, Enum.NormalId.Bottom)
local axes = Axes.new(Enum.Axis.X, Enum.Axis.Y)
local ray = Ray.new(Vector3.new(0, 0, 0), Vector3.new(0, 1, 0))

-- step 5: where it runs
local studio = RunService:IsStudio()
local client = RunService:IsClient()
local server = RunService:IsServer()

-- step 6: the key. Five folded numbers plus 1729227716 from the file.
-- The interpreter turns them into three numbers and opens slice 4 with them.
-- Slice 4's tag (1ffe7907...) says yes or no.
return {
    reads = reads,
    mass = mass,
    massCheck = massCheck,
    centreCheck = centreCheck,
    okTorque = okTorque,
    okBack = okBack,
    toWorld = toWorld,
    children = #children,
    same = same,
    plastic = plastic.Value,
    ball = ball.Name,
    faces = faces.Top and faces.Bottom,
    axes = axes.X and axes.Y,
    ray = ray.Direction,
    studio = studio, client = client, server = server,
}
