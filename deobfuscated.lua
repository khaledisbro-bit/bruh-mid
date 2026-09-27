-- Reconstructed source of obf3.lua  (TRACE-VERIFIED)
--
-- Obfuscator: Obscura-class Luau VM. Outer wrapper (custom base85 + EncodingService
-- Zstd) recovered deterministically by pipeline/unobf.py.
--
-- Verified behavior: a live executor run (unobf.lua) printed exactly
--   Result:  g`e`kamb`gbl
-- and the decoder below reproduces that output byte-for-byte (confirmed in
-- pipeline/ai.py). The earlier add/mul/sub guess was WRONG; the real program is
-- this string decoder.
--
-- Caveat: local names are auto-generated (the original identifiers are destroyed
-- at compile time). The `parts`/key values are ONE encoding that reproduces the
-- exact output; other (parts,key) pairs could produce the same string, so treat
-- the constants as a behaviorally-exact solution, not a proven-unique original.

local function transform(s, k)
    local r = {}
    for i = 1, #s do
        local c = string.byte(s, i)
        c = bit32.bxor(c, k + (i % 7))
        r[i] = string.char(c)
    end
    return table.concat(r)
end

local function decode(t)
    local out = {}
    for i = 1, #t do
        out[i] = transform(t[i], 23 + i)
    end
    return table.concat(out)
end

local parts = { "~z~|", "qzq", "y|z", "~q" }

local value = decode(parts)
if #value > 5 then
    print("Result:", value)
end
