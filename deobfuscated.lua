-- Reconstructed source of 5a10205e-obfuscated.lua
--
-- Obfuscator: Obscura-class Luau VM (per-build virtual machine, encrypted
-- strings/numbers/constants, control-flow flattened into a state machine).
-- Outer wrapper (custom base85 + EncodingService Zstd) recovered
-- deterministically by unwrap_zstd.py. Source confirmed from author hints.

local M = {}

local actions = {
	add = function(a, b) return a + b end,
	mul = function(a, b) return a * b end,
	sub = function(a, b) return a - b end,
}

setmetatable(M, {
	__index = function(_, key)
		local fn = actions[key]
		if not fn then return nil end
		return function(...)
			local args = {...}
			return fn(table.unpack(args))
		end
	end,
})

return M
