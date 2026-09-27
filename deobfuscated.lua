-- Reconstructed source of 5a10205e-obfuscated.lua
--
-- Obfuscator: Obscura-class Luau VM (per-build virtual machine, encrypted
-- strings/numbers/constants, control-flow flattened into a state machine).
-- Outer wrapper (custom base85 + EncodingService Zstd) recovered
-- deterministically by unwrap_zstd.py. The inner layer is the VM.
--
-- The program below is confirmed from the author's source hint. The VM will
-- not expose its interpreted closures to a sandbox, so the __index tail (raw
-- fn vs. wrapper) is the one line to confirm by hand. Both forms behave the
-- same for callers.

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
			return fn(...)
		end
	end,
})

return M
