-- Reconstructed source of 5a10205e-obfuscated.lua
-- Outer layer (base85 + Zstd) recovered deterministically by unwrap_zstd.py.
-- Inner layer is a bytecode VM; this module is its actual program.
-- Structure confirmed from the provided source hint. The __index tail (raw fn
-- vs. wrapper) is pending studio_probe.lua output; the wrapper form is shown.

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
