# Final semantic verification - obf3.lua

Sample: obf3.lua (615725 bytes, md5 6dc65f4d6524799a8d029675024b66e6).
Verdict: INCOMPLETE. Layer 1 is proven. The inner program logic is UNKNOWN,
because no clean execution of the payload exists yet. Per the rule, no confident
final reconstruction is declared.

---

## FINAL_SOURCE

Not certified. The candidate below is author-asserted and structurally
plausible, but the VM never ran its payload in any available trace, so machine
verification cannot confirm it.

```lua
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
```

This becomes FINAL only after a run_ok=true trace shows ADD, MUL, SUB from the
module probe. ai.py already accepts it against such a trace and rejects it
against a failed one.

---

## DECODING_LAYERS

1. encoded constants: inner pool, decoder BE over table Yd. NOT decoded (runtime key).
2. string decoding: same pool. NOT decoded statically.
3. numeric transformations: per-pc LCG Dz = (Dz*48271 + 1522986580) % 2147483647. Identified, not unrolled statically.
4. aliases: outer locals map string.byte/char/floor/sub and buffer. Resolved.
5. nested functions: 42 inner local functions inventoried.
6. closures: the module wrapper closure over fn. Present in candidate, not trace-confirmed.
7. tables: outer BM (base85 map), inner Yd (constants), DP (protos). Resolved by role.
8. metatables: the module __index dispatcher. Present in candidate, not trace-confirmed.
9. proxy tables: none found in the outer wrapper.
10. dynamic dispatch: loadstring(inner_source)(inner_data). Resolved.
11. runtime reconstruction: the VM builds the program from inner_data. Needs the oracle.
12. control-flow indirection: state-machine flattening in the interpreter. Identified.
13. dead-code separation: see REAL/DECOY below.
14. decoy separation: see DECOY_CODE.
15. semantic reconstruction: BLOCKED on a clean run.

Layers 4, 5, 7, 10 are STATIC-VERIFIED. Layers 1-3, 6, 8, 11, 15 need the oracle.

---

## REAL_CODE

Evidence-backed as on the decode or execute path.

- outer.base85 decoder K: consumes the blob [240063], feeds DecompressBuffer. Data flow proven.
- outer.EncodingService:DecompressBuffer (Zstd): consumes base85 output, produces J. Proven.
- outer.header split: two u32le minus 2152627013 and 2369095519, slices J into source and data. Proven.
- outer.loadstring(source)(data): entry into the inner VM. Proven.
- inner.resolver Nv(ow): returns BE(Yd[ow]); every constant flows through it. Proven by reference.
- inner.LCG Dz: per-pc decryption. Changing it yields garbage, so it is load-bearing.

---

## DECOY_CODE

No live decoy reaches the final source. Checked with evidence, not by looks.

- extra base85 alphabets: 0 present.
- extra data blobs: 0 present beyond [240063].
- The Players/CharacterAdded source (your out3) and the raycast/ColorSequence
  source (your out4) are REJECTED. Both traces of this exact file failed to run
  the payload (out3 arithmetic ops = 0; out4 run_ok = false, pc = 0). They are
  heuristic guesses from the anti-tamper gauntlet, not the program. Evidence:
  identical md5 across obf3.lua, out3/whole.lua, out4/whole.lua, plus the
  zero-execution counters.

---

## RESTORED_CODE

None. Nothing was deleted, so nothing needed restoring. All SUSPICIOUS sections
are preserved in analysis_log.json and the trace, not removed.

---

## UNKNOWN_CODE

- The inner program logic itself. No clean run exists, so the actual opcodes and
  their operands are not recovered. The add/mul/sub module is asserted, not proven.
- The inner constant pool contents (strings and numbers). Encrypted under the
  runtime key. Unresolved.
- The __index return form (raw fn vs. wrapper). Not observable from a sandbox.

---

## MISSING_CODE

What a clean oracle run must supply before FINAL_SOURCE is certified:
- the module table build and its setmetatable call, captured live.
- ADD, MUL, SUB operations from the probe, with tracked operands.
- the decoded constant set, to confirm no extra logic exists beyond the three actions.
Until then, treat any claim about branches, extra functions, or side effects as
unverified.

---

## VERIFICATION_REPORT

- [PASS] Layer 1 decodes cleanly (Zstd magic, header lengths fit body).
- [PASS] VM knobs auto-detected: Nv / BE / Yd, LCG, 42 inner functions.
- [PASS] No live decoy (no unaccounted alphabet or blob).
- [PASS] Multi-sample with no hardcoding: obf2 detects Ro / Qe / Ks; 25ms flagged as a different family.
- [FAIL] run_ok: no available trace executed the payload. Both prior traces failed.
- [BLOCKED] operation coverage, string coverage, closure and metatable confirmation: all wait on a clean run.
- [PASS] candidate Lua is syntactically valid and contains no leftover decode machinery or unresolved dynamic dispatch.

---

## CONFIDENCE

- Layer 1 unwrap and VM structure: HIGH (static, reproducible).
- Decoy rejection of the prior guesses: HIGH (zero-execution evidence).
- Inner program logic (add/mul/sub): LOW / UNVERIFIED. Author-asserted, awaiting
  a run_ok=true trace. Do not ship as final until that trace exists.
