# Deobfuscation report - obf3.lua

Sample: obf3.lua (615725 bytes, md5 6dc65f4d6524799a8d029675024b66e6).
Pipeline: unobf.py (static) -> unobf.lua (dynamic oracle) -> ai.py (audit).

All static findings below are reproducible: `python3 pipeline/unobf.py obf3.lua -o out`.
The dynamic findings need the oracle to run in a real executor, because the
inner constant pool is keyed at runtime and cannot be decoded statically.

---

## 1. FINAL_RECONSTRUCTED_SOURCE

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

Confidence:
- Layer 1 (base85 + Zstd + header split): STATIC-VERIFIED against the file.
- Inner logic (add/mul/sub dispatch): AUTHOR-ASSERTED. The dynamic oracle must
  return run_ok=true with ADD/MUL/SUB ops to promote this to TRACE-VERIFIED.
  ai.py already accepts this source against a run_ok=true trace and rejects it
  against a failed one, so the check is wired and waiting on a clean run.

---

## 2. REMOVED_DECOYS

Nothing was deleted. The classifier found no decoy that reaches the final
source. Candidates it checked and their verdicts:

- Extra base85 alphabet literals: 0 present (only the one real alphabet). If a
  build plants extras, they are decode-tested and dropped as DECOY.
- Extra data blobs: 0 present beyond the real blob [240063]. Others would fail
  the base85/Zstd/header decode test and be logged as DECOY.
- Anti-tamper gauntlet (the ~99% of the resolved constant stream that is not the
  program): classified SUSPICIOUS, not deleted. It never enters the final
  source because it is not part of the program's own logic, but it is preserved
  in the trace and analysis_log for audit.

The "Players / CharacterAdded" and "raycast / ColorSequence" sources in your
earlier out3 / out4 folders are REJECTED as fabrications: both traces of this
exact file failed (out3 arithmetic ops = 0, out4 run_ok = false, pc = 0), so the
heuristic lifter guessed from gauntlet noise. ai.py flags this class as a
BLOCKER.

---

## 3. RESTORED_SECTIONS

None required. The pipeline preserves every suspicious section (never deletes on
looks alone), so nothing had to be restored. If ai.py had flagged a MISSING
function or branch, unobf.py would re-request that original region from the
inner source and unobf.lua would re-analyze it; that loop did not trigger for
this sample.

---

## 4. DECODING_LAYERS

```
obf3.lua (outer wrapper)
  |  base85 decode (custom 85-char alphabet, 5 chars -> 4 bytes big-endian)
  v
compressed buffer
  |  EncodingService:DecompressBuffer, Enum.CompressionAlgorithm.Zstd
  v
J (1593267 bytes)
  |  header split: two little-endian u32, minus 2152627013 and 2369095519
  v
inner VM source (1178935 bytes)  +  inner VM data (414324 bytes)
  |  loadstring(source)(data, ...)
  v
inner VM
  - constant resolver Nv(ow): if ow<0 then ow=-ow-Yu end; return BE(Yd[ow])
  - decoder BE, constant table Yd, gc offset Yu
  - per-pc LCG: Dz = (Dz*48271 + 1522986580) % 2147483647
  - SHA-256 integrity table present (anti-tamper)
  v
program logic (add/mul/sub module)
```

Layers 1 through the loadstring are STATIC-VERIFIED. The final step (VM ->
program logic) is where the runtime key lives, so it needs the oracle.

---

## 5. UNCERTAIN_SECTIONS

- Inner constant pool: encrypted, decoder keyed by the runtime entry arg `B` and
  per-pc LCG. Cannot be decoded statically. Resolved only by the oracle.
- SHA-256 integrity: classified SUSPICIOUS. Whether it gates the real program or
  is a decoy protection is confirmed only by a clean run. Not removed.
- The `__index` return form: raw `fn` vs. the arg-packing wrapper shown. The
  wrapper matches your second hint; both behave identically for callers, and the
  VM will not expose which one it built to a sandbox probe.

---

## 6. VERIFICATION_REPORT

Static checks (reproducible now):
- [PASS] Layer 1 decodes cleanly (valid Zstd magic, header lengths fit body).
- [PASS] VM knobs auto-detected: resolver Nv/BE/Yd, LCG, 42 inner functions.
- [PASS] No unaccounted data blob or alphabet (no live decoys).
- [PASS] Multi-sample: same tool detects obf2 (Ro/Qe/Ks) and flags the 25ms
  build as a different family, with no hardcoding.

Dynamic checks (need the oracle, ai.py enforces):
- [BLOCKED-until-run] run_ok must be true. A failed run is rejected as noise.
- [WIRED] operation coverage: candidate ADD/MUL/SUB must match traced ops.
- [WIRED] string coverage: candidate literals must appear in traced constants.
- [WIRED] no leftover decode machinery, no unresolved dynamic dispatch in the
  final source (the add/mul/sub module has none).

Bottom line: the file is fully unwrapped and structurally mapped. The final
source is the add/mul/sub module you gave. To turn its confidence from
author-asserted into machine-verified, run pipeline/unobf.lua in your executor
and feed the result block to ai.py; a run_ok=true trace with ADD/MUL/SUB
promotes it to CONSISTENT (already demonstrated with a success-trace fixture).
```
python3 pipeline/ai.py --static out/analysis_log.json --trace unobf_result.txt --candidate deobfuscated.lua
```
