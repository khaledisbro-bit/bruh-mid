# VmSmart deobfuscation pipeline

One program does every stage. It reads the **whole** obfuscated file (nothing is
truncated) and never fabricates: everything in the reports is derived from the
bytes or observed at runtime.

## One command

```
python3 deob.py <obf.lua>
```

This runs:
1. DETECT  - identify the obfuscator family and per-build knobs.
2. STATIC  - unwrap layer 1, dump inner VM source/data, lift the import table.
3. HARNESS - write `out/harness.lua` with the full obfuscated script embedded.

Then run `out/harness.lua` in your executor and save everything it prints (or the
`opcode_trace.txt` / `resolved_constants.txt` files it writes) and feed them back:

```
python3 deob.py <obf.lua> --trace result.txt
```

You can pass **several** traces from different runs; the obfuscator takes a
different path each run, so more runs reveal more of the program and they are
merged into one report:

```
python3 deob.py <obf.lua> --trace run1.txt run2.txt opcode_trace.txt resolved_constants.txt
```

## What you get in `out/`

- `FINAL_RECONSTRUCTION.txt` - the combined picture: what the script is, the API
  surface grouped by area, a reconstructed Lua skeleton, merged across all runs.
- `FLOW.txt`         - real program operations with the actual values that flowed.
- `DISASSEMBLY.txt`  - the executed instruction stream, machinery folded, opcodes
  named where their stack effect is verified.
- `OPCODE_MAP.txt`   - each opcode's verified meaning (measured stack effect).
- `RECONSTRUCTED.lua`- source-shaped rebuild from one run's evidence.
- `BEHAVIOR.txt`     - REAL vs DECOY (anti-tamper) split + coverage audit.
- `vm_structure.txt`, `vm_imports.txt`, `inner_source.lua`, `inner_data.bin`.

## Modules (each stage, importable)

- `unobf.py`  layer-1 unwrap + inner-VM static analysis
- `lift.py`   static import-table / string recovery from the VM bytes
- `ai.py`     decoy classifier, constant filter, coverage audit
- `devirt.py` opcode-trace disassembly + machinery folding
- `opmap.py`  opcode semantics from handler bodies, verified vs the trace
- `flow.py`   value-flow: attach real decoded values to the program ops
- `final.py`  merge every run into one reconstruction
- `universal.lua` the executor harness (embeds the full obf, hooks resolver +
  dispatch; dispatch trace is applied to one chunk only, integrity-safe)

Honesty: this recovers the program's real constant + behaviour surface. It is not
byte-exact source - the VM discards the original text and randomizes opcodes per
run, so unrun branches and exact statement structure are left unrecovered rather
than guessed.
