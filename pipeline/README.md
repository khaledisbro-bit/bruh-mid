# Deobfuscation pipeline

A hybrid static + dynamic pipeline for the base85 + Zstd Luau VM obfuscator
family (obf2, obf3, and siblings). It recovers the genuine program logic, not
just readable code, and it refuses to fabricate.

## Why hybrid
The outer layers are deterministic and yield to pure static analysis. The inner
VM is not: its constant pool is decrypted by a key built at run time, and each
instruction is decrypted per-pc by an LCG. There is no static key. So the
runtime-keyed layer is handed to a dynamic oracle that runs in a real executor,
and the results are reconciled by an audit layer that rejects failed runs.

## Stages
1. unobf.py (static). Unwraps Layer 1 (base85, Zstd, header split), auto-detects
   every per-build knob (resolver, decoder, constant table, LCG, integrity),
   inventories functions, and classifies constructs REAL / SUSPICIOUS / DECOY /
   UNKNOWN with a reason each. Nothing is hardcoded per sample. Nothing is
   deleted on looks alone.
2. unobf.lua (dynamic oracle). Runs in your executor. Unwraps at runtime,
   auto-patches the detected resolver with capture hooks, runs the inner VM under
   an executor-sim env, taint-tracks arithmetic, captures the returned module,
   and probes each action with tracked arguments. Emits a structured result
   block.
3. ai.py (semantic audit). Compares the candidate source against the trace and
   the static log. Enforces: the VM actually ran (run_ok), operation coverage,
   string coverage, no leftover decode layers, no unresolved dynamic dispatch.
   A failed trace is a BLOCKER, so guesses from anti-tamper noise are rejected.

## Run
```
# static (works here, no executor)
python3 pipeline/unobf.py obf3.lua -o out
cat out/vm_structure.txt

# dynamic (in your executor, obf.lua saved alongside)
#   run pipeline/unobf.lua, copy the BEGIN_UNOBF_RESULT block to unobf_result.txt

# audit
python3 pipeline/ai.py --static out/analysis_log.json \
    --trace unobf_result.txt --candidate deobfuscated.lua
```

ai.py exits 0 and prints CONSISTENT only when the candidate matches a real run.
Set ANTHROPIC_API_KEY and ANTHROPIC_MODEL to add an LLM audit pass on top of the
deterministic checks.

## Multi-sample, proven
- obf3: resolver Nv / decoder BE / table Yd, LCG add 1522986580.
- obf2: resolver Ro / decoder Qe / table Ks, LCG add 1616593069.
- 25ms build: correctly flagged as a different obfuscator family.

See REPORT_obf3.md for the full six-section result on obf3.
