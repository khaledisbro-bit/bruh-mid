# pipeline

From an obfuscated Luau file to a reconstruction, in four stages.

```
python3 deob.py obf.lua                       # detect, unwrap, write the harness
#   run out/harness.lua in your executor, save its BEGIN..END block
python3 deob.py obf.lua --trace capture.txt   # analyse
```

| stage | what happens |
|---|---|
| 1 DETECT | identify the outer layer and unwrap it (`unobf.py`) |
| 2 STATIC | dump the inner interpreter and what the bytes give up without running (`lift.py`) |
| 3 HARNESS | embed the **whole** file in a harness that captures the interpreter's own execution (`universal.lua`) |
| 4 ANALYSE | lift the capture into a value graph and rebuild the program from it (`core/`) |

Stage 4 is the deobfuscator. It is documented in [`core/README.md`](core/README.md),
and it is built under one rule: nothing is reconstructed from recognition. No
stage matches a known string, API or sample and emits prepared output. Everything
is measured from the capture in front of it, because this obfuscator randomises
opcode numbering per run, decrypts constants only at runtime, duplicates handlers
and mixes decoy work into real work.

Check it yourself:

```
python3 core/driver.py --selftest
```

That compiles programs whose source is known through a reference VM which
randomises the opcode numbering, hides the constants behind a resolver and buries
everything in interpreter machinery, hands the engine only the capture, and
compares what comes back with what went in.

## Files

| file | role |
|---|---|
| `deob.py` | the driver for all four stages |
| `unobf.py` | outer-layer unwrapping and interpreter structure detection |
| `lift.py` | static recovery from the inner data block, without executing |
| `universal.lua` | the capture harness (resolver and dispatch instrumentation) |
| `unobf.lua` | the earlier family-specific harness, kept for comparison |
| `core/` | the analysis engine |

## Reports it writes

| file | contents |
|---|---|
| `RECONSTRUCTED.lua` | the program, every line tagged with its evidence class |
| `PROVENANCE.txt` | why each emitted line exists, and from which instructions |
| `SUMMARY.txt` | what was recovered, and what was not |
| `VERIFICATION.txt` | every named operation and value recomputed against the VM's record |
| `behaviour_check.lua` | run the reconstruction under the same watched environment and compare call sequences |
| `MACHINERY.txt` | which instructions are the interpreter's own, and why |
| `OPCODES.txt` | each opcode's measured arity and proved operation |
| `VALUES.txt` | the value graph, and any place the replay disagreed with the VM |
| `VARIABLES.txt` | the variables found, and the proof that found them |
| `CONTROL_FLOW.txt` | blocks, loops, and branch targets nothing entered |
| `DECOY.txt` | what influences the program's behaviour and what does not |
| `ACROSS_RUNS.txt` | what several runs of the same program add up to |
