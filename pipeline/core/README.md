# core - the deobfuscator

The rule this is built under: **nothing is reconstructed from recognition.**

There is no table anywhere in this package that maps a string, an API name, a
constant or a file to a piece of output. No stage asks "have I seen this
before". No stage holds a prepared reconstruction to emit when something
matches. If a stage cannot derive a fact from the capture in front of it, the
fact does not get written - it gets marked unknown.

Everything is measured per capture, because this obfuscator changes it per
capture: opcode numbers are randomised per run, constants are decrypted only at
runtime, handlers are duplicated, and decoy work is mixed into real work.

## The stages

| stage | file | what it derives, and from what |
|---|---|---|
| read the capture | `tracefmt.py` | sections and records, classified by shape alone |
| split interpreter from program | `noise.py` | helper routines, from call/return shape in the executed flow |
| opcode arity | `opsem.py` | pushes from the pending-value report, pops from the stack-pointer delta |
| opcode meaning | `opsem.py` | candidate operations tested against every instance's real values |
| value graph | `stackint.py` | symbolic replay of the stack, checked against the VM's own stack pointer |
| variables | `dataflow.py` | write/read opcode pairs proved by "a read returns the last write" |
| containers | `dataflow.py` | the same proof applied to a container and a key |
| control flow | `cfgx.py` | blocks, dominators, natural loops, and branch targets nothing entered |
| calls | `exprs.py` | the environment's own call records, matched to instructions in order |
| name resolution | `exprs.py` | the opcode whose output became a receiver recorded under the name it consumed |
| what matters | `decoy.py` | influence computed backwards from observable behaviour |
| output | `emit.py` | a rendering of the graph, nothing else |
| checking | `verify.py` | every named operation and every value recomputed against the VM's record |

`driver.py` runs them and writes the reports. `refvm.py` is test
infrastructure: it compiles programs whose source is known, randomises the
opcode numbering, hides the constants and buries the result in machinery, so
`driver.py --selftest` can compare what the engine rebuilds against what went
in.

## Evidence

Every recovered value, statement and verdict carries one of four classes and the
provenance behind it - which instructions, which data-flow relationships:

* `[O] OBSERVED` the VM did this at runtime.
* `[I] INFERRED` forced by data flow over observed facts.
* `[U] UNKNOWN` present, not resolved on this evidence. Kept, never deleted.
* `[D] DECOY` shown to have no effect, with the signals that showed it.

`PROVENANCE.txt` lists the reason for every emitted line.

## What it does not claim

The reconstruction is the program that ran, rebuilt from the interpreter's own
execution. It is not the original file. Identifiers, comments and formatting were
destroyed at compile time and no amount of analysis brings them back. Code that
never executed is marked as unexplored, not invented, and a branch that only went
one way is reported as a branch, never flattened into straight-line code.

## Running it

```
python3 driver.py --selftest              # round-trip against known sources
python3 driver.py capture.txt -o out      # analyse one capture
python3 driver.py run1.txt run2.txt -o out   # several runs of the same program
```

Several captures of one program are merged at the level of facts, never text: an
instruction explained in any run counts as explained, and a branch target counts
as unexplored only when no run took it. Different samples are never merged.
