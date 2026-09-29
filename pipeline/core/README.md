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

The first thing recovered is the call stack. A VM numbers instructions per
function, so instruction 2 means a different instruction in every function it
runs. Until calls are matched with their returns, an instruction number is only
half an address, and every block, loop and branch built on it merges code from
functions that have nothing to do with each other.

## The stages

| stage | file | what it derives, and from what |
|---|---|---|
| read the capture | `tracefmt.py` | sections and records, classified by shape alone |
| functions | `frames.py` | calls matched with their returns, so an instruction number means something |
| split interpreter from program | `noise.py` | helper routines, from call/return shape in the executed flow |
| opcode arity | `opsem.py` | pushes from the pending-value report, pops from the stack-pointer delta |
| opcode meaning | `opsem.py` | candidate operations tested against every instance's real values |
| value graph | `stackint.py` | symbolic replay of the stack, checked against the VM's own stack pointer |
| variables | `dataflow.py` | write/read opcode pairs proved by "a read returns the last write" |
| one slot, several variables | `webs.py` | reads and writes grouped by what reaches what, so a reused slot becomes separate variables |
| facts along every path | `sccp.py` | constants and truthiness carried into a point from all sides, not only the side that ran |
| containers | `dataflow.py` | the same proof applied to a container and a key |
| control flow | `cfgx.py` | blocks, dominators, natural loops, and branch targets nothing entered |
| loop bounds | `induct.py` | counters found as arithmetic progressions in the stored values, bound read from the test that feeds a branch |
| repeated calls | `probes.py` | calls repeated with identical arguments whose answer nothing took |
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

## Two passes that reason about paths, not about the run

Most of this package measures the path the capture took. Two stages reason
about every path instead, which is what it takes to say anything about code the
run did not enter.

**`webs.py` - one slot is not one variable.** A compiler reuses a slot. The
same slot can hold a player at the top of a function and a string at the
bottom, with nothing connecting them, and writing both as one variable claims
an assignment the program never made. So the reads and writes of each slot are
grouped by reaching definitions: a read belongs with every write that can reach
it, and writes that share a read belong together. Each group is one variable
and gets its own name. The same pass answers two more questions for free - a
read with no write reaching it came in from outside the capture (a parameter,
an upvalue), and a write that every path overwrites before any read is a store
nothing could see. A write that merely reaches the end of the capture is NOT
that: the run stopping is not evidence, and it is reported as unsettled.

**`sccp.py` - what holds on every path in.** Per variable, one of: the same
constant everywhere, never-false, always-false, or nothing known. Facts meet at
a join, so a fact that survives to a point held on every path that reached it.
The use is on branches with a side this run did not take. If the value feeding
such a branch was the same constant on every path into it, that side cannot be
entered while that holds. If the value differed, the condition is real. If
nothing is established, nothing is claimed.

Neither pass deletes anything. "This side is unreachable" is a statement about
reachability, not about who wrote the code: a programmer's own test on a fixed
value reads exactly like an obfuscator's opaque predicate, and no pass here can
tell them apart. The finding is attached to the branch and counted; the code
stays in the output.

## Counters, and why the bound is converted and then checked

`induct.py` looks at every value a variable was given, in order. If the
differences are all the same non-zero number, it is an arithmetic progression -
a counter, measured rather than guessed. Three values are the minimum: any two
numbers differ by something.

The bound is separate work. The number of iterations is not the bound; it is
what the bound produced on this input. So the bound is only written when one
instruction consumed the counter next to a number, did it at least once per
advance, always against the same number, and fed a branch with the result. That
last condition is what separates a test from arithmetic - `i < 5` decides where
control goes and `acc + i` does not, and both consume the counter next to a
number.

Then the part that is easy to get wrong. `while i < 5` and `for i = 0, 5` are
different loops: Lua's `for` bound is inclusive, so the second runs an extra
time and leaves `i` one higher. A header like that reads perfectly and behaves
differently, which is the one outcome this project counts as a failure. So the
comparison is read (`LT` stops short, `LE` reaches), the inclusive bound is
computed, and then it is **checked against the last value the run actually
entered the body with**. If the check does not hold, or the comparison was
never named, no header is written at all.

## Repeated calls, and why there is no signature table

The published deobfuscators strip anti-tamper scaffolding by scoring a file
against a list of what it has looked like before - `Instance.new("ScreenGui")`,
`Path2D`, `AncestryChanged:Connect` - and deleting the lines that matched once
the score clears a threshold. That is wrong in both directions: a script that
really does build a ScreenGui loses real code, and a protection doing the same
job through any other API is not touched.

`probes.py` measures instead. A call is listed when this capture shows it made
repeatedly, with the same receiver, name and arguments, and nothing ever took
what it returned. Either property alone is ordinary; together they are unusual.
And that is all it says - the count and the fact, in the code's own terms. No
call is named anti-tamper, and nothing is removed from the reconstruction on
this evidence.

## The harness shields

Tracing changes two things a protected script can measure about itself without
naming anything, so both are answered consistently for every caller:

* **Time.** Logging every instruction makes the run hundreds of times slower,
  and a script that checks elapsed time sees a number that could not happen on
  a real machine. Freezing the clock is no better - a clock that never moves is
  as detectable as one that jumps, and code waiting on it hangs. The clock is
  virtual: it starts where the real one did and advances by a small steady
  amount per reading.
* **Its own source.** The logger is injected into the interpreter's text.
  `debug.info` and `debug.traceback` report lines, so the shield corrects them
  by however much the injection actually moved them - measured at patch time,
  not assumed. Today that is zero, because the logger is deliberately written
  on one line.

## Measuring the shields instead of trusting them

The harness shields two things tracing makes measurable, and a third that
searching never turned up: its own hooks were plain fields on the environment.
`__OP`, `__CODE`, `__SL` and `__CAP` sat there in the open, and

    for k in pairs(getfenv()) do ... end

lists them. Four names that exist in no Roblox environment are a more direct
giveaway than timing or line numbers, and cost nothing to look for. They are
served through the environment's `__index` now: a global read is an `__index`
lookup, so the injected logger still reaches them, while `pairs` does not walk
a metamethod and `rawget` returns nil.

That fix came from auditing the harness rather than from reading about what
protections check, which is why `exposure.py` exists. Before it runs the
payload, the harness asks the questions any script can ask about its own
environment - which globals are here that are not in the real one, whether the
hooks can be read off the table, whether the environment carries a metatable,
whether the functions are the objects they replaced, what the clock reports for
a fixed amount of work, what line the script reads for itself - and writes the
answers into the capture. `EXPOSURE.txt` turns them into a report.

The report does not claim the harness is undetectable. It is not, and the
report names the parts that are: the environment does carry a metatable,
because the fallback to the real globals needs one, and any function the
harness logs through is not the object it replaced. Those are the cost of
tracing at all. What the report gives is a list measured on the run in front of
you instead of assumed from the last time somebody looked, and a clean line
means that question did not give it away - not that nothing could.
