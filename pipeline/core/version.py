#!/usr/bin/env python3
"""
version.py - which engine produced a report.

Three rounds of this project were spent reading reports from an older copy of
the pipeline and reasoning about failures that had already been fixed. A report
that does not say what made it cannot be trusted to describe the code you have,
so every report now says, and the stages it lists are the ones that actually ran.
"""

VERSION = 41

STAGES = (
    "captures read by shape",
    "interpreter split by where control leaves it",
    "arity measured per instruction from the stack pointer",
    "operations read from the interpreter's own handlers, then checked",
    "value graph replayed against the VM's stack",
    "variables proved by read-returns-last-write",
    "calls anchored on names and arguments",
    "frames recovered only where numbers collide",
    "stored slots named from the handlers that read them",
    "decoys decided by influence, withheld when unproven",
    "a runnable rendering, checked to compile, for the behaviour comparison",
    "the program's actions lined up against the reconstruction's, one for one",
    "one harness per nested interpreter, so the program's tail is reachable",
    "calls the program made but nothing could place, quoted rather than written",
    "readings withdrawn when the values make them impossible",
    "each check reported on its own, never as one headline number",
    "behaviour compared by replaying the reconstruction and lining the calls up",
    "verdicts also said in the code's own terms, readable content first",
    "what the program does, grouped and counted in plain terms",
    "the interpreter's whole instruction array, so coverage is of the program",
    "reads and writes grouped by what reaches what, so one slot reused for two "
    "things becomes two variables and not one being reassigned",
    "facts carried along every path into a point, not only the path that ran, "
    "so a condition decided before it is tested is told apart from a real one",
    "counters found from the values themselves, and a loop bound written only "
    "when the inclusive form was checked against what the run entered",
    "calls repeated with the same arguments whose answer nothing took, "
    "reported as that fact and matched against no table of names",
    "the harness shielded where tracing is measurable: a clock that advances "
    "as an untraced run would, and debug reporting the lines the file shipped",
    "the instruction array fed to the graph, so a branch can have a side whose "
    "instructions never appeared in the trace at all",
    "a branch settled only when the run entered it more than once, because a "
    "single pass never varies",
    "machinery still found when the program sits in a loop and is as busy as "
    "the interpreter, decided by the stack pointer being handed back unchanged",
    "the tracer's own hooks served through the environment's metatable, so "
    "walking the globals does not list them",
    "the harness interrogating itself before it runs the payload, so what a "
    "traced script could notice is measured on the run rather than assumed",
    "a call written where it was made, not where its receiver was resolved, "
    "and a direct call written as one rather than as __call",
    "the executor's own folder found by asking the executor, instead of "
    "guessing at folders that already happen to hold an old capture",
    "each self-check in its own guard, so one that raises does not silently "
    "take the rest with it, and an unasked question is not read as a clean one",
    "errors on the script's own spawned threads written into the capture, "
    "instead of surfacing only as an engine message nobody analysing can see",
    "an empty capture told apart into its three causes by what the harness "
    "recorded doing, rather than all three reported as the one nobody can act on",
    "output written as UTF-8, so a folder named in the user's own language "
    "prints instead of ending the run",
    "the behaviour harness written as the Lua it is meant to be, and refusing "
    "to compare an empty rendering as though it had passed",
    "the logger's own read of the register array guarded, so observing the "
    "program cannot be what stops it",
    "a run that raised early said so at the top of the report, rather than its "
    "first few steps being described as the program",
    "the trace's instruction numbers lined up against the array's by matching "
    "the operands both report, rather than assumed to be the same",
    "operations that could only have gone through a metatable told apart from "
    "readings that are simply wrong, by whether the type could carry one",
    "call sites grouped by what each was seen reaching, so one instruction "
    "with several targets is not written as though it had one",
    "every stage asked what it does on a capture with nothing in it, and the "
    "metamethod list asserted to hold nothing that can never fire",
    "Lua's values kept apart where Python would merge them, so a path "
    "carrying 0 and one carrying false are not read as carrying the same thing",
    "a damaged capture read as damaged: a stack depth that is negative or past "
    "anything the run could have built is not believed rather than acted on",
    "the interpreter's helpers found in a short capture too, decided by the "
    "stack pointer coming back unchanged rather than by counts it cannot meet",
    "an arity nobody could measure marked as unmeasured, so an instruction is "
    "not called dead for having been unobservable",
    "a call site taken from instructions a call was matched to, not from every "
    "instruction sharing an opcode the matcher happened to land on",
    "the behaviour comparison itself tested against reconstructions wrong in "
    "known ways, and refusing to call a comparison of nothing a pass",
    "every report built from an empty capture and read for words that assert "
    "a finding, so no verdict is reached on no evidence",
    "the Lua this package writes actually executed, not merely parsed, so a "
    "reconstruction that calls a string or cannot terminate is caught here",
    "a script that dies just after the trace hook goes in named as what it "
    "looks like, with the untraced harness written beside it to settle it",
    "the harness settling that by itself: when the traced run raises while the "
    "dispatch patch is in, the same payload is run again unpatched in the same "
    "session and both outcomes are written down, so the answer is a finding "
    "rather than a suspicion and no capture has to be identified by hand",
    "each capture naming the harness that made it, because inferring that from "
    "its side effects is how the wrong file came to be read twice",
    "the run's own headers in a section of their own, so run_ok is read at all: "
    "they used to arrive inside the probe section and a clean run was reported "
    "as a run that stopped early",
    "the early-stop warning keyed on which attempt produced the instructions, "
    "not on the headline, so a capture whose untraced retry finished is still "
    "not read as a whole program",
)


def banner():
    return "engine %d" % VERSION


def describe():
    L = ["engine %d - the stages that produced this:" % VERSION]
    for s in STAGES:
        L.append("   " + s)
    return "\n".join(L)
