#!/usr/bin/env python3
"""
version.py - which engine produced a report.

Three rounds of this project were spent reading reports from an older copy of
the pipeline and reasoning about failures that had already been fixed. A report
that does not say what made it cannot be trusted to describe the code you have,
so every report now says, and the stages it lists are the ones that actually ran.
"""

VERSION = 21

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
)


def banner():
    return "engine %d" % VERSION


def describe():
    L = ["engine %d - the stages that produced this:" % VERSION]
    for s in STAGES:
        L.append("   " + s)
    return "\n".join(L)
