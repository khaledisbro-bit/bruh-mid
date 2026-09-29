#!/usr/bin/env python3
"""
version.py - which engine produced a report.

Three rounds of this project were spent reading reports from an older copy of
the pipeline and reasoning about failures that had already been fixed. A report
that does not say what made it cannot be trusted to describe the code you have,
so every report now says, and the stages it lists are the ones that actually ran.
"""

VERSION = 15

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
)


def banner():
    return "engine %d" % VERSION


def describe():
    L = ["engine %d - the stages that produced this:" % VERSION]
    for s in STAGES:
        L.append("   " + s)
    return "\n".join(L)
