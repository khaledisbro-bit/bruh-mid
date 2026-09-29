#!/usr/bin/env python3
"""
version.py - which engine produced a report.

Three rounds of this project were spent reading reports from an older copy of
the pipeline and reasoning about failures that had already been fixed. A report
that does not say what made it cannot be trusted to describe the code you have,
so every report now says, and the stages it lists are the ones that actually ran.
"""

VERSION = 8

STAGES = (
    "captures read by shape",
    "interpreter split by where control leaves it",
    "arity measured per instruction from the stack pointer",
    "operations read from the interpreter's own handlers, then checked",
    "value graph replayed against the VM's stack",
    "variables proved by read-returns-last-write",
    "calls anchored on names and arguments",
    "frames recovered only where numbers collide",
    "decoys decided by influence, withheld when unproven",
)


def banner():
    return "engine %d" % VERSION


def describe():
    L = ["engine %d - the stages that produced this:" % VERSION]
    for s in STAGES:
        L.append("   " + s)
    return "\n".join(L)
