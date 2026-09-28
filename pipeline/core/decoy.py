#!/usr/bin/env python3
"""
decoy.py - decide what actually affects the program, and what only pretends to.

These samples carry deliberate decoy work: instructions that execute, look busy,
and change nothing the program does. Separating them is where a deobfuscator is
easiest to fool, in both directions, so two tempting shortcuts are refused here.

  Complicated does not mean decoy, and simple does not mean real. Nothing is
  judged by how it looks.

  Not appearing in a trace does not mean decoy. An instruction that never ran is
  missing evidence, not proof of irrelevance, and it is never classified from
  absence.

The decision is made on influence, computed backwards from the points where the
program is observable: the arguments and receivers of calls it made, the
conditions it branched on, the values it returned, and the variables it later
read. Anything those depend on, transitively, is real. An instruction that
executed, produced something, and reaches none of them influenced nothing on
this path.

Even then the verdict is held back when the evidence is incomplete. If an
instruction's result could still be consumed on a branch this capture never
entered, it stays a candidate with both readings recorded rather than being
called a decoy, because the run that settles it has not happened yet.
"""
from evidence import OBSERVED, UNKNOWN, DECOY


class Verdict:
    __slots__ = ("pc", "verdict", "why", "alternative")

    def __init__(self, pc, verdict, why, alternative=None):
        self.pc = pc
        self.verdict = verdict
        self.why = why
        self.alternative = alternative


def sinks(L, calls, g, slots, env_ops=()):
    """The values the program's observable behaviour depends on."""
    out, why = set(), {}

    def mark(vid, reason):
        out.add(vid)
        why.setdefault(vid, reason)

    for c in calls:
        if c.recv_value is not None:
            mark(c.recv_value.id, "receiver of the recorded call %s"
                 % c.record.get("raw", ""))
        for a in c.arg_values:
            mark(a.id, "argument of the recorded call %s"
                 % c.record.get("raw", ""))
    for b in g.branches:
        st = next((s for s in L.steps if s.pc == b["pc"] and s.popped), None)
        if st is not None:
            mark(st.popped[0].id, "the condition the branch at pc %d tested"
                 % b["pc"])
    last = next((st for st in reversed(L.steps)
                 if st.pops >= 1 and st.pushes == 0), None)
    if last is not None and last.popped:
        mark(last.popped[0].id, "the value handed back when execution ended")
    read_slots = set(slots.reads.values())
    for st in L.steps:
        key = slots.writes.get(st.row)
        if key is not None and key in read_slots and st.popped:
            mark(st.popped[0].id,
                 "stored into variable slot%s, which the program reads again"
                 % key)
            continue
        # An instruction that consumes values and produces none has an effect we
        # cannot see. Its inputs are therefore not provably irrelevant, so they
        # count as observable. Claiming otherwise is exactly the mistake this
        # module exists to avoid.
        if st.pushes == 0 and st.pops >= 1 and key is None:
            for v in st.popped:
                mark(v.id, "consumed by the instruction at pc %d, whose effect "
                           "this capture cannot observe" % st.pc)
    # A call whose callee was resolved from a name is a call even when the
    # environment did not record it, so its arguments are observable too.
    for st in L.steps:
        if st.pushes != 1 or not st.popped:
            continue
        head = st.popped[0]
        if head.op in env_ops:
            for v in st.popped[1:]:
                mark(v.id, "argument of the call made at pc %d" % st.pc)
            mark(head.id, "the thing called at pc %d" % st.pc)
    return out, why


def influence(L, seeds, amap):
    """Everything the observable behaviour depends on, transitively."""
    live, stack = set(), list(seeds)
    while stack:
        vid = stack.pop()
        if vid in live:
            continue
        live.add(vid)
        v = L.values[vid]
        stack.extend(v.inputs)
        if vid in amap:
            stack.append(amap[vid])
    return live


def classify(L, g, calls, slots, amap, env_ops=()):
    """Verdict per program counter, with the evidence behind it."""
    seeds, why_seed = sinks(L, calls, g, slots, env_ops)
    live = influence(L, seeds, amap)
    call_rows = {c.step.row for c in calls}
    jumps = {a.pc for a, b in zip(L.steps, L.steps[1:]) if b.pc != a.pc + 1}
    unexplored_from = {b["pc"] for b in g.branches if b["untaken"]}
    reachable_unknown = bool(g.unexplored)

    out = {}
    for st in L.steps:
        if st.pc in out:
            continue
        if st.row in call_rows:
            out[st.pc] = Verdict(st.pc, OBSERVED,
                                 "makes a call the environment recorded")
            continue
        if any(v.id in live for v in st.pushed):
            reason = next((why_seed[v.id] for v in st.pushed
                           if v.id in why_seed), None)
            out[st.pc] = Verdict(
                st.pc, OBSERVED,
                reason or "its result is used, directly or through other "
                          "instructions, by something the program observably did")
            continue
        if st.pushes == 0 and st.pops == 0:
            if (st.pc in jumps or st.pc in unexplored_from
                    or any(b["pc"] == st.pc for b in g.branches)):
                out[st.pc] = Verdict(st.pc, OBSERVED,
                                     "control did not fall through after it, so "
                                     "it decides where execution goes")
                continue
            out[st.pc] = Verdict(
                st.pc, DECOY,
                "it executed, moved nothing on the stack, produced no value and "
                "made no recorded call, so nothing about the program can depend "
                "on it")
            continue
        if not st.pushed:
            out[st.pc] = Verdict(
                st.pc, UNKNOWN,
                "it consumed values and produced none; what it did with them was "
                "not observable, so its effect is unproven either way")
            continue
        # Everything that is left produced something nothing used. That is a
        # fact about the path that ran, and on its own it is not enough to call
        # an instruction a decoy: the verdict is withheld and both readings are
        # recorded. Only an instruction that can have no effect at all - which
        # was decided above - is named a decoy outright.
        extra = (" this capture also left %d branch target(s) unexplored, so a "
                 "path that was not taken may consume it" % len(g.unexplored)
                 ) if reachable_unknown else ""
        out[st.pc] = Verdict(
            st.pc, UNKNOWN,
            "it produced a value that nothing consumed on the path that ran;" +
            (extra or " whether anything consumes it elsewhere is not settled "
                      "by this capture"),
            "decoy: on the evidence available its result influences nothing")
    return out


def report(verdicts, g):
    order = {OBSERVED: 0, UNKNOWN: 1, DECOY: 2}
    rows = sorted(verdicts.values(), key=lambda v: (order.get(v.verdict, 3), v.pc))
    n = {}
    for v in rows:
        n[v.verdict] = n.get(v.verdict, 0) + 1
    L = ["WHAT MATTERS AND WHAT DOES NOT",
         "=" * 46,
         "Verdicts computed backwards from what the program was observed to do:",
         "the calls it made, the conditions it tested, the value it returned and",
         "the variables it read again. Nothing is judged by how complicated it",
         "looks, and nothing is called a decoy for being absent from a trace.",
         "",
         "real: %d   unproven: %d   decoy: %d   unexplored branch targets: %d"
         % (n.get(OBSERVED, 0), n.get(UNKNOWN, 0), n.get(DECOY, 0),
            len(g.unexplored)),
         ""]
    if g.unexplored:
        L.append("Because branch targets were left unexplored, instructions whose")
        L.append("result is unused are reported as unproven rather than as decoys.")
        L.append("Driving those branches in another run is what would settle them.")
        L.append("")
    for v in rows:
        L.append("  pc %-8d %-9s %s" % (v.pc, v.verdict, v.why))
        if v.alternative:
            L.append("  %-8s %-9s rival reading kept: %s" % ("", "", v.alternative))
    return "\n".join(L)
