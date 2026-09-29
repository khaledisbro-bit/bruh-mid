#!/usr/bin/env python3
"""
dispatch.py - call sites that do not always call the same thing.

A call written in the source as one line can be several calls in practice.
`handler(x)` where `handler` was assigned in a branch, `t[k](x)` where the key
varies, a method looked up on whatever object arrived - each is one instruction
that reaches a different function on different passes. Reading the output as if
that instruction had one target is a quiet way of describing a program that
does not exist.

A trace answers this directly and without any guessing: the same instruction
executed several times, and each time the value it called was reported. Group
by instruction, count the distinct things called, and the sites with more than
one are the dynamic ones.

What the answer is worth
------------------------
It is a statement about this run. A site that called one target here may call
five on another input, and this says so rather than calling it settled. A site
that called several is settled in the other direction: it IS dynamic, because
it was seen being so.

The targets themselves are reported as the capture reported them. Where a call
was matched to a record, the name the environment logged is used, because that
is what the program reached for; otherwise the value's own description stands.
"""
from collections import defaultdict

from evidence import OBSERVED, UNKNOWN


class Site:
    """One call instruction, and what it was seen calling."""

    __slots__ = ("key", "op", "targets", "count", "evidence", "why")

    def __init__(self, key, op):
        self.key, self.op = key, op
        self.targets = {}        # description -> how many times
        self.count = 0
        self.evidence = OBSERVED
        self.why = ""

    def dynamic(self):
        return len(self.targets) > 1


def _describe(st, call):
    """What this call reached for, in the program's own terms where possible."""
    if call is not None:
        rec = getattr(call, "record", None) or {}
        name = rec.get("method") or ""
        recv = rec.get("recv")
        if name and name != "__call":
            return ("%s:%s" % (recv, name)) if recv else name
        if recv:
            return recv
    if st.popped:
        v = st.popped[0].runtime
        if v:
            return v
    return "<not reported>"


def find(L, calls, models=None):
    """Every call site, with the distinct targets it was seen reaching."""
    by_row = {c.step.row: c for c in calls if getattr(c, "step", None)}
    # An opcode the engine NAMED as a call is a call wherever it runs, so every
    # execution of it counts as a site.
    named_ops = {op for op, m in (models or {}).items()
                 if getattr(m, "operation", None) in ("CALL", "SELFCALL")}

    sites = {}
    for st in L.steps:
        # An opcode that is only here because the call matcher happened to land
        # on it is NOT a call opcode. Taking it as one and then sweeping in
        # every other instruction that shares it turns one uncertain match into
        # a pile of invented targets - on a capture too small for the
        # interpreter's own helpers to be recognised, the matcher lands on a
        # helper and every pass of that helper is then reported as a call site
        # reaching whatever it happened to be holding. Those rows are the
        # interpreter's bookkeeping, not the program's calls.
        #
        # So an opcode from the matcher only accounts for the rows a call was
        # actually matched to.
        if st.op not in named_ops and st.row not in by_row:
            continue
        s = sites.get(st.key())
        if s is None:
            s = sites[st.key()] = Site(st.key(), st.op)
        who = _describe(st, by_row.get(st.row))
        s.targets[who] = s.targets.get(who, 0) + 1
        s.count += 1

    for s in sites.values():
        if s.dynamic():
            s.why = ("ran %d time(s) and called %d different things: %s. The "
                     "target is computed, not fixed"
                     % (s.count, len(s.targets),
                        ", ".join("%s x%d" % (k, v)
                                  for k, v in sorted(s.targets.items(),
                                                     key=lambda kv: -kv[1])[:6])))
        elif s.count > 1:
            s.why = ("ran %d time(s) and called %s every time. That it is fixed "
                     "holds for this run; another input could send it elsewhere"
                     % (s.count, next(iter(s.targets))))
        else:
            s.evidence = UNKNOWN
            s.why = ("ran once, calling %s. One pass cannot say whether the "
                     "target is fixed" % next(iter(s.targets)))
    return sites


def report(sites):
    L = ["CALL SITES AND WHAT THEY REACHED", "=" * 46, ""]
    if not sites:
        L.append("  No call instruction was identified in this capture.")
        return "\n".join(L)
    dyn = [s for s in sites.values() if s.dynamic()]
    fixed = [s for s in sites.values() if not s.dynamic() and s.count > 1]
    once = [s for s in sites.values() if s.count == 1]
    L.append("  %d call site(s): %d called more than one thing, %d called the "
             "same thing" % (len(sites), len(dyn), len(fixed)))
    L.append("  more than once, and %d ran only once." % len(once))
    L.append("")
    if dyn:
        L.append("CALLED MORE THAN ONE THING")
        L.append("-" * 46)
        L.append("  These are dispatch: one instruction, several targets. A")
        L.append("  reconstruction that writes one name here describes a")
        L.append("  program that does not exist.")
        for s in sorted(dyn, key=lambda s: -len(s.targets))[:40]:
            L.append("    fn%d:%-6d %s" % (s.key[0], s.key[1], s.why))
        L.append("")
    if fixed:
        L.append("CALLED ONE THING, MORE THAN ONCE")
        L.append("-" * 46)
        for s in sorted(fixed, key=lambda s: -s.count)[:40]:
            L.append("    fn%d:%-6d %s" % (s.key[0], s.key[1], s.why))
        L.append("")
    if once:
        L.append("  %d site(s) ran once. One pass says nothing about whether"
                 % len(once))
        L.append("  their target is fixed, and none is claimed.")
    return "\n".join(L)


def _selftest():
    class V:
        def __init__(self, rt):
            self.runtime = rt

    class St:
        def __init__(self, row, pc, op, popped):
            self.row, self.pc, self.op, self.fn = row, pc, op, 0
            self.popped = [V(p) for p in popped]
            self.pushed = []

        def key(self):
            return (0, self.pc)

    class C:
        def __init__(self, row, pc, op, rec):
            self.step = St(row, pc, op, [])
            self.record = rec

    class L:
        def __init__(self, steps):
            self.steps = steps

    class M:
        operation = "CALL"

    # one site, two different targets -> dynamic
    steps = [St(0, 5, 7, ["function: 0xA"]), St(1, 5, 7, ["function: 0xB"])]
    sites = find(L(steps), [], {7: M()})
    s = sites[(0, 5)]
    assert s.dynamic() and s.count == 2, s.targets

    # one site, same target twice -> fixed for this run
    steps = [St(0, 5, 7, ["function: 0xA"]), St(1, 5, 7, ["function: 0xA"])]
    sites = find(L(steps), [], {7: M()})
    assert not sites[(0, 5)].dynamic()
    assert "this run" in sites[(0, 5)].why

    # one site, one pass -> nothing claimed
    sites = find(L([St(0, 5, 7, ["function: 0xA"])]), [], {7: M()})
    assert sites[(0, 5)].evidence == UNKNOWN

    # the environment's own name is preferred over the value's description
    c = C(0, 5, 7, {"recv": "game", "method": "GetService"})
    sites = find(L([c.step]), [c], {7: M()})
    assert "game:GetService" in sites[(0, 5)].targets, sites[(0, 5)].targets
    print("dispatch selftest ok")


if __name__ == "__main__":
    _selftest()
