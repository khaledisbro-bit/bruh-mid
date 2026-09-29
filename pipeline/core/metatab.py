#!/usr/bin/env python3
"""
metatab.py - operations that went through a metatable.

Why this exists, and what it fixes
----------------------------------
types_.py withdraws a reading when the values make the operation impossible:
`nil[1]`, `1()`, `{} + 8`. That is right for most of them and wrong for some,
because Lua has metatables. A table CAN be added to a number, if it carries
`__add`. A table CAN be called, if it carries `__call`. Withdrawing those
readings threw away the one piece of evidence that says the program uses a
metatable at all.

So the same impossibility splits in two, and the type decides which:

  * nil, a boolean, a number - no metatable of their own in Lua, so the
    operation really could not have happened and the reading goes, as before;

  * a table or a userdata - the operation is possible through a metamethod,
    and the value came back, so a metamethod is what happened.

The second case is not a failure of the reading. It is a finding: this value
has a metatable, and this is the event that proves it.

What is claimed, and what is not
--------------------------------
Claimed: at this instruction, a value of this type took part in this operation
and produced a result, which in Lua requires the metamethod named here. That is
the language's own rule, not a guess about the program.

Not claimed: what the metamethod does. The capture shows the operation and its
result, not the function behind it. `__index` that returned 7 is recorded as
having returned 7, and nothing is invented about how.
"""
from collections import defaultdict

from evidence import OBSERVED, UNKNOWN
import types_ as T

# Lua's metamethod for each operation, and the types it can rescue. A table and
# a userdata can carry a metatable; nil, booleans and numbers cannot be given
# one from Lua, so an operation on those is impossible however it is read.
# Only a table, as far as this can see. "userdata" was listed here too, and
# typeof() never returns it: a userdata reads as unknown, and so does every
# Roblox value that is not a plain table or scalar. Unknown admits everything,
# so those are never flagged - no false positives, and no detection either.
_RESCUABLE = {T.TABLE}

# ONLY the operations where an impossible type can actually be rescued by a
# metatable. Each of the four that used to be here is undetectable this way,
# and listing them claimed a coverage this cannot deliver:
#
#   __index    a table IS indexable, so indexing one is never impossible. The
#              metamethod fires on a key that is absent, which a type cannot
#              see.
#   __newindex the same, for assignment.
#   __len      a table HAS a length. Only a number or nil has none, and neither
#              can carry a metatable.
#   __call     a table IS callable as far as the admissible set is concerned,
#              so calling one raises nothing to notice.
#   __eq       `a == b` never raises in Lua whatever the types.
#
# The self-test below asserts this table holds no dead entry, so the list
# cannot quietly grow one again.
_EVENT = {
    "ADD": "__add", "SUB": "__sub", "MUL": "__mul", "DIV": "__div",
    "MOD": "__mod", "POW": "__pow", "CONCAT": "__concat",
    "LT": "__lt", "LE": "__le", "GT": "__lt", "GE": "__le",
}


class Event:
    """One operation that can only have gone through a metatable."""

    __slots__ = ("row", "pc", "op", "operation", "event", "on", "inputs",
                 "result", "evidence", "why")

    def __init__(self, row, pc, op, operation, event, on, inputs, result):
        self.row, self.pc, self.op = row, pc, op
        self.operation, self.event, self.on = operation, event, on
        self.inputs, self.result = inputs, result
        self.evidence = OBSERVED
        self.why = ""


def _offending(operation, previews):
    """The input whose type makes the primitive impossible, or None."""
    ok, _why = T.admits(operation, previews)
    if ok:
        return None
    for i, p in enumerate(previews):
        t = T.typeof(p)
        one = list(previews)
        one[i] = None                  # unknown admits anything
        if T.admits(operation, one)[0]:
            return i, t, p
    return None


def find(models, lift):
    """Every operation in this capture that required a metamethod."""
    out = []
    for st in lift.steps:
        m = models.get(st.op)
        if m is None or not m.operation:
            continue
        event = _EVENT.get(m.operation)
        if event is None:
            continue
        previews = [v.runtime for v in st.popped]
        hit = _offending(m.operation, previews)
        if hit is None:
            continue
        i, t, p = hit
        if t not in _RESCUABLE:
            continue                   # genuinely impossible; types_ withdraws it
        result = st.pushed[0].runtime if st.pushed else None
        e = Event(st.row, st.pc, st.op, m.operation, event, t, previews, result)
        e.why = ("%s took a %s as input %d (%s) and %s. In Lua that is only "
                 "possible through the %s metamethod, so this value carries a "
                 "metatable"
                 % (m.operation, t, i, p,
                    ("produced %s" % result) if result is not None
                    else "completed", event))
        if result is None and m.operation not in ("SETINDEX",):
            e.evidence = UNKNOWN
            e.why += ("; the capture did not report what it produced, so that "
                      "it completed at all is the weaker half of this")
        out.append(e)
    return out


def rescued(events):
    """Opcodes whose reading should NOT be withdrawn on type grounds, because a
    metamethod explains them. Maps opcode -> why."""
    out = {}
    for e in events:
        if e.evidence != OBSERVED:
            continue
        out.setdefault(e.op, e.why)
    return out


def report(events):
    L = ["OPERATIONS THAT WENT THROUGH A METATABLE", "=" * 46, ""]
    if not events:
        L.append("  No operation in this capture required one. Every operation")
        L.append("  whose meaning was established took inputs its own rules")
        L.append("  allow.")
        L.append("")
        L.append("  This is not the same as saying the program has no")
        L.append("  metatables. A metamethod that does what the primitive would")
        L.append("  have done anyway leaves nothing in a trace to distinguish")
        L.append("  it, and is not detectable from here at all.")
        return "\n".join(L)
    L.append("  Each of these took an input whose type makes the plain")
    L.append("  operation impossible, and completed anyway. In Lua that needs")
    L.append("  the metamethod named, so the value carries a metatable.")
    L.append("")
    L.append("  What the metamethod DOES is not recovered. The capture shows")
    L.append("  the operation and its result, not the function behind it.")
    L.append("")
    by_event = defaultdict(list)
    for e in events:
        by_event[e.event].append(e)
    for ev in sorted(by_event):
        es = by_event[ev]
        L.append("  %-12s %d site(s)" % (ev, len(es)))
        for e in es[:8]:
            L.append("      pc %-6s %s" % (e.pc, e.why))
        if len(es) > 8:
            L.append("      ... and %d more" % (len(es) - 8))
        L.append("")
    return "\n".join(L)


def _selftest():
    class M:
        def __init__(self, operation):
            self.operation = operation

    class V:
        def __init__(self, rt):
            self.runtime = rt

    class St:
        def __init__(self, row, op, popped, pushed=()):
            self.row, self.pc, self.op = row, row, op
            self.popped = [V(p) for p in popped]
            self.pushed = [V(p) for p in pushed]

    class L:
        def __init__(self, steps):
            self.steps = steps

    # a table added to a number, producing a value: __add
    ev = find({1: M("ADD")}, L([St(0, 1, ["table", "8"], ["12"])]))
    assert len(ev) == 1 and ev[0].event == "__add", ev
    assert ev[0].on == "table"

    # nil added to a number is impossible however it is read: not rescued
    ev = find({1: M("ADD")}, L([St(0, 1, ["nil", "8"], ["12"])]))
    assert ev == [], ev

    # a table called: __call
    ev = find({1: M("CALL")}, L([St(0, 1, ["table"], ["3"])]))
    assert ev == [], "a table IS callable in the admissible set already"

    # a number indexed is impossible; a table indexed is ordinary
    ev = find({1: M("INDEX")}, L([St(0, 1, ["3", '"k"'], ["7"])]))
    assert ev == [], "a number has no metatable to rescue it"

    # two tables concatenated: __concat
    ev = find({1: M("CONCAT")}, L([St(0, 1, ["table", '"x"'], ['"ax"'])]))
    assert len(ev) == 1 and ev[0].event == "__concat", ev

    # an operation whose result the capture did not report is the weaker half
    ev = find({1: M("ADD")}, L([St(0, 1, ["table", "8"], [])]))
    assert len(ev) == 1 and ev[0].evidence == UNKNOWN, ev
    assert rescued(ev) == {}, "a weak event does not rescue a reading"

    ev = find({1: M("ADD")}, L([St(0, 1, ["table", "8"], ["12"])]))
    assert list(rescued(ev)) == [1]

    # No entry may claim coverage it cannot deliver. An operation belongs here
    # only if SOME set of inputs makes the primitive impossible AND the
    # offending type is one that can carry a metatable.
    kinds = ["nil", "true", "3", '"s"', "table", "function: 0x1"]
    dead = []
    for opn in _EVENT:
        live = False
        for a in kinds:
            for b in kinds:
                for ins in ([a], [a, b], [a, b, "1"]):
                    h = _offending(opn, ins)
                    if h and h[1] in _RESCUABLE:
                        live = True
        if not live:
            dead.append(opn)
    assert not dead, "these can never be detected: %s" % dead
    print("metatab selftest ok")


if __name__ == "__main__":
    _selftest()
