#!/usr/bin/env python3
"""
probes.py - calls the program made that nothing in it depends on.

Why this is not a signature list
--------------------------------
The published deobfuscators handle anti-tamper scaffolding by keeping a table
of what it looks like: score the file for `Instance.new("ScreenGui")`, for
`Path2D`, for `AncestryChanged:Connect`, and past a threshold delete the lines
that matched. That is fast and it is wrong in both directions. A script that
genuinely builds a ScreenGui and connects to AncestryChanged scores the same
and loses real code. A protection that does the identical job through any other
API scores zero and survives untouched. The table describes files that have
been seen before, not code that does nothing.

What is measured here instead
-----------------------------
Two properties of a call, both read off this capture:

  * nothing consumed what it returned - no other instruction took its result,
    and it reached nothing the program observably did;
  * it happened again, with the same receiver, the same name and the same
    arguments, more than a handful of times.

Either alone is ordinary. `print("x")` returns nothing anybody uses. A draw
call in a loop repeats. Together they are unusual: a program that computes
something does not normally ask the same question with the same arguments
twenty times and throw every answer away.

And that is all this says. It reports the count and the fact, in the code's own
terms, and stops there. It does not name the calls anti-tamper, it does not
score them, and nothing is removed from the reconstruction on its evidence -
the call happened, the program made it, and it is written out. A reader who
knows the program decides what it was for.
"""
from collections import defaultdict

from evidence import OBSERVED, UNKNOWN

MIN_REPEATS = 5          # below this, repetition says nothing


class Probe:
    __slots__ = ("recv", "method", "args", "count", "rows", "why", "evidence")

    def __init__(self, recv, method, args):
        self.recv, self.method, self.args = recv, method, args
        self.count = 0
        self.rows = []
        self.why = ""
        self.evidence = OBSERVED

    def text(self):
        a = ", ".join(self.args)
        if self.recv:
            return "%s:%s(%s)" % (self.recv, self.method, a)
        return "%s(%s)" % (self.method, a)


def _unused(call, consumers):
    """Whether nothing took what this call returned.

    The consumer map is passed in. Building it inside here meant rebuilding the
    whole value graph once for every call examined - work that cannot change
    between two calls of the same capture."""
    st = getattr(call, "step", None)
    if st is None:
        return False
    if not st.pushed:
        return True                     # it produced nothing to take
    return not any(consumers.get(v.id) for v in st.pushed)


def find(L, calls, records, min_repeats=MIN_REPEATS):
    """Group the calls by exactly what was asked, and keep the groups that
    repeat with nothing taking the answer."""
    groups = defaultdict(list)
    unused = {}
    consumers = L.consumers() if hasattr(L, "consumers") else {}
    for c in calls:
        rec = getattr(c, "record", None) or {}
        key = (rec.get("recv") or "", rec.get("method") or "",
               tuple(rec.get("args") or ()))
        groups[key].append(c)
        unused[id(c)] = _unused(c, consumers)

    out = []
    for (recv, method, args), members in groups.items():
        if len(members) < min_repeats:
            continue
        if not all(unused[id(c)] for c in members):
            continue
        p = Probe(recv, method, list(args))
        p.count = len(members)
        p.rows = [c.step.row for c in members if getattr(c, "step", None)]
        p.why = ("made %d time(s) with the same receiver, the same name and "
                 "the same argument(s), and on every one of them nothing took "
                 "what it returned" % p.count)
        out.append(p)
    out.sort(key=lambda p: -p.count)
    return out


def report(ps, total_calls=0):
    L = ["CALLS NOTHING DEPENDED ON", "=" * 46, ""]
    if not ps:
        L.append("  Every repeated call in this capture had its result taken by")
        L.append("  something, or did not repeat often enough to mean anything.")
        L.append("")
        L.append("  Note on what this section is NOT: it is not a list of known")
        L.append("  anti-tamper APIs. Nothing here is matched against a table of")
        L.append("  names. A call is listed only when this capture shows it")
        L.append("  being made repeatedly with the same arguments and its answer")
        L.append("  thrown away every time.")
        return "\n".join(L)
    L.append("  Each of these was made over and over with identical arguments,")
    L.append("  and nothing ever took the answer. That is worth a reader's")
    L.append("  attention. It is not a verdict: the calls happened, they are in")
    L.append("  the reconstruction, and nothing was removed because of this.")
    L.append("")
    for p in ps[:60]:
        L.append("  %-4d x  %s" % (p.count, p.text()))
        L.append("          %s" % p.why)
    L.append("")
    if total_calls:
        n = sum(p.count for p in ps)
        L.append("  %d of the %d recorded call(s) fall into these groups."
                 % (n, total_calls))
    return "\n".join(L)


def _selftest():
    class V:
        def __init__(self, vid):
            self.id = vid

    class St:
        def __init__(self, row, pushed=()):
            self.row = row
            self.pushed = list(pushed)

    class C:
        def __init__(self, row, rec, pushed=()):
            self.step = St(row, pushed)
            self.record = rec

    class Lf:
        def __init__(self, cons):
            self._c = cons

        def consumers(self):
            return self._c

    rec = {"recv": "a", "method": "Check", "args": ()}
    # six identical calls, nothing takes the result -> reported
    calls = [C(i, rec) for i in range(6)]
    ps = find(Lf({}), calls, [])
    assert len(ps) == 1 and ps[0].count == 6, ps
    # the map is built once, not once per call
    class Counting(Lf):
        def __init__(self, c):
            Lf.__init__(self, c)
            self.built = 0

        def consumers(self):
            self.built += 1
            return self._c

    cl = Counting({})
    find(cl, [C(i, rec) for i in range(6)], [])
    assert cl.built == 1, "consumer map built %d times" % cl.built

    # four is below the floor -> not reported
    ps = find(Lf({}), [C(i, rec) for i in range(4)], [])
    assert ps == [], ps

    # six identical calls, but one result IS taken -> not reported
    calls = [C(i, rec, [V(i)]) for i in range(6)]
    ps = find(Lf({3: ["someone"]}), calls, [])
    assert ps == [], ps

    # same name, different arguments -> different questions, not reported
    calls = [C(i, {"recv": "a", "method": "Check", "args": (str(i),)})
             for i in range(6)]
    ps = find(Lf({}), calls, [])
    assert ps == [], ps
    print("probes selftest ok")


if __name__ == "__main__":
    _selftest()
