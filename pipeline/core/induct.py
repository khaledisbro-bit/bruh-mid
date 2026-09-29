#!/usr/bin/env python3
"""
induct.py - counters, and the loops built on them.

The problem this fixes
----------------------
A loop whose condition this analysis could not recover used to be written as

    for _ = 1, 4 do   -- times observed

which is honest but says nothing about the program. The count is a property of
the run: give the script a different input and it is wrong. Worse, the variable
the loop actually counts on is still in the body, being incremented, with no
sign that it is the loop's counter.

What a counter looks like in a trace
------------------------------------
Take every value a variable was given, in the order the run gave them. If the
differences between consecutive values are all the same number, and that number
is not zero, the variable is an arithmetic progression:

    0, 1, 2, 3        step  1
    10, 8, 6, 4       step -2

That is a counter, and it is measured, not guessed. Two values are not enough
to establish a step - any two numbers differ by something - so at least three
are required, which means the loop has to have gone round at least twice.

Getting from there to `for v = start, limit, step do` needs one more thing: the
limit. The count of iterations is NOT the limit; it is what the limit produced
on this input. The limit is only written when the branch that leaves the loop
was seen comparing the counter against a value, and that value held still. When
it did not, the counter is still named and reported - it just does not become a
`for` header, because writing one would state a bound the capture never showed.
"""
from collections import defaultdict

from evidence import OBSERVED, UNKNOWN
from sccp import parse_runtime

MIN_VALUES = 3          # two values cannot establish a step


class Counter:
    """A variable that advanced by a fixed amount."""

    __slots__ = ("web", "slot", "name", "start", "step", "last", "values",
                 "rows", "limit", "limit_op", "evidence", "why", "loop",
                 "inclusive", "compare")

    def __init__(self, web, slot):
        self.web, self.slot = web, slot
        self.name = None
        self.start = self.step = self.last = None
        self.values, self.rows = [], []
        self.limit = self.limit_op = None
        self.inclusive = self.compare = None
        self.loop = None
        self.evidence = OBSERVED
        self.why = ""

    def header(self):
        """The `for` header this supports, or None when it is not settled.

        `while i < 5` and `for i = 0, 5` are NOT the same loop: Lua's `for`
        bound is inclusive, so the second runs one more time and leaves `i`
        one higher. Getting this wrong does not look wrong - it produces a
        header that reads perfectly and behaves differently, which is the one
        outcome this project treats as a failed reconstruction.

        So the bound is converted, and then checked. The converted bound has to
        equal the last value the run actually entered the body with. If the
        comparison was never named, or the check does not hold, no header is
        written and the counter is reported without one.
        """
        if self.limit is None or self.inclusive is None:
            return None
        return (self.start, self.inclusive, self.step)


def _number(text):
    v = parse_runtime(text)
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _written(L, S, W):
    """Per variable, the numbers it was given, in the order the run gave them."""
    seq = defaultdict(list)
    for st in L.steps:
        slot = S.writes.get(st.row)
        if slot is None:
            continue
        wid = W.def_web.get(st.row)
        if wid is None:
            continue
        n = _number(st.popped[-1].runtime) if st.popped else None
        seq[wid].append((st.row, st.key(), n, slot))
    return seq


def counters(L, S, W, g=None, models=None):
    """Every variable whose values form an arithmetic progression."""
    out = {}
    if not S or not S.active() or not W or not W.active():
        return out
    for wid, rows in _written(L, S, W).items():
        nums = [n for _r, _k, n, _s in rows]
        if len(nums) < MIN_VALUES or any(n is None for n in nums):
            continue
        deltas = {round(b - a, 10) for a, b in zip(nums, nums[1:])}
        if len(deltas) != 1:
            continue
        step = deltas.pop()
        if step == 0:
            continue
        c = Counter(wid, rows[0][3])
        c.values = nums
        c.rows = [r for r, _k, _n, _s in rows]
        c.start, c.step, c.last = nums[0], step, nums[-1]
        c.why = ("it was given %d value(s), and every one was exactly %s more "
                 "than the one before: %s. That is a counter, measured from "
                 "the values themselves"
                 % (len(nums), _fmt(step), ", ".join(_fmt(n) for n in nums[:6])
                    + (", ..." if len(nums) > 6 else "")))
        out[wid] = c
    if g is not None:
        _attach_loops(out, g, L, S, W, models)
    else:
        cons = L.consumers() if hasattr(L, "consumers") else {}
        for c in out.values():
            _find_limit(c, L, W, None, models, cons)
    return out


def _attach_loops(out, g, L, S, W, models=None):
    """Tie each counter to the loop it counts, where the graph found one, and
    look for the value it was compared against.

    The bound is looked for whether or not a loop was recognised. A natural
    loop needs a back edge to a block that dominates it, and a capture that
    entered the loop through more than one path may not give one - but the
    comparison the run performed on every pass is in the records either way,
    and that is what the bound is read from."""
    for lp in g.loops:
        body = set(lp["body"]) | {lp["head"]}
        for st in L.steps:
            if st.key() in body and st.row in W.def_web:
                c = out.get(W.def_web[st.row])
                if c is not None and c.loop is None:
                    c.loop = lp
    consumers = L.consumers() if hasattr(L, "consumers") else {}
    for c in out.values():
        _find_limit(c, L, W, g, models, consumers)


def _find_limit(c, L, W, g=None, models=None, consumers=None):
    """The value the counter was compared against, once per advance.

    Three things have to hold before a number is called the counter's bound:

      * an instruction consumed the counter and one other value, that other
        value was a number, and what the instruction produced was consumed by a
        branch. That last part is what separates a test from arithmetic:
        `i < 5` decides where control goes, `acc + i` does not, and both
        consume the counter next to a number;
      * it did so at least as many times as the counter advanced, so it is a
        test performed every pass and not something that happened once;
      * the number was the same every single time.

    If two different instructions both qualify, neither is written: the capture
    does not say which one the loop turns on. A bound the capture did not show
    is not invented - the counter is still named and reported, just without a
    `for` header.
    """
    deciding = _branch_pcs(g)
    if consumers is None:
        consumers = L.consumers() if hasattr(L, "consumers") else {}
    per_pc = defaultdict(list)
    for st in L.steps:
        if len(st.popped) != 2:
            continue
        reads = [W.use_web.get(v.row) for v in st.popped]
        if c.web not in reads:
            continue
        i = reads.index(c.web)
        other = st.popped[1 - i]
        n = _number(other.runtime)
        if n is None:
            continue
        if deciding is not None:
            fed = [u for v in st.pushed for u in consumers.get(v.id, [])]
            if not any(u.key() in deciding for u in fed):
                continue        # arithmetic on the counter, not a test of it
        per_pc[st.key()].append((n, st.op, i))

    advances = len(c.values) - 1
    stable = []
    for pc, hits in per_pc.items():
        if len(hits) < advances:
            continue
        if len({h[0] for h in hits}) != 1:
            continue
        stable.append((pc, hits[0][0], hits[0][1], hits[0][2], len(hits)))
    if len(stable) != 1:
        if not stable:
            c.evidence = OBSERVED
            c.why += ("; no instruction compared it against a number that "
                      "held still on every pass, so its bound was never shown "
                      "and no `for` header is written for it")
        else:
            c.why += ("; %d different instructions each compared it against a "
                      "value that held still, so the capture does not say "
                      "which one the loop turns on and none is written"
                      % len(stable))
        return
    pc, limit, op, side, times = stable[0]
    c.limit, c.limit_op = limit, (op, side)
    _close_bound(c, models)
    c.why += ("; OP_%d at %s consumed it together with %s, %d time(s) for %d "
              "advance(s), and that number never changed - so it is the value "
              "the loop turns on"
              % (op, "fn%d:%d" % pc, _fmt(limit), times, advances))


# What each comparison means for a `for` bound. The loop runs while the test
# holds, so a strict test stops one step short of the number it names and a
# non-strict test reaches it.
_STRICT = {"LT": True, "GT": True, "LE": False, "GE": False}
# Reading the test with the counter on the right instead of the left flips it:
# `5 > i` is `i < 5`.
_FLIP = {"LT": "GT", "GT": "LT", "LE": "GE", "GE": "LE"}


def _close_bound(c, models):
    """Turn the number the loop tested against into the inclusive bound a Lua
    `for` header takes, then check it against what the run did."""
    op, side = c.limit_op
    m = (models or {}).get(op)
    name = getattr(m, "operation", None)
    if name is None:
        c.why += ("; what that instruction does was not established, so "
                  "whether the bound is reached or stopped short of is not "
                  "known, and no `for` header is written")
        return
    if side == 1:
        name = _FLIP.get(name, name)
    strict = _STRICT.get(name)
    if strict is None:
        c.why += ("; that instruction is %s, which is not a comparison this "
                  "can turn into a `for` bound, so none is written" % name)
        return
    c.compare = name
    bound = c.limit - c.step if strict else c.limit
    entered = c.values[-2] if len(c.values) >= 2 else None
    if entered is None or bound != entered:
        c.why += ("; read as `counter %s %s`, the inclusive bound would be %s, "
                  "but the last value the run entered the body with was %s. "
                  "Those disagree, so no `for` header is written"
                  % (name, _fmt(c.limit), _fmt(bound), _fmt(entered)))
        return
    c.inclusive = bound
    c.why += ("; that instruction is %s, so the loop runs while the counter is "
              "%s %s. The inclusive bound is %s, and that is exactly the last "
              "value the run entered the body with"
              % (name, name, _fmt(c.limit), _fmt(bound)))


def _branch_pcs(g):
    """The instructions this capture proved decide where control goes. None
    when there is no graph to ask, in which case the test below is skipped and
    said to be skipped."""
    if g is None:
        return None
    pcs = {b["pc"] for b in g.branches}
    return pcs or None


def _fmt(n):
    if isinstance(n, float) and n == int(n):
        return str(int(n))
    return str(n)


def report(C, names=None):
    L = ["COUNTERS", "=" * 46, ""]
    if not C:
        L.append("  no variable in this capture advanced by a fixed amount")
        L.append("  three or more values are needed to establish a step: two")
        L.append("  numbers always differ by something, which proves nothing.")
        return "\n".join(L)
    L.append("  A counter is a variable whose values form an arithmetic")
    L.append("  progression. The step is measured from the values the run")
    L.append("  stored, not guessed from the shape of the code.")
    L.append("")
    for wid, c in sorted(C.items()):
        nm = (names or {}).get(wid, "variable %s" % wid)
        L.append("  %s" % nm)
        L.append("      %s" % c.why)
        if c.header():
            st_, lim, stp = c.header()
            L.append("      -> for %s = %s, %s%s do"
                     % (nm, _fmt(st_), _fmt(lim),
                        "" if stp == 1 else ", " + _fmt(stp)))
        else:
            L.append("      -> no `for` header: it ran from %s to %s here, but"
                     % (_fmt(c.start), _fmt(c.last)))
            L.append("         that is where this input stopped, not a bound")
            L.append("         the program states.")
        L.append("")
    return "\n".join(L)


def _selftest():
    class V:
        def __init__(self, rt, row=None):
            self.runtime, self.row = rt, row

    class St:
        def __init__(self, row, pc, popped, op=0):
            self.row, self.pc, self.op, self.fn = row, pc, op, 0
            self.popped = list(popped)
            self.pushed, self.operands = [], []

        def key(self):
            return (0, self.pc)

    class Sl:
        def __init__(self, reads, writes):
            self.reads, self.writes = reads, writes

        def active(self):
            return True

    class Wb:
        def __init__(self, dw, uw):
            self.def_web, self.use_web = dw, uw

        def active(self):
            return True

    class Lf:
        def __init__(self, steps):
            self.steps = steps

        def consumers(self):
            return {}

    # 0, 1, 2, 3 -> a counter with step 1
    steps = [St(i, i, [V(str(i))]) for i in range(4)]
    C = counters(Lf(steps), Sl({}, {i: 9 for i in range(4)}),
                 Wb({i: 0 for i in range(4)}, {}))
    assert list(C) == [0] and C[0].step == 1 and C[0].start == 0, C
    assert C[0].header() is None, "no comparison was seen, so no bound"

    # 10, 8, 6 -> step -2
    steps = [St(i, i, [V(v)]) for i, v in enumerate(("10", "8", "6"))]
    C = counters(Lf(steps), Sl({}, {i: 9 for i in range(3)}),
                 Wb({i: 0 for i in range(3)}, {}))
    assert C[0].step == -2, C[0].step

    # two values prove nothing
    steps = [St(i, i, [V(v)]) for i, v in enumerate(("0", "1"))]
    C = counters(Lf(steps), Sl({}, {0: 9, 1: 9}), Wb({0: 0, 1: 0}, {}))
    assert C == {}, C

    # values that are not a progression are not a counter
    steps = [St(i, i, [V(v)]) for i, v in enumerate(("1", "2", "9"))]
    C = counters(Lf(steps), Sl({}, {i: 9 for i in range(3)}),
                 Wb({i: 0 for i in range(3)}, {}))
    assert C == {}, C

    # a value that is not a number is not a counter, however regular
    steps = [St(i, i, [V('"a"')]) for i in range(4)]
    C = counters(Lf(steps), Sl({}, {i: 9 for i in range(4)}),
                 Wb({i: 0 for i in range(4)}, {}))
    assert C == {}, C
    print("induct selftest ok")


if __name__ == "__main__":
    _selftest()
