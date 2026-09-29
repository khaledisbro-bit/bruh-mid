#!/usr/bin/env python3
"""
sccp.py - sparse conditional constant propagation over the VM's variables.

Why this exists
---------------
The branch analysis in cfgx can say a branch has a side this run did not take.
It cannot say WHY it was not taken. Two very different things look the same
from a single run:

  * a condition that is decided before it is ever tested - the value feeding it
    is the same constant on every path that reaches it, so the other side can
    never run in any run. That is an opaque predicate, and the code behind it
    is dead by construction.

  * a condition that really does depend on something, which this run happened
    to answer one way. The other side is live code that simply was not reached,
    and deleting it would be deleting the program.

Telling them apart needs facts that hold on EVERY path into the branch, not
just on the path this run took. That is what this pass computes.

The lattice
-----------
For each variable, one of:

    ("c", value)   the same concrete value on every path examined
    ("t",)         not a constant, but never nil and never false
    ("f",)         not a constant, but always nil or false
    absent         nothing is known

Facts meet at a merge: a fact present on both paths and equal survives; two
different facts that agree on truthiness collapse to that truthiness; anything
else is dropped. This is the standard meet - it can only ever lose information
at a join, so a fact that survives to a branch held on every path that reached
it.

What it does NOT do
-------------------
It never invents a value. Every constant here was observed in the capture, on
the instruction that stored it. A variable this run never wrote has no fact,
and a branch fed by one is reported as undecided, not as dead.
"""
from collections import defaultdict

from evidence import OBSERVED, UNKNOWN, DECOY

# A branch that ran once went one way once. That is not a value holding still
# across the paths into it - a single sample never varies, whatever it is. So a
# branch is only ever called settled when the run entered it more than once,
# the same rule this project already applies to counters (three values before a
# step is a step) and to proportions (no share printed below five checks).
MIN_DECIDED = 2

# facts
CONST = "c"
TRUTHY = "t"
FALSY = "f"

_WORD = {"true": True, "false": False, "nil": None}


def parse_runtime(text):
    """The concrete value a trace field stands for, or _NOVALUE when the text
    names a thing rather than a value (a table, a function, a userdata)."""
    if text is None:
        return _NOVALUE
    t = text.strip()
    if t in _WORD:
        return _WORD[t]
    if len(t) >= 2 and t[0] == '"' and t[-1] == '"':
        return t[1:-1]
    try:
        return int(t)
    except ValueError:
        pass
    try:
        return float(t)
    except ValueError:
        pass
    return _NOVALUE


class _NoValue:
    def __repr__(self):
        return "<not a scalar>"


_NOVALUE = _NoValue()

# Text the VM prints for things that are values but not scalars. They are not
# constants - two tables that print the same are not the same table - but Lua
# treats every one of them as true, and that alone decides a condition.
_ALWAYS_TRUE = ("table", "function", "userdata", "thread", "{}")


def fact_of(runtime):
    """The fact a stored value supports, or None when it supports none."""
    v = parse_runtime(runtime)
    if not isinstance(v, _NoValue):
        return (CONST, v)
    t = (runtime or "").strip()
    if t.startswith(_ALWAYS_TRUE) or t.startswith("table:") or \
            t.startswith("function:"):
        return (TRUTHY,)
    return None


def truth_of(f):
    """Whether a fact decides a Lua condition, or None when it does not.
    In Lua exactly two values are false: nil and false. Zero is true."""
    if f is None:
        return None
    if f[0] == TRUTHY:
        return True
    if f[0] == FALSY:
        return False
    v = f[1]
    return not (v is None or v is False)


def meet(a, b):
    """Facts true on both paths. Equal facts survive; two that disagree but
    agree on truthiness collapse to that truthiness; the rest are dropped."""
    out = {}
    for k, f in a.items():
        g = b.get(k)
        if g is None:
            continue
        if g == f:
            out[k] = f
            continue
        ta, tb = truth_of(f), truth_of(g)
        if ta is not None and ta == tb:
            out[k] = (TRUTHY,) if ta else (FALSY,)
    return out


class Facts:
    """The result of the propagation."""

    def __init__(self):
        self.entry = {}        # block -> facts holding on entry to it
        self.at_step = {}      # step row -> facts holding before that step
        self.rounds = 0
        self.why = ""
        self.constants = {}    # slot -> value, when constant everywhere it is read
        self.decided = {}      # branch pc -> dict describing the verdict


def _block_events(g, S):
    """Per block, the writes it performs in order: (step, slot, fact)."""
    ev = {}
    for head, steps in g.blocks.items():
        rows = []
        for st in steps:
            slot = S.writes.get(st.row) if S.active() else None
            if slot is None:
                continue
            # the value this write stored is the one it consumed
            stored = st.popped[-1].runtime if st.popped else None
            rows.append((st, slot, fact_of(stored)))
        ev[head] = rows
    return ev


def _transfer(rows, inn):
    cur = dict(inn)
    per_step = {}
    for st, slot, f in rows:
        per_step[st.row] = dict(cur)
        if f is None:
            cur.pop(slot, None)
        else:
            cur[slot] = f
    return cur, per_step


def propagate(g, L, S, max_rounds=200):
    """Run the meet-over-paths propagation to a fixed point."""
    F = Facts()
    if not g.blocks or not S or not S.active():
        F.why = ("no variable model was established for this capture, so there "
                 "is nothing to propagate facts over")
        return F
    ev = _block_events(g, S)
    IN = {b: None for b in g.blocks}
    OUT = {b: {} for b in g.blocks}
    IN[g.entry] = {}
    work = [g.entry]
    seen_steps = {}
    rounds = 0
    while work and rounds < max_rounds * max(len(g.blocks), 1):
        rounds += 1
        b = work.pop()
        inn = IN.get(b)
        if inn is None:
            inn = {}
        out, per_step = _transfer(ev.get(b, []), inn)
        seen_steps.update(per_step)
        if out != OUT[b]:
            OUT[b] = out
        for s in g.succ.get(b, ()):
            old = IN.get(s)
            new = dict(out) if old is None else meet(old, out)
            if new != old:
                IN[s] = new
                work.append(s)
    F.entry = {b: (v or {}) for b, v in IN.items()}
    F.at_step = seen_steps
    F.rounds = rounds
    F.why = ("facts were propagated over %d block(s) to a fixed point in %d "
             "step(s); a fact listed for a block held on every path that "
             "reached it in this capture" % (len(g.blocks), rounds))
    _constants(F, g, L, S)
    return F


def _constants(F, g, L, S):
    """Variables that carried one value at every point they were read."""
    seen = defaultdict(set)
    for st in L.steps:
        slot = S.reads.get(st.row)
        if slot is None:
            continue
        f = (F.at_step.get(st.row) or F.entry.get(g.block_of(st.key()), {})
             ).get(slot)
        if f is None or f[0] != CONST:
            seen[slot].add(_NOVALUE)
        else:
            seen[slot].add(f[1])
    for slot, vals in seen.items():
        if len(vals) == 1:
            v = next(iter(vals))
            if not isinstance(v, _NoValue):
                F.constants[slot] = v


def decide_branches(F, g, L, S):
    """For every branch with a side this run did not take, say whether the
    condition could ever have gone the other way.

    Three answers, and only three:

      decided   the value feeding it is one constant on every path that reaches
                it. The other side is unreachable by construction - an opaque
                predicate.
      varied    the value feeding it was not the same twice. The condition is
                real; the side not taken is code this run did not reach, and it
                stays.
      unknown   nothing about the value is established. It stays, untouched.
    """
    per_pc = defaultdict(list)
    for st in L.steps:
        per_pc[st.key()].append(st)
    out = {}
    for br in g.branches:
        if not br.get("untaken"):
            continue
        pc = br["pc"]
        steps = per_pc.get(pc, [])
        facts = []
        observed = set()
        for st in steps:
            src = st.popped[-1] if st.popped else None
            if src is None:
                facts.append(None)
                continue
            if src.runtime is not None:
                observed.add(src.runtime)
            f = None
            if src.slot is not None:
                block = g.block_of(st.key())
                f = (F.at_step.get(st.row) or F.entry.get(block, {})).get(src.slot)
            if f is None:
                f = fact_of(src.runtime)
            facts.append(f)
        if not facts or any(f is None for f in facts):
            out[pc] = {"verdict": UNKNOWN, "evidence": UNKNOWN,
                       "why": ("nothing is established about the value this "
                               "branch tested, so the side it did not take is "
                               "code that was not reached, not code that "
                               "cannot run")}
            continue
        const = [f for f in facts if f[0] == CONST]
        settled = len(const) == len(facts) and len({f[1] for f in const}) == 1
        if settled and len(facts) < MIN_DECIDED:
            out[pc] = {"verdict": UNKNOWN, "evidence": UNKNOWN,
                       "why": ("this branch ran %d time(s), and that one pass "
                               "carried %r. A single sample never varies, so "
                               "it says nothing about whether the other side "
                               "can be entered. The side not taken stays, and "
                               "no verdict is given."
                               % (len(facts), const[0][1]))}
            continue
        if settled:
            out[pc] = {"verdict": DECOY, "evidence": OBSERVED,
                       "value": const[0][1],
                       "why": ("the value this branch tested was %r on every "
                               "path that reached it (%d time(s) in this "
                               "capture, no path carrying anything else), so "
                               "the side it did not take cannot be entered "
                               "while that stays true. This says the side is "
                               "unreachable, not that it was planted: a "
                               "programmer's own test on a fixed value reads "
                               "exactly the same. Nothing is removed on it."
                               % (const[0][1], len(facts)))}
            continue
        truths = {truth_of(f) for f in facts}
        if len(truths) == 1 and None not in truths:
            out[pc] = {"verdict": UNKNOWN, "evidence": UNKNOWN,
                       "why": ("the value this branch tested was not one "
                               "constant, but every path that reached it "
                               "carried a value Lua reads as %s. That settles "
                               "this run, not the program: the side not taken "
                               "stays." % ("true" if True in truths else "false"))}
            continue
        out[pc] = {"verdict": OBSERVED, "evidence": OBSERVED,
                   "why": ("the value this branch tested differed between the "
                           "paths that reached it (%d distinct value(s) "
                           "observed), so the condition is real and the side "
                           "not taken is live code this run did not enter"
                           % len(observed))}
    F.decided = out
    return out


def report(F, S):
    L = ["CONSTANT PROPAGATION", "=" * 46, "", "  " + (F.why or "not run"), ""]
    if F.constants:
        L.append("VARIABLES THAT NEVER CHANGED")
        L.append("-" * 46)
        for slot, v in sorted(F.constants.items(), key=lambda kv: str(kv[0]))[:200]:
            L.append("  slot %-10s = %r" % (slot, v))
            L.append("      every read of it returned this, on every path")
        L.append("")
    else:
        L.append("  no variable held one value at every point it was read")
        L.append("")
    if F.decided:
        L.append("BRANCHES WITH A SIDE THIS RUN DID NOT TAKE")
        L.append("-" * 46)
        order = {DECOY: 0, OBSERVED: 1, UNKNOWN: 2}
        for pc, d in sorted(F.decided.items(),
                            key=lambda kv: (order.get(kv[1]["verdict"], 3), kv[0])):
            L.append("  fn%d:%d   %s" % (pc[0], pc[1], d["verdict"]))
            L.append("      " + d["why"])
        L.append("")
        n = sum(1 for d in F.decided.values() if d["verdict"] == DECOY)
        L.append("  %d of %d were fed a value that never varied on any path "
                 "that reached them. Every branch above, settled or not, stays "
                 "in the reconstruction exactly as it was: this pass reports, "
                 "it does not delete." % (n, len(F.decided)))
    else:
        L.append("  no branch in this capture had a side it did not take")
    return "\n".join(L)


def _selftest():
    class St:
        def __init__(self, row, pc, popped=(), slot=None):
            self.row, self.pc, self.op = row, pc, 0
            self.fn = 0
            self.popped = list(popped)
            self.pushed = []
            self.operands = []

        def key(self):
            return (0, self.pc)

    class V:
        def __init__(self, rt, slot=None):
            self.runtime, self.slot = rt, slot

    assert truth_of(("c", 0)) is True, "zero is true in Lua"
    assert truth_of(("c", None)) is False
    assert truth_of(("c", False)) is False
    assert truth_of(("t",)) is True
    assert meet({"a": ("c", 1)}, {"a": ("c", 1)}) == {"a": ("c", 1)}
    assert meet({"a": ("c", 1)}, {"a": ("c", 2)}) == {"a": ("t",)}
    assert meet({"a": ("c", 1)}, {"a": ("c", None)}) == {}
    assert meet({"a": ("c", 1)}, {}) == {}
    assert fact_of('"hi"') == ("c", "hi")
    assert fact_of("table: 0x1") == ("t",)
    assert fact_of("garbage") is None

    # the three branch verdicts, on a graph small enough to check by hand
    class G:
        def __init__(self, branches, blocks):
            self.branches, self.blocks = branches, blocks
            self.succ, self.pred, self.entry = {}, {}, (0, 0)

        def block_of(self, pc):
            return (0, 0)

    class Sl:
        reads, writes = {}, {}

        def active(self):
            return True

    class L_:
        def __init__(self, steps):
            self.steps = steps

    def run(runtimes):
        steps = [St(i, 5, [V(rt)]) for i, rt in enumerate(runtimes)]
        g = G([{"pc": (0, 5), "untaken": [(0, 9)]}], {(0, 0): steps})
        F = Facts()
        F.entry = {(0, 0): {}}
        return decide_branches(F, g, L_(steps), Sl())[(0, 5)]["verdict"]

    # the same constant every time: the other side cannot be entered
    assert run(["1", "1", "1"]) == DECOY, run(["1", "1", "1"])
    # ONE pass is not "never varied" - a single sample never varies
    assert run(["1"]) == UNKNOWN, run(["1"])
    assert run(["1", "1"]) == DECOY, run(["1", "1"])
    # the tested value took both truth values, so the condition is real and the
    # side not taken is live code this run did not enter
    assert run(["true", "false"]) == OBSERVED, run(["true", "false"])
    assert run(["nil", "1"]) == OBSERVED
    # different values that Lua reads the same way. The branch went one way
    # every time, but the value was not fixed, so this run settles nothing
    # about the other side and it stays.
    assert run(["1", "2", "3"]) == UNKNOWN, run(["1", "2", "3"])
    assert run(["table: 0x1", "table: 0x2"]) == UNKNOWN
    # nothing established: untouched
    assert run(["garbage", "1"]) == UNKNOWN
    print("sccp selftest ok")


if __name__ == "__main__":
    _selftest()
