#!/usr/bin/env python3
"""
webs.py - which reads and writes of a VM slot are the SAME variable.

The problem
-----------
A compiler reuses a slot. The same slot number can hold a player at the top of
a function and a string at the bottom, with nothing connecting them. Treating a
slot as one variable merges two unrelated things into one name, and the
reconstruction then says a player was assigned a string.

The opposite mistake is as bad: a variable written in two branches and read
after the join is ONE variable, and giving each branch its own name loses the
fact that the read sees either.

Both are answered by the same classic result: a read belongs with every write
that can reach it, and writes that share a read belong together. Group them with
a union-find and what falls out is a set of webs. One web is one variable.

What it gives
-------------
  * webs          the variables, each with its writes and its reads
  * orphans       reads with no write that reaches them - values that entered
                  the capture from outside it (a parameter, an upvalue, or a
                  write in code this run did not record). They are never
                  invented a value; they are named and marked.
  * split slots   slots that carry more than one web, which is the case a
                  single name would have got wrong.

Nothing here reads the program's meaning. It is reachability over the graph
that was already built from the capture, and it holds for any program.
"""
from collections import defaultdict

from evidence import OBSERVED, UNKNOWN


class UF:
    """Union-find, path-halving."""

    def __init__(self):
        self.p = {}

    def find(self, x):
        p = self.p
        p.setdefault(x, x)
        while p[x] != x:
            p[x] = p[p[x]]
            x = p[x]
        return x

    def union(self, a, b):
        a, b = self.find(a), self.find(b)
        if a != b:
            self.p[b] = a


class Web:
    """One variable: the writes that define it and the reads that see them."""

    __slots__ = ("id", "slot", "defs", "uses", "evidence", "why")

    def __init__(self, wid, slot):
        self.id = wid
        self.slot = slot
        self.defs = []     # step rows
        self.uses = []     # step rows
        self.evidence = OBSERVED
        self.why = ""


class Webs:
    def __init__(self):
        self.webs = {}          # web id -> Web
        self.use_web = {}       # read step row -> web id, or None
        self.def_web = {}       # write step row -> web id
        self.orphans = []       # read step rows with nothing reaching them
        self.dead = []          # webs written and never read
        self.split = {}         # slot -> number of webs on it
        self.why = ""

    def active(self):
        return bool(self.webs)

    def of_row(self, row):
        return self.use_web.get(row, self.def_web.get(row))


def _events(g, S):
    """Per block, the reads and writes of slots it performs, in the order the
    instructions sit in the block.

    A block in the graph holds every execution of itself - a loop body appears
    once, with the records of all five of its passes in it. The order that
    matters here is the block's own instruction order, not the order the
    records were written, so each instruction is taken once and the records
    that share it are attached to it. Reading the records in capture order
    instead would make one instruction look like five, and the write on the
    second pass would appear to be a different variable from the read on the
    first.

    Returns per block a list of (index, kind, slot, [rows]), and the instruction
    each event belongs to."""
    ev = {}
    for head, steps in g.blocks.items():
        by_pc = {}
        for st in steps:
            by_pc.setdefault(st.pc, []).append(st)
        rows = []
        for i, pc in enumerate(sorted(by_pc)):
            group = by_pc[pc]
            reads, writes = {}, {}
            for st in group:
                r = S.reads.get(st.row)
                w = S.writes.get(st.row)
                if r is not None:
                    reads.setdefault(r, []).append(st.row)
                if w is not None:
                    writes.setdefault(w, []).append(st.row)
            for slot, rs in reads.items():
                rows.append((i, "u", slot, rs))
            for slot, rs in writes.items():
                rows.append((i, "d", slot, rs))
        ev[head] = rows
    return ev


def _reaching(g, ev):
    """Reaching definitions: for each block, the set of writes live on entry.

    A write kills the earlier writes of its own slot and nothing else. The
    entry block starts with nothing live, which is what makes a read there an
    orphan rather than a guess."""
    IN = {b: {} for b in g.blocks}
    OUT = {b: {} for b in g.blocks}
    order = list(g.blocks)
    changed = True
    guard = 0
    while changed and guard < 100 * max(len(order), 1):
        changed = False
        guard += 1
        for b in order:
            inn = {}
            for p in g.pred.get(b, ()):
                for slot, ds in OUT[p].items():
                    inn[slot] = inn.get(slot, frozenset()) | ds
            IN[b] = inn
            cur = dict(inn)
            for i, kind, slot, rows in ev.get(b, []):
                if kind == "d":
                    cur[slot] = frozenset([("d", b, i, slot)])
            if cur != OUT[b]:
                OUT[b] = cur
                changed = True
    return IN


def _killed_everywhere(g, ev, block, index, slot):
    """Whether every path out of this write reaches another write to the same
    slot before it reaches the end of the graph.

    This is the whole difference between a store nothing could read and a store
    whose reader the run never got to. If any path leaves the graph without the
    slot being written again, the capture simply stopped, and that proves
    nothing about the program. Only when every path overwrites it first can the
    store be called unreadable."""
    seen = set()
    stack = [(block, index + 1)]
    while stack:
        b, start = stack.pop()
        if (b, start) in seen:
            continue
        seen.add((b, start))
        killed = False
        for i, kind, sl, _rows in ev.get(b, []):
            if i < start or sl != slot:
                continue
            if kind == "u":
                return False        # something does read it
            killed = True
            break
        if killed:
            continue
        outs = g.succ.get(b, ())
        if not outs:
            return False            # a path left the graph with it still live
        for nxt in outs:
            stack.append((nxt, 0))
    return True


def build(g, L, S):
    """Group the reads and writes of every slot into variables."""
    W = Webs()
    if not g.blocks or not S or not S.active():
        W.why = ("no variable model was established for this capture, so there "
                 "are no reads and writes to group")
        return W
    ev = _events(g, S)
    IN = _reaching(g, ev)
    uf = UF()
    use_of = []
    def_of = []
    for b, evs in ev.items():
        cur = dict(IN.get(b, {}))
        for i, kind, slot, rows in evs:
            if kind == "u":
                ds = sorted(cur.get(slot, ()))
                if ds:
                    for d in ds[1:]:
                        uf.union(ds[0], d)
                    use_of.append((ds[0], slot, rows))
                else:
                    # nothing in this capture wrote it before this read
                    syn = ("o", b, i, slot)
                    uf.find(syn)
                    use_of.append((syn, slot, rows))
                    cur[slot] = frozenset([syn])
                    W.orphans.extend(rows)
            else:
                d = ("d", b, i, slot)
                uf.find(d)
                # a write on its own starts a new variable; it joins an earlier
                # one only when some read can see both
                cur[slot] = frozenset([d])
                def_of.append((d, slot, rows))

    reps = {}

    def web_for(k, slot):
        rep = uf.find(k)
        wid = reps.get(rep)
        if wid is None:
            wid = reps[rep] = len(reps)
            W.webs[wid] = Web(wid, slot)
        return wid

    at = {}
    for k, slot, rows in def_of:
        wid = web_for(k, slot)
        at.setdefault(wid, []).append((k[1], k[2], slot))
        for row in rows:
            W.webs[wid].defs.append(row)
            W.def_web[row] = wid
    for k, slot, rows in use_of:
        wid = web_for(k, slot)
        for row in rows:
            W.webs[wid].uses.append(row)
            W.use_web[row] = wid

    per_slot = defaultdict(int)
    for w in W.webs.values():
        per_slot[w.slot] += 1
        if not w.defs:
            w.evidence = UNKNOWN
            w.why = ("read %d time(s) and never written inside the capture: it "
                     "came in from outside - a parameter, a captured value, or "
                     "a write in code this run did not record" % len(w.uses))
        elif not w.uses and all(_killed_everywhere(g, ev, b, i, slot)
                                for b, i, slot in at.get(w.id, ())):
            # a store no read can ever see. That is a fact about the graph, not
            # a guess: every path out of the write reaches either another write
            # to the same slot or the end of the capture. It is listed, not
            # removed - a read in code this run never entered would see it.
            w.evidence = UNKNOWN
            w.why = ("written %d time(s) and never read: on every path out of "
                     "it the slot is written again before anything reads it, "
                     "so nothing in this run could see what it stored"
                     % len(w.defs))
            W.dead.append(w.id)
        elif not w.uses:
            w.evidence = UNKNOWN
            w.why = ("written %d time(s) and never read in this capture, but "
                     "at least one path out of it runs to the end of the "
                     "capture without the slot being written again. The run "
                     "stopping is not the same as the value going unused, so "
                     "this is not settled either way" % len(w.defs))
        else:
            w.why = ("written %d time(s), read %d time(s); every one of those "
                     "reads can see one of those writes and no other"
                     % (len(w.defs), len(w.uses)))
    W.split = {s: n for s, n in per_slot.items() if n > 1}
    W.why = ("%d read/write group(s) over %d slot(s); %d slot(s) carried more "
             "than one variable, %d read(s) had no write reaching them, and %d "
             "group(s) were written but never read"
             % (len(W.webs), len(per_slot), len(W.split), len(W.orphans),
                len(W.dead)))
    return W


def names(W, S):
    """A name per web. A slot that carries one variable keeps the slot's name;
    a slot that carries several gets one name per web, so two unrelated things
    are never written as one."""
    out = {}
    counter = defaultdict(int)
    for wid, w in sorted(W.webs.items()):
        base = _slotname(w.slot)
        if W.split.get(w.slot):
            counter[w.slot] += 1
            out[wid] = "%s_%d" % (base, counter[w.slot])
        else:
            out[wid] = base
    return out


def _slotname(slot):
    if isinstance(slot, tuple):
        # the leading part is the frame, and -1 means "no frame was needed
        # here". Printing it adds a minus sign and no information.
        parts = [x for x in slot if x != -1]
        return "v" + "_".join(str(x) for x in (parts or slot))
    return "v%s" % slot


def report(W):
    L = ["VARIABLES GROUPED BY WHAT REACHES WHAT", "=" * 46, "",
         "  " + (W.why or "not run"), ""]
    if not W.active():
        return "\n".join(L)
    nm = names(W, None)
    if W.split:
        L.append("SLOTS THAT CARRIED MORE THAN ONE VARIABLE")
        L.append("-" * 46)
        L.append("  Reusing a slot is normal. Each of these holds values that")
        L.append("  no read connects, so each gets its own name.")
        for slot, n in sorted(W.split.items(), key=lambda kv: str(kv[0]))[:100]:
            L.append("    slot %-10s -> %d separate variables" % (slot, n))
        L.append("")
    dead = [W.webs[i] for i in W.dead]
    if dead:
        L.append("STORES NOTHING COULD READ")
        L.append("-" * 46)
        L.append("  Each of these is overwritten before anything reads it, on")
        L.append("  every path out of the write. They stay in the output: a")
        L.append("  read in code this run never entered would see them.")
        for w in sorted(dead, key=lambda w: -len(w.defs))[:60]:
            L.append("    %-12s %s" % (nm[w.id], w.why))
        L.append("")
    unread = [w for w in W.webs.values()
              if w.defs and not w.uses and w.id not in set(W.dead)]
    if unread:
        L.append("STORES NOTHING READ, BUT NOT SETTLED")
        L.append("-" * 46)
        L.append("  Nothing read these in this run, and nothing overwrote them")
        L.append("  either. The capture ended, which is not the same as the")
        L.append("  value going unused, so no verdict is given.")
        for w in sorted(unread, key=lambda w: -len(w.defs))[:60]:
            L.append("    %-12s %s" % (nm[w.id], w.why))
        L.append("")
    orph = [w for w in W.webs.values() if not w.defs]
    if orph:
        L.append("VALUES THAT CAME IN FROM OUTSIDE")
        L.append("-" * 46)
        for w in sorted(orph, key=lambda w: -len(w.uses))[:60]:
            L.append("    %-12s %s" % (nm[w.id], w.why))
        L.append("")
    L.append("EVERY VARIABLE")
    L.append("-" * 46)
    for wid, w in sorted(W.webs.items(), key=lambda kv: -len(kv[1].uses))[:200]:
        L.append("    %-12s %s" % (nm[wid], w.why))
    return "\n".join(L)


def _selftest():
    class St:
        def __init__(self, row, pc):
            self.row, self.pc, self.fn, self.op = row, pc, 0, 0
            self.popped, self.pushed, self.operands = [], [], []

        def key(self):
            return (0, self.pc)

    class G:
        def __init__(self, blocks, succ, pred, entry):
            self.blocks, self.succ, self.pred, self.entry = blocks, succ, pred, entry

        def block_of(self, pc):
            return None

    class Sl:
        def __init__(self, reads, writes):
            self.reads, self.writes = reads, writes

        def active(self):
            return True

    # one block: write slot 1, read slot 1, write slot 1 again, read it.
    # the two halves share no read, so they are two variables on one slot.
    steps = [St(0, 0), St(1, 1), St(2, 2), St(3, 3)]
    g = G({(0, 0): steps}, {}, {}, (0, 0))
    S = Sl({1: 1, 3: 1}, {0: 1, 2: 1})
    W = build(g, None, S)
    assert len(W.webs) == 2, W.why
    assert W.split.get(1) == 2, W.split

    # a read before any write is an orphan and keeps its own variable
    steps = [St(0, 0), St(1, 1)]
    g = G({(0, 0): steps}, {}, {}, (0, 0))
    S = Sl({0: 7}, {1: 7})
    W = build(g, None, S)
    assert W.orphans == [0], W.orphans
    assert W.dead == [], W.dead

    # a write that every path overwrites before a read is a dead store
    steps = [St(0, 0), St(1, 1), St(2, 2)]
    g = G({(0, 0): steps}, {}, {}, (0, 0))
    S = Sl({2: 3}, {0: 3, 1: 3})
    W = build(g, None, S)
    assert len(W.dead) == 1, [(w.defs, w.uses) for w in W.webs.values()]

    # a write that nothing overwrites and nothing reads, at the end of the
    # capture. The run ending is not evidence, so it is not called dead.
    steps = [St(0, 0)]
    g = G({(0, 0): steps}, {}, {}, (0, 0))
    S = Sl({}, {0: 3})
    W = build(g, None, S)
    assert W.dead == [], [(w.defs, w.uses, w.why) for w in W.webs.values()]

    # and in the two-write case only the FIRST is dead: the second is the one
    # the capture stopped on
    steps = [St(0, 0), St(1, 1)]
    g = G({(0, 0): steps}, {}, {}, (0, 0))
    S = Sl({}, {0: 3, 1: 3})
    W = build(g, None, S)
    assert len(W.dead) == 1, [(w.defs, w.uses) for w in W.webs.values()]
    assert W.webs[W.dead[0]].defs == [0], W.webs[W.dead[0]].defs

    # a variable written on two branches and read after the join is ONE variable
    b1 = [St(0, 0)]
    b2 = [St(1, 10)]
    b3 = [St(2, 20)]
    g = G({(0, 0): b1, (0, 10): b2, (0, 20): b3},
          {(0, 0): {(0, 10), (0, 20)}, (0, 10): {(0, 20)}},
          {(0, 10): {(0, 0)}, (0, 20): {(0, 0), (0, 10)}}, (0, 0))
    S = Sl({2: 5}, {0: 5, 1: 5})
    W = build(g, None, S)
    assert len(W.webs) == 1, [(w.defs, w.uses) for w in W.webs.values()]
    print("webs selftest ok")


if __name__ == "__main__":
    _selftest()
