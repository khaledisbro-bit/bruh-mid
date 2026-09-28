#!/usr/bin/env python3
"""
cfgx.py - rebuild the program's control flow from the instructions that ran.

Basic blocks come from where control actually went: a block starts at the entry,
at anything jumped to, and after anything that branched. Edges are the observed
transitions between those blocks. Dominators are then computed the usual way, and
a natural loop is an edge back to a block that dominates its source - which is
what a loop is, rather than a pc that happened to repeat.

The part that matters most here is what did NOT run. A conditional branch has two
successors and one run takes one of them. The other target is still written in
the instruction, so the edge is recorded and marked unknown instead of being left
out. A branch that only ever went one way is reported as a branch whose other
side was never entered, never as straight-line code: one execution is not the
program, and an unexplored path is missing evidence, not absent code.
"""
from collections import defaultdict

from evidence import OBSERVED, UNKNOWN


class CFG:
    def __init__(self):
        self.blocks = {}          # head pc -> list of step rows
        self.succ = defaultdict(set)
        self.pred = defaultdict(set)
        self.taken = defaultdict(int)
        self.entry = None
        self.loops = []           # (head, back-edge source, body)
        self.idom = {}
        self.branches = []        # dict per conditional branch
        self.unexplored = []      # (from_pc, to_pc, why)

    def block_of(self, pc):
        return self._owner.get(pc)


def build(L, slots=None, pc_universe=None):
    steps = L.steps
    if not steps:
        return CFG()
    seq = [(st.pc, st) for st in steps]
    succ_pcs = defaultdict(set)
    for (pa, _sa), (pb, _sb) in zip(seq, seq[1:]):
        succ_pcs[pa].add(pb)

    known = pc_universe or {pc for pc, _ in seq}
    leaders = {seq[0][0]}
    for (pa, _sa), (pb, _sb) in zip(seq, seq[1:]):
        if pb != pa + 1:
            leaders.add(pb)                 # jumped to
            if pa + 1 in known:
                leaders.add(pa + 1)         # the side that falls through
    for pc, outs in succ_pcs.items():
        if len(outs) > 1:
            leaders |= outs

    g = CFG()
    g.entry = seq[0][0]
    cur = None
    owner = {}
    for pc, st in seq:
        if pc in leaders or cur is None:
            cur = pc
            g.blocks.setdefault(cur, [])
        owner[pc] = cur
        if st.row not in [x.row for x in g.blocks[cur]]:
            g.blocks[cur].append(st)
    g._owner = owner

    for (pa, _sa), (pb, _sb) in zip(seq, seq[1:]):
        ba, bb = owner[pa], owner[pb]
        if ba != bb:
            g.succ[ba].add(bb)
            g.pred[bb].add(ba)
            g.taken[(ba, bb)] += 1

    g.idom = _dominators(g)
    g.loops = _loops(g)
    _branches(g, succ_pcs, seq, known, slots)
    return g


def _dominators(g):
    nodes = list(g.blocks)
    if not nodes:
        return {}
    order = _rpo(g)
    rank = {n: i for i, n in enumerate(order)}
    idom = {g.entry: g.entry}
    changed = True
    while changed:
        changed = False
        for n in order:
            if n == g.entry:
                continue
            preds = [p for p in g.pred[n] if p in idom]
            if not preds:
                continue
            new = preds[0]
            for p in preds[1:]:
                new = _intersect(p, new, idom, rank)
            if idom.get(n) != new:
                idom[n] = new
                changed = True
    return idom


def _intersect(a, b, idom, rank):
    while a != b:
        while rank.get(a, 0) > rank.get(b, 0):
            a = idom.get(a, a)
            if a == idom.get(a, a) and rank.get(a, 0) > rank.get(b, 0):
                break
        while rank.get(b, 0) > rank.get(a, 0):
            b = idom.get(b, b)
            if b == idom.get(b, b) and rank.get(b, 0) > rank.get(a, 0):
                break
        if a == b:
            break
        if idom.get(a, a) == a and idom.get(b, b) == b:
            break
        a, b = idom.get(a, a), idom.get(b, b)
    return a


def _rpo(g):
    seen, order = set(), []

    def visit(n):
        stack = [(n, iter(sorted(g.succ[n])))]
        seen.add(n)
        while stack:
            node, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                order.append(node)
                stack.pop()
            elif nxt not in seen:
                seen.add(nxt)
                stack.append((nxt, iter(sorted(g.succ[nxt]))))

    visit(g.entry)
    for n in g.blocks:
        if n not in seen:
            visit(n)
    return order[::-1]


def _dominates(a, b, idom):
    seen = set()
    while b not in seen:
        if a == b:
            return True
        seen.add(b)
        nb = idom.get(b)
        if nb is None or nb == b:
            return False
        b = nb
    return False


def _loops(g):
    out = []
    for src in g.blocks:
        for dst in g.succ[src]:
            if _dominates(dst, src, g.idom):
                body = _natural_body(g, dst, src)
                out.append({"head": dst, "back": src, "body": sorted(body),
                            "iterations": g.taken[(src, dst)]})
    return out


def _natural_body(g, head, back):
    body, stack = {head, back}, [back]
    while stack:
        n = stack.pop()
        for p in g.pred[n]:
            if p not in body:
                body.add(p)
                stack.append(p)
    return body


def _branchers(seq, succ_pcs, slots):
    """Opcodes that decide where control goes.

    Proof comes first: an opcode seen sending control to two different places is
    a branch, whatever its number. Where one run only ever went one way, an
    opcode still counts as a candidate branch if it consumes a value and produces
    none - it consumed a condition - but opcodes already proved to be variable
    writes are excluded, because their operand is a slot, not a destination."""
    offsets = {}
    for pc, st in seq:
        for nxt in succ_pcs.get(pc, ()):
            offsets.setdefault(st.op, set()).add(nxt - pc)
    proved = {op for op, offs in offsets.items() if len(offs) > 1}
    excluded = set(slots.write_ops) | set(slots.read_ops) if slots else set()
    cands = set()
    for _pc, st in seq:
        if st.op in excluded:
            continue
        if st.pops >= 1 and st.pushes == 0 and st.operands:
            cands.add(st.op)
    return proved, (cands - excluded)


def _branches(g, succ_pcs, seq, known, slots=None):
    """Conditional branches, and the sides of them that never ran."""
    by_pc = {}
    for pc, st in seq:
        by_pc.setdefault(pc, st)
    proved, cands = _branchers(seq, succ_pcs, slots)
    lo, hi = min(known), max(known)
    for pc, outs in sorted(succ_pcs.items()):
        st = by_pc[pc]
        targets = set(outs)
        if len(targets) > 1:
            g.branches.append({"pc": pc, "taken": sorted(targets), "untaken": [],
                               "row": st.row, "op": st.op, "evidence": OBSERVED,
                               "why": "both destinations were taken in this run"})
            continue
        if st.op not in proved and st.op not in cands:
            continue
        possible = set(targets)
        for o in st.operands:
            if isinstance(o, int) and lo <= o <= hi and o != pc:
                possible.add(o)
        if pc + 1 in known:
            possible.add(pc + 1)
        missed = sorted(possible - targets)
        if not missed:
            continue
        ev = OBSERVED if st.op in proved else UNKNOWN
        why = ("OP_%d was seen sending control to more than one place elsewhere "
               "in this run" % st.op) if st.op in proved else \
              ("OP_%d consumes a value and produces none, and carries an operand "
               "that names a valid instruction, so it reads as a condition whose "
               "other side was not taken" % st.op)
        g.branches.append({"pc": pc, "taken": sorted(targets), "untaken": missed,
                           "row": st.row, "op": st.op, "evidence": ev,
                           "why": why})
        for m in missed:
            g.unexplored.append((pc, m, why))


def report(g):
    L = ["CONTROL FLOW (reconstructed from the executed transitions)",
         "=" * 56,
         "Blocks start at the entry, at jump targets, and after branches. A loop",
         "is an edge back to a block that dominates it. Branch targets that never",
         "ran are listed as unexplored, not removed.", "",
         "basic blocks: %d   edges: %d   loops: %d   unexplored branches: %d"
         % (len(g.blocks), sum(len(v) for v in g.succ.values()),
            len(g.loops), len(g.unexplored)), ""]
    if g.loops:
        L.append("loops:")
        for lp in g.loops:
            L.append("  head pc %-6d back edge from pc %-6d  %d block(s), "
                     "%d iteration(s) observed"
                     % (lp["head"], lp["back"], len(lp["body"]), lp["iterations"]))
        L.append("")
    if g.branches:
        L.append("branches:")
        for b in g.branches:
            L.append("  pc %-6d [%s] went to %s%s"
                     % (b["pc"], b.get("evidence", OBSERVED)[:1],
                        ", ".join(str(t) for t in b["taken"]),
                        ("   NEVER TAKEN: " + ", ".join(str(t) for t in b["untaken"]))
                        if b["untaken"] else ""))
            L.append("      " + b.get("why", ""))
        L.append("")
    if g.unexplored:
        L.append("unexplored paths (kept as unknown, not deleted):")
        for a, b, why in g.unexplored[:20]:
            L.append("  pc %d -> pc %d : %s" % (a, b, why))
    return "\n".join(L)
