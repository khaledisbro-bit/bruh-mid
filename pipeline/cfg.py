#!/usr/bin/env python3
"""
cfg.py - control-flow reconstruction from the opcode trace.

The step past a flat call list: recover the program's control structure. From
the executed program-counter stream we build basic blocks, find the edges
between them, detect loops (a block re-entered = a loop head / back edge), and
place the real decoded values that each block produced. The VM's constant-
decrypt / hash machinery is folded out first (it reuses a tiny hot pc set), so
what remains is the program spine's control flow.

Honest scope: this recovers the control-flow GRAPH that actually executed
(blocks, branches, loops) with real values attached - not a byte-exact
if/for/while nesting, which needs full structuring across merged runs. Loops and
branch points are OBSERVED; unentered blocks are not invented.
"""
import re
from collections import Counter, defaultdict

import flow as flowmod


def _steps(text):
    return flowmod.parse(text)   # (pc, op, operands, sp, val)


def build(text):
    steps = _steps(text)
    if not steps:
        return None
    # machinery = the heavily-reused low pcs (decrypt/hash). Fold them out.
    freq = Counter(s[0] for s in steps)
    counts = sorted(freq.values())
    med = counts[len(counts) // 2] if counts else 1
    mach = {pc for pc, n in freq.items() if n >= max(med * 4, 8)}

    # spine = program steps; collapse each machinery burst to a marker between them
    spine = []
    for pc, op, od, sp, val in steps:
        if pc in mach:
            if spine and spine[-1][0] != "MACH":
                spine.append(("MACH", None, None))
            continue
        spine.append((pc, op, val))

    # basic blocks over the spine: a new block starts when pc is not the
    # sequential successor of the previous spine pc (a jump/branch target).
    blocks, cur, prev = [], [], None
    for item in spine:
        if item[0] == "MACH":
            continue
        pc = item[0]
        if prev is not None and pc != prev + 1 and pc != prev + 2:
            if cur:
                blocks.append(cur); cur = []
        cur.append(item)
        prev = pc
    if cur:
        blocks.append(cur)

    # edges between block head pcs, in execution order; back edge => loop
    edges = defaultdict(Counter)
    heads = [b[0][0] for b in blocks]
    seen_heads = {}
    loops = []
    order = []
    for i, b in enumerate(blocks):
        h = b[0][0]
        order.append(h)
        if h in seen_heads and h != (blocks[i - 1][0][0] if i else None):
            loops.append(h)              # re-entered head = loop head
        seen_heads[h] = i
    for a, b in zip(order, order[1:]):
        edges[a][b] += 1

    return {"blocks": blocks, "edges": edges, "loops": sorted(set(loops)),
            "mach": len(mach), "steps": len(steps)}


def report(text):
    g = build(text)
    if not g:
        return "no opcode stream to reconstruct control flow from."
    blocks = g["blocks"]
    # dedup consecutive identical block heads for a readable outline
    L = []
    L.append("CONTROL-FLOW RECONSTRUCTION (from the executed pc stream)")
    L.append("=" * 56)
    L.append("machinery pcs folded: %d   program basic blocks: %d   loops: %d"
             % (g["mach"], len(blocks), len(g["loops"])))
    L.append("Blocks and edges are OBSERVED (they actually executed). A re-entered")
    L.append("block head is a loop. Real decoded values produced in a block are")
    L.append("shown; nothing unentered is invented.")
    L.append("")
    HEX = re.compile(r'^"[0-9a-f]{16,}')
    seen = set()
    shown = 0
    for i, b in enumerate(blocks):
        head = b[0][0]
        # real values produced inside this block
        vals = []
        for pc, op, val in b:
            if val and val.startswith('"') and not HEX.match(val):
                inner = val.strip('"')
                if inner and inner not in vals and not flowmod._looks_random(inner):
                    vals.append(inner)
        key = (head, tuple(vals))
        if key in seen:
            continue
        seen.add(key)
        loop = "  <-- LOOP head" if head in g["loops"] else ""
        line = "  block@%-5d %2d instr%s" % (head, len(b), loop)
        if vals:
            line += "   values: " + ", ".join(vals[:8])
        L.append(line)
        shown += 1
        if shown >= 200:
            L.append("  ... (%d more blocks)" % (len(blocks) - shown))
            break
    return "\n".join(L)


if __name__ == "__main__":
    import sys
    print(report(open(sys.argv[1], encoding="latin1").read()))
