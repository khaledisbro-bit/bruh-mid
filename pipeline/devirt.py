#!/usr/bin/env python3
"""
devirt.py - lift the VM opcode trace (from the dispatch hook) into a readable
disassembly and control-flow view.

The harness patches the inner VM's dispatch loop so every executed instruction
is logged as one line:

    <pc>;<opcode>;<operand>,<operand>,...

That is the real, decrypted instruction stream of the code paths that ran -
genuine devirtualization data, not the API surface. This module turns it into:
  * an opcode histogram (which handlers dominate),
  * a linear disassembly (pc -> opcode -> operands), decoys marked,
  * basic-block / loop structure from the program-counter movement
    (a backward jump in pc marks a loop edge; a gap marks a branch target).

It does NOT invent semantics it cannot prove. Opcodes are named only when their
behavior is established; everything else is shown as OP_<n> with its operands,
so nothing is fabricated. As the opcode->Lua map is filled in (from the VM's
handler bodies), the same trace lifts closer to source.
"""
import re
from collections import Counter


def parse_ops(text):
    """Return a list of (pc, opcode, [operands]) from an opcode-trace body."""
    if "---OPCODES---" in text:
        text = text.split("---OPCODES---", 1)[1]
    text = text.split("END_UNOBF_RESULT", 1)[0]
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        m = re.match(r"^(-?\d+);(-?\d+);(.*)$", ln)
        if not m:
            continue
        pc, op = int(m.group(1)), int(m.group(2))
        operands = [x for x in m.group(3).split(",") if x != ""]
        out.append((pc, op, operands))
    return out


def decoy_opcodes(steps):
    """The VM's decoy branches churn a rolling hash and touch no stack; they
    recur with near-constant operand shape. Heuristic: opcodes whose operand
    rows are (almost) always empty and that never sit on a real call path.
    Reported, not silently dropped."""
    empties = Counter()
    total = Counter()
    for _pc, op, operands in steps:
        total[op] += 1
        if not operands:
            empties[op] += 1
    decoys = set()
    for op, n in total.items():
        if n >= 5 and empties[op] >= n * 0.95:
            decoys.add(op)
    return decoys


def blocks(steps):
    """Split the linear trace into basic blocks at pc discontinuities. A step
    whose pc is not prev_pc+1 begins a new block; a backward target is a loop."""
    bl, cur, prev = [], [], None
    loop_edges = 0
    for pc, op, operands in steps:
        if prev is not None and pc != prev + 1:
            if cur:
                bl.append(cur); cur = []
            if pc <= prev:
                loop_edges += 1
        cur.append((pc, op, operands))
        prev = pc
    if cur:
        bl.append(cur)
    return bl, loop_edges


def summarize(text, max_lines=400):
    steps = parse_ops(text)
    if not steps:
        return "no opcode trace found (the dispatch hook may not have matched " \
               "this build, or the VM did not run)."
    decoys = decoy_opcodes(steps)
    hist = Counter(op for _pc, op, _o in steps)
    bl, loops = blocks(steps)
    real = [s for s in steps if s[1] not in decoys]

    out = []
    out.append("VM DEVIRTUALIZATION (from the executed instruction stream)")
    out.append("=" * 58)
    out.append("instructions executed (logged): %d" % len(steps))
    out.append("distinct opcodes: %d   decoy opcodes: %d   real: %d"
               % (len(hist), len(decoys), len(hist) - len(decoys)))
    out.append("basic blocks: %d   loop edges (backward jumps): %d" % (len(bl), loops))
    out.append("real (non-decoy) instructions: %d" % len(real))
    out.append("")
    out.append("opcode histogram (opcode: count, [decoy] marked):")
    for op, n in hist.most_common(40):
        tag = "  [decoy]" if op in decoys else ""
        out.append("  OP_%-6d %6d%s" % (op, n, tag))
    out.append("")
    out.append("linear disassembly (real instructions, pc: opcode operands):")
    shown = 0
    for pc, op, operands in real:
        out.append("  %6d: OP_%-6d %s" % (pc, op, " ".join(operands)))
        shown += 1
        if shown >= max_lines:
            out.append("  ... (%d more real instructions in opcode_trace.txt)"
                       % (len(real) - shown))
            break
    return "\n".join(out)


if __name__ == "__main__":
    import sys
    txt = open(sys.argv[1], encoding="latin1").read()
    print(summarize(txt))
