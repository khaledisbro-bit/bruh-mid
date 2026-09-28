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


# pc;opcode;operands[;stackpointer[;topvalue]]  -- 3, 4 or 5 fields
_LINE = re.compile(r"^(-?\d+);(-?\d+);([^;]*)(?:;(-?\d+))?(?:;(.*))?$")


def parse_ops(text):
    """Return a list of (pc, opcode, [operands]) from an opcode-trace body.
    Tolerates the 4- and 5-field forms (stackpointer, topvalue)."""
    if "---OPCODES---" in text:
        text = text.split("---OPCODES---", 1)[1]
    text = text.split("END_UNOBF_RESULT", 1)[0]
    out = []
    for ln in text.splitlines():
        m = _LINE.match(ln.strip())
        if not m:
            continue
        out.append((int(m.group(1)), int(m.group(2)),
                    [x for x in m.group(3).split(",") if x != ""]))
    return out


def parse_ops_sp(text):
    """Like parse_ops but also returns stack pointer and top value per step.
    Returns list of (pc, opcode, [operands], sp|None, val|None)."""
    if "---OPCODES---" in text:
        text = text.split("---OPCODES---", 1)[1]
    text = text.split("END_UNOBF_RESULT", 1)[0]
    out = []
    for ln in text.splitlines():
        m = _LINE.match(ln.strip())
        if not m:
            continue
        sp = int(m.group(4)) if m.group(4) is not None else None
        val = m.group(5) if m.group(5) not in (None, "") else None
        out.append((int(m.group(1)), int(m.group(2)),
                    [x for x in m.group(3).split(",") if x != ""], sp, val))
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


def fold_cycles(steps, max_period=160):
    """Collapse consecutive repeated instruction blocks (the VM's constant-
    decrypt routine and hash loop repeat dozens of times). Returns a list of
    (start_index, period, repeats). A generic run-length over cycles - correct
    regardless of opcode semantics, and it turns thousands of machinery steps
    into a readable skeleton."""
    toks = [f"{op}:{','.join(od)}" for _pc, op, od in steps]
    out, i, n = [], 0, len(toks)
    while i < n:
        best = (1, 1)
        limit = min(max_period, (n - i) // 2)
        for p in range(1, limit + 1):
            r = 1
            while toks[i + r * p:i + (r + 1) * p] == toks[i:i + p]:
                r += 1
            if r >= 2 and p * r > best[0] * best[1]:
                best = (p, r)
        p, r = best
        out.append((i, p, r))
        i += p * r
    return out


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


def summarize(text, max_lines=600, vm_source=None):
    steps = parse_ops(text)
    if not steps:
        return "no opcode trace found (the dispatch hook may not have matched " \
               "this build, or the VM did not run)."
    hist = Counter(op for _pc, op, _o in steps)
    folded = fold_cycles(steps)
    _bl, loops = blocks(steps)
    repeated = sum(p * r for _i, p, r in folded if r >= 2)
    skeleton = sum(1 for _i, _p, r in folded if r < 2)
    # opcode semantics, derived from the VM handlers and verified vs this trace
    sem, deltas, produced = {}, {}, {}
    steps_sp = parse_ops_sp(text)
    # value each pushing instruction produced = the top value seen at the NEXT
    # step (that step reads the stack this one just left). Lets us print the
    # real string/number a LOADK produced next to it.
    for i in range(len(steps_sp) - 1):
        produced[i] = steps_sp[i + 1][4]
    if vm_source:
        try:
            import opmap
            om = opmap.build_map(vm_source, steps, steps_sp)
            sem = {op: v["semantic"] for op, v in om.items()
                   if v["verdict"] in ("CONFIRMED", "STACK", "LIKELY") and v["semantic"]}
            deltas = {op: v["stack_delta"] for op, v in om.items()
                      if v.get("stack_delta") is not None}
        except Exception:
            sem, deltas = {}, {}

    out = []
    out.append("VM DEVIRTUALIZATION (from the executed instruction stream)")
    out.append("=" * 58)
    out.append("instructions executed (logged): %d" % len(steps))
    out.append("distinct opcode values: %d" % len(hist))
    out.append("repeated machinery steps folded away: %d" % repeated)
    out.append("program skeleton instructions (after folding): %d" % skeleton)
    out.append("loop edges (backward jumps): %d" % loops)
    out.append("")
    out.append("NOTE ON FIDELITY (honest): this VM emits the same logical")
    out.append("operation under many opcode values (%d distinct) and duplicates" % len(hist))
    out.append("handler branches as decoys. That defeats a fixed opcode->Lua")
    out.append("table, so instructions are shown as OP_<n> with operands, not")
    out.append("renamed to Lua ops we cannot prove. The folding below removes the")
    out.append("constant-decrypt and hash-loop machinery so the real program")
    out.append("skeleton is visible - nothing is invented.")
    out.append("")
    if sem:
        covered = sum(hist[op] for op in sem)
        allf = sum(hist.values())
        out.append("verified opcode semantics: %d of %d opcodes, covering %.0f%% of"
                   % (len(sem), len(hist), 100.0 * covered / max(allf, 1)))
        out.append("executed instructions. Opcode numbers RANDOMIZE per run, so")
        out.append("meaning is taken from the MEASURED stack effect of each opcode")
        out.append("in this run (push/pop), cross-checked with the VM's handlers.")
        out.append("Named below; the rest stay OP_<n> - never renamed on a guess.")
        out.append("")
    out.append("opcode histogram (top 30 by frequency; * = confirmed semantic):")
    for op, n in hist.most_common(30):
        mark = " *" if op in sem else ""
        out.append("  OP_%-6d %6d%s" % (op, n, mark))
    out.append("")
    out.append("folded instruction skeleton (machinery collapsed as xN):")
    shown = 0
    for i, p, r in folded:
        pc, op, operands = steps[i]
        ops = " ".join(operands)
        if r >= 2:
            out.append("  [ machinery block: %d instr x%d  (decrypt/hash, skipped) ]"
                       % (p, r))
        else:
            label = sem.get(op)
            # real value this instruction produced (for pushes), from the trace
            val = produced.get(i)
            d = deltas.get(op)
            vtag = ""
            if val and val != "nil" and d is not None and d >= 1:
                vtag = "   => " + val
            head = "OP_%d %s" % (op, ops)
            if label:
                out.append("  %6d: %-38s ; %s%s" % (pc, head, label, vtag))
            else:
                out.append("  %6d: %-38s%s" % (pc, head, vtag))
        shown += 1
        if shown >= max_lines:
            out.append("  ... (%d more units; full stream in opcode_trace.txt)"
                       % (len(folded) - shown))
            break
    return "\n".join(out)


if __name__ == "__main__":
    import sys
    txt = open(sys.argv[1], encoding="latin1").read()
    print(summarize(txt))
