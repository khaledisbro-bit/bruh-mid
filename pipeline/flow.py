#!/usr/bin/env python3
"""
flow.py - value-flow reconstruction from a stack+value opcode trace.

The VM decrypts each constant on demand: a real program instruction (the
"spine") triggers a burst of decrypt/hash machinery that produces the constant,
which the spine instruction then consumes. This module separates the two and
attaches the real decoded constants to the spine instruction that used them, in
execution order. The result is the program's actual operation sequence with real
strings/numbers - the closest honest view of the source for the code that ran.

Nothing is invented: every value shown was observed on the VM's own stack. VM
noise (constant-decrypt hashes, anti-tamper decoy names, interpreter-internal
type strings) is filtered by structure, not by matching a known sample.
"""
import re
from collections import Counter

_HEX = re.compile(r"^[0-9a-f]{16,}$")
_VM_INTERNAL = {
    "string", "number", "boolean", "table", "function", "userdata", "thread",
    "nil", "EnumItem", "Enum", "Enums", "EnumType", "Number", "RBXScriptSignal",
    "RBXScriptConnection", "The metatable is locked", "buffer",
}


def _looks_random(s):
    if len(s) < 8:
        return False
    hu = any(c.isupper() for c in s)
    hl = any(c.islower() for c in s)
    hd = any(c.isdigit() for c in s)
    if hu and hl and hd:
        return True
    # no digit but erratic capitalisation (e.g. "rMZIVrQslw"): count case
    # switches between adjacent letters. Real API names (RaycastParams) switch
    # once or twice; random probe names switch constantly.
    letters = [c for c in s if c.isalpha()]
    if hu and hl and len(letters) >= 8:
        switches = sum(1 for a, b in zip(letters, letters[1:])
                       if a.isupper() != b.isupper())
        if switches >= len(letters) * 0.4:
            return True
    return False


def _real_string(val):
    """val is a preview token like '"RaycastParams"'. Return the inner string if
    it is a genuine program value, else None."""
    if not val or not val.startswith('"'):
        return None
    inner = val[1:-1] if val.endswith('"') else val[1:]
    if inner.endswith(".."):            # truncated long/opaque value
        inner = inner[:-2]
    if not inner or _HEX.match(inner) or _looks_random(inner):
        return None
    if inner in _VM_INTERNAL:
        return None
    return inner


def parse(text):
    if "---OPCODES---" in text:
        text = text.split("---OPCODES---", 1)[1]
    text = text.split("END_UNOBF_RESULT", 1)[0]
    out = []
    for ln in text.splitlines():
        m = re.match(r"^(-?\d+);(-?\d+);([^;]*)(?:;(-?\d+))?(?:;([^;]*))?(?:;.*)?$", ln.strip())
        if m:
            out.append((int(m.group(1)), int(m.group(2)), m.group(3),
                        m.group(4) and int(m.group(4)), m.group(5)))
    return out


def machinery_pcs(steps):
    """The constant-decrypt / hash loop reuses a small set of program counters
    very heavily. Treat the most-repeated pcs (which also form the low, dense
    region) as machinery. Derived from frequency, not hard-coded ranges."""
    freq = Counter(s[0] for s in steps)
    if not freq:
        return set()
    # machinery pcs: those hit far more than the median (the decrypt loop bodies)
    counts = sorted(freq.values())
    median = counts[len(counts) // 2]
    thresh = max(median * 4, 8)
    return {pc for pc, n in freq.items() if n >= thresh}


def reconstruct(text, max_ops=400):
    steps = parse(text)
    if not steps:
        return "no value trace found."
    mach = machinery_pcs(steps)
    # walk: attach real constants produced during machinery bursts to the most
    # recent spine (non-machinery) instruction.
    prog, cur, bucket = [], None, []
    for pc, op, od, sp, v in steps:
        if pc not in mach:
            if cur is not None:
                prog.append((cur, bucket))
            cur, bucket = (pc, op, od), []
        s = _real_string(v)
        if s:
            bucket.append(s)
    if cur is not None:
        prog.append((cur, bucket))

    # ordered, de-duplicated real constants as the program consumed them
    seq, seen = [], set()
    for (_pc, _op, _od), vals in prog:
        for x in vals:
            if x not in seen:
                seen.add(x); seq.append(x)

    L = []
    L.append("VALUE-FLOW RECONSTRUCTION (real values from the VM stack)")
    L.append("=" * 58)
    L.append("instructions: %d   machinery pcs folded: %d   spine ops: %d"
             % (len(steps), len(mach), len(prog)))
    L.append("Each line is a real program instruction with the actual constant")
    L.append("it pulled from the (decrypted) pool - observed on the stack, not")
    L.append("guessed. VM hashes, decoy names and internal type strings removed.")
    L.append("")
    L.append("recovered constant surface, in first-use order (%d values):" % len(seq))
    line = "  "
    for x in seq:
        piece = repr(x) + ", "
        if len(line) + len(piece) > 78:
            L.append(line.rstrip()); line = "  "
        line += piece
    if line.strip():
        L.append(line.rstrip(", "))
    L.append("")
    L.append("program operation sequence (spine op <- constant it used):")
    shown = 0
    for (pc, op, od), vals in prog:
        uv = []
        for x in vals:
            if x not in uv:
                uv.append(x)
        if uv:
            L.append("  OP_%-4d [%-16s] <- %s" % (op, od, ", ".join(uv[:6])))
            shown += 1
            if shown >= max_ops:
                L.append("  ... (%d more)" % (sum(1 for _, vs in prog if vs) - shown))
                break
    return "\n".join(L)


if __name__ == "__main__":
    import sys
    print(reconstruct(open(sys.argv[1], encoding="latin1").read()))
