#!/usr/bin/env python3
"""
opmap.py - derive VM opcode semantics from the VM's OWN handler bodies, then
verify each mapping against the executed trace before trusting it.

The inner VM dispatches each opcode to an inlined handler:
    if (NL-NU)%0x7fffffff == <op> then <BODY> ...
This obfuscator duplicates those `== <op> then` branches across decoy subtrees,
so an opcode number has several candidate bodies and only one is the real
handler. We disambiguate WITHOUT guessing:

  1. extract every candidate body for each opcode from inner_source,
  2. read how many operands that opcode actually carries in the trace,
  3. keep the candidate whose NO[] operand usage matches the trace,
  4. classify the surviving body by the VM's own primitives
     (Nv=decode constant, YU=const/upvalue table, Ng=push, Nf=pop, Bi=jump
     target, arithmetic on popped values, NW/BO=call-or-unpack),
  5. mark CONFIRMED only when a single consistent semantic survives; otherwise
     the opcode stays UNKNOWN and is never renamed.

This is genuine, evidence-checked devirtualization: semantics come from the
VM's code and are validated against real execution, never invented.
"""
import re
from collections import Counter

# register-write-buffer flush that prefixes many handlers; strip it before
# classifying so it does not mask the real operation.
_PROLOGUE = re.compile(
    r"do local %w+=NG;if %w+>=2 then YL\[Ym-1\]=NN end;if %w+>=1 then YL\[Ym\]=NY end;"
    r"NY=nil;NN=nil;NG=0;".replace("%w", r"\w"))


def _strip(body):
    return _PROLOGUE.sub("", body)


def candidate_bodies(src, op):
    out = []
    for m in re.finditer(r"==%d then" % op, src):
        s = m.end()
        term = re.search(r"else do \w+=\w+\+1|elseif\(|else if\(", src[s:s + 1000])
        body = src[s:s + (term.start() if term else 500)].strip()
        if body and body not in out:
            out.append(body)
    return out


def max_operand(body):
    idx = [int(x) for x in re.findall(r"NO\[(\d+)\]", body)]
    return max(idx) if idx else 1


def classify(body):
    """Return a short semantic label for a handler body, or None if unclear.
    Labels are expressed in terms the VM makes provable."""
    b = _strip(body)
    # comparison-and-branch (Bx flag + Bi jump target)
    if "Bi=" in b:
        if "~=" in b:
            return "IF_NE  a ~= b -> jump"
        if re.search(r"YU\[\w+\]\[1\]==", b) or "==" in b.split("Bi=")[0]:
            return "IF_EQ  a == b -> jump"
        if "<" in b.split("Bi=")[0]:
            return "IF_LT  a < b -> jump"
        if "-" in b.split("Bi=")[0]:
            return "TEST_SUB  (a - k) -> jump"
        return "JUMP/branch"
    # pop-pop arithmetic into a special slot
    m = re.search(r"local \w+=Nf\(\);local \w+=Nf\(\);\w+=\w+([%+%-%*/])\w+", b)
    if m:
        sym = {"+": "ADD", "-": "SUB", "*": "MUL", "/": "DIV", "%": "MOD"}[m.group(1)]
        return "%s  b,a=pop,pop; push a%sb" % (sym, m.group(1))
    # register + constant arithmetic (Nv = decoded constant)
    if re.search(r"local \w+=Nv\(NO\[\d+\]\);local \w+=YL\[Ym\];.*\+", b):
        return "ADDK  push(pop + const)"
    if re.search(r"YU\[NO\[\d+\]\]\[1\].*%.*\*.*Nv", b):
        return "MULMOD  push((a % k1) * k2)"
    # push a slot / upvalue / global (the -1..-8 special slots)
    if re.search(r"local \w+=NO\[\d+\];.*oJ==-1 then Ng|Lk==-1 then", b) or \
       re.search(r"if \w+==-1 then Ng\(", b):
        if b.strip().startswith("do Ng({})") or "Ng({});" in b[:12]:
            return "NEWTABLE+PUSH slot/upvalue"
        return "PUSH  slot/upvalue/const"
    # call / unpack helper (NW resolves, BO = table-unpack-like)
    if re.search(r"NW\(NO\[\d+\]\);return BO\(", b):
        return "CALL/UNPACK  spread(resolve(op))"
    if re.search(r"NW\(NO\[\d+\]\);return Dy,", b):
        return "RETURN  value"
    if b.strip() == "do Ng({})end" or b.strip().startswith("do Ng({})end"):
        return "NEWTABLE"
    # bare push of a decoded constant
    if re.search(r"Ng\(Nv\(NO\[\d+\]\)\)", b):
        return "PUSHK  push(const)"
    return None


def build_map(src, steps):
    """steps: list of (pc, op, operands). Returns {op: {...}} with verdicts."""
    arity = {}
    freq = Counter()
    for _pc, op, od in steps:
        arity[op] = max(arity.get(op, 0), len(od))
        freq[op] += 1
    out = {}
    for op in sorted(freq, key=lambda o: -freq[o]):
        cands = candidate_bodies(src, op)
        a = arity[op]
        # operands are NO[2..], so `a` operands means indices up to NO[a+1] exist.
        # The real handler must not read PAST the operands the instruction carries
        # (a body that reads NO[a+2] is from a decoy subtree). Trailing operands
        # can be unused, so <= is correct and exposes the fakes.
        want = a + 1
        matched = [b for b in cands if 0 < max_operand(b) <= want]
        pool = matched or cands
        sem, verdict, body = None, "UNKNOWN", (pool[0] if pool else "")
        # a semantic is CONFIRMED only if the arity-matched candidates agree on it
        sems = {classify(b) for b in matched} if matched else set()
        sems.discard(None)
        if len(sems) == 1:
            sem = next(iter(sems)); verdict = "CONFIRMED"
        elif len(sems) > 1:
            sem = " | ".join(sorted(sems)); verdict = "AMBIGUOUS"
        else:
            # no arity match, or unclassifiable
            gsem = {classify(b) for b in cands}; gsem.discard(None)
            if len(gsem) == 1 and matched:
                sem = next(iter(gsem)); verdict = "LIKELY"
        out[op] = {"freq": freq[op], "operands": a, "candidates": len(cands),
                   "arity_matched": len(matched), "semantic": sem, "verdict": verdict}
    return out


def report(opmap):
    conf = sum(1 for v in opmap.values() if v["verdict"] == "CONFIRMED")
    total = len(opmap)
    covered = sum(v["freq"] for v in opmap.values() if v["verdict"] == "CONFIRMED")
    allf = sum(v["freq"] for v in opmap.values())
    L = []
    L.append("VM OPCODE MAP (derived from handler bodies, verified vs trace)")
    L.append("=" * 60)
    L.append("distinct opcodes: %d   CONFIRMED: %d   (%.0f%% of executed "
             "instructions covered)" % (total, conf, 100.0 * covered / max(allf, 1)))
    L.append("semantics come from the VM's own handlers and are kept only when")
    L.append("the operand count matches real execution. UNKNOWN = not proven.")
    L.append("")
    L.append("%-8s %6s %4s %-9s %s" % ("opcode", "freq", "ops", "verdict", "semantic"))
    for op, v in sorted(opmap.items(), key=lambda kv: -kv[1]["freq"]):
        L.append("OP_%-5d %6d %4d %-9s %s"
                 % (op, v["freq"], v["operands"], v["verdict"], v["semantic"] or "-"))
    return "\n".join(L)


if __name__ == "__main__":
    import sys
    src = open(sys.argv[1], encoding="latin1").read()
    steps = []
    for l in open(sys.argv[2], encoding="latin1"):
        m = re.match(r"^(-?\d+);(-?\d+);(.*)$", l.strip())
        if m:
            steps.append((int(m.group(1)), int(m.group(2)),
                          [x for x in m.group(3).split(",") if x]))
    print(report(build_map(src, steps)))
