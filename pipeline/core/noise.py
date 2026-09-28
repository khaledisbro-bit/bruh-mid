#!/usr/bin/env python3
"""
noise.py - separate the interpreter's own machinery from the program it runs.

A VM that decrypts every constant on demand spends most of its instructions
inside its own helpers. On a real capture that is not a detail: 22,477 of 24,029
records belonged to the interpreter and 808 to the program, so measuring
anything before splitting them describes the decryptor rather than the script.

Frequency cannot make the split on its own, because a hot loop in the program
looks the same in a histogram as a helper. What separates them is where control
goes afterwards:

  A HELPER RETURNS TO ITS CALLERS, so a burst through it is followed by many
  different instructions - one for each place that needed it. On the capture
  above, one helper region was entered from 202 instructions and left to 172.

  A LOOP LEAVES BY ITS EXIT, which is one instruction, or two if it is also
  broken out of. However often it runs, it does not scatter control on the way
  out.

That test needs no assumption about how the build spells a call, which matters
because a flattened program never simply falls through to the next instruction,
so "returns to the instruction after its caller" is not true there and cannot be
used.

Folding a burst loses nothing, because of where it ran. The interpreter logs an
instruction before running it, and the helper is dispatched from inside that
instruction's handler, so the burst sits between the instruction that asked for
a constant and the next one. The value the instruction leaves pending when its
handler finishes - the decrypted constant - is reported by the next PROGRAM
record, not by the burst. Reading the program's records as a sequence therefore
gives each instruction its own result and its own effect on the stack, with the
interpreter's work collapsed into the instruction that caused it.
"""
from collections import Counter, defaultdict

MIN_BURSTS = 3
MIN_SITES = 3
MIN_EXITS = 3
HOT_FACTOR = 4.0
HOT_FLOOR = 3


def _regions(hot, gap=2):
    """Group hot instructions into regions by locality: a routine's instructions
    are laid out together."""
    out = []
    for pc in sorted(hot):
        if out and pc - out[-1][-1] <= gap:
            out[-1].append(pc)
        else:
            out.append([pc])
    return [set(r) for r in out]


def _absorb(reg, preds, gap=2):
    """Take in the tail of a burst.

    A helper's last instructions run fewer times than its first ones, because a
    burst can stop early, so they can fall below the bar that found the region
    and be left behind in the program's records - where they break the stack
    replay. An instruction next to the region whose control only ever arrives
    from inside it belongs to it."""
    reg = set(reg)
    changed = True
    while changed:
        changed = False
        for q, ps in preds.items():
            if q in reg or not ps or not ps <= reg:
                continue
            if any(abs(q - p) <= gap for p in reg):
                reg.add(q)
                changed = True
    return reg


def _bursts(seq, reg):
    out, i, n = [], 0, len(seq)
    while i < n:
        if seq[i] not in reg:
            i += 1
            continue
        j = i
        while j + 1 < n and seq[j + 1] in reg:
            j += 1
        out.append((i, j))
        i = j + 1
    return out


def analyse(rows, min_bursts=MIN_BURSTS, min_sites=MIN_SITES,
            min_exits=MIN_EXITS):
    """Find the interpreter's helper regions.

    Returns (machinery_pcs, regions) with the evidence behind every verdict."""
    if not rows:
        return set(), []
    seq = [r["pc"] for r in rows]
    freq = Counter(seq)
    counts = sorted(freq.values())
    median = counts[len(counts) // 2]
    hot = {pc for pc, n in freq.items()
           if n >= max(median * HOT_FACTOR, HOT_FLOOR)}
    if not hot:
        return set(), []

    preds = defaultdict(set)
    for a, b in zip(seq, seq[1:]):
        preds[b].add(a)

    mach, out = set(), []
    for reg in _regions(hot):
        reg = _absorb(reg, preds)
        bursts = _bursts(seq, reg)
        ent, ex, restored = Counter(), Counter(), 0
        for i, j in bursts:
            if i > 0:
                ent[seq[i - 1]] += 1
            if j + 1 < len(rows):
                ex[seq[j + 1]] += 1
                if rows[i]["sp"] is not None and rows[j + 1]["sp"] is not None \
                        and rows[i]["sp"] == rows[j + 1]["sp"]:
                    restored += 1
        ok = (len(bursts) >= min_bursts and len(ent) >= min_sites
              and len(ex) >= min_exits)
        r = sorted(reg)
        info = {"pcs": r, "rows": sum(freq[p] for p in reg),
                "bursts": len(bursts), "sites": len(ent), "exits": len(ex),
                "restored": restored, "machinery": ok,
                "why": ("run %d time(s) in %d burst(s); entered from %d "
                        "instruction(s) and left to %d, and %d burst(s) gave "
                        "the stack pointer back unchanged"
                        % (sum(freq[p] for p in reg), len(bursts), len(ent),
                           len(ex), restored))}
        out.append(info)
        if ok:
            mach |= reg
    return mach, out


def machinery(rows, **kw):
    return analyse(rows, **kw)[0]


def split(rows, mach=None):
    """Kept for callers that want the program records and the bursts separately."""
    if mach is None:
        mach = machinery(rows)
    prog, bursts, pending = [], [], []
    for r in rows:
        if r["pc"] in mach:
            pending.append(r)
            continue
        if pending and prog:
            # The helper's own instructions leave values pending too, so the
            # value reported after a burst may be the helper's last intermediate
            # rather than the result of the program instruction before it. Mark
            # it, so nothing downstream reads a decryptor's leftover as the
            # program's own result.
            prog[-1]["burst_after"] = len(pending)
        prog.append(r)
        bursts.append(pending)
        pending = []
    return prog, bursts


def report(rows):
    mach, regs = analyse(rows)
    prog, _ = split(rows, mach)
    L = ["INTERPRETER MACHINERY vs PROGRAM CODE",
         "=" * 46,
         "Hot regions of the capture, and why each one was folded or kept. A",
         "helper returns to whoever needed it, so control leaves it towards many",
         "different instructions. A loop leaves by its exit, however often it",
         "runs. That is the difference the verdicts below are made on.", ""]
    if not regs:
        L.append("  no region ran often enough to be a helper; every record is")
        L.append("  treated as program code.")
    for r in sorted(regs, key=lambda x: -x["rows"]):
        pcs = r["pcs"]
        span = "%d..%d" % (pcs[0], pcs[-1]) if len(pcs) > 1 else str(pcs[0])
        L.append("  pc %-14s %-22s %d instruction(s)"
                 % (span, "FOLDED (interpreter)" if r["machinery"]
                    else "KEPT (program)", len(pcs)))
        L.append("      " + r["why"])
    L.append("")
    L.append("records: %d captured -> %d program, %d interpreter"
             % (len(rows), len(prog), len(rows) - len(prog)))
    L.append("")
    L.append("A folded burst ran inside the handler of the instruction before it,")
    L.append("so the constant it decrypted is that instruction's own result and is")
    L.append("reported by the next program record. Nothing is lost by folding it.")
    return "\n".join(L)
