#!/usr/bin/env python3
"""
noise.py - separate the interpreter's own machinery from the program it runs.

A VM that decrypts every constant on demand spends most of its instructions
inside its own helper routines. Those belong to the interpreter, not to the
program, and folding them away is what makes the later analysis describe the
program instead of the decryptor.

Frequency cannot decide this: a hot program loop and a hot helper look identical
in a histogram. The split is made on three properties of the executed stream that
a called helper has and ordinary program code does not:

  NO FALL-THROUGH   the helper's first instruction is never reached from the
                    instruction physically before it. Program code is reached by
                    falling through from its predecessor; a helper is only ever
                    jumped into.
  FAN-IN            it is entered from several unrelated instructions. A loop
                    head is entered from its predecessor and its own back edge.
  BALANCED RETURN   the burst gives control back to the instruction after its
                    caller and leaves the program's stack pointer exactly where
                    it found it. A loop's back edge returns to its own head.

A fourth check, SEALED OUTPUT (no program instruction consumes what the helper
produced), is applied later by the lifter, which can reclassify a region that
turns out to feed the program. Nothing here is keyed to a pc range, an opcode
number, a burst length or a build.
"""
from collections import Counter, defaultdict

MIN_SITES = 3
MIN_RETURN = 0.6
MAX_BURST = 20000
GAP = 2


def _edges(rows):
    preds = defaultdict(set)
    fall = set()
    for a, b in zip(rows, rows[1:]):
        preds[b["pc"]].add(a["pc"])
        if b["pc"] == a["pc"] + 1:
            fall.add(b["pc"])
    return preds, fall


def _near(q, body, gap):
    return any(abs(q - b) <= gap for b in body)


def _seed_body(h, preds, freq, gap=GAP):
    """First guess at the helper's body: instructions that are reached only from
    inside it, run more than once, and sit next to the code already in it.

    The locality test is what keeps the caller's own code out. A routine's
    instructions are laid out together, so the helper's body is contiguous, while
    the instruction the helper returns to lives back in the caller - far away in
    the instruction stream even though the helper is its only predecessor."""
    body = {h}
    changed = True
    while changed:
        changed = False
        for q, ps in preds.items():
            if q in body or freq[q] < 2:
                continue
            if ps <= body and _near(q, body, gap):
                body.add(q)
                changed = True
    return body


def _rate(rows, body):
    """How often a burst through `body` hands control back to the instruction
    after its caller with the stack pointer restored."""
    pairs = matched = 0
    for caller, entry, resume in _runs(rows, body):
        if caller is None or resume is None:
            continue
        pairs += 1
        if (resume["pc"] - caller["pc"] in (1, 2) and
                (entry["sp"] is None or resume["sp"] is None or
                 entry["sp"] == resume["sp"])):
            matched += 1
    return matched, pairs


def _grow_body(h, preds, freq, rows, max_steps=32):
    """Grow the body until bursts through it return cleanly.

    A burst that stops early was cut short by an instruction that belongs to the
    helper but was not in the seed. Adding it is accepted only when it makes MORE
    bursts return to their caller - so program code, which never improves the
    return rate, cannot be absorbed."""
    body = _seed_body(h, preds, freq)
    matched, pairs = _rate(rows, body)
    best = matched / pairs if pairs else 0.0
    for _ in range(max_steps):
        cand = set()
        for caller, _entry, resume in _runs(rows, body):
            if caller is None or resume is None:
                continue
            if resume["pc"] - caller["pc"] not in (1, 2):
                cand.add(resume["pc"])
        cand = {q for q in cand - body if _near(q, body, GAP)}
        if not cand:
            break
        gained = False
        for pc in sorted(cand, key=lambda q: -freq[q]):
            m2, p2 = _rate(rows, body | {pc})
            r2 = m2 / p2 if p2 else 0.0
            if r2 > best:
                body.add(pc)
                best = r2
                gained = True
        if not gained:
            break
    return body


def _runs(rows, body):
    """Maximal runs of consecutive rows executing inside the body, each with the
    row that called into it and the row control resumed at."""
    out, i, n = [], 0, len(rows)
    while i < n:
        if rows[i]["pc"] not in body:
            i += 1
            continue
        j = i
        while j + 1 < n and rows[j + 1]["pc"] in body:
            j += 1
        out.append((rows[i - 1] if i > 0 else None, rows[i],
                    rows[j + 1] if j + 1 < n else None))
        i = j + 1
    return out


def analyse(rows, min_sites=MIN_SITES, min_return=MIN_RETURN):
    """Find interpreter helper routines in the executed stream.

    Returns (machinery_pcs, entries); entries carries the evidence behind every
    verdict so the report can justify each folded instruction."""
    if not rows:
        return set(), []
    preds, fall = _edges(rows)
    freq = Counter(r["pc"] for r in rows)

    cands = [pc for pc, ps in preds.items()
             if len(ps) >= min_sites and pc not in fall]
    cands.sort(key=lambda pc: -freq[pc])

    mach, entries, claimed = set(), [], set()
    for h in cands:
        if h in claimed:
            continue
        body = _grow_body(h, preds, freq, rows)
        matched, pairs = _rate(rows, body)
        rate = (matched / pairs) if pairs else 0.0
        ok = pairs >= min_sites and rate >= min_return
        info = {"entry": h, "sites": len(preds[h]), "bursts": pairs,
                "returned": matched, "return_match": rate, "machinery": ok,
                "body": sorted(body),
                "why": ("never fallen into from pc %d; entered from %d distinct "
                        "instruction(s); %d/%d bursts returned to the caller's "
                        "next instruction with the stack pointer restored (%.0f%%)"
                        % (h - 1, len(preds[h]), matched, pairs, 100 * rate))}
        entries.append(info)
        if ok:
            mach |= body
            claimed |= body
    return mach, entries


def machinery(rows, **kw):
    return analyse(rows, **kw)[0]


def split(rows, mach=None):
    """Return (program_rows, bursts). bursts[i] holds the machinery rows that ran
    immediately before program_rows[i]; program rows keep their capture indices so
    provenance still points at the raw capture lines."""
    if mach is None:
        mach = machinery(rows)
    prog, bursts, pending = [], [], []
    for r in rows:
        if r["pc"] in mach:
            pending.append(r)
            continue
        prog.append(r)
        bursts.append(pending)
        pending = []
    return prog, bursts


def report(rows, reclassified=None):
    mach, entries = analyse(rows)
    prog, _ = split(rows, mach)
    L = ["INTERPRETER MACHINERY vs PROGRAM CODE",
         "=" * 46,
         "Helper routines found in the executed control flow, with the evidence",
         "for each verdict. A helper is only ever jumped into, is entered from",
         "many unrelated instructions, and returns to its caller with the stack",
         "pointer restored. A program loop matches none of those.", ""]
    if not entries:
        L.append("  no instruction matched the helper shape; the whole stream is")
        L.append("  treated as program code.")
    for e in sorted(entries, key=lambda x: -x["bursts"]):
        L.append("  entry pc %-7d %-22s %d instruction(s) in body"
                 % (e["entry"], "FOLDED (machinery)" if e["machinery"]
                    else "KEPT (program)", len(e["body"])))
        L.append("      " + e["why"])
    if reclassified:
        L.append("")
        L.append("  reclassified after value lifting (their output DID reach the")
        L.append("  program, so they are program code after all): " +
                 ", ".join(str(p) for p in sorted(reclassified)))
    L.append("")
    L.append("instructions: %d captured -> %d program, %d folded as machinery"
             % (len(rows), len(prog), len(rows) - len(prog)))
    return "\n".join(L)
