#!/usr/bin/env python3
"""
frames.py - tell one function's instructions from another's.

A VM numbers instructions per function, not per program: every closure it runs
starts counting from the beginning again. So the instruction number in a record
is only half an address. Without the other half, instruction 2 of forty
different functions is one instruction with forty predecessors, and everything
built on top - blocks, loops, branches, the split between the interpreter and
the program - is built on addresses that collide.

The missing half is recovered by matching calls with their returns, which the
trace shows directly:

  a function is ENTERED at an instruction that is never fallen into from the one
  before it and that many unrelated instructions jump to,

  and it RETURNS when control resumes at the instruction after whichever one
  called it.

Walking the trace with a stack of pending returns turns those two facts into a
frame for every record: which function it belongs to, and how deep the call
stack was. The function is then identified by its entry instruction, so the same
closure called from twenty places is one function, while instruction 2 of two
different closures stops being the same address.

The result is checked before it is used. Every push must find its return, and
the proportion that does is reported. When calls and returns do not line up, the
trace is left as a single frame and the report says so, because a wrong call
stack would invent structure rather than recover it.
"""
from collections import Counter, defaultdict

MIN_SITES = 3
MIN_MATCH = 0.5
MAX_DEPTH = 256


def entries(rows, min_sites=1):
    """Instructions that can begin a function: control reaches them by a jump
    and never by falling through from the instruction before them. A loop head
    is reached by falling in the first time round, so it is not one of these,
    which is what keeps a loop from being mistaken for a call."""
    jumped, fall = defaultdict(set), set()
    for a, b in zip(rows, rows[1:]):
        if b["pc"] == a["pc"] + 1:
            fall.add(b["pc"])
        else:
            jumped[b["pc"]].add(a["pc"])
    return {pc for pc, srcs in jumped.items()
            if pc not in fall and len(srcs) >= min_sites}


def _pairs(rows, ents, step=1):
    """Calls that were seen to return, as (call record, return record, entry).

    A jump into a function entry is only a guess until control comes back to the
    instruction after the one that jumped. Guesses that never come back are
    dropped, so a jump that merely looked like a call leaves no frame behind."""
    stack, pairs, abandoned = [], [], 0
    for i in range(1, len(rows)):
        b = rows[i]
        hit = None
        for d in range(len(stack) - 1, -1, -1):
            if b["pc"] == stack[d][0]:
                hit = d
                break
        if hit is not None:
            abandoned += len(stack) - 1 - hit
            del stack[hit + 1:]
            _exp, ci, ent = stack.pop()
            pairs.append((ci, i, ent))
            continue
        if b["pc"] in ents and b["pc"] != rows[i - 1]["pc"] + step \
                and len(stack) < MAX_DEPTH:
            stack.append((rows[i - 1]["pc"] + step, i, b["pc"]))
    return pairs, abandoned + len(stack)


def addresses_unique(rows, bar=0.9):
    """Whether an instruction number already identifies an instruction.

    Recovering frames only matters when numbers collide. They do not when almost
    every number carries one opcode and runs once: then the capture is a
    straight run through distinct instructions, the number is the address, and
    there is nothing for a call stack to disambiguate. Two signals say so, and
    both come from the capture."""
    if not rows:
        return False, "there are no records", 0.0, 0.0
    ops = defaultdict(set)
    hits = Counter()
    for r in rows:
        ops[r["pc"]].add(r["opcode"])
        hits[r["pc"]] += 1
    n = len(ops)
    one_op = sum(1 for v in ops.values() if len(v) == 1) / n
    once = sum(1 for c in hits.values() if c == 1) / n
    ok = one_op >= bar and once >= 0.5
    why = ("%.0f%% of instruction numbers carry a single opcode and %.0f%% ran "
           "exactly once, so a number already identifies an instruction"
           % (100 * one_op, 100 * once))
    if not ok:
        why = ("only %.0f%% of instruction numbers carry a single opcode and "
               "%.0f%% ran once, so numbers may be shared between functions"
               % (100 * one_op, 100 * once))
    return ok, why, one_op, once


def reconstruct(rows, min_match=MIN_MATCH):
    """Assign every record a function and a call depth.

    Returns (info, ok). `info` carries the evidence; `ok` is False when too few
    calls returned for the call stack to be trusted, in which case every record
    is left in one frame and the report says so."""
    if not rows:
        return _flat(rows, "there are no records to place"), False
    # Frames only matter when instruction numbers collide. When each number
    # already identifies one instruction there is nothing to disambiguate, and
    # inventing a call stack would only add structure the capture does not show.
    unique, uwhy, _a, _b = addresses_unique(rows)
    if unique:
        info = _flat(rows, uwhy + ", so no call stack had to be recovered")
        info["unique_addresses"] = True
        return info, True
    # How a build spells a call is not known in advance: how many places have
    # to jump to something before it counts as a function entry, and whether a
    # call resumes at the next instruction or the one after, both vary. Each
    # combination is tried and the one whose calls actually return is kept. The
    # measurement picks the reading; nothing here assumes one.
    best = None
    tried = []
    for step in (1, 2):
        for min_sites in (1, 2, 3, 5, 10, 20):
            ents = entries(rows, min_sites)
            if not ents:
                continue
            pairs, unreturned = _pairs(rows, ents, step)
            total = len(pairs) + unreturned
            if not total:
                continue
            rate = len(pairs) / total
            tried.append((step, min_sites, len(pairs), total, rate))
            if best is None or (rate, len(pairs)) > (best[0], len(best[1])):
                best = (rate, pairs, total, step, min_sites)
    if best is None:
        return _flat(rows, "no instruction is reached only by a jump, so there "
                           "is nothing that behaves like a function entry"), False
    rate, pairs, total, step, min_sites = best
    if not pairs or rate < min_match:
        detail = "; ".join("resume +%d, entered from %d+ site(s): %d/%d (%.0f%%)"
                           % (s2, m2, p2, t2, 100 * r2)
                           for s2, m2, p2, t2, r2 in sorted(
                               tried, key=lambda x: -x[4])[:4])
        return _flat(rows, "no way of reading calls in this build had enough of "
                           "them return: %s" % detail), False

    root = rows[0]["pc"]
    opened = defaultdict(list)
    for ci, ri, ent in pairs:
        opened[ci].append((ri, ent))

    # place every record in the innermost frame that contains it
    owner = [None] * len(rows)
    depths = [0] * len(rows)
    stack, frame_id, frame_of = [], {}, {}
    order = []
    for i in range(len(rows)):
        while stack and stack[-1][0] == i:
            stack.pop()
        for ri, ent in opened.get(i, ()):
            key = (i, ri, ent)
            frame_id[key] = len(order)
            order.append(key)
            stack.append((ri, ent, frame_id[key]))
        owner[i] = stack[-1][2] if stack else None
        depths[i] = len(stack)

    # Two functions can both start at instruction zero, so the entry alone does
    # not identify one. Frames are grouped by the instructions they actually
    # executed: the same function called twice runs the same instructions, while
    # a different function that happens to start at the same number does not.
    body = defaultdict(set)
    for i, f in enumerate(owner):
        if f is not None:
            body[f].add(rows[i]["pc"])
    groups, gid_of = [], {}
    for f, pcs in body.items():
        placed = None
        for g, (sig, members) in enumerate(groups):
            inter = len(sig & pcs)
            if inter and inter >= 0.8 * max(len(sig), len(pcs)):
                placed = g
                groups[g] = (sig | pcs, members + [f])
                break
        if placed is None:
            groups.append((set(pcs), [f]))
            placed = len(groups) - 1
        gid_of[f] = placed

    callers = defaultdict(set)
    fns = Counter()
    entry_of = {}
    for (ci, _ri, ent), f in frame_id.items():
        g = gid_of[f]
        entry_of.setdefault(g, ent)
        callers[g].add(rows[ci - 1]["pc"] if ci else root)
    for i, r in enumerate(rows):
        g = gid_of[owner[i]] + 1 if owner[i] is not None else 0
        r["fn"] = g
        r["proto"] = entry_of.get(g - 1, root) if g else root
        r["depth"] = depths[i]
        # which invocation, not which function: one call's local variables are
        # not the next call's, even in the same function
        r["frame"] = owner[i] if owner[i] is not None else -1
        fns[g] += 1
    entry_of = {g + 1: e for g, e in entry_of.items()}
    entry_of[0] = root
    callers = {g + 1: v for g, v in callers.items()}
    return {"functions": fns, "callers": callers, "entries": entry_of,
            "pushes": total, "returns": len(pairs), "rate": rate,
            "why": ("read as: a call resumes %d instruction(s) after its "
                    "caller, and an entry is jumped to from at least %d place(s)"
                    " - the reading whose calls actually returned. %d jump(s) "
                    "looked like a call; %d returned (%.0f%%), and only those "
                    "became frames; frames running the same instructions were "
                    "grouped into one function"
                    % (step, min_sites, total, len(pairs), 100 * rate)),
            "flat": False}, True


def _flat(rows, why):
    for r in rows:
        r["fn"] = 0
        r["proto"] = rows[0]["pc"] if rows else 0
        r["depth"] = 0
        r["frame"] = -1
    return {"functions": Counter({0: len(rows)}), "callers": {},
            "entries": {0: (rows[0]["pc"] if rows else 0)},
            "pushes": 0, "returns": 0, "rate": 0.0,
            "why": why, "flat": True, "unique_addresses": False}


def report(info):
    L = ["FUNCTIONS (recovered by matching calls with their returns)",
         "=" * 56,
         "A VM numbers instructions per function, so the same number means a",
         "different instruction in every function it runs. Records are placed in",
         "the function they belong to by walking the trace with a stack of",
         "pending returns.", "",
         "  " + info["why"], ""]
    if info.get("unique_addresses"):
        L.append("  No frames were needed, and none were invented. Every record")
        L.append("  keeps its own instruction number as its address, and the")
        L.append("  blocks, loops and branches reported elsewhere are addressed")
        L.append("  correctly.")
        return "\n".join(L)
    if info["flat"]:
        L.append("  Everything is treated as one function. Instruction numbers")
        L.append("  from different functions may collide, so blocks, loops and")
        L.append("  branches below are less reliable than usual and are reported")
        L.append("  as such rather than presented as structure.")
        return "\n".join(L)
    fns = info["functions"]
    L.append("  functions that ran: %d" % len(fns))
    L.append("")
    L.append("  %-14s %8s %10s %s"
             % ("function", "entry", "records", "called from"))
    for g, n in fns.most_common(40):
        cs = sorted(info["callers"].get(g, ()))
        where = ("%d site(s): %s" % (len(cs), ", ".join(str(c) for c in cs[:6]))
                 ) if cs else "the program's entry point"
        L.append("  fn%-12d %8d %10d %s"
                 % (g, info["entries"].get(g, 0), n, where))
    if len(fns) > 40:
        L.append("  ... %d more" % (len(fns) - 40))
    return "\n".join(L)
