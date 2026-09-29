#!/usr/bin/env python3
"""
staticcode.py - measure the program, not the run.

Without the interpreter's instruction array there is only the trace, and every
number taken from it is a number about one execution. "814 of 1219 instructions
accounted for" sounds like most of the program when 1219 is only what happened to
run; if the program holds four thousand instructions, the real figure is a fifth
of that. A report that cannot tell the difference flatters itself, and reading
the reference implementations makes the reason plain: they analyse a static
instruction list per prototype and measure against it.

The array gives four things the trace cannot:

  TRUE COVERAGE      how much of the program ran at all, not how much of the run
                     was understood.
  REAL BRANCH TARGETS  whether the side of a branch nobody took is an
                     instruction that exists, or a number that only looked like
                     one.
  CODE NEVER RUN     the instructions no execution reached, which is where the
                     behaviour this capture cannot account for lives.
  OPERAND SHAPE      what every instruction carries, including those that never
                     ran, which bounds what they could be.

What it cannot give is the meaning of an instruction that never ran. This
interpreter derives an opcode from the program counter and its own running state,
so an instruction that never executed has no opcode to read, and nothing here
guesses one. Unreached code is reported as present and unexplained, which is what
the evidence supports.
"""
from collections import Counter



def report(code, rows, cfg=None):
    if not code:
        return ("THE PROGRAM'S OWN INSTRUCTION ARRAY\n" + "=" * 46 + "\n"
                "The capture did not carry it, so everything measured here is\n"
                "measured against the instructions that ran rather than against\n"
                "the program. Coverage figures elsewhere in these reports are\n"
                "shares of the run, not of the script, and cannot be read as\n"
                "progress towards a complete reconstruction.\n\n"
                "The harness writes the array to code_array.txt when it can\n"
                "patch the dispatch loop; passing that file alongside the trace\n"
                "is what makes the figures below possible.")
    code, _shift, _wit, _alignwhy = aligned(code, rows)
    ran = {r["pc"] for r in rows}
    total = len(code)
    covered = len(ran & set(code))
    outside = sorted(ran - set(code))
    never = sorted(set(code) - ran)
    L = ["THE PROGRAM'S OWN INSTRUCTION ARRAY",
         "=" * 46,
         "Measured against the program, not against the run.", "",
         "How the two were lined up:",
         "  " + _alignwhy, "",
         "instructions in the program      %d" % total,
         "instructions this capture ran    %d (%.0f%% of the program)"
         % (covered, 100.0 * covered / max(total, 1)),
         "instructions never reached       %d" % len(never)]
    if outside:
        L.append("ran but not in the array         %d - the array read here does"
                 % len(outside))
        L.append("                                 not cover every chunk that ran")
    L.append("")
    if never:
        L.append("The instructions never reached are where behaviour this capture")
        L.append("cannot account for lives. Their operands are known; their")
        L.append("meaning is not, because this interpreter derives an opcode from")
        L.append("the program counter and its own running state, so an")
        L.append("instruction that never executed has no opcode to read. None is")
        L.append("guessed.")
        L.append("")
        L.append("first unreached instructions, with what they carry:")
        for pc in never[:30]:
            ops = [str(o) for o in code[pc] if o not in (None, "")]
            L.append("  pc %-6d %s" % (pc, ", ".join(ops[:8]) or "(no operands)"))
        if len(never) > 30:
            L.append("  ... %d more" % (len(never) - 30))
        L.append("")
    if cfg is not None and cfg.unexplored:
        real = [t for _a, t, _w in cfg.unexplored if t[1] in code]
        phantom = [t for _a, t, _w in cfg.unexplored if t[1] not in code]
        L.append("the branch sides nobody took, checked against the array:")
        L.append("  %d point at an instruction that exists" % len(real))
        L.append("  %d point at a number that is not an instruction - those were"
                 % len(phantom))
        L.append("    not branch targets at all, whatever they looked like")
        L.append("")
    return "\n".join(L)


def aligned(code, rows):
    """The array re-keyed into the trace's numbering, so the two can be
    compared at all. Returns (code, shift, witnesses, why)."""
    k, n, why = offset(code, rows)
    if not code or not k:
        return code, k, n, why
    return {pc + k: row for pc, row in code.items()}, k, n, why


def coverage(code, rows):
    """(instructions in the program, how many ran). Zeros when the array is
    absent, so a caller can tell the difference between full coverage and no
    measurement."""
    if not code:
        return 0, 0
    code, _k, _n, _why = aligned(code, rows)
    ran = {r["pc"] for r in rows}
    return len(code), len(ran & set(code))


# ---------------------------------------------------------------- alignment
# The trace numbers an instruction the way the interpreter's program counter
# does. The array is indexed the way the interpreter stores it. Those are not
# obliged to agree, and in at least one build they do not: an executed
# instruction reported at 4 carries the operands of array row 3.
#
# Comparing the two directly then shifts every coverage figure by one and, worse,
# offers the graph a fall-through target that is really the next instruction's
# neighbour - a phantom branch, from arithmetic rather than from evidence.
#
# The offset is not assumed. It is measured, by lining the operands the trace
# reported against the operands the array holds, and it is only used when
# enough instructions agree on the same answer.
MIN_WITNESSES = 3
MAX_SHIFT = 4


def _row_matches(row, ops):
    """Whether an array row carries exactly these operands after its first
    field, which is the instruction's own word rather than an operand."""
    if row is None or not ops:
        return False
    have = [x for x in row[1:1 + len(ops)]]
    return len(have) == len(ops) and have == list(ops)


def offset(code, rows, max_shift=MAX_SHIFT, min_witnesses=MIN_WITNESSES):
    """(shift, witnesses, why) - how far the trace's numbers sit from the
    array's, measured from the operands both of them report."""
    if not code or not rows:
        return 0, 0, ("there is no instruction array to line the trace up "
                      "against, so nothing is assumed about the numbering")
    votes = Counter()
    usable = 0
    for r in rows:
        ops = r.get("operands") or []
        if not ops:
            continue
        usable += 1
        for k in range(-max_shift, max_shift + 1):
            if _row_matches(code.get(r["pc"] - k), ops):
                votes[k] += 1
    if not votes:
        return 0, 0, ("no instruction reported operands that appear in the "
                      "array, so the two numberings could not be lined up; "
                      "they are treated as the same, which is what they "
                      "usually are")
    best, n = votes.most_common(1)[0]
    rival = max((v for k, v in votes.items() if k != best), default=0)
    if n < min_witnesses or n == rival:
        return 0, n, ("only %d instruction(s) of %d with operands could be "
                      "matched against the array%s, which is not enough to "
                      "establish the numbering. The two are treated as the "
                      "same and every figure measured against the array is "
                      "worth that much less"
                      % (n, usable,
                         " and another shift fits equally well" if n == rival
                         else ""))
    if best == 0:
        return 0, n, ("%d instruction(s) carried the operands of the array row "
                      "with the same number, so the trace and the array count "
                      "the same way" % n)
    return best, n, ("%d instruction(s) carried the operands of the array row "
                     "%d before their own number, so the trace counts %d ahead "
                     "of the array and is shifted back before anything is "
                     "measured against it" % (n, best, best))
