"""The program as text: every function, every instruction, both parts.

What this is and is not. It is not Lua source: recovering that needs the stack
simulated through every path, and the paths no run took have no values to
simulate with. It is the program's own instructions, in its own order, with the
things that ARE established written in:

  - the operation each opcode performs, read from the interpreter's handler for
    it rather than guessed from its number;
  - the constants an instruction names, decrypted by the interpreter's own
    resolver, so a string reads as a string;
  - where each jump goes, resolved by the interpreter's own arithmetic and
    checked against every jump the run took;
  - whether the run executed the instruction, and whether anything can reach it
    from its function's entry at all.

The last two are the point. A protected build of this family spends most of
itself measuring the host, and that part RUNS. The part that does the program's
own work sits behind a decryption and does not. So "what ran" and "what the
program does" are close to opposites here, and a reader needs both marked rather
than one of them presented as the answer.

Nothing is named a decoy. What an instruction is for is a judgement about intent,
and this file reports what was established: executed or not, reachable or not,
and the words it uses.
"""


def _ranges(nums):
    out = []
    for n in sorted(nums):
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return [tuple(x) for x in out]


def operand_text(fn, op, operands, const_ops, targets, pc, consts):
    """One instruction's operands, with what is known about them written in."""
    parts = []
    want = const_ops.get(op, ())
    for i, v in enumerate(operands):
        idx = i + 2
        if idx in want:
            c = consts.get(v)
            if isinstance(c, str):
                parts.append('%r' % c)
                continue
            if isinstance(c, (int, float)) and not isinstance(c, bool):
                parts.append("%s" % c)
                continue
            parts.append("const[%d]" % v)
            continue
        t = targets.get(pc)
        if t is not None and i == 0:
            parts.append("-> %d" % t[0])
            continue
        parts.append(str(v))
    return ", ".join(parts)


def listing(fns, decoded_by_pid, jumpers, const_ops, names=None,
            executed=None, limit_per_function=None):
    """Every function, every instruction, with what is established about it.

    `executed` is a set of (program counter, opcode) pairs, not of counters. The
    counter alone is shared between functions - every one of them starts at 1 -
    so marking by counter said three thousand of three thousand instructions had
    run, in a capture whose whole trace is smaller than that.
    """
    names = names or {}
    executed = executed or set()
    T = ["THE PROGRAM, INSTRUCTION BY INSTRUCTION",
         "=" * 58,
         "Both parts: the one the run executed and the one it did not. In a",
         "build of this family those are close to opposites - what runs is the",
         "measuring, and the program's own work sits behind a decryption it",
         "never got past - so neither is presented as the answer.",
         "",
         "Each line is:  pc  operation  operands",
         "  a name in quotes is a constant, decrypted by the interpreter's own",
         "    resolver",
         "  `-> n` is a jump target, resolved by the interpreter's own",
         "    arithmetic and checked against every jump the run took",
         "  `*` marks an instruction the run executed",
         "    matched by its counter AND its opcode: the counter alone is",
         "    shared between functions and marked instructions no run reached",
         "  `!` marks one nothing can reach from this function's entry",
         "  OP_<n> is an opcode whose handler this reading could not name; the",
         "    number is the build's own",
         ""]
    # How much of the mark can be trusted: the trace holds this many distinct
    # (counter, opcode) pairs, and the listing carries this many marks. Two
    # functions CAN share a pair, so the difference is the number of marks that
    # could belong to another function. Said here rather than left to be assumed.
    marks = sum(1 for pid in decoded_by_pid
                for pc, (op, _n, _o) in decoded_by_pid[pid].items()
                if (pc, op) in executed)
    total = sum(len(d) for d in decoded_by_pid.values())
    if executed:
        T += ["  The trace holds %d distinct (counter, opcode) pair(s). This"
              % len(executed),
              "  listing marks %d of its %d instruction(s) with one of them, so"
              % (marks, total),
              "  at most %d mark(s) belong to a different function that happens"
              % max(0, marks - len(executed)),
              "  to use the same counter for the same opcode.", ""]
    for pid in sorted(decoded_by_pid):
        fn = fns.get(pid)
        dec = decoded_by_pid[pid]
        if fn is None or not dec:
            continue
        reach = fn.reach or set()
        strs = sorted(v for v in (fn.consts.get(_const_field(fn)) or {}).values()
                      if isinstance(v, str) and v)
        T += ["", "=" * 58,
              "FUNCTION %d - %d instruction(s), %d reachable from its entry"
              % (pid, len(dec), len(reach)),
              "=" * 58]
        if strs:
            T.append("  the words it uses: " + ", ".join(repr(s) for s in strs))
            T.append("")
        gone = _ranges(set(dec) - reach)
        if gone:
            T.append("  unreachable: " + ", ".join(
                ("%d..%d" % r) if r[0] != r[1] else str(r[0])
                for r in gone[:12]))
            if len(gone) > 12:
                T.append("    ... and %d more stretch(es)" % (len(gone) - 12))
            T.append("")
        consts = fn.consts.get(_const_field(fn)) or {}
        shown = 0
        for pc in sorted(dec):
            if limit_per_function and shown >= limit_per_function:
                T.append("  ... %d more instruction(s)"
                         % (len(dec) - shown))
                break
            op, number, operands = dec[pc]
            mark = ("*" if (pc, op) in executed else " ")
            mark += ("!" if pc not in reach else " ")
            if op is None:
                what = "UNKNOWN(%d)" % number
            else:
                what = names.get(op) or ("OP_%d" % op)
            T.append("  %s %5d  %-12s %s"
                     % (mark, pc, what,
                        operand_text(fn, op, operands, const_ops, fn.targets,
                                     pc, consts)))
            shown += 1
    T.append("")
    return "\n".join(T)


def _const_field(fn):
    best, best_n = None, -1
    for fld, entries in (fn.consts or {}).items():
        n = sum(1 for v in entries.values() if v is not None)
        if n > best_n:
            best, best_n = fld, n
    return best


def split(fns, decoded_by_pid, jumpers, const_ops, names=None, executed=None):
    """The two parts on their own, so they can be read against each other.

    `executed` is a set of (counter, opcode) pairs, for the reason in `listing`.
    """
    names = names or {}
    executed = executed or set()
    ran, never = [], []
    for pid in sorted(decoded_by_pid):
        fn = fns.get(pid)
        dec = decoded_by_pid[pid]
        if fn is None or not dec:
            continue
        consts = fn.consts.get(_const_field(fn)) or {}
        reach = fn.reach or set()
        for pc in sorted(dec):
            op, number, operands = dec[pc]
            what = (names.get(op) or ("OP_%d" % op)) if op is not None \
                else "UNKNOWN(%d)" % number
            line = ("  f%-3d %5d  %-12s %s"
                    % (pid, pc, what,
                       operand_text(fn, op, operands, const_ops, fn.targets,
                                    pc, consts)))
            if (pc, op) in executed:
                ran.append(line)
            elif pc not in reach:
                never.append(line)
    T = ["THE TWO PARTS, APART",
         "=" * 58,
         "First what the run executed. In a build of this family that is the",
         "measuring: it reads the host's datatypes, instances and enums and",
         "folds what it reads into the key its own program is decrypted with.",
         "",
         "Then what nothing can reach from a function's entry. That part is",
         "not the program either - it is unreachable - and it is listed so a",
         "reader can see it rather than take anyone's word for it.",
         "",
         "What is NOT in either list is the rest: reachable, never executed.",
         "That is where the program's own work is, and it stays unexecuted",
         "while the decryption is wrong.",
         "",
         "EXECUTED (%d instruction(s))" % len(ran), "-" * 58]
    T += ran[:4000]
    if len(ran) > 4000:
        T.append("  ... and %d more" % (len(ran) - 4000))
    T += ["", "UNREACHABLE (%d instruction(s))" % len(never), "-" * 58]
    T += never[:4000]
    if len(never) > 4000:
        T.append("  ... and %d more" % (len(never) - 4000))
    T.append("")
    return "\n".join(T)


def _selftest():
    class F:
        def __init__(self):
            self.consts = {17: {3: "hello", 4: 7}}
            self.targets = {1: (4, "looked up")}
            self.reach = {1, 4}
    fn = F()
    decoded = {1: (275, 0, [99]), 2: (99, 0, []), 3: (99, 0, []),
               4: (287, 0, [3]), 5: (None, 4242, [])}
    names = {275: "JMP", 287: "LOADK", 99: "TRANSFORM"}
    ran = {(1, 275), (4, 287)}
    txt = listing({1: fn}, {1: decoded}, {275: 2}, {287: {2}}, names, ran)
    probs = []
    for want in ["FUNCTION 1", "JMP", "-> 4", "'hello'", "UNKNOWN(4242)",
                 "unreachable: 2..3", "the words it uses: 'hello'"]:
        if want not in txt:
            probs.append("the listing does not say %r" % want)
    if "*  " not in txt:
        probs.append("an executed instruction is not marked")
    if "!" not in txt:
        probs.append("an unreachable instruction is not marked")
    two = split({1: fn}, {1: decoded}, {275: 2}, {287: {2}}, names, ran)
    if "(4, 287)" in two:
        probs.append("the pair leaked into the text")
    if "EXECUTED (2 instruction(s))" not in two:
        probs.append("the executed count is wrong: %r"
                     % two.split("\n")[13:15])
    if "UNREACHABLE (3 instruction(s))" not in two:
        probs.append("the unreachable count is wrong")
    for p in probs:
        print("  PROBLEM: " + p)
    print("render selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()
