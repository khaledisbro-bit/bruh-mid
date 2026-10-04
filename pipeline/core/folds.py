"""Where two runs stop agreeing, and what that says about the host.

The key is five numbers the program accumulates, and the gate reads them at the
end. Reading them at the end says nothing: change one host answer and all five
move, so the five have no way of pointing at the answer that was wrong.

What does point at it is the CHAIN. The program folds its measurements one at a
time, through one helper - ninety-three instructions, three parameters, called a
hundred and ninety-four times a run - and the interpreter performs that helper's
modulo in one place per fused opcode. Watching that place writes the chain down:
every value folded, in order, with the counter it was folded at.

Two runs of the same build on the same bytes fold the same chain, step for step,
unless the host answered differently. So:

  run it once, change ONE answer, run it again, and find the first step where the
  two chains part. That step is where the answer was read.

That turns a key that is wrong all over into a position. Do it once per answer and
the map says which step belongs to which host fact - and a step with no answer
against it is a measurement this analysis has not accounted for at all, which is
the most useful thing the chain can say.

Nothing here reconstructs anything. It reads two captures and reports where they
differ.
"""


def section(path, name):
    """One named section of a capture, as a list of lines."""
    out, on = [], False
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line == "---%s---" % name:
                on = True
                continue
            if on and line.startswith("---"):
                break
            if on:
                out.append(line)
    return out


def mods(path):
    """The moduli the fold performed: (pc, before, modulus, after, opcode, fn)."""
    out = []
    for line in section(path, "MODS"):
        parts = line.split(";")
        if len(parts) < 4:
            continue
        try:
            row = [int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])]
        except ValueError:
            continue
        row += parts[4:6]
        out.append(tuple(row))
    return out


def call_args(path, fn=None):
    """What each logged call was handed: (fn, [arguments])."""
    out = []
    for line in section(path, "CALLARGS"):
        parts = line.split(";")
        if len(parts) < 3:
            continue
        try:
            who = int(parts[0])
        except ValueError:
            continue
        if fn is not None and who != fn:
            continue
        vals = []
        for piece in parts[2].split(","):
            if piece == "":
                continue
            try:
                vals.append(int(piece))
            except ValueError:
                vals.append(piece)
        out.append((who, vals))
    return out


def first_difference(a, b):
    """The index where two chains part, and both entries there."""
    for i in range(min(len(a), len(b))):
        if a[i] != b[i]:
            return i, a[i], b[i]
    if len(a) != len(b):
        i = min(len(a), len(b))
        return i, (a[i] if i < len(a) else None), (b[i] if i < len(b) else None)
    return None, None, None


def compare(base_path, other_path, fn=None):
    """Both chains of two captures, and where each one parts."""
    out = {}
    ba, oa = call_args(base_path, fn), call_args(other_path, fn)
    bm, om = mods(base_path), mods(other_path)
    i, x, y = first_difference(ba, oa)
    out["args"] = {"base": len(ba), "other": len(oa), "at": i,
                   "base_here": x, "other_here": y}
    i, x, y = first_difference(bm, om)
    out["mods"] = {"base": len(bm), "other": len(om), "at": i,
                   "base_here": x, "other_here": y}
    return out


def timeline(path, fn=93, steps=None):
    """The fold steps of one pass, each with the host question it sits after.

    The run makes several attempts at several patch levels and the chain repeats,
    so one pass is taken from the front. Repeated positions are collapsed: what is
    left is the order the build puts its questions in.
    """
    rows = []
    for line in section(path, "CALLARGS"):
        parts = line.split(";")
        if len(parts) < 3 or parts[0] != str(fn):
            continue
        rows.append(parts)
    if steps:
        rows = rows[:steps]
    out, last = [], None
    for i, parts in enumerate(rows, 1):
        here = (parts[4] if len(parts) > 4 else "-",
                parts[5] if len(parts) > 5 else "-")
        if here != last:
            out.append((i, here[0], here[1]))
            last = here
    return out, len(rows)


def write_timeline(rows, total, path):
    lines = ["WHAT THE BUILD MEASURES, IN ORDER", "",
             "Every step where the build folds something into the numbers that",
             "become its key, with the question it had just put to the host. The",
             "step count is one pass of the measurement layer. A step is not the",
             "same thing as a question - several steps can follow one answer - but",
             "the order is the build's own, and a wrong answer shows up at the",
             "first step after it.",
             "",
             "%d fold step(s) in one pass." % total,
             ""]
    for step, read, call in rows:
        lines.append("step %4d" % step)
        if read and read != "-":
            lines.append("    last read: %s" % read)
        if call and call != "-":
            lines.append("    last call: %s" % call)
    open(path, "w").write("\n".join(lines) + "\n")


def write_report(rows, path):
    """rows: [(what was changed, the comparison)] in the order they were run."""
    lines = ["FOLD CHAIN", "",
             "The answers this build folds into its key, and the ones it reads and",
             "throws away. Sorted by where each one enters the chain.",
             ""]
    ordered = sorted(rows, key=lambda r: (r[1]["args"]["at"] is None,
                                          r[1]["args"]["at"] or 0))
    for what, cmp in ordered:
        at = cmp["args"]["at"]
        if at is None:
            lines.append("  read and thrown away   %s" % what)
        else:
            lines.append("  folded at step %-4d    %s" % (at, what))
    lines += ["",
              "A change that parts the chain is folded. A change that leaves it",
              "identical step for step is a decoy read: the build asked, and did",
              "nothing with the answer.",
              "", "----", ""]
    lines += [
             "Each line is one host answer changed on purpose, and the step where",
             "the run stopped agreeing with the untouched run. The step is where",
             "that answer is read and folded. A change that parts the chain at a",
             "later step is read later; one that parts it at step 0 is read before",
             "anything else; one that does not part it at all is not folded.",
             ""]
    for what, cmp in rows:
        lines.append(what)
        for name in ("args", "mods"):
            d = cmp[name]
            if d["at"] is None:
                lines.append("    %-5s identical, %d step(s)" % (name, d["base"]))
            else:
                lines.append("    %-5s parts at step %d of %d"
                             % (name, d["at"], d["base"]))
                lines.append("          untouched: %s" % (d["base_here"],))
                lines.append("          changed:   %s" % (d["other_here"],))
        lines.append("")
    open(path, "w").write("\n".join(lines) + "\n")


def selftest():
    bad = []
    a = [(1, [1, 2, 3]), (1, [4, 5, 6]), (2, [7, 8, 9])]
    b = [(1, [1, 2, 3]), (1, [4, 5, 7]), (2, [7, 8, 9])]
    i, x, y = first_difference(a, b)
    if i != 1 or x != a[1] or y != b[1]:
        bad.append("the first difference of two chains is not where it is")
    if first_difference(a, a)[0] is not None:
        bad.append("a chain differs from itself")
    i, _, _ = first_difference(a, a[:2])
    if i != 2:
        bad.append("a chain that stops early does not report where")
    for line in bad:
        print("  WRONG: %s" % line)
    print("folds selftest: %s" % ("ok" if not bad else "%d problem(s)" % len(bad)))
    return not bad


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        selftest()
    else:
        base = sys.argv[1]
        tl, total = timeline(base, fn=93, steps=194)
        write_timeline(tl, total, "MEASUREMENTS.txt")
        rows = []
        for other in sys.argv[2:]:
            # label=path names the answer that was changed, for the report
            label, _, path = other.partition("=")
            if not path:
                label, path = other, other
            rows.append((label, compare(base, path, fn=93)))
        write_report(rows, "FOLD_CHAIN.txt")
        for what, cmp in rows:
            print("%s: args at %s, mods at %s"
                  % (what, cmp["args"]["at"], cmp["mods"]["at"]))
