"""What the program asked its host, and what it did with the answer.

A build that is protecting itself spends much of its run measuring the machine
it is on: it asks whether an object is a Lighting, then a Model, then a
Workspace; it makes a Folder, sets an attribute, reads it back, destroys it; it
asks the run service whether this is a client and whether it is a server. None
of that is work. It is the build checking that it is where it expects to be,
and a reader who takes it for the program's behaviour has the wrong program.

Telling the two apart by how the names read is not analysis. `Folder` is a real
class and an unreadable name can belong to a real object. What separates them is
what happens to the answer, and that is in the records once the environment
numbers every object it hands out:

  ASKED AND NEVER USED   the host answered with an object or a value, and
                         nothing the program did afterwards was done to it or
                         with it. The program wanted to know, not to have.
  ASKED AND USED         the answer came back as the receiver of a later call,
                         or as an argument to one. The program is working with
                         what it got.
  BUILT AND ABANDONED    an object was constructed and nothing ever touched it
                         again: not parented, not read, not destroyed.
  BUILT AND USED         constructed, then used.

Nothing here is deleted and nothing is called a decoy. "The program never used
this answer" is a fact about this run; it is strong evidence that the call is a
measurement rather than work, and it is left as evidence rather than turned into
a verdict. The repeated-suite count is reported for the same reason: a sequence
of questions asked over and over, with the answers dropped each time, is what
self-checking looks like from outside - but a program may poll its world too,
and this analysis cannot tell intent, only use.
"""
from collections import Counter, OrderedDict


ASKED_UNUSED = "asked and never used"
ASKED_USED = "asked and used"
BUILT_ABANDONED = "built and abandoned"
BUILT_USED = "built and used"


def _is_construction(rec):
    return (rec.get("method") or "") in ("Instance.new", "new")


def _is_lookup(rec):
    return (rec.get("method") or "") in ("GetService", "FindService",
                                         "service")


def study(records):
    """One verdict per recorded call, from the identities in the records."""
    used_ids = set()
    for rec in records or ():
        if not isinstance(rec, dict):
            continue
        if rec.get("on") is not None:
            used_ids.add(rec["on"])
        for a in rec.get("args") or ():
            a = a.strip()
            if a.startswith("#") and a[1:].isdigit():
                used_ids.add(int(a[1:]))
    out = []
    for rec in records or ():
        if not isinstance(rec, dict):
            continue
        gave = rec.get("gave")
        built = _is_construction(rec)
        if gave is None:
            # nothing identifiable came back: a boolean, a number, a string, or
            # nothing at all. Whether the program used it cannot be told this
            # way, so nothing is claimed about it.
            out.append((rec, None))
            continue
        if gave in used_ids:
            out.append((rec, BUILT_USED if built else ASKED_USED))
        else:
            out.append((rec, BUILT_ABANDONED if built else ASKED_UNUSED))
    return out


def suites(records, least=2):
    """Sequences of calls that repeat verbatim, with how often.

    A build checking itself runs the same questions again and again. The
    sequence is found by its own repetition, not by what the calls are called.
    """
    keys = [(r.get("recv"), r.get("method"), tuple(r.get("args") or ()))
            for r in records or () if isinstance(r, dict)]
    seen = Counter()
    n = len(keys)
    for size in (6, 5, 4, 3):
        for i in range(n - size + 1):
            seen[tuple(keys[i:i + size])] += 1
    out = [(k, c) for k, c in seen.items() if c >= least]
    out.sort(key=lambda kv: (-kv[1] * len(kv[0]), -len(kv[0])))
    return out[:8]


def report(records):
    verdicts = study(records)
    counts = Counter(v for _r, v in verdicts if v)
    T = ["WHAT THE PROGRAM ASKED ITS HOST, AND WHAT IT DID WITH THE ANSWER",
         "=" * 64,
         "The environment numbers every object it hands out, so a record can",
         "say whether the answer came back later as something the program used.",
         "That is the difference between a build doing its work and a build",
         "measuring the machine it is on - and it is in the records, not in how",
         "the names read.",
         "",
         "Nothing below is deleted and nothing is called a decoy. An answer the",
         "program never used is evidence, and it is left as evidence.",
         ""]
    if not counts:
        T.append("  No call in this capture came back with an object this")
        T.append("  environment could number, so nothing can be said this way.")
        return "\n".join(T)
    for k in (ASKED_UNUSED, ASKED_USED, BUILT_ABANDONED, BUILT_USED):
        T.append("  %-4d %s" % (counts.get(k, 0), k))
    T.append("")
    groups = OrderedDict()
    for rec, v in verdicts:
        if v is None:
            continue
        groups.setdefault(v, []).append(rec)
    for v, rows in groups.items():
        T.append(v.upper())
        T.append("-" * 64)
        what = Counter(r.get("raw") or "" for r in rows)
        for line, n in what.most_common(14):
            T.append("  %s%s" % (line, "" if n == 1 else "   x%d" % n))
        if len(what) > 14:
            T.append("  ... %d more" % (len(what) - 14))
        T.append("")
    rep = suites(records)
    if rep:
        T += ["THE SAME QUESTIONS, ASKED AGAIN",
              "-" * 64,
              "Sequences that repeat in this one run, found by their own",
              "repetition. A build that keeps asking and keeps dropping the",
              "answers is checking itself; a program may also poll its world,",
              "and this cannot tell intent - only that the sequence repeats.",
              ""]
        for keys, n in rep[:5]:
            T.append("  x%d:" % n)
            for recv, meth, args in keys:
                T.append("      %s%s(%s)"
                         % ((recv + ":") if recv else "", meth,
                            ", ".join(args)))
            T.append("")
    return "\n".join(T)


def _selftest():
    recs = [
        {"method": "Instance.new", "args": ['"Folder"'], "gave": 1,
         "raw": 'Instance.new: Folder'},
        {"recv": "Folder", "method": "Destroy", "args": [], "on": 1,
         "raw": "Folder:Destroy()"},
        {"method": "Instance.new", "args": ['"Noise"'], "gave": 2,
         "raw": "Instance.new: Noise"},
        {"method": "GetService", "args": ['"Players"'], "gave": 3,
         "raw": "GetService: Players"},
        {"recv": "Players", "method": "IsA", "args": ['"Model"'], "on": 3,
         "raw": 'Players:IsA("Model")'},
    ]
    got = {r.get("raw"): v for r, v in study(recs)}
    probs = []
    if got.get("Instance.new: Folder") != BUILT_USED:
        probs.append("an object that was later destroyed was not seen as used")
    if got.get("Instance.new: Noise") != BUILT_ABANDONED:
        probs.append("an object nothing ever touched was not seen as abandoned")
    if got.get("GetService: Players") != ASKED_USED:
        probs.append("a service that was later called on was not seen as used")
    if not report(recs).strip():
        probs.append("the report came out empty")
    for p in probs:
        print("  PROBLEM: " + p)
    print("antitamper selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()
