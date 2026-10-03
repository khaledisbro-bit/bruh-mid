"""The point where the build stops checking and starts running the program.

A protected build of this family does not compare the host against anything it
carries. It MEASURES the host and uses the measurements as the decryption key for
its own program:

    K       = three numbers mixed from what it measured
    PROGRAM = deserialise(decrypt(SLICE(n), K))
    return  MAKER(PROGRAM, {})(...)

So there is no branch to force and no digest to satisfy. A host that answers one
measurement differently produces a different key, the decryption yields noise,
and the deserialiser hands back a number instead of a program - which is why a
run that gets this far ends by indexing a number rather than by failing a check.

Everything here is read out of the capture the harness wrote. The harness records
the key where it is built, what the decryption produced, every slice in the
table rather than only the ones asked for, every value the digest function was
given, and every property the program read off a host object. None of it is
inferred.
"""
import re


def _section(capture, name):
    return (getattr(capture, "sections", None) or {}).get(name, []) or []


def read(capture):
    """The key, what it was made of, and what the decryption produced."""
    out = {"keys": [], "inputs": [], "produced": None, "slices": [],
           "asked": [], "swap": None, "digests": {}, "reads": [],
           "reads_total": None, "refused": []}
    for ln in _section(capture, "SLICES"):
        m = re.match(r"^key:(.*?)(?:\s\sfrom:(.*))?$", ln)
        if m:
            nums = [int(x) for x in re.findall(r"=(-?\d+)", m.group(1) or "")]
            if nums and nums not in out["keys"]:
                out["keys"].append(nums)
            if m.group(2):
                ins = [x for x in m.group(2).split(",")]
                if ins and ins not in out["inputs"]:
                    out["inputs"].append(ins)
            continue
        m = re.match(r"^gate: the payload decrypted to (.+)$", ln)
        if m:
            out["produced"] = m.group(1)
            continue
        m = re.match(r"^table:(\w+):(\d+):(.*)$", ln)
        if m:
            f = dict((int(a), int(b))
                     for a, b in re.findall(r"(\d+)=(-?\d+)", m.group(3)))
            out["slices"].append({"accessor": m.group(1),
                                  "index": int(m.group(2)),
                                  "length": f.get(1), "offset": f.get(2)})
            continue
        m = re.match(r"^swap:(.*)$", ln)
        if m:
            out["swap"] = m.group(1)
            continue
        m = re.match(r"^(\w+):(\d+):(ok|MISSING):(-?\d+)$", ln)
        if m and int(m.group(2)) not in out["asked"]:
            out["asked"].append(int(m.group(2)))
    # what the digest function was given, and what it answered
    for ln in _section(capture, "HASHES"):
        m = re.match(r"^out=(\w+)\|in1=(.+?)(?:\|in2=.*)?$", ln)
        if not m:
            continue
        what = m.group(2)
        if what.startswith("s$"):
            hx = what[2:].split(":cut")[0]
            if len(hx) > 80:
                continue
            try:
                what = '"%s"' % bytes.fromhex(hx).decode("utf8")
            except Exception:
                continue
        elif what.startswith("n=") or what.startswith("b="):
            what = what[2:]
        else:
            continue
        out["digests"].setdefault(m.group(1), what)
    for ln in _section(capture, "READS"):
        m = re.match(r"^reads_total: (\d+)$", ln)
        if m:
            out["reads_total"] = int(m.group(1))
        elif " -> " in ln:
            out["reads"].append(ln)
    out["refused"] = list(_section(capture, "REFUSEDCLASSES"))
    return out


def report(g):
    T = ["THE GATE: WHERE THE CHECKING ENDS AND THE PROGRAM BEGINS",
         "=" * 58,
         "This build does not compare the host against anything it carries. It",
         "measures the host, and the measurements ARE the key its own program is",
         "decrypted with. So no branch can be forced to reach the program, and a",
         "host that answers one measurement differently gets noise back.",
         ""]
    if not g["keys"]:
        T += ["The run did not reach the gate, so there is nothing to read "
              "here.", ""]
        return "\n".join(T)
    T += ["THE KEY THIS RUN PRODUCED", "-" * 58]
    for k in g["keys"]:
        T.append("  " + ", ".join(str(x) for x in k))
    if g["inputs"]:
        T += ["", "  made from the numbers it measured:"]
        for ins in g["inputs"]:
            T.append("    " + ", ".join(ins))
    T.append("")
    T += ["WHAT THE DECRYPTION PRODUCED", "-" * 58]
    if g["produced"] is None:
        T += ["  Nothing recorded: the run did not get past the decryption, so",
              "  it raised between the key and the call.", ""]
    elif g["produced"].startswith("table"):
        T += ["  " + g["produced"],
              "  A table is a program. The key was right.", ""]
    else:
        T += ["  " + g["produced"],
              "  Not a program. The deserialiser does not raise on bad input -",
              "  it hands back a number - so a wrong key reaches the maker as a",
              "  number, and indexing it is the error the run ends on. The key",
              "  this environment produced is not the one the payload was",
              "  encrypted with.", ""]
    if g["slices"]:
        T += ["THE DATA IT IS DECRYPTED FROM", "-" * 58,
              "  Every slice in the table, not only the ones the run asked for.",
              ""]
        for s in g["slices"]:
            mark = "asked for" if s["index"] in g["asked"] else "NEVER ASKED FOR"
            T.append("  slice %d: %s byte(s) at offset %s   %s"
                     % (s["index"], s["length"], s["offset"], mark))
        T.append("")
    if g["swap"]:
        T += ["  a round answered one request with another slice: " + g["swap"],
              ""]
    if g["digests"]:
        T += ["THE DIGESTS IT CARRIES, AND WHAT THEY ARE OF",
              "-" * 58,
              "  The build replaces comparisons with digest comparisons, so the",
              "  constants that look like a fingerprint of the host are digests",
              "  of its own literals. Watching the digest function says which.",
              ""]
        for d, what in sorted(g["digests"].items(), key=lambda kv: kv[1]):
            if len(d) == 64:
                T.append("  %s  is the digest of %s" % (d[:16] + "...", what))
        T.append("")
    if g["refused"]:
        T += ["WHAT THIS ENVIRONMENT REFUSED, AS THE HOST REFUSES IT",
              "-" * 58,
              "  Class names the host cannot create. The build asks for them on",
              "  purpose: creating one anyway says plainly that nothing here is",
              "  real, and the answer goes into the key.",
              ""]
        for n in g["refused"]:
            T.append("  Instance.new(%r) -> refused" % n)
        T.append("")
    if g["reads_total"] is not None:
        T += ["WHAT IT READ OFF THE HOST", "-" * 58,
              "  %d read(s), %d distinct. Each one is folded into the key, so"
              % (g["reads_total"], len(g["reads"])),
              "  each one has to match what a real client would answer.", ""]
        for ln in g["reads"][:60]:
            T.append("    " + ln)
        if len(g["reads"]) > 60:
            T.append("    ... and %d more" % (len(g["reads"]) - 60))
        T.append("")
    return "\n".join(T)


class _Cap:
    def __init__(self, sections):
        self.sections = sections


def _selftest():
    cap = _Cap({
        "SLICES": [
            "RX:4:ok:4", "RX:2:ok:4",
            "table:RX:1:1=96891 2=11",
            "table:RX:2:1=10494 2=96902",
            "key:1=11 2=22 3=33  from:1,2,3",
            "gate: the payload decrypted to number",
        ],
        "HASHES": ["out=" + "a" * 64 + "|in1=n=1",
                   "out=" + "b" * 64 + "|in1=s$6e756d626572"],
        "READS": ["reads_total: 7", "Part.Name -> \"Part\"  x2"],
        "REFUSEDCLASSES": ["part"],
    })
    g = read(cap)
    probs = []
    if g["keys"] != [[11, 22, 33]]:
        probs.append("the key was not read: %r" % (g["keys"],))
    if g["inputs"] != [["1", "2", "3"]]:
        probs.append("the numbers it was made of were not read: %r"
                     % (g["inputs"],))
    if g["produced"] != "number":
        probs.append("what the decryption produced was not read: %r"
                     % (g["produced"],))
    if len(g["slices"]) != 2:
        probs.append("the slice table was not read: %r" % (g["slices"],))
    if 1 in g["asked"]:
        probs.append("a slice the run never asked for was counted as asked for")
    if g["digests"].get("a" * 64) != "1":
        probs.append("a digest of a number was not read: %r" % (g["digests"],))
    if g["digests"].get("b" * 64) != '"number"':
        probs.append("a digest of a string was not read: %r" % (g["digests"],))
    if g["reads_total"] != 7:
        probs.append("the read count was not read")
    if g["refused"] != ["part"]:
        probs.append("the refused class was not read")
    txt = report(g)
    for want in ["11, 22, 33", "NEVER ASKED FOR", "Not a program",
                 "is the digest of 1", "Instance.new('part')"]:
        if want not in txt:
            probs.append("the report does not say %r" % want)
    if "slice 1: 96891 byte(s) at offset 11" not in txt:
        probs.append("the slice table is not in the report")
    g2 = read(_Cap({}))
    if "did not reach the gate" not in report(g2):
        probs.append("a run that never reached the gate is not said so")
    for p in probs:
        print("  PROBLEM: " + p)
    print("gate selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()
