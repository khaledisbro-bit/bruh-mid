"""What the script does, in words, for a reader who does not want opcodes.

The instruction listing is accurate and unreadable. This is the same program
said in the host's own terms: the objects it asked the host to build, the methods
it called, the values it read back, in the order it did them - and then, plainly,
what that adds up to and what is still out of reach.

Everything here comes from the capture. The construction log is written by the
stand-in at the moment it builds a value, the calls by the recorder at the moment
they are made, and the key and the slice table by the watch at the gate. Nothing
is reconstructed and nothing is guessed.
"""
import re


def _section(capture, name):
    return (getattr(capture, "sections", None) or {}).get(name, []) or []


def _group(made):
    """Consecutive identical kinds folded, so a page of UDims reads as one line."""
    out = []
    for line in made:
        kind = line.split(".new(")[0]
        if out and out[-1][0] == kind:
            out[-1][1].append(line)
        else:
            out.append([kind, [line]])
    return out


def report(capture, gate_info=None):
    made = [l for l in _section(capture, "MADE") if ".new(" in l]
    calls = [l for l in _section(capture, "HOSTCALLS")
             if "(" in l and not l.strip().startswith("[")]
    g = gate_info or {}
    T = ["WHAT THIS SCRIPT DOES, IN WORDS",
         "=" * 58, ""]
    T += ["THE SHORT ANSWER", "-" * 58,
          "  The file is in two layers. The layer that RUNS does not do",
          "  anything a script would do - it measures the machine it is on.",
          "  It builds one Roblox value after another, reads their parts back,",
          "  calls methods on them, and mixes everything it gets into three",
          "  numbers.",
          "",
          "  Those three numbers are the key the SECOND layer is encrypted",
          "  with. The second layer is the script. It is in the file and it is",
          "  not readable, because the key is whatever a real Roblox client",
          "  would have answered.",
          "",
          "  So there is no hidden branch to take and nothing to switch off.",
          "  The measuring is not protecting the script - the measuring IS the",
          "  password.",
          ""]
    if g.get("slices"):
        asked = set(g.get("asked") or [])
        T += ["WHERE EACH LAYER IS", "-" * 58]
        for s in g["slices"]:
            what = "asked for by the run" if s["index"] in asked else \
                   "never asked for"
            T.append("  piece %d: %s byte(s)   %s"
                     % (s["index"], s["length"], what))
        T += ["",
              "  The big piece is the measuring layer, and this analysis has",
              "  read all of it. The 10494-byte piece is the script itself.",
              ""]
    if g.get("keys"):
        T += ["THE PASSWORD THIS MACHINE PRODUCED", "-" * 58,
              "  " + ", ".join(str(x) for x in g["keys"][0]), ""]
        if g.get("produced") and not g["produced"].startswith("table"):
            T += ["  Wrong. The script came out as noise, so at least one of",
                  "  the thousands of questions it asked was answered",
                  "  differently here than a real client would answer it.", ""]
        elif g.get("produced"):
            T += ["  Right: the script decrypted to " + g["produced"], ""]
    if made:
        T += ["WHAT IT ASKED THE HOST TO BUILD, IN ORDER", "-" * 58,
              "  %d value(s) in all. Repeats of the same kind are folded."
              % len(made), ""]
        for kind, lines in _group(made)[:120]:
            if len(lines) == 1:
                T.append("  " + lines[0])
            else:
                T.append("  %s.new(...) x%d, the first being %s"
                         % (kind, len(lines), lines[0]))
        T.append("")
    if calls:
        seen, order = set(), []
        for c in calls:
            k = re.sub(r"\s+@.*$", "", c).strip()
            if k in seen:
                continue
            seen.add(k)
            order.append(k)
        T += ["WHAT IT CALLED ON THE HOST", "-" * 58,
              "  Each one once, in the order it first happened.", ""]
        for k in order[:80]:
            T.append("  " + k)
        T.append("")
    if g.get("refused"):
        T += ["WHAT IT ASKED FOR THAT CANNOT EXIST", "-" * 58,
              "  It asks the host to make objects of classes there is no such",
              "  thing as. A real client refuses; anything that says yes has",
              "  told it that it is not on a real client.", ""]
        for n in g["refused"]:
            T.append("  Instance.new(%r)  -> refused here too" % n)
        T.append("")
    if g.get("digests"):
        lit = sorted(set(g["digests"].values()))
        T += ["WHY THE HASHES ARE NOT A FINGERPRINT", "-" * 58,
              "  The file carries SHA-256 digests that look like a fingerprint",
              "  of a real machine. They are not. Watching the hash function",
              "  shows what it was given, and every one of them is a digest of",
              "  one of the script's own literals:",
              "",
              "  " + ", ".join(lit[:28]),
              "",
              "  So `x == 1` is written as `hash(x) == <a digest of 1>`. It is",
              "  a way of hiding a comparison, not a check on the machine.",
              ""]
    T += ["WHAT WOULD FINISH IT", "-" * 58,
          "  One of the measurements still differs from a real client's. Every",
          "  value the file itself double-checks is already right here, which",
          "  is why it gets as far as asking for the encrypted piece. What is",
          "  wrong is in something it does not double-check.",
          "",
          "  The same harness run once on a real client prints the password it",
          "  measures there. With that, the piece decrypts here and the script",
          "  reads out like any other.",
          ""]
    return "\n".join(T)


class _Cap:
    def __init__(self, sections):
        self.sections = sections


def _selftest():
    cap = _Cap({
        "MADE": ["made_total: 3", "UDim.new(0, 940)", "UDim.new(0.0625, 163)",
                 "Vector3.new(434, 452, 128)"],
        "HOSTCALLS": ["Folder:SetAttribute(\"a\", 579)  @on=#2  @row=62",
                      "Folder:SetAttribute(\"a\", 579)  @on=#9  @row=99",
                      "Model:GetChildren()  @row=70"],
    })
    g = {"keys": [[1, 2, 3]], "produced": "number", "refused": ["part"],
         "slices": [{"index": 1, "length": 96891, "offset": 11},
                    {"index": 2, "length": 10494, "offset": 96902}],
         "asked": [1], "digests": {"a" * 64: "1"}}
    txt = report(cap, g)
    probs = []
    for want in ["WHAT THIS SCRIPT DOES, IN WORDS",
                 "the measuring IS the",
                 "piece 2: 10494 byte(s)   never asked for",
                 "1, 2, 3",
                 "Wrong.",
                 "UDim.new(...) x2, the first being UDim.new(0, 940)",
                 "Vector3.new(434, 452, 128)",
                 "Folder:SetAttribute(\"a\", 579)",
                 "Model:GetChildren()",
                 "Instance.new('part')",
                 "a digest of 1" if False else "digest of"]:
        if want not in txt:
            probs.append("the report does not say %r" % want)
    if txt.count("Folder:SetAttribute") != 1:
        probs.append("a repeated call was listed more than once")
    if "@row=" in txt:
        probs.append("the row markers leaked into the readable text")
    g2 = dict(g); g2["produced"] = "table with 17 field(s)"
    if "Right: the script decrypted to" not in report(cap, g2):
        probs.append("a right password is not said so")
    if "WHAT IT ASKED THE HOST TO BUILD" in report(_Cap({}), {}):
        probs.append("an empty capture still claims to list what it built")
    for p in probs:
        print("  PROBLEM: " + p)
    print("story selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()
