"""The layer that runs, written back out as Lua a person can read.

What it is. The capture holds one ordered transcript of everything the program
did to the host: each value it asked to be built, each member it read back, each
method it called, in the order it happened. That is enough to write the layer out
as Lua, and this does exactly that and nothing more.

What it is not. It is not the script. The script is the other piece of the file,
and it is encrypted with the numbers this layer measures. It is also not a
decompilation: the transcript says a Vector3 was built and that its X was read,
not which local the program kept it in, so the names here are this file's.

Two honest limits, written into the output as well as here:

  - a read records the TYPE of the value it came off, not which one. Where the
    program held several values of a type, the read is attached to the most
    recent one, which is right whenever it is used as soon as it is built and is
    a guess otherwise.
  - control flow is absent. The transcript is what happened on one run, in
    order, so loops come out unrolled and branches not taken are simply missing.
"""
import re


def _section(capture, name):
    return (getattr(capture, "sections", None) or {}).get(name, []) or []


def events(capture):
    out = []
    for ln in _section(capture, "TRANSCRIPT"):
        if ":" not in ln or ln.startswith("events_total"):
            continue
        kind, text = ln.split(":", 1)
        if kind in ("made", "read", "call"):
            out.append((kind, text))
    return out


def _prefix(typ, taken):
    """A short name per type, and never the same one for two types.

    Three letters of UDim and of UDim2 are both "uDi", so both were written as
    uDi1 and the second shadowed the first: the output said a UDim2 was a UDim.
    """
    if typ in taken:
        return taken[typ]
    base = typ[0].lower() + typ[1:]
    for n in range(3, len(base) + 1):
        cand = base[:n]
        if cand not in taken.values():
            taken[typ] = cand
            return cand
    cand = base + str(len(taken) + 1)
    taken[typ] = cand
    return cand


def write(capture, limit=3000):
    ev = events(capture)
    T = ["-- THE LAYER THAT RUNS, AS LUA",
         "--",
         "-- This is the part of the file that executes. It does not do anything",
         "-- a script would do: it measures the host and mixes the answers into",
         "-- three numbers, and those numbers are the key the OTHER part of the",
         "-- file is encrypted with. That other part is the script, and it is not",
         "-- in here, because it has not been decrypted.",
         "--",
         "-- Written from the capture's ordered transcript: every value the",
         "-- program asked the host to build, every member it read back, every",
         "-- method it called, in the order it happened. Two limits come with",
         "-- that and are not hidden:",
         "--",
         "--   * a read records the TYPE it came off, not which value, so where",
         "--     several of a type were alive the read is attached to the most",
         "--     recent one;",
         "--   * this is one run in order, so loops are unrolled and a branch",
         "--     the run did not take is not here at all.",
         "--",
         "-- The names are this file's. The program's own names are not in the",
         "-- capture, because a compiled function does not carry them.",
         ""]
    if not ev:
        T += ["-- The capture holds no transcript, so there is nothing to",
              "-- write out."]
        return "\n".join(T)
    counts = {}
    prefixes = {}
    last = {}
    chain = []          # a read that returned another value, waiting for its own
    lines = []
    for kind, text in ev[:limit]:
        if kind == "made":
            m = re.match(r"^(\w+)\.new\((.*)\)$", text)
            if not m:
                continue
            _flush(chain, lines)
            typ, args = m.group(1), m.group(2)
            counts[typ] = counts.get(typ, 0) + 1
            # an underscore before the number: without it the second UDim2
            # is "uDim2", which reads as the type name and not as a variable
            name = "%s_%d" % (_prefix(typ, prefixes), counts[typ])
            last[typ] = name
            lines.append("local %s = %s.new(%s)" % (name, typ, args))
        elif kind == "read":
            m = re.match(r"^([\w.]+)\.(\w+)(?: \(computed\))? -> (.*)$", text)
            if not m:
                continue
            owner, member, value = m.group(1), m.group(2), m.group(3)
            held = re.match(r"^table/(\w+)$", value)
            if chain and chain[-1][0] == owner:
                chain.append((held.group(1) if held else None, member, value))
            else:
                _flush(chain, lines)
                del chain[:]
                base = last.get(owner)
                if base is None:
                    base = owner
                chain.append((held.group(1) if held else None, member, value,
                              base))
            if not held:
                _flush(chain, lines)
                del chain[:]
        elif kind == "call":
            _flush(chain, lines)
            del chain[:]
            lines.append(re.sub(r"\s+on=#\d+$", "", text))
    _flush(chain, lines)
    T += lines
    if len(ev) > limit:
        T.append("-- ... and %d more step(s)" % (len(ev) - limit))
    T.append("")
    return "\n".join(T)


def _flush(chain, lines):
    """One chain of reads, written as the expression it is."""
    if not chain:
        return
    base = chain[0][3] if len(chain[0]) > 3 else None
    if base is None:
        del chain[:]
        return
    path = base + "".join("." + step[1] for step in chain)
    value = chain[-1][2]
    if value.startswith("table/"):
        lines.append("local _ = %s" % path)
    else:
        lines.append("local _ = %s  --> %s" % (path, value))
    del chain[:]



# WHICH ANSWERS THE PASSWORD IS MADE OF.
#
# Each of these was settled the same way: change what this environment answers
# for it, run again, and see whether the key the build computes moves. A key that
# moves means the answer is folded into it. A key that does not move means the
# build reads the answer and throws it away.
#
# That is a measurement, not an opinion, and it is why the two lists are not the
# same length as the list of things the program touches.
FEEDS = {
    "UDim": True, "UDim2": True, "Vector3": True, "Vector2": True,
    "Color3": True, "NumberRange": True, "TweenInfo": True,
    "NumberSequenceKeypoint": True, "NumberSequence": True,
    "BrickColor": False, "Random": False,
}

CALL_FEEDS = {
    "Destroy": True, "SetAttribute": True, "GetAttribute": True,
    "GetAttributes": True, "GetFullName": True, "IsA": True,
    "GetChildren": True, "FindFirstChild": True, "FindFirstChildOfClass": True,
    "FindFirstChildWhichIsA": True, "set_Parent": True, "set_Name": True,
    "set_Size": True,
    "NextInteger": False, "Clone": False, "GenerateGUID": False,
}


def _verdict(line):
    """Whether this line's answer is one the password is made of."""
    m = re.match(r"^local \w+ = (\w+)\.new\(", line)
    if m:
        v = FEEDS.get(m.group(1))
        return v
    m = re.match(r"^local _ = (\w+)", line)
    if m:
        # a read is attributed by the type its variable name was made from
        name = m.group(1)
        if name.startswith("Enum."):
            return False
        for typ, v in FEEDS.items():
            if name.startswith(typ[0].lower() + typ[1:3]):
                return v
        return None
    m = re.match(r"^\w+:(\w+)\(", line)
    if m:
        return CALL_FEEDS.get(m.group(1))
    return None


def marked(text):
    """The same source with each line marked by what the key is made of."""
    out = []
    for line in text.split("\n"):
        if not line or line.startswith("--"):
            out.append(line)
            continue
        v = _verdict(line)
        if v is True:
            out.append(line + "  -- IN THE PASSWORD")
        elif v is False:
            out.append(line + "  -- noise: read and thrown away")
        else:
            out.append(line)
    return "\n".join(out)


class _Cap:
    def __init__(self, sections):
        self.sections = sections


def _selftest():
    cap = _Cap({"TRANSCRIPT": [
        "events_total: 9",
        'call:Folder:SetAttribute("a", 579)  on=#2',
        "made:UDim.new(0, 940)",
        "made:UDim.new(0.03125, 155)",
        "made:UDim2.new(0, 940, 0.03125, 155)",
        "read:UDim2.X -> table/UDim",
        "read:UDim.Offset -> 940",
        "made:Vector3.new(434, 452, 128)",
        "read:Vector3.X -> 434",
        "call:Folder:Destroy()",
    ]})
    txt = write(cap)
    probs = []
    for want in ['Folder:SetAttribute("a", 579)',
                 "local uDi_1 = UDim.new(0, 940)",
                 "local uDi_2 = UDim.new(0.03125, 155)",
                 # a UDim and a UDim2 must not share a name
                 "local uDim_1 = UDim2",
                 "local uDim_1 = UDim2.new(0, 940, 0.03125, 155)",
                 "local _ = uDim_1.X.Offset  --> 940",
                 "local vec_1 = Vector3.new(434, 452, 128)",
                 "local _ = vec_1.X  --> 434",
                 "Folder:Destroy()"]:
        if want not in txt:
            probs.append("the source does not contain %r" % want)
    if "on=#2" in txt:
        probs.append("an internal marker leaked into the source")
    if "it has not been decrypted" not in txt:
        probs.append("the output does not say the script itself is absent")
    if "nothing to" not in write(_Cap({})):
        probs.append("an empty capture does not say so")
    mk = marked(txt)
    if "local vec_1 = Vector3.new(434, 452, 128)  -- IN THE PASSWORD" not in mk:
        probs.append("a value the password is made of is not marked")
    if "Folder:Destroy()  -- IN THE PASSWORD" not in mk:
        probs.append("a call the password is made of is not marked")
    if marked("-- a comment").endswith("PASSWORD"):
        probs.append("a comment was marked")
    nm = marked("local bri_1 = BrickColor.new(\"Really black\", 1003)")
    if "noise" not in nm:
        probs.append("a value that is thrown away is not marked: %r" % nm)
    for p in probs:
        print("  PROBLEM: " + p)
    print("source selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()
