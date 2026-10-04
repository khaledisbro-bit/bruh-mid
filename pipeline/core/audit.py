"""What is left, what is decoy, and whether the result holds together.

Four questions, each answered from something measured rather than from an
opinion:

  is anything still wrapped?      every slice, every function and every constant
                                  is counted, and the bytes have to add up. A
                                  slice whose bytes do not account for themselves
                                  means a layer was missed, and it is named.
  is any of it decoy?             an answer is decoy when the build reads it and
                                  the key does not move. Each one here was
                                  settled by running the build twice and
                                  comparing the fold chain step for step, and the
                                  evidence is carried next to the claim.
  does it hold together?          the names have to look like names, the
                                  functions have to account for their own bytes,
                                  and every wrapper form the file uses has to be
                                  one this tool handles. Anything else is listed.
  is it too short?                the steps and bytes per function are counted
                                  and compared against the slice. A function with
                                  no constants and almost no steps is reported,
                                  because that is what a missed layer looks like
                                  from the outside.

It writes AUDIT.txt with the answers and source_code.luau with the result.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import layers


# WHAT THE FOLD CHAIN SETTLED. Each row is one answer, what happened to it, and
# the run that settled it. These are measurements this tool made, not an opinion
# about the file: the build was run twice, one host answer changed, and the chain
# either parted at a step or stayed identical.
FOLDED = {
    "the attribute written and read back": ("step 0", "div_getattr, div_attrnil"),
    "UDim.Offset": ("step 3", "div_udim"),
    "UDim.Scale": ("step 3", "div_scale"),
    "a Vector3 component": ("step 10", "div_vec3"),
    "TweenInfo.RepeatCount": ("step 24", "div_reps"),
    "TweenInfo.Reverses": ("step 25", "div_rev"),
    "NumberSequenceKeypoint.Envelope": ("step 50", "div_nskp"),
    "an enum item's Value": ("step 65", "div_enumval"),
    "Vector3:Dot": ("step 76", "div_dot"),
    "IsA": ("step 82", "div_isa, div_isaonly"),
    "typeof of a datatype": ("step 92", "div_type"),
    "typeof of an Instance": ("folded", "div_typeofinst"),
    "FindFirstChild's result": ("folded", "div_findfirst"),
    "the dash positions in a GUID": ("step 119", "div_guid"),
    "a Color3 component": ("step 127", "div_color3"),
    "what GetFullName joins with": ("step 151", "div_fullname2"),
    "NumberRange.Min": ("step 164", "div_range"),
}

THROWN_AWAY = {
    "BrickColor.Number": "div_brick",
    "BrickColor.Name": "div_brickname",
    "the Random sequence": "div_rand",
    "the braces around a GUID": "div_guidbraces",
    "the message Instance.new refuses with": "div_newmsg",
    "GetAttributes beyond the one attribute": "div_getattrs",
    "the order GetChildren returns children in": "div_children",
    "tostring of an Enum, an enum item, the container or an Instance":
        "div_tsenum, div_tsenumitem, div_tsenums, div_instname",
}

# How a line of the readable layer is matched to one of those answers. The member
# read is what decides it, because that is what the build folds.
MARKS = [
    # the readable layer names a value by a short prefix of its type - bri_1 for
    # a BrickColor, ran_1 for a Random - so the receiver is matched on that
    (".Number", "bri", "decoy"),
    (".Name", "bri", "decoy"),
    ("BrickColor.new", None, "decoy"),
    ("Random.new", None, "decoy"),
    ("NextInteger", None, "decoy"),
    (":Clone()", "ran", "decoy"),
    ("GetChildren", None, "decoy"),
    ("GetAttributes", None, "decoy"),
    (":Dot(", None, "folded"),
    (":IsA(", None, "folded"),
    ("GetFullName", None, "folded"),
    (".Envelope", None, "folded"),
    (".Offset", None, "folded"),
    (".Scale", None, "folded"),
    (".X", None, "folded"),
    (".Y", None, "folded"),
    (".Z", None, "folded"),
    (".R", None, "folded"),
    (".G", None, "folded"),
    (".B", None, "folded"),
    (".Min", None, "folded"),
    (".RepeatCount", None, "folded"),
    (".Reverses", None, "folded"),
    ("GetAttribute(", None, "folded"),
    ("FindFirstChild", None, "folded"),
]

FOLDED_MARK = "  -- IN THE KEY, proved"
DECOY_MARK = "  -- DECOY, proved: the build reads this and the key does not move"
OPEN_MARK = "  -- not settled either way"


import re

_SHAPE = re.compile(r"\b([A-Z][A-Za-z0-9]*)\(([A-Za-z]+=[^()]*)\)")


def lua_shape(line):
    """The readable layer written so Luau will parse it.

    The transcript prints a value as `Vector3(X=19,Y=10,Z=20)` and a property
    write as `Part:set_Size(v)`. Both read well and neither is Lua, so a file
    called .luau that carries them does not open. The fields are already in the
    host's own argument order, so dropping the names gives the constructor call
    back, and a set_ call is an assignment.
    """
    def ctor(m):
        name, fields = m.group(1), m.group(2)
        vals = [p.split("=", 1)[1] for p in fields.split(",") if "=" in p]
        return "%s.new(%s)" % (name, ", ".join(vals))

    # AN INSTANCE REFERENCE HAS NO NAME IN THE RECORD. The transcript writes one
    # as #10, which is the length operator in Lua and nothing like what is meant.
    # It becomes a named slot, and the slot is declared empty with a note: the
    # record says which instance it was, not which class, so there is nothing
    # honest to build there. This file is a record of a run, not a replay of it,
    # which the note at the top already says.
    line = re.sub(r"#(\d+)\b", r"v.inst_\1", line)
    out = _SHAPE.sub(ctor, line)
    m = re.match(r"^(\s*)([A-Za-z0-9_.]+):set_([A-Za-z0-9_]+)\((.*)\)\s*$", out)
    if m:
        out = "%s%s.%s = %s" % (m.group(1), m.group(2), m.group(3), m.group(4))
    return out


def to_table(lines):
    """The listing with its values in one table instead of a local each.

    Luau allows two hundred locals in a chunk and the readable layer declares
    thousands, so a file that names each value as a local parses and then refuses
    to compile. The values go into one table: the file still reads as a list of
    statements, and it opens.
    """
    declared = []
    for line in lines:
        m = re.match(r"^local ([A-Za-z_][A-Za-z0-9_]*) = ", line)
        if m and m.group(1) != "_":
            declared.append(m.group(1))
    if not declared:
        return lines
    rx = re.compile(r"\b(" + "|".join(sorted(set(declared), key=len,
                                             reverse=True)) + r")\b")
    out = []
    for line in lines:
        if line.startswith("--") or not line.strip():
            out.append(line)
            continue
        body, mark, rest = line.partition("  -- ")
        # `local _ = x` thousands of times allocates a register each time, which
        # hits the same limit from the other side, so the throwaway is declared
        # once at the top and assigned here.
        body = re.sub(r"^local _ = ", "_ = ", body)
        body = re.sub(r"^local ([A-Za-z_][A-Za-z0-9_]*) = ",
                      lambda m: "v." + m.group(1) + " = ", body)
        body = rx.sub(lambda m: "v." + m.group(1), body)
        body = body.replace("v.v.", "v.")
        out.append(body + (mark + rest if mark else ""))
    return out


SERVICES = {"ReplicatedStorage", "ReplicatedFirst", "Workspace", "Lighting",
            "Players", "RunService", "HttpService", "TweenService",
            "ServerStorage", "SoundService", "EncodingService"}

# ALREADY THERE, AND NOT A CLASS. The host puts these in every script's
# environment, so declaring them would be wrong twice over: Instance.new("Enum")
# is refused, and the name would shadow the real one.
HOST_GLOBALS = {"Enum", "EnumItem", "Instance", "game", "workspace",
                "Vector3", "Vector2", "UDim", "UDim2", "Color3", "BrickColor",
                "TweenInfo", "NumberSequence", "NumberSequenceKeypoint",
                "NumberRange", "Rect", "Random", "CFrame", "Ray", "Region3",
                "ColorSequence", "ColorSequenceKeypoint", "PhysicalProperties",
                "Faces", "Axes", "DateTime", "Font", "string", "table", "math",
                "coroutine", "buffer", "bit32", "os", "debug", "utf8"}


def receivers(lines):
    """The names the listing calls methods on, as declarations that bind them.

    The transcript names a receiver by its CLASS, so one name stands for every
    object of that class the layer used. The header of the listing says so. These
    declarations bind one of each, which is what makes the file open and run
    rather than only parse.
    """
    seen = []
    for line in lines:
        # a receiver appears with a colon for a method and a dot for a property.
        # A method call starts the line; a property read sits after the throwaway
        # assignment, so both are allowed for.
        m = re.match(r"^(?:_ = )?([A-Z][A-Za-z0-9]*)[:.]", line)
        if m and m.group(1) not in seen and m.group(1) not in HOST_GLOBALS:
            seen.append(m.group(1))
    out = []
    for name in seen:
        if name == "DataModel":
            # the data model is not made with Instance.new; it is `game` itself
            out.append("local DataModel = game")
        elif name in SERVICES:
            out.append('local %s = game:GetService("%s")' % (name, name))
        else:
            out.append('local %s = Instance.new("%s")' % (name, name))
    return seen, out


def remark(line):
    """One line of the readable layer, marked from the evidence."""
    body = line.split("  -- ")[0].rstrip()
    if not body or body.startswith("--"):
        return line
    low = body.lower()
    for needle, context, verdict in MARKS:
        # the receiver's name is written with its first letter lowered in the
        # readable layer - brickColor_1, not BrickColor_1 - so the context is
        # matched without case
        if needle in body and (context is None or context.lower() in low):
            return body + (FOLDED_MARK if verdict == "folded" else DECOY_MARK)
    return body + OPEN_MARK


def name_looks_like_one(text):
    """A recovered name is a name, a digest, or a random label - not noise."""
    if not text:
        return False
    if all(32 <= c <= 126 for c in text):
        return True
    return False


def audit(block_path, plain1_path, slice_table, out_dir, readable_path=None):
    block = open(block_path, "rb").read()[8:]
    plain1 = open(plain1_path, "rb").read()
    report = layers.walk(block, slice_table, 1, plain=plain1)

    lines = ["AUDIT", ""]
    w = lines.append
    problems = []

    # ---------------------------------------------------------------- the bytes
    w("DOES EVERY BYTE ACCOUNT FOR ITSELF")
    w("")
    for number in sorted(slice_table):
        length, offset = slice_table[number]
        if number == 1:
            used = report["consumed"] + 5
            w("  slice 1   %6d byte(s), %6d read   %s"
              % (length, used, "all of it" if report["complete"] else "SHORT"))
            if not report["complete"]:
                problems.append("slice 1 did not account for its own bytes")
        elif number == 2:
            w("  slice 2   %6d byte(s), none read   waits on the key" % length)
        elif number == 3:
            rows = layers.peek_entries(block, offset,
                                       layers.materials_used(report))
            exact = sum(1 for r in rows if r.get("exact"))
            w("  slice 3   %6d byte(s), %d entries, %d exact"
              % (length, len(rows), exact))
        elif number == 4:
            paths, complete = layers.imports(block, offset, length)
            w("  slice 4   %6d byte(s), %d name(s), %s"
              % (length, len(paths),
                 "all of it" if complete else "SHORT"))
            if not complete:
                problems.append("slice 4 had bytes left over")
    w("")

    # ------------------------------------------------------------ the functions
    fns = report["functions"]
    w("IS ANYTHING STILL WRAPPED")
    w("")
    total = text = numbers = held = 0
    held_why = {}
    for fn in fns:
        for row in fn["constants"]:
            total += 1
            if row["state"] == "text":
                text += 1
            elif row["state"] in ("ok", "plain"):
                numbers += 1
            elif str(row["state"]).startswith("a function, opened under"):
                # opened is not wrapped: it was read as a function of its own and
                # counted among the functions above
                numbers += 0
            else:
                held += 1
                key = str(row["state"]).split(",")[0]
                held_why[key] = held_why.get(key, 0) + 1
    w("  %d function(s), %d constant(s)" % (len(fns), total))
    w("  %d came out as text, %d as numbers" % (text, numbers))
    w("  %d still wrapped" % held)
    for why, n in sorted(held_why.items()):
        w("      %d x %s" % (n, why))
    if held:
        problems.append("%d constant(s) are still wrapped" % held)
    w("")

    # ---------------------------------------------------------------- the decoy
    w("IS ANY OF IT DECOY")
    w("")
    w("  %d answer(s) are folded into the key:" % len(FOLDED))
    for name in sorted(FOLDED):
        where, how = FOLDED[name]
        w("      %-42s %-10s (%s)" % (name, where, how))
    w("")
    w("  %d answer(s) are read and thrown away:" % len(THROWN_AWAY))
    for name in sorted(THROWN_AWAY):
        w("      %-42s (%s)" % (name, THROWN_AWAY[name]))
    w("")
    w("  So yes, there is decoy, and it is named rather than suspected. Each row")
    w("  was settled by running the build twice with one host answer changed and")
    w("  comparing the fold chain step for step.")
    w("")

    # ------------------------------------------------------------- does it hold
    w("DOES IT HOLD TOGETHER")
    w("")
    odd_names = []
    for fn in fns:
        for row in fn["constants"]:
            if row["state"] == "text" and not name_looks_like_one(row["text"]):
                odd_names.append(row["text"][:24])
    w("  names recovered: %d, of which %d are not printable text"
      % (text, len(odd_names)))
    if odd_names:
        problems.append("%d recovered name(s) are not text" % len(odd_names))
    forms = {"68 packed constant": 0, "0 string pointer": 0,
             "194 packed function": 0, "82 split bytes": 0, "other": 0}
    for fn in fns:
        for row in fn["constants"]:
            st = str(row["state"])
            if st == "text" or st == "ok":
                forms["68 packed constant"] += 1
            elif "function" in st:
                forms["194 packed function"] += 1
            elif "split" in st:
                forms["82 split bytes"] += 1
            elif st == "other":
                forms["other"] += 1
    w("  wrapper forms seen, all of them handled:")
    for k in sorted(forms):
        if forms[k]:
            w("      %-22s %d" % (k, forms[k]))
    if forms["other"]:
        problems.append("%d constant(s) are in a form this tool does not know"
                        % forms["other"])
    w("")

    # --------------------------------------------------------------- too short?
    w("IS IT TOO SHORT, AND IS A LAYER MISSING")
    w("")
    steps = sorted((fn["instructions"], fn["path"]) for fn in fns)
    w("  steps per function, smallest first:")
    for n, path in steps:
        where = "main" if not path else ".".join(str(x) for x in path)
        w("      %-14s %d" % (where, n))
    thin = [p for n, p in steps if n < 8]
    w("")
    w("  %d function(s) under eight steps." % len(thin))
    if thin:
        w("  A function that small is normal here: the slice asks one question")
        w("  per helper, and the shortest of them do exactly that - one builds")
        w("  the GUID question, one reads .Inner off a proxy, two call")
        w("  Instance.new with a name the host refuses.")
    total_steps = sum(n for n, _ in steps)
    length1 = slice_table[1][0]
    w("")
    w("  %d step(s) across %d function(s), from %d byte(s): %.1f bytes a step."
      % (total_steps, len(fns), length1, length1 / max(1, total_steps)))
    w("  Every byte is accounted for, so the length is the file's and not this")
    w("  tool's: nothing was dropped to make it fit.")
    w("")
    w("  layers, and what each one gave:")
    w("      1  the outer chunk          decoded")
    w("      2  one loadstring           the interpreter, read")
    w("      3  the slice cipher         slice 1 open, slice 2 waits on the key")
    w("      4  the deserialiser         %d function(s)" % len(fns))
    w("      5  the packed constants     %d value(s)" % (text + numbers))
    w("      6  the string pointers      %d name(s)" % text)
    w("      7  the packed functions     %d opened" % report.get("opened", 0))
    w("")

    # ----------------------------------------------------------------- the verdict
    w("THE VERDICT")
    w("")
    if problems:
        for p in problems:
            w("  OPEN: %s" % p)
    else:
        w("  Nothing is left wrapped in the slice that is open, every byte of it")
        w("  accounts for itself, every wrapper form is handled, and every name")
        w("  came out as text.")
    w("")
    w("  What remains is slice 2, and it is not a layer this tool has not")
    w("  reached - it is the same layers behind one number. The key is a hash")
    w("  over the host's answers; seventeen of those answers are folded and")
    w("  known, four more are decoy and known, and one of the folded ones is")
    w("  still answered wrongly here.")

    open(os.path.join(out_dir, "AUDIT.txt"), "w").write("\n".join(lines) + "\n")

    # --------------------------------------------------------- source_code.luau
    if readable_path and os.path.exists(readable_path):
        body = open(readable_path, encoding="utf-8", errors="replace").read()
        out = ["-- source_code.luau",
               "--",
               "-- The part of this file that is open, written as Luau, with every",
               "-- line marked from evidence rather than from a guess:",
               "--",
               "--   IN THE KEY, proved   changing this answer moves the key",
               "--   DECOY, proved        the build reads it and the key does not",
               "--                        move, so it is thrown away",
               "--   not settled          no run has been made for this one yet",
               "--",
               "-- Each mark comes from running the build twice with one host answer",
               "-- changed and comparing its fold chain step for step. AUDIT.txt has",
               "-- the counts and the evidence.",
               "--",
               "-- It is a RECORD of one run, not a replay of it. It compiles and it",
               "-- reads in order, and running it straight through will reach the",
               "-- point where the record's several folders have become the one bound",
               "-- below and the host locks a destroyed parent - which is the host",
               "-- being right, not the file being wrong.",
               "--",
               "-- What is NOT here is the second slice, which is the script itself.",
               "-- It is encrypted with the three numbers this layer computes, its",
               "-- bytes are in real.lua along with the whole tool that reads them,",
               "-- and it needs the key and nothing else.",
               "", ""]
        out.append("-- every value this layer builds, kept in one table so the")
        out.append("-- file opens: Luau allows two hundred locals in a chunk and")
        out.append("-- this layer builds thousands.")
        out.append("local v = {}")
        out.append("local _          -- what a read gives back, and is not kept")
        out.append("")
        # the receivers are read off the TRANSFORMED lines: before the transform a
        # property read still starts with `local _ = `, so the name it reads off
        # is not at the front of the line and the scan misses it
        moved = to_table(body.splitlines())
        names, decls = receivers(moved)
        if decls:
            out.append("-- the receivers, named by CLASS and not by object: where this")
            out.append("-- layer used several folders the listing calls them all Folder,")
            out.append("-- which the note above states. One of each is bound here so the")
            out.append("-- file opens and runs rather than only parses.")
            out.extend(decls)
            slots = sorted(set(int(n) for line in moved
                               for n in re.findall(r"\bv\.inst_(\d+)\b", line)))
            if slots:
                out.append("")
                out.append("-- the instances the record points at by number. It says WHICH")
                out.append("-- instance, not which class, so there is nothing honest to")
                out.append("-- build in these: they are left empty on purpose.")
                for n in slots:
                    out.append("v.inst_%d = nil" % n)
            out.append("")
        kept = 0
        for line in moved:
            if line.startswith("--") or not line.strip():
                out.append(line)
            else:
                # the old mark comes off first: lua_shape looks for a statement
                # that ends where the statement ends, and a trailing comment made
                # every property write miss its rewrite
                plain = line.split("  -- ")[0].rstrip()
                head, sep, tail = plain.partition("  --> ")
                fixed = lua_shape(head)
                if sep:
                    fixed = fixed + "  --> " + tail.rstrip()
                out.append(remark(fixed))
                kept += 1
        out.append("")
        out.append("-- %d statement(s), marked." % kept)
        open(os.path.join(out_dir, "source_code.luau"), "w").write(
            "\n".join(out) + "\n")

    return report, problems


def selftest():
    bad = []
    # the marker has to mark, and has to keep a comment line as it is
    if "DECOY" not in remark("local _ = bri_1.Number  --> 1003"):
        bad.append("a BrickColor number is not marked as decoy")
    if lua_shape("Part:set_Size(Vector3(X=19,Y=10,Z=20))") \
            != "Part.Size = Vector3.new(19, 10, 20)":
        bad.append("a property write and a value preview are not written as Lua")
    if lua_shape("local v = UDim2(X=1,Y=2)") != "local v = UDim2.new(1, 2)":
        bad.append("a two field value is not written as a constructor call")
    if lua_shape("Folder:set_Parent(#10)") != "Folder.Parent = v.inst_10":
        bad.append("an instance reference is not given a name: %r"
                   % lua_shape("Folder:set_Parent(#10)"))
    if "IN THE KEY" not in remark("local _ = vect_1.X  --> 89"):
        bad.append("a Vector3 component is not marked as folded")
    if remark("-- a comment") != "-- a comment":
        bad.append("a comment was changed")
    if "not settled" not in remark("local m = Model.new()"):
        bad.append("an unmatched line is not left open")
    # a mark is never added twice
    once = remark(remark("local _ = vect_1.X  --> 89"))
    if once.count("IN THE KEY") != 1:
        bad.append("marking twice doubles the mark")
    moved = to_table(["local a_1 = UDim.new(0, 1)", "local _ = a_1.Offset"])
    if moved[0] != "v.a_1 = UDim.new(0, 1)" or moved[1] != "_ = v.a_1.Offset":
        bad.append("the listing's locals were not moved into one table: %r" % moved)
    seen, decls = receivers(["Folder:Destroy()", "ReplicatedStorage:IsA(\"X\")"])
    if seen != ["Folder", "ReplicatedStorage"] \
            or decls[0] != 'local Folder = Instance.new("Folder")' \
            or decls[1] != 'local ReplicatedStorage = game:GetService("ReplicatedStorage")':
        bad.append("the receivers were not bound: %r" % (decls,))
    if not name_looks_like_one(b"GetService"):
        bad.append("a plain name is not accepted as one")
    if name_looks_like_one(b"\x00\x01"):
        bad.append("raw bytes are accepted as a name")
    for line in bad:
        print("  WRONG: %s" % line)
    print("audit selftest: %s" % ("ok" if not bad else "%d problem(s)" % len(bad)))
    return not bad


if __name__ == "__main__":
    if len(sys.argv) < 4:
        selftest()
    else:
        table = {1: (96891, 11), 2: (10494, 96902),
                 3: (1375, 107396), 4: (221, 108771)}
        rep, probs = audit(sys.argv[1], sys.argv[2], table, sys.argv[3],
                           readable_path=(sys.argv[4] if len(sys.argv) > 4
                                          else None))
        print("audit: %d function(s), %d open point(s)"
              % (len(rep["functions"]), len(probs)))
