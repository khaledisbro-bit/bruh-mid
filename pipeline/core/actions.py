"""The program's effects on its host, in order, as Luau that runs.

The full rendering is the whole machine: every instruction the capture explains,
arithmetic and jumps and all. It is the truthful account and it is hard to read.
This is the other half of the answer - what the program DID to the world outside
itself, which for a script of this kind is most of what anyone wants to know.

It is written from the environment's own records, in the order they happened,
with one rule: an object the host handed back is given a name, and every later
use of that object uses the name. The environment numbers what it hands out, so
"the thing this call was made on" is a fact in the record rather than a guess.

Nothing is invented and nothing is filled in from a template. A call whose
receiver was never handed out by this environment is written on what the record
says it was made on, and that is said in a comment rather than dressed up as a
variable. What this file does NOT have is the program's own arithmetic and
control flow: those are in the full rendering, and a line here is not evidence
about which branch chose it.

The file is checked the same way everything else is: it is run, and the calls it
makes are compared with the ones the program made.
"""
import re

_NAME = re.compile(r"^[A-Za-z_]\w*$")
_PLAIN = re.compile(r"^(-?\d+(\.\d+)?|true|false|nil)$")


def _arg(a, names):
    """One argument, as Lua. An identity is the variable holding that object."""
    a = (a or "").strip()
    m = re.fullmatch(r'"?#(\d+)"?', a)
    if m:
        return names.get(int(m.group(1)), "nil")
    if a.startswith('"') or _PLAIN.match(a) or a.startswith("{"):
        return a
    if a in ("table", "function", "userdata", "thread"):
        # the recorder could not show it; the value is not known, and saying so
        # is better than writing a word that is a type and not a value
        return "nil --[[ %s the recorder could not show ]]" % a
    return '"%s"' % a


def _varname(kind, n, used):
    base = re.sub(r"\W", "", kind) or "obj"
    if base[0].isdigit():
        base = "o" + base
    name = base[0].lower() + base[1:]
    i = 1
    cand = name
    while cand in used:
        i += 1
        cand = "%s%d" % (name, i)
    used.add(cand)
    return cand


def build(records):
    """The Luau file, and how many calls it performs."""
    names, used, out, made = {}, set(), [], 0
    head = [
        "-- WHAT THE PROGRAM DID TO ITS HOST, in the order it did it.",
        "--",
        "-- Written from the environment's own records of this run. An object",
        "-- the host handed back is named, and every later call on that same",
        "-- object uses the name - the environment numbers what it hands out,",
        "-- so this is a fact in the record and not a guess.",
        "--",
        "-- What is NOT here: the program's own arithmetic and its control",
        "-- flow. Those are in RECONSTRUCTED.lua. A line here says the program",
        "-- did this; it does not say what decided it.",
        "",
        "local game = game or getfenv().game",
        "",
    ]
    for rec in records or ():
        if not isinstance(rec, dict):
            continue
        meth = rec.get("method") or ""
        args = list(rec.get("args") or ())
        recv = rec.get("recv")
        gave = rec.get("gave")
        on = rec.get("on")
        if meth in ("Instance.new", "new") and args:
            cls = args[0].strip().strip('"')
            call = 'Instance.new("%s")' % cls
            made += 1
            if gave is not None:
                nm = _varname(cls, gave, used)
                names[gave] = nm
                out.append("local %s = %s" % (nm, call))
            else:
                out.append(call)
            continue
        if meth in ("GetService", "FindService", "service") and args:
            svc = args[0].strip().strip('"')
            call = 'game:GetService("%s")' % svc
            made += 1
            if gave is not None:
                nm = _varname(svc, gave, used)
                names[gave] = nm
                out.append("local %s = %s" % (nm, call))
            else:
                out.append(call)
            continue
        target = names.get(on) if on is not None else None
        if target is None and recv and _NAME.match(recv):
            # the record says what it was made on, and this environment never
            # handed that object out - a service the run reached another way,
            # or an object from before the trace began
            target = recv
            if target not in used:
                used.add(target)
                out.append('local %s = game:GetService("%s")  '
                           '-- named by the record, not handed out here'
                           % (target, target))
        if target is None:
            out.append("-- %s(%s)  -- on an object this run cannot name"
                       % (meth, ", ".join(args)))
            continue
        made += 1
        line = "%s:%s(%s)" % (target, meth,
                              ", ".join(_arg(a, names) for a in args))
        if gave is not None and gave not in names:
            nm = _varname(meth, gave, used)
            names[gave] = nm
            line = "local %s = %s" % (nm, line)
        out.append(line)
    if not out:
        return "\n".join(head + ["-- this run recorded no host calls"]) + "\n", 0
    return "\n".join(head + out) + "\n", made


def _selftest():
    recs = [
        {"method": "GetService", "args": ['"Players"'], "gave": 1,
         "raw": "GetService: Players"},
        {"method": "Instance.new", "args": ['"Folder"'], "gave": 2,
         "raw": "Instance.new: Folder"},
        {"recv": "Folder", "method": "SetAttribute", "args": ['"k"', "7"],
         "on": 2, "raw": 'Folder:SetAttribute("k", 7)'},
        {"recv": "Folder", "method": "set_Parent", "args": ["#1"], "on": 2,
         "raw": "Folder:set_Parent(#1)"},
        {"recv": "Folder", "method": "Destroy", "args": [], "on": 2,
         "raw": "Folder:Destroy()"},
    ]
    text, made = build(recs)
    probs = []
    if 'local players = game:GetService("Players")' not in text:
        probs.append("a service lookup was not named")
    if 'local folder = Instance.new("Folder")' not in text:
        probs.append("a construction was not named")
    if "folder:SetAttribute(\"k\", 7)" not in text:
        probs.append("a method on a named object did not use the name")
    if "folder:set_Parent(players)" not in text:
        probs.append("an object passed as an argument did not use its name")
    if made != 5:
        probs.append("counted %d calls, expected 5" % made)
    for p in probs:
        print("  PROBLEM: " + p)
    print("actions selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()
