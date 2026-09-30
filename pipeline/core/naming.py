#!/usr/bin/env python3
"""
naming.py - give a reconstructed variable a name that says what it holds.

A reconstruction full of v0, v1_2, v7 is correct and nearly unreadable. The
value assigned to a variable usually says what the variable is for, so the name
is derived from that value.

WHAT THIS IS NOT
----------------
The Luraph v15 devirtualizer (caomod2077/Deobfuscator-Luraph-V15, MIT) does this
with tables: METHOD_NAMES maps GetChildren -> children, GLOBAL_CALLS maps
tostring -> str, SIGNAL_PARAMS maps PlayerAdded -> ["player"], and so on for
about a hundred entries. Those tables are not taken, on purpose. This project's
rule is that no table of API names decides how a sample is read, and a hundred
entries of "when you see this name, write that" is that table however harmless
each row looks.

So every name here comes from a RULE applied to the text that is already there:
strip a leading verb from a method name, take the last segment of a string
argument, singularise a plural. GetChildren becomes children because "Get" is a
verb and "Children" is what is left, not because a row says so. That reaches
most of what the tables reach and it reaches names nobody wrote down.

WHY IT IS SAFE
--------------
Renaming cannot change what the reconstruction means. Every name is a fresh
identifier that appears nowhere else in the text, the substitution is
whole-word, and a variable with no derivable name keeps the one it had. The
report records which name came from which value, so a reader can check the
naming the same way they check everything else here. `rename` returns the
provenance for exactly that reason.
"""
import re

# A name this pass invented, and therefore may replace: the emitter's own shape.
_GENERATED = re.compile(r"^v\d+(?:_\d+)*$")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ASSIGN = re.compile(r"^(\s*)(local\s+)?(v\d+(?:_\d+)*)\s*=\s*(.*?)\s*$")
_STRING = re.compile(r'^"((?:[^"\\]|\\.)*)"|^\'((?:[^\'\\]|\\.)*)\'')

KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
    "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
    "true", "until", "while", "continue", "self",
}

# Verbs a method name starts with that say nothing about the VALUE it returns.
# A rule, not a list of APIs: any name beginning with one of these is stripped,
# whatever follows it, including names nobody has written down.
_VERBS = ("Get", "Find", "Fetch", "Read", "Load", "Create",
          "New", "Make", "Build", "Compute", "Calculate", "Is", "Has", "To",
          "Parse", "Decode", "Encode", "Wait", "Require")


def camel(s):
    """'UICorner' -> 'uiCorner'; 'Humanoid Root' -> 'humanoidRoot'; None if unusable."""
    parts = re.findall(r"[A-Za-z0-9]+", s or "")
    if not parts:
        return None
    if len(parts) > 1:
        parts = [p.capitalize() if p.isupper() else p for p in parts]
    w = "".join(p[:1].upper() + p[1:] for p in parts)
    m = re.match(r"^([A-Z]+)([A-Z][a-z].*)$", w)
    if m:
        w = m.group(1).lower() + m.group(2)
    elif re.match(r"^[A-Z]+$", w):
        w = w.lower()
    else:
        w = w[:1].lower() + w[1:]
    if not w or w[0].isdigit():
        return None
    return w[:32]


def singular(name):
    """A plural named for a container of one thing reads better singular in the
    one place it matters: nothing here depends on getting this right."""
    if not name:
        return None
    if name.endswith("ies") and len(name) > 4:
        return name[:-3] + "y"
    if name.endswith("s") and not name.endswith("ss") and len(name) > 3:
        return name[:-1]
    return None


def _strip_verb(method):
    """'GetChildren' -> 'Children'; 'IsDescendantOf' -> 'DescendantOf'.
    Returns None when nothing is left, because a bare verb names no value."""
    for v in _VERBS:
        if method.startswith(v) and len(method) > len(v):
            rest = method[len(v):]
            if rest[:1].isupper() or rest[:1] == "_":
                return rest
    return method


def _string_at(text):
    m = _STRING.match(text.strip())
    if not m:
        return None
    return m.group(1) if m.group(1) is not None else m.group(2)


def _first_arg_string(rhs):
    """The first argument of a call, when it is a plain string literal.

    A call whose first argument is a name -- GetService("Players"),
    WaitForChild("Humanoid"), require("TradeApi") -- names what it returns far
    better than the method does."""
    i = rhs.find("(")
    if i < 0:
        return None
    inner = rhs[i + 1:]
    s = _string_at(inner)
    if s is None:
        return None
    last = re.split(r"[/.:\\]", s)[-1]
    if not re.match(r"^[A-Za-z_]\w{1,40}$", last):
        return None
    return last


_CALL = re.compile(r"([A-Za-z_][\w.]*)\s*[:.]\s*([A-Za-z_]\w*)\s*\(")
_BARE = re.compile(r"^([A-Za-z_][\w.]*)\s*\(")


def derive(rhs):
    """A name for whatever this expression produces, and why. (None, None) when
    the expression says nothing -- a number, an arithmetic result, a slot read.
    Silence is the right answer there: a wrong name is worse than v7."""
    rhs = rhs.strip()
    # An identifier carrying a long run of digits is a placeholder standing in
    # for something this analysis could NOT read - the emitter writes
    # OP_1627695678() for an instruction whose operation is unknown. A name
    # derived from that pretends to know what it is, which is worse than the vN
    # it replaces. The rule is about the shape, not about that one prefix.
    if re.search(r"\d{3}", rhs.split("(")[0]):
        return None, None
    # a call's string argument first: it names the thing, not the operation
    arg = _first_arg_string(rhs)
    if arg:
        n = camel(arg)
        if n:
            return n, "the string this call was given"
    m = _CALL.search(rhs) or _BARE.match(rhs)
    if m:
        method = m.group(2) if m.re is _CALL else m.group(1).split(".")[-1]
        base = _strip_verb(method)
        n = camel(base)
        if n:
            return n, "the call that produced it"
    # a bare string constant, short enough to be a name rather than a message
    s = _string_at(rhs)
    if s is not None and 1 < len(s) <= 40 and re.match(r"^[\w .\-]+$", s):
        n = camel(s)
        if n:
            return n, "the string it holds"
    return None, None


# Identifiers that live after a `.` or `:` are fields and methods, not locals.
# Collecting them as taken names meant every name derived from a method collided
# with that very method - Service:report(x) could only ever produce `report2`.
_MEMBER = re.compile(r"[.:]\s*[A-Za-z_]\w*")


def _bare_identifiers(text):
    """The names in this text that occupy the local namespace."""
    return set(_IDENT.findall(_MEMBER.sub(" ", text)))


def rename(text):
    """Returns (new_text, provenance). provenance: [(old, new, why, value)]."""
    if not text:
        return text, []
    taken = _bare_identifiers(text) | KEYWORDS
    chosen, why_of, value_of = {}, {}, {}
    for line in text.splitlines():
        m = _ASSIGN.match(line)
        if not m:
            continue
        var, rhs = m.group(3), m.group(4)
        if var in chosen:
            continue          # the first definition names it; later ones follow
        rhs = re.sub(r"\s*--\[.\]\s*$", "", rhs).strip()
        base, why = derive(rhs)
        if not base or base in KEYWORDS or len(base) < 2:
            continue
        cand = base
        if cand in taken:
            s = singular(base)
            cand = s if (s and s not in taken and len(s) >= 2) else None
            if cand is None:
                for i in range(2, 60):
                    trial = "%s%d" % (base, i)
                    if trial not in taken:
                        cand = trial
                        break
            if cand is None:
                continue
        taken.add(cand)
        chosen[var] = cand
        why_of[var] = why
        value_of[var] = rhs[:60]
    if not chosen:
        return text, []
    # whole-word substitution, longest first so v1_2 is never hit by v1
    order = sorted(chosen, key=len, reverse=True)
    pat = re.compile(r"\b(%s)\b" % "|".join(re.escape(v) for v in order))
    out = pat.sub(lambda m: chosen[m.group(1)], text)
    prov = [(v, chosen[v], why_of[v], value_of[v])
            for v in sorted(chosen, key=lambda x: (len(x), x))]
    return out, prov


def report(prov):
    L = ["NAMES, AND WHERE THEY CAME FROM", "=" * 46, ""]
    if not prov:
        L += ["  No variable was renamed. Every name here is the one the",
              "  reconstruction gave it, because no value it was assigned said",
              "  what it was for. That is the honest outcome for a run made of",
              "  arithmetic and slot reads.",
              ""]
        return "\n".join(L)
    L += ["  A name is derived from the value assigned to the variable, by rule",
          "  and never from a table of API names. A variable whose value says",
          "  nothing keeps the name it had.",
          ""]
    for old, new, why, val in prov:
        L.append("  %-10s -> %-24s %s" % (old, new, why))
        L.append("  %-10s    %s" % ("", val))
    L += ["", "  %d name(s) derived." % len(prov)]
    return "\n".join(L)


def _selftest():
    bad = []

    def eq(what, got, want):
        if got != want:
            bad.append("%s: %r, expected %r" % (what, got, want))

    eq("camel of an acronym run", camel("UICorner"), "uiCorner")
    eq("camel of one all-caps word", camel("HTTP"), "http")
    eq("camel of spaced words", camel("Humanoid Root"), "humanoidRoot")
    eq("a name cannot start with a digit", camel("3d"), None)
    # A rule, so it handles regular plurals and leaves irregular ones alone.
    # Their version carries a row for "children"; one English irregular is not
    # worth starting a table for, and None is a safe answer here.
    eq("plural to singular", singular("players"), "player")
    eq("an irregular plural is left alone", singular("children"), None)
    eq("y-plural", singular("properties"), "property")
    eq("verb stripped", _strip_verb("GetChildren"), "Children")
    eq("the verb comes off whatever follows", _strip_verb("GetService"),
       "Service")
    eq("nothing to strip", _strip_verb("Clone"), "Clone")

    # the string argument names the thing better than the method does
    n, _ = derive('game:GetService("Players")')
    eq("service from its argument", n, "players")
    n, _ = derive('root:WaitForChild("Humanoid")')
    eq("child from its argument", n, "humanoid")
    n, _ = derive('x.get("TradeAPI/SendTrade")')
    eq("last path segment", n, "sendTrade")
    n, _ = derive("obj:GetChildren()")
    eq("verb stripped from a method", n, "children")
    n, _ = derive("thing:Clone()")
    eq("a method that is already a noun-ish name", n, "clone")

    # a placeholder for something unknown must not become a name
    for rhs in ("OP_1627695678()", "OP_42133(v0, 1)", "f12345()"):
        n, _ = derive(rhs)
        if n is not None:
            bad.append("%r stands in for something unknown and must name "
                       "nothing, got %r" % (rhs, n))
    # ...but a real name that happens to end in a short number is fine
    n, _ = derive("obj:GetPart2()")
    eq("a short number is part of a real name", n, "part2")

    # a method-derived name must not collide with its own method
    out, prov = rename('local v0 = Service:report(1)\nreturn v0\n')
    if "local report =" not in out:
        bad.append("a name derived from a method collided with the method "
                   "itself: %r" % out)

    # values that say nothing must be left alone
    for rhs in ("(v0 + 1)", "42", "v3", "-1", "(v1 - v2)", "nil"):
        n, _ = derive(rhs)
        if n is not None:
            bad.append("%r should name nothing, got %r" % (rhs, n))

    # a rename must not change structure, and must not collide with a name the
    # program already uses
    src = ('local v0 = game:GetService("Players")\n'
           'local v1 = v0:GetChildren()\n'
           'v1_2 = v1\n'
           'return v0, v1, v1_2\n')
    out, prov = rename(src)
    eq("line count unchanged", len(out.splitlines()), len(src.splitlines()))
    if "v0" in out or re.search(r"\bv1\b", out):
        bad.append("an old name survived: %r" % out)
    # v1_2 holds a plain copy of another variable, which names nothing, so it
    # keeps its name - and the v1 substitution must not have reached inside it.
    if "v1_2" not in out:
        bad.append("v1_2 should have been left alone, got %r" % out)
    if "children_2" in out or "players_2" in out:
        bad.append("a substitution reached inside another name: %r" % out)
    eq("two names derived", len(prov), 2)

    # a name already present in the text must not be reused
    src2 = 'local players = 1\nlocal v0 = game:GetService("Players")\n'
    out2, _ = rename(src2)
    if out2.count("local players = 1") != 1:
        bad.append("the program's own name was disturbed: %r" % out2)
    if re.search(r"local players = game", out2):
        bad.append("a derived name collided with an existing one: %r" % out2)

    # nothing derivable -> nothing changed, and no claim made
    src3 = "local v0 = 1\nlocal v1 = (v0 + 2)\nreturn v1\n"
    out3, prov3 = rename(src3)
    eq("untouched when nothing is derivable", out3, src3)
    eq("and no provenance claimed", prov3, [])
    if "No variable was renamed" not in report(prov3):
        bad.append("the report should say plainly that nothing was renamed")

    print("naming selftest %s" % ("ok" if not bad else "FAILURES"))
    for b in bad:
        print("  - %s" % b)
    return bad


if __name__ == "__main__":
    raise SystemExit(1 if _selftest() else 0)
