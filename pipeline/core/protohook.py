"""Taking the program's functions from the interpreter that builds them.

A capture shows what ran. In a protected build what runs is the checking, and
the program sits behind a branch the checks decide. Reading more of the run does
not reach it: the run is the wrong place to look.

The interpreter builds a closure for every function of the program, and it is
handed that function's instruction arrays to do it. So the arrays can be taken
there - at the moment the closure is made, before any of it runs, and whether or
not it is ever called. The functions this run never enters are in hand for the
same price as the ones it does.

What this module does, on the interpreter's own source:

  1. find the loop that dispatches instructions (the interpreter);
  2. find the functions that enclose it, by reading the chunk as tokens so a
     `function` inside a string cannot move the count;
  3. the innermost enclosing function with named parameters is the one called
     once per program function - the maker;
  4. decide which of its parameters is the instruction data, by what the body
     does with them: a parameter indexed by a number is data, and one indexed
     by something taken from itself is the instruction table;
  5. write an edit at the start of the maker's body that records it.

The edit is table operations only: no call, no new local. A protected build
watches its own stack, and a hook that calls out changes what it sees. One
table write is enough, because the table it writes to does the work from its
metatable, where the build cannot look.
"""
import re

import lua_tokens


class Found:
    __slots__ = ("maker", "proto", "upvals", "loop_at", "why", "enclosing",
                 "maker_name")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))


def _loop_at(src, row, pc):
    """Where the dispatch loop reads its instruction."""
    if not row or not pc:
        return None
    m = re.search(r"local\s+%s\s*=\s*\(?\s*(\w+)\s*\[\s*%s\s*\]"
                  % (re.escape(row), re.escape(pc)), src)
    return m.start() if m else None


def _score_params(src, f):
    """Which parameter holds the instruction data.

    Counted over the maker's body, by what is done to each name:
      p[<number>]      the parameter is a table of fields          weight 4
      p[p[...]]        it is indexed by something out of itself,
                       which is what reading an instruction looks
                       like                                        weight 8
    The highest is the instruction data; the next one that is used at all is
    taken as the upvalues, because that is the other thing a maker is given.
    """
    body = src[f.body_at:f.end or len(src)]
    toks = [t for t in lua_tokens.tokens(body) if t.kind != "comment"]
    direct = {p: 0 for p in f.params}
    nested = {p: 0 for p in f.params}
    used = {p: 0 for p in f.params}
    for i, t in enumerate(toks):
        if t.kind != "name" or t.text not in direct:
            continue
        used[t.text] += 1
        if i + 2 < len(toks) and toks[i + 1].text == "[":
            if toks[i + 2].kind == "number":
                direct[t.text] += 4
            elif toks[i + 2].kind == "name" and toks[i + 2].text == t.text:
                nested[t.text] += 8
    order = sorted(f.params,
                   key=lambda p: (-(direct[p] + nested[p]), -direct[p],
                                  f.params.index(p)))
    proto = order[0] if order else None
    rest = [p for p in order[1:] if used[p]]
    return proto, (rest[0] if rest else None), direct, nested, used


def find(src, row=None, pc=None, loop_at=None):
    """The maker, and which of its parameters is the instruction data."""
    at = loop_at if loop_at is not None else _loop_at(src, row, pc)
    if at is None:
        return None, "the dispatch loop was not found in this source"
    enc = lua_tokens.enclosing(src, at)
    if not enc:
        return None, ("nothing encloses the dispatch loop, so there is no "
                      "function being handed one program function at a time")
    named = [f for f in enc if [p for p in f.params if p != "..."]]
    if not named:
        return None, ("every function enclosing the dispatch loop takes only "
                      "varargs, so none of them is handed an instruction "
                      "table by name")
    maker = named[0]
    maker.params = [p for p in maker.params if p != "..."]
    proto, upvals, direct, nested, used = _score_params(src, maker)
    if proto is None:
        return None, "the maker's parameters could not be told apart"
    why = ("the dispatch loop is at %d; %d function(s) enclose it, and the "
           "innermost with named parameters is at %d taking (%s). In its body "
           "%s is indexed by a number %d time(s) and by something out of "
           "itself %d time(s), which is what reading an instruction looks "
           "like, so it is the instruction data%s"
           % (at, len(enc), maker.start, ", ".join(maker.params), proto,
              direct[proto] // 4, nested[proto] // 8,
              ("; %s is the other thing it is given and is taken as the "
               "upvalues" % upvals) if upvals else ""))
    # the maker's own name, for the places that need to find its call site: the
    # text right before the function expression it was assigned to
    nm = re.search(r"(\w+)\s*=\s*function\s*\(",
                   src[max(0, maker.start - 48):maker.start + 20])
    return Found(maker=maker, proto=proto, upvals=upvals, loop_at=at, why=why,
                 enclosing=len(enc), maker_name=(nm.group(1) if nm else None)), why


# The edit. Table operations only - a protected build watches its own stack,
# and a call would change what it sees. `__VMPROTO` is a table the harness
# serves; its metatable does the copying, where the build cannot look.
# No leading semicolon: Luau has no empty statement, and `function(a,b);if ...`
# is a syntax error rather than a no-op. This cost two rounds of a chunk that
# silently would not compile.
EDIT = ("if __VMPROTO and not __VMPROTO[%s] then __VMPROTO[%s]=%s end ")


def patch(src, found):
    """`src` with the edit at the start of the maker's body."""
    at = found.maker.body_at
    edit = EDIT % (found.proto, found.proto, found.upvals or "true")
    return src[:at] + edit + src[at:], edit


# ------------------------------------------------------------------ constants
#
# An instruction that loads a constant carries an index, and the constant table
# holds a small record per index: a type tag, a seed, and the VALUE AS
# CIPHERTEXT. Reading the index is not reading the constant, so a function that
# never ran decodes to instructions with no strings in them - the shape of the
# program without any of its words.
#
# The interpreter decrypts a constant the first time it is asked for, through a
# memoised resolver. Rather than reimplement that decryption - which would be a
# second implementation to keep right - the resolver itself is taken, and the
# program's own code turns its own constants into values.
#
# It is found by shape, like the maker: a local function of ONE parameter whose
# first act is to look that parameter up in a captured table and return field 1
# of what it finds. That is a memo cache, and a memo cache in front of one
# argument is what a lazy resolver looks like. No name is assumed.
_RESOLVER = re.compile(
    r"local\s+function\s+(\w+)\s*\(\s*(\w+)\s*\)\s*"
    r"local\s+(\w+)\s*=\s*(\w+)\s*\[\s*\2\s*\]\s*;?\s*"
    r"if\s+\3\s+then\s+return\s+\3\s*\[\s*1\s*\]\s*end")


def find_resolver(src):
    """The memoised one-parameter resolver, and where its body ends."""
    best = None
    for m in _RESOLVER.finditer(src):
        name, param, _memo, cache = m.groups()
        # the cache must be something the function captured rather than made:
        # a resolver remembers across calls, so its table is declared outside
        if re.search(r"local\s+%s\s*=" % re.escape(cache), src[:m.start()]) \
                is None:
            continue
        f = None
        for g in lua_tokens.functions(src):
            if g.start >= m.start() and g.end:
                f = g
                break
        if f is None:
            continue
        why = ("a one-parameter function at %d (%s) whose first act is to look "
               "its argument up in %s and return field 1 of what it finds: a "
               "memo cache in front of one argument, which is what a lazy "
               "resolver looks like" % (m.start(), name, cache))
        best = (name, param, f.end, why)
        break
    if best is None:
        return None, ("no memoised one-parameter resolver was found, so the "
                      "constants stay as the numbers the instructions carry")
    return best, best[3]


# The second edit, in the same currency as the first: one table write, no call.
# The resolver is handed over as a KEY, so the harness can ask it for every
# constant after the copying - the program decrypting its own strings.
# A leading space is not cosmetic: the edit lands straight after the
# resolver's `end`, and `endif` is one name to a Lua lexer.
RESOLVER_EDIT = " if __VMPROTO then __VMPROTO[%s]=%s end "


def patch_resolver(src, found):
    """`src` with the resolver handed over, after the resolver is defined."""
    name, _param, end_at, _why = found
    edit = RESOLVER_EDIT % (name, '"resolver"')
    return src[:end_at] + edit + src[end_at:], edit


# ------------------------------------------------------------------- the check
#
# A protected build of this family does not only hide the program: it decides
# whether to run it. The decision is a hash. It asks the host for values - what
# a datatype prints, what a method returns - digests them, and compares against
# digests it carries. In a real client they match. In anything standing in for
# one they do not, and the program is never reached.
#
# That comparison is the most useful thing in the file, because it is a TEST
# with an answer the build already knows. Hook the digest and you learn, per
# value, whether this environment behaved like the real one - and when it did
# not, exactly which value was wrong. Nothing is guessed and nothing is
# inserted: the digests are the build's own, and the only way to make them agree
# is for the host to be right.
#
# Found by the algorithm's own constants. SHA-256's initial hash values are the
# fractional parts of the square roots of the first eight primes and are the
# same in every implementation, so finding them is recognising a published
# algorithm rather than recognising this build.
_SHA256_INIT = ("1779033703", "3144134277", "1013904242", "2773480762",
                "1359893119", "2600822924", "528734635", "1541459225")


def find_hasher(src):
    """The function that digests a value, and where its body ends."""
    at = -1
    for c in _SHA256_INIT:
        i = src.find(c)
        if i >= 0:
            at = i
            break
    if at < 0:
        return None, ("no SHA-256 constants are in this source, so nothing "
                      "here digests a value and there is no check to watch")
    chain = lua_tokens.enclosing(src, at)
    best = None
    for f in chain:
        if f.end is None:
            continue
        named = [p for p in f.params if p != "..."]
        if not named:
            continue
        # the digest function, not the chunk that contains it: a span that is
        # most of the file is the chunk
        if f.end - f.start > len(src) // 4:
            continue
        best = f
        break
    if best is None:
        return None, ("the SHA-256 constants are not inside a function this "
                      "reads, so the digest cannot be watched")
    m = re.search(r"local\s+function\s+(\w+)\s*\(\s*$",
                  src[:best.start + 1])
    if not m:
        m = re.search(r"local\s+function\s+(\w+)\s*\(",
                      src[max(0, best.start - 80):best.start + 40])
    if not m:
        return None, ("the digest function has no name to stand in front of, "
                      "so it cannot be watched")
    name = m.group(1)
    why = ("SHA-256's own initial constants are at %d, inside a %d-byte "
           "function named %s taking (%s) - so that is what digests a value"
           % (at, best.end - best.start, name, ", ".join(best.params)))
    return (name, best.end, why), why


# One wrapper, after the function is defined: the digest and what was digested.
# A wrapper is a call and a call is a stack frame, which this harness avoids
# elsewhere on purpose - so this is its own round of the ladder, and a build that
# notices gets the round without it.
HASHER_EDIT = (" local %s_VS=%s %s=function(...) local r=%s_VS(...) "
               "if __HASH then __HASH(r,...) end return r end ")


def patch_hasher(src, found):
    """`src` with the digest function wrapped, after it is defined."""
    name, end_at, _why = found
    edit = HASHER_EDIT % (name, name, name, name)
    return src[:end_at] + edit + src[end_at:], edit


# ------------------------------------------------------------------- the gate
#
# The point where a build of this family stops checking and starts running the
# program - and the thing worth understanding about it is that the check is not a
# comparison. The numbers the program measured from the host ARE the key:
#
#   local K = { f1(m1..m6), f2(m1..m6), f3(m1..m6) }
#   PROGRAM = deserialise(decrypt(SLICE(2), K, salt, salt))
#   return MAKER(PROGRAM, {})(args)
#
# So there is no branch to take and no digest to satisfy. A host that answers one
# of those measurements differently produces a different key, the decryption
# yields noise, and the deserialiser walks off the end of it. That is why forcing
# a branch cannot reach the program and why host fidelity is the whole task.
#
# Watching it is what makes fidelity measurable: the key and the numbers it was
# made from, written down each run, so the same harness run in a real client and
# run here can be compared number by number and the one that differs is the one
# to fix.
#
# Found by shape: the only place that hands the maker a table it has just built
# from a slice and immediately calls the result.
def _key_inputs(back, q):
    """The locals the key was computed from, read just above it.

    One key that differs from a real client's says the host was wrong somewhere.
    The numbers it was made of say WHERE. They are looked for before the key's own
    table rather than in the last few hundred bytes, because that table is long
    enough on its own to push them out of reach.
    """
    head = back[:q] if q >= 0 else back
    return re.findall(
        r"local\s+(\w+)\s*=\s*\w+\[[^\]]+\](?:\[[^\]]+\])?\s*;", head)[-7:]


def find_gate(src, maker_name):
    """Where the payload is decrypted and run, and the key it is decrypted with.

    Returns (key_var, prog_var, at, why) with `at` the offset of the `return`.
    """
    if not maker_name:
        return None, "the maker has no name, so its call site cannot be found"
    pat = re.compile(r"return\s+%s\s*\(\s*(\w+)\s*,\s*\{\s*\}\s*\)\s*\("
                     % re.escape(maker_name))
    sites = []
    for m in pat.finditer(src):
        prog = m.group(1)
        back = src[max(0, m.start() - 2000):m.start()]
        # the key: a local assigned a table constructor of parenthesised
        # arithmetic, which is then given to the decryption and to the loop
        keys = re.findall(r"local\s+(\w+)\s*=\s*\{\s*\(", back)
        if not keys:
            continue
        key = keys[-1]
        if ("%s," % key) not in back and ("%s)" % key) not in back:
            continue
        # WHERE TO WRITE IT DOWN: after the key is built, not before the call.
        # The decryption and the deserialising happen between the two, and when
        # the key is wrong the deserialiser raises - so an edit at the call site
        # never runs on the runs that most need explaining. The first version of
        # this recorded nothing for exactly that reason.
        base = max(0, m.start() - 2000)
        q = back.rfind("local %s={" % key)
        at = m.start()
        if q >= 0:
            i = base + q + len("local %s=" % key)
            depth = 0
            while i < m.start():
                c = src[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            while i < m.start() and src[i] == ";":
                i += 1
            at = i
        why = ("the maker is called at %d on a table built just above it, and "
               "the local %s - a table of computed numbers - is handed to the "
               "decryption that built it: so %s is the key the payload is "
               "decrypted with, and it is made of numbers measured from the "
               "host. It is written down at %d, as soon as it exists, because "
               "the decryption between there and the call is what raises when "
               "the key is wrong" % (m.start(), key, key, at))
        sites.append((key, prog, at, _key_inputs(back, q), m.start()))
    if not sites:
        return None, ("no place hands the maker a table built from a slice and "
                      "calls it, so this build has no gate of that shape")
    # EVERY COPY OF IT. This interpreter carries its dispatch six times over -
    # one per stack-handling variant it chooses between at run time - so the gate
    # exists six times and only one of them runs. Patching the first recorded
    # nothing on a run that went through the fifth.
    why = ("%d copy(s) of the gate: the maker is called on a table built just "
           "above it from a slice, and the local %s - a table of computed "
           "numbers - is handed to the decryption that built it. So %s is the "
           "key the payload is decrypted with, and it is made of numbers "
           "measured from the host. Each is written down as soon as it exists, "
           "because the decryption between there and the call is what raises "
           "when the key is wrong"
           % (len(sites), sites[0][0], sites[0][0]))
    if sites[0][3]:
        why += (", together with the %d number(s) it was made of (%s)"
                % (len(sites[0][3]), ", ".join(sites[0][3])))
    return sites, why


# The edit: the key and the measurements, written down before the payload runs.
# A call, so it is its own round of the ladder.
# The program table does not exist yet where this lands, so only the key
# is passed; what became of the program is in the error, not here.
GATE_EDIT = (" if __KEY then __KEY(%s%s) end "
             # AND A WAY TO SUPPLY THE ONE THIS CONTAINER CANNOT MEASURE. The
             # key is what a real client measures; nothing here can produce it,
             # and no analysis can invert it. So a key measured by this same
             # harness in a real client can be handed back in, and then the
             # payload decrypts and its functions are read here like any other.
             # Absent unless something sets it, reported when used, and it is a
             # measurement of the host - not an answer written into this file.
             "if VMSMART_PAYLOAD_KEY then %s=VMSMART_PAYLOAD_KEY end ")


def patch_gate(src, sites):
    """`src` with the key recorded at every copy of the gate.

    Applied back to front so the offsets of the earlier ones stay valid.
    """
    edit = ""
    # Both points, back to front so the earlier offsets stay valid: where the key
    # exists, and where the decrypted program is about to be run. The second one
    # is what says whether the decryption produced a program at all - when the key
    # is wrong the deserialiser raises between the two and the second never runs,
    # which is itself the answer.
    marks = []
    for key, prog, at, ins, call_at in sites:
        # The substitution comes FIRST and the record second, so what is written
        # down is the key actually used. Recording before substituting meant a
        # supplied key left no trace and there was no way to tell whether it had
        # reached the decryption at all.
        marks.append((at,
                      " if VMSMART_PAYLOAD_KEY then %s=VMSMART_PAYLOAD_KEY end "
                      "if __KEY then __KEY(%s%s) end "
                      % (key, key, ("," + ",".join(ins)) if ins else "")))
        marks.append((call_at, " if __GATE then __GATE(%s) end " % prog))
    for at, text in sorted(marks, key=lambda m: -m[0]):
        edit = text
        src = src[:at] + text + src[at:]
    return src, edit


# ---------------------------------------------------------------- the cipher
#
# The payload is decrypted with a keystream: three numbers advanced per byte and
# exclusive-ored into the data. The arithmetic is in the interpreter's own
# source, so it can be reimplemented - and a reimplementation that is never
# checked against the original is a guess with extra steps.
#
# This watches the real one. The build decrypts more than one piece, and the
# pieces that are NOT the payload are decrypted with keys the file carries rather
# than with keys it measures - so those calls succeed. One of them is enough to
# check a reimplementation against: same input, same key, same output, or the
# reimplementation is wrong.
#
# Found by the algorithm's own constants: the three-way state update uses 48271,
# 65599 and 31337 in one expression each, which is this cipher and not a
# published one.
def find_cipher(src):
    """The decryption function, and where its body ends."""
    at = -1
    for m in re.finditer(r"48271", src):
        w = src[m.start():m.start() + 400]
        if "65599" in w and "31337" in w:
            at = m.start()
            break
    if at < 0:
        return None, ("no three-way keystream update is in this source, so "
                      "there is no cipher of this shape to watch")
    chain = lua_tokens.enclosing(src, at)
    best = None
    for f in chain:
        if f.end is None:
            continue
        named = [p for p in f.params if p != "..."]
        if len(named) < 2:
            continue
        if f.end - f.start > len(src) // 4:
            continue
        best = f
        break
    if best is None:
        return None, "the keystream update is not inside a function this reads"
    m = re.search(r"local\s+function\s+(\w+)\s*\(",
                  src[max(0, best.start - 80):best.start + 40])
    if not m:
        return None, "the decryption function has no name to stand in front of"
    name = m.group(1)
    why = ("the three-way keystream update is at %d, inside a %d-byte function "
           "named %s taking (%s) - so that is what decrypts a piece"
           % (at, best.end - best.start, name, ", ".join(best.params)))
    return (name, best.end, why), why


CIPHER_EDIT = (" local %s_VC=%s %s=function(...) local r=%s_VC(...) "
               "if __CIPHER then __CIPHER(r,...) end return r end ")


def patch_cipher(src, found):
    """`src` with the decryption watched, after it is defined."""
    name, end_at, _why = found
    edit = CIPHER_EDIT % (name, name, name, name)
    return src[:end_at] + edit + src[end_at:], edit


def _selftest():
    # an interpreter the shape this looks for: a maker handed a proto table and
    # an upvalue table, returning the closure that runs it
    src = (
        "local function helper(x) return x + 1 end\n"
        "local s = \"function(fake) end\"\n"
        "local make = function(proto, ups, start)\n"
        "  return function(...)\n"
        "    local pc = start or 1\n"
        "    while true do\n"
        "      local row = proto[pc]\n"
        "      if row[1] == 1 then pc = pc + 1 end\n"
        "      local k = proto[proto[2]]\n"
        "      if row == nil then break end\n"
        "    end\n"
        "  end\n"
        "end\n")
    at = src.index("local row = proto[pc]")
    f, why = find(src, loop_at=at)
    probs = []
    if f is None:
        probs.append("no maker found: %s" % why)
    else:
        if f.maker.params != ["proto", "ups", "start"]:
            probs.append("the maker came out as %r" % (f.maker.params,))
        if f.proto != "proto":
            probs.append("the instruction data came out as %r" % f.proto)
        out, edit = patch(src, f)
        if "__VMPROTO[proto]" not in out:
            probs.append("the edit did not mention the proto")
        if "(" in edit.split("__VMPROTO", 1)[1].split("]")[0]:
            probs.append("the edit calls something; it must not")
        # the edit must land at the start of the maker's body, before the
        # `return function(...)`
        i = out.index("__VMPROTO")
        if out[i - 1] != "f" and out[:i].rstrip()[-1] != ";":
            pass
        if out.index("__VMPROTO") > out.index("return function(...)"):
            probs.append("the edit landed after the body started")
    # a `function` inside a string must not be taken for the maker
    if f is not None and "fake" in (f.maker.params or []):
        probs.append("a function inside a string was taken for the maker")
    for p in probs:
        print("  PROBLEM: " + p)
    print("protohook selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()
