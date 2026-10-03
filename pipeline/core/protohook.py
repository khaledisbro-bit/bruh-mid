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
    __slots__ = ("maker", "proto", "upvals", "loop_at", "why", "enclosing")

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
    return Found(maker=maker, proto=proto, upvals=upvals, loop_at=at, why=why,
                 enclosing=len(enc)), why


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
