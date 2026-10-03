"""Reading Luau as tokens, so a decision about its structure is not a guess.

Everything this package does to a chunk - find the dispatch loop, find the
function that encloses it, put an edit at the start of a body - is a decision
about where something is. Made on the raw text those decisions are wrong often
enough to matter: the word `function` appears inside this family's string
literals, and counting it there walks the block depth out of step. The edit then
lands inside a literal and the chunk does not compile, which the loader hides by
falling back to the original.

So the text is read as tokens first. Strings of every Luau form - quoted, long
bracket, backtick - and comments of both forms are skipped as single tokens, and
only what is left can open or close a block.

The block rules are the language's:

    function / if / do / repeat   open one
    end / until                   close one
    for / while                   open one, and their own `do` does not open
                                  another

That last line is the one worth stating: `for i=1,n do ... end` has two block
words and one block.
"""
import re

NAME = re.compile(r"[A-Za-z_]\w*")
NUMBER = re.compile(r"0[xX][0-9A-Fa-f_]+|0[bB][01_]+|"
                    r"(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d+)?")
_LONG_OPEN = re.compile(r"\[(=*)\[")


class Token:
    __slots__ = ("kind", "text", "start", "end")

    def __init__(self, kind, text, start, end):
        self.kind = kind
        self.text = text
        self.start = start
        self.end = end

    def __repr__(self):
        return "<%s %r @%d>" % (self.kind, self.text[:20], self.start)


def _long_end(src, i):
    """The end of a long bracket starting at i, or None if one does not."""
    m = _LONG_OPEN.match(src, i)
    if not m:
        return None
    close = "]" + m.group(1) + "]"
    j = src.find(close, m.end())
    return None if j < 0 else j + len(close)


def tokens(src, stop=None):
    """Every token of `src`, in order. `stop` ends the scan early."""
    i, n = 0, len(src)
    while i < n:
        if stop is not None and i > stop:
            return
        c = src[i]
        if c in " \t\r\n":
            i += 1
            continue
        if src.startswith("--", i):
            j = _long_end(src, i + 2)
            if j is None:
                j = src.find("\n", i + 2)
                j = n if j < 0 else j + 1
            yield Token("comment", src[i:j], i, j)
            i = j
            continue
        if c in "\"'":
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == c:
                    j += 1
                    break
                if src[j] == "\n":
                    break        # an unterminated quote ends at the line
                j += 1
            yield Token("string", src[i:j], i, j)
            i = j
            continue
        if c == "`":
            # Luau's interpolated string. Braces inside it hold expressions;
            # the parts outside them are text, and the whole thing is one token
            # here because nothing in it opens a block of its own.
            j, depth = i + 1, 0
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == "{":
                    depth += 1
                elif src[j] == "}" and depth:
                    depth -= 1
                elif src[j] == "`" and not depth:
                    j += 1
                    break
                j += 1
            yield Token("string", src[i:j], i, j)
            i = j
            continue
        if c == "[":
            j = _long_end(src, i)
            if j is not None:
                yield Token("string", src[i:j], i, j)
                i = j
                continue
        m = NAME.match(src, i)
        if m:
            yield Token("name", m.group(0), i, m.end())
            i = m.end()
            continue
        m = NUMBER.match(src, i)
        if m:
            yield Token("number", m.group(0), i, m.end())
            i = m.end()
            continue
        yield Token("op", c, i, i + 1)
        i += 1


OPEN = {"function", "if", "do", "repeat"}
CLOSE = {"end", "until"}


class Func:
    """One function, from its `function` word to the end of its body."""
    __slots__ = ("start", "params", "body_at", "end")

    def __init__(self, start, params, body_at):
        self.start = start
        self.params = params
        self.body_at = body_at      # offset just after the `)`
        self.end = None

    def __repr__(self):
        return "<function(%s) @%d..%s>" % (",".join(self.params), self.start,
                                           self.end)


def functions(src, stop=None):
    """Every function in `src`, with where its body starts and ends.

    Reading to `stop` only - the functions still open there are the ones that
    enclose it, innermost last.
    """
    toks = list(tokens(src, stop=None if stop is None else len(src)))
    out, stack, pending_do = [], [], 0
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.kind != "name":
            i += 1
            continue
        w = t.text
        if w == "function":
            params, body_at = [], t.end
            j = i + 1
            # an optional name, then the parameter list
            while j < len(toks) and (toks[j].kind == "name"
                                     or toks[j].text in (".", ":")):
                j += 1
            if j < len(toks) and toks[j].text == "(":
                k = j + 1
                while k < len(toks) and toks[k].text != ")":
                    if toks[k].kind == "name":
                        params.append(toks[k].text)
                    elif toks[k].text == "." and k + 2 < len(toks) \
                            and toks[k + 1].text == "." \
                            and toks[k + 2].text == ".":
                        # the tokenizer emits `...` as three operators; a
                        # vararg parameter is still a parameter and a maker
                        # that takes only varargs is not one this can hook
                        params.append("...")
                        k += 2
                    k += 1
                body_at = toks[k].end if k < len(toks) else t.end
                j = k
            f = Func(t.start, params, body_at)
            out.append(f)
            stack.append(f)
            i = j + 1
            continue
        if w in ("for", "while"):
            stack.append(None)
            pending_do += 1
        elif w == "do":
            if pending_do:
                pending_do -= 1      # the `do` of a for/while, already counted
            else:
                stack.append(None)
        elif w in ("if", "repeat"):
            stack.append(None)
        elif w in CLOSE:
            if stack:
                f = stack.pop()
                if f is not None:
                    f.end = t.end
        i += 1
    return out


def enclosing(src, at):
    """The functions that enclose `at`, innermost first."""
    out = [f for f in functions(src)
           if f.start < at and (f.end is None or f.end > at)]
    out.sort(key=lambda f: -f.start)
    return out


def _selftest():
    probs = []
    # a `function` inside a string must not open a block
    src = ('local s = "function(x) end"\n'
           'local t = [[ function(y) end ]]\n'
           '-- function(z) end\n'
           'function outer(a, b)\n'
           '  for i = 1, 10 do\n'
           '    local inner = function(c) return c end\n'
           '    MARK()\n'
           '  end\n'
           'end\n')
    at = src.index("MARK()")
    enc = enclosing(src, at)
    names = [f.params for f in enc]
    if names != [["c"], ["a", "b"]]:
        # the innermost enclosing function at MARK is `function(c)`? No: MARK is
        # after that function's `end`, so only `outer` encloses it.
        if names != [["a", "b"]]:
            probs.append("enclosing functions came out as %r" % (names,))
    fs = functions(src)
    if len(fs) != 2:
        probs.append("found %d functions, expected 2 (the two in strings and "
                     "the comment must not count)" % len(fs))
    # repeat/until and for/do balance
    src2 = "function f()\n repeat\n  for i=1,2 do end\n until true\n HERE()\nend\n"
    enc2 = enclosing(src2, src2.index("HERE()"))
    if len(enc2) != 1 or enc2[0].params != []:
        probs.append("repeat/until or for/do unbalanced the stack: %r" % (enc2,))
    # a long bracket with equals signs
    src3 = "local x = [==[ end end end ]==]\nfunction g(p)\n THERE()\nend\n"
    enc3 = enclosing(src3, src3.index("THERE()"))
    if len(enc3) != 1 or enc3[0].params != ["p"]:
        probs.append("a long bracket with = signs was not skipped: %r" % (enc3,))
    # an interpolated string
    src4 = 'local y = `a{1}b end`\nfunction h(q)\n WHERE()\nend\n'
    enc4 = enclosing(src4, src4.index("WHERE()"))
    if len(enc4) != 1 or enc4[0].params != ["q"]:
        probs.append("an interpolated string was not skipped: %r" % (enc4,))
    # the body offset points just past the parameter list
    f = [x for x in functions(src3) if x.params == ["p"]][0]
    if src3[f.body_at:f.body_at + 8].strip().startswith("THERE") is False:
        probs.append("the body offset is not at the first statement")
    for p in probs:
        print("  PROBLEM: " + p)
    print("lua_tokens selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()
