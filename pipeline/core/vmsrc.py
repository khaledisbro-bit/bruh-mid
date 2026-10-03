#!/usr/bin/env python3
"""
vmsrc.py - read the interpreter's own handlers to learn what its opcodes do.

Measuring an opcode from execution needs instances, and a script that runs
straight through gives about four of each - enough to fix how many values an
instruction moves, not enough to prove which operation it performs. The
interpreter, though, says so itself: every opcode has a handler, and the handler
is Lua.

The handler for one opcode in a real sample reads:

    local Mz = Jy(); local Mq = Jy(); Jx(Mq[Mz])

Two values taken off the stack, and the second indexed by the first put back.
That is an index operation, stated outright, and nothing had to run four times
to establish it.

Nothing here knows the interpreter's names. They are different in every build,
so they are found by shape:

  the stack helpers   the call with no arguments whose result is kept is the
                      pop; the call with one argument whose result is discarded
                      is the push. Whichever names dominate the handlers in
                      those two positions are those two operations.
  the resolver        the function that flips a negative key and returns a
                      decoded table entry is what turns an operand into a
                      constant.
  the operand row     the table indexed by small literals inside handlers.

An opcode that the obfuscator gave several handlers keeps only the candidates
whose operand use matches what the instruction actually carried, and a reading
is accepted only when the surviving candidates agree with each other AND with
the arity measured from execution. Where they disagree, the opcode keeps its
number.
"""
import re
from collections import Counter, defaultdict

MAX_BODY = 600
OPS = {"+": "ADD", "-": "SUB", "*": "MUL", "/": "DIV", "%": "MOD",
       "..": "CONCAT", "<": "LT", "<=": "LE", ">": "GT", ">=": "GE",
       "==": "EQ", "~=": "NE"}


class VM:
    def __init__(self):
        self.ok = False
        self.nl = None
        self.nu = None
        self.branch = None
        self.pop = None
        self.push = None
        self.resolver = None
        self.row = None
        self.pc = None
        self.regs = None
        self.sp = None
        self.opvar = None
        self.branch_plain = None
        self.notes = []

    def describe(self):
        if not self.ok:
            return "the interpreter's source was not in a readable shape"
        return ("pop=%s() push=%s(v) constant=%s(k) operands=%s[i]"
                % (self.pop, self.push, self.resolver, self.row))


def discover(src):
    """Find the interpreter's own primitives by the shape of their use."""
    vm = VM()
    # The dispatch compares one difference against each opcode. Anchoring on
    # that exact difference is what separates an opcode branch from the other
    # comparisons the interpreter makes - its anti-analysis bit tests compare
    # against numbers in the same way, and matching those instead hands back a
    # body containing dozens of unrelated handlers.
    d = re.search(r"\(\((\w+)-(\w+)\)%0[xX][0-9a-fA-F]+", src)
    if d:
        vm.nl, vm.nu = d.group(1), d.group(2)
        vm.branch = re.compile(r"\(%s-%s\)%%[0-9a-fA-FxX]+==(\d+) then"
                               % (re.escape(vm.nl), re.escape(vm.nu)))
    m = re.search(r"local (\w+)=\(\((\w+)-1\)\*\d+", src)
    if m:
        vm.pc = m.group(2)
        r = re.search(r"local (\w+)=(\w+)\[%s\];" % re.escape(vm.pc), src)
        if r:
            vm.row = r.group(1)
    m = re.search(r"local function (\w+)\((\w+)\)if \2<0 then \2=-\2-\w+ end;"
                  r"return \w+\(\w+\[\2\]\)end", src)
    if m:
        vm.resolver = m.group(1)
    # The register array and the stack pointer, from the flush this family writes
    # at the top of a handler: `if n>=2 then ARR[SP-1]=X end;if n>=1 then
    # ARR[SP]=Y end`. Those two names are what the handlers that do NOT use the
    # stack helpers work on, and without them four handlers in five read as
    # unclassifiable.
    m = re.search(r"if\s+\w+>=2\s+then\s+(\w+)\[(\w+)-1\]\s*=", src)
    if m:
        vm.regs, vm.sp = m.group(1), m.group(2)

    # The SECOND dispatch form. This family puts its hottest opcodes in a plain
    # `OP==N then` chain and the rest in the masked bit-tree above. Reading only
    # the tree left the eight most frequent opcodes of the real sample unnamed -
    # 2,681 of the steps in one run - because their handlers were never looked
    # at. The opcode variable is the one compared against the most distinct
    # numbers, which is what a dispatch chain is.
    # The opcode variable is READ FROM THE ROW. Picking the name compared against
    # the most distinct numbers instead chose a handler-local that selects one of
    # the interpreter's slots by a negative operand - it is compared against
    # eight numbers and is not the opcode - so the whole plain chain was read
    # against the wrong name and produced no handlers at all.
    row_reads = set()
    for pat in (r"local\s+([A-Za-z_]\w*)\s*=\s*%s\s+and\s+%s\s*\[",
                r"local\s+([A-Za-z_]\w*)\s*=\s*%s\s*\["):
        if vm.row:
            row_reads.update(re.findall(pat % (re.escape(vm.row),
                                               re.escape(vm.row)), src)
                             if pat.count("%s") == 2 else
                             re.findall(pat % re.escape(vm.row), src))
    counts = defaultdict(set)
    for name, num in re.findall(r"\b([A-Za-z_]\w*)\s*==\s*(\d+)\s+then", src):
        if not row_reads or name in row_reads:
            counts[name].add(num)
    if counts:
        best = max(counts, key=lambda k: len(counts[k]))
        if len(counts[best]) >= 4:
            vm.opvar = best
            vm.branch_plain = re.compile(r"\b%s\s*==\s*(\d+)\s+then"
                                         % re.escape(best))
    bodies = " ".join(_raw_bodies(src, vm))
    zero = Counter(re.findall(r"=\s*(\w+)\(\)", bodies))
    one = Counter(re.findall(r"(?:^|;|\s)(\w+)\([^();]{1,80}\)\s*(?:;|$)", bodies))
    if zero:
        vm.pop = zero.most_common(1)[0][0]
    if one:
        for name, _n in one.most_common(6):
            if name != vm.pop and name != vm.resolver:
                vm.push = name
                break
    vm.ok = bool(vm.pop and vm.push and vm.row
                 and (vm.branch or vm.branch_plain))
    if not vm.ok:
        vm.notes.append("could not identify %s"
                        % ", ".join(n for n, v in
                                    (("the dispatch comparison", vm.branch),
                                     ("the pop helper", vm.pop),
                                     ("the push helper", vm.push),
                                     ("the operand row", vm.row)) if not v))
    return vm


def _branches(vm):
    """Every pattern that marks the start of a handler body."""
    return [p for p in (vm.branch, vm.branch_plain) if p is not None]


def _raw_bodies(src, vm, limit=4000):
    out = []
    for pat in _branches(vm):
        for m in pat.finditer(src):
            out.append(_cut(src, m.end()))
            if len(out) >= limit:
                return out
    return out


# Tokens that open and close a Lua block, plus string literals, which are skipped
# so a keyword inside one cannot be mistaken for structure.
_TOKENS = re.compile(
    r"""(?P<str>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\[\[.*?\]\])"""
    r"|(?P<open>\b(?:then|do|function)\b)"
    r"|(?P<close>\bend\b)"
    r"|(?P<repeat>\brepeat\b)"
    r"|(?P<until>\buntil\b)"
    r"|(?P<alt>\b(?:elseif|else)\b)",
    re.S)


def _cut(src, start, window=6000):
    """One handler's body.

    The obfuscator writes the dispatch as one if-chain with no line breaks, so
    the body ends at the `elseif`, `else` or `end` that belongs to THAT chain -
    not at the first one that appears. Handlers in this family contain if-chains
    of their own, several levels deep, and stopping at the first `else` cut four
    bodies in five off before the work they do: the handler for one opcode came
    back as `local Go=NO[4];local Gy;if Go>0 then Gy=YU[Go]` and read as
    unclassifiable.

    So blocks are counted. Depth zero is the branch body itself; an `elseif`,
    `else` or `end` at depth zero ends it.
    """
    text = src[start:start + window]
    depth = 0
    # `if ... then ... elseif ... then ... end` has two `then` and ONE `end`: the
    # second `then` continues the same block rather than opening another. Counting
    # both made the depth climb and never come back, so a body ran on past its own
    # handler and into the ones after it - the handler for one opcode came back
    # 5,910 characters long with three other handlers inside it.
    skip_next_then = False
    for m in _TOKENS.finditer(text):
        kind = m.lastgroup
        if kind == "str":
            continue
        if kind == "open":
            if m.group("open") == "then" and skip_next_then:
                skip_next_then = False
                continue
            depth += 1
        elif kind == "repeat":
            depth += 1
        elif kind in ("close", "until"):
            if depth == 0:
                return text[:m.start()].strip()
            depth -= 1
        elif kind == "alt":
            if depth == 0:
                return text[:m.start()].strip()
            if m.group("alt") == "elseif":
                skip_next_then = True
    return text.strip()


def handlers(src, vm):
    """Every candidate handler body, by opcode, from both dispatch forms."""
    out = defaultdict(list)
    for pat in _branches(vm):
        for m in pat.finditer(src):
            body = _cut(src, m.end())
            if body and body not in out[int(m.group(1))]:
                out[int(m.group(1))].append(body)
    return out


def _operands(body, row):
    return [int(x) for x in re.findall(r"%s\[(\d+)\]" % re.escape(row), body)]


def _result(body, vm):
    """The expression the handler produces.

    A handler either pushes its result or writes it somewhere the next one
    reads. Both are the operation; only where it lands differs, so both are
    taken."""
    m = re.search(r"%s\((.+)$" % re.escape(vm.push), body)
    if m:
        expr = _balanced(m.group(1))
        if expr is not None:
            return expr
    taken = set(re.findall(r"local (\w+)\s*=\s*%s\(\)" % re.escape(vm.pop),
                           body))
    for m in re.finditer(r"(?:^|;)\s*[\w\[\]\.]+\s*=\s*([^;]+)", body):
        expr = m.group(1).strip()
        if any(re.search(r"\b%s\b" % re.escape(t), expr) for t in taken):
            return expr
    return None


def _store(body, vm):
    """A handler whose effect is a write rather than a value.

    Three shapes, by what is written to:
      BOX[row[i]][1] = v   a variable the program declared, kept in a one-element
                           box so closures can share it
      SLOT = v             one of the interpreter's own single-name slots, which
                           the handlers select between by a negative operand
      T[k] = v             a field of a table
    The register array itself is not a store: writing it is how a value is
    returned, and that is handled above.
    """
    if vm.row is None:
        return None
    if re.search(r"\w+\[%s\[\d+\]\]\[1\]\s*=[^=]" % re.escape(vm.row), body):
        return "SETVAR"
    # The same write, with the operand reached through a local or two:
    # `local g = row[2]; local h = g[1]; BOX[h[2]][1] = v`. What makes it a
    # variable write is the one-element box on the left, not how the index was
    # worked out - and insisting on the direct shape left the busiest store in
    # this build reading as a write to a table field.
    if re.search(r"\w+\[.{1,40}?\]\[1\]\s*=[^=]", body):
        return "SETVAR"
    # a negative-operand chain selecting a named slot, then a write to it
    if re.search(r"(\w+)\s*=\s*\w+\s*;?\s*$", body) and \
       re.search(r"\w+==-\d+\s+then", body):
        return "SETSLOT"
    regs = re.escape(vm.regs) if vm.regs else None
    for m in re.finditer(r"(\w+)\[([^\]]+)\]\s*=\s*[^=]", body):
        if regs and m.group(1) == vm.regs:
            continue
        if m.group(1) == vm.row:
            continue
        return "SETINDEX"
    if vm.sp and re.search(r"%s\s*=\s*%s\s*-\s*1" % (re.escape(vm.sp),
                                                      re.escape(vm.sp)), body):
        return "POP"
    return None


def _chase(expr, body, rounds=3):
    """Follow a bare name back to what it was assigned.

    A minified handler computes into temporaries and pushes the temporary:
    `local a = x * k; ...; SP = SP + 1; ARR[SP] = a`. The result is the name `a`,
    which says nothing, and the operation is in its assignment. Followed back, a
    few steps at most, and only for a plain identifier - an index or a call is
    already the answer.
    """
    seen = set()
    for _ in range(rounds):
        e = expr.strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", e) or e in seen:
            return expr
        seen.add(e)
        last = None
        for m in re.finditer(r"(?:local\s+)?\b%s\s*=\s*([^;]+)" % re.escape(e),
                             body):
            last = m.group(1)
        if last is None:
            return expr
        expr = last
    return expr


def branch_nets(body, vm):
    """The net stack effect of each top-level alternative in this handler.

    A handler with alternatives performs ONE of them, and the measured delta
    says which. Comparing the measured delta against a single number computed
    over the whole body rejected a correct reading whenever the branch that ran
    was not the one the count described.
    """
    body = strip_flush(body)
    parts, depth, start = [], 0, 0
    skip_then = False
    for m in _TOKENS.finditer(body):
        kind = m.lastgroup
        if kind == "str":
            continue
        if kind == "open":
            if m.group("open") == "then" and skip_then:
                skip_then = False
                continue
            depth += 1
        elif kind == "repeat":
            depth += 1
        elif kind in ("close", "until"):
            depth = max(0, depth - 1)
        elif kind == "alt" and depth == 1:
            # an alternative of the handler's own outermost if-chain
            parts.append(body[start:m.start()])
            start = m.end()
            if m.group("alt") == "elseif":
                skip_then = True
    parts.append(body[start:])
    nets = set()
    for part in parts:
        pushes = _pushes_in(part, vm)
        pops = _pops_in(part, vm)
        nets.add(pushes - pops)
    return nets


def _pushes_in(text, vm):
    needles = []
    if vm.push:
        needles.append(re.compile(r"\b%s\(" % re.escape(vm.push)))
    if vm.regs and vm.sp:
        needles.append(re.compile(r"%s\[%s\]\s*=\s*(?!nil)"
                                  % (re.escape(vm.regs), re.escape(vm.sp))))
    return _path_count(text, needles) if needles else 0


def _pops_in(text, vm):
    needles = []
    if vm.pop:
        needles.append(re.compile(r"=\s*%s\(\)" % re.escape(vm.pop)))
    if vm.sp:
        needles.append(re.compile(r"%s\s*=\s*%s\s*-\s*1"
                                  % (re.escape(vm.sp), re.escape(vm.sp))))
    return _path_count(text, needles) if needles else 0


def _path_count(body, needles):
    """How many times something happens along ONE path through this body.

    Counting every occurrence is wrong where the occurrences are alternatives. A
    handler that selects one of the interpreter's named slots writes
    `if k==-1 then push(A) elseif k==-2 then push(B) ... end` with eight pushes,
    of which exactly one runs - and counting eight made the handler's net effect
    nine where execution measured one, which rejected the handler.

    So branches are folded: inside an if-chain, the count is the LARGEST of its
    branches, not their sum. Everything outside a branch is simply added.
    """
    counts = [0]           # one accumulator per open block
    branch_max = [0]       # the best alternative seen at each level
    pos = 0
    for m in _TOKENS.finditer(body):
        kind = m.lastgroup
        if kind == "str":
            continue
        seg = body[pos:m.start()]
        pos = m.end()
        for pat in needles:
            counts[-1] += len(pat.findall(seg))
        if kind == "open" or kind == "repeat":
            counts.append(0)
            branch_max.append(0)
        elif kind == "alt":
            # a new alternative at this level: remember the best so far
            if len(counts) > 1:
                branch_max[-1] = max(branch_max[-1], counts[-1])
                counts[-1] = 0
        elif kind in ("close", "until"):
            if len(counts) > 1:
                best = max(branch_max.pop(), counts.pop())
                counts[-1] += best
            # an unbalanced `end` closes the handler itself
    tail = body[pos:]
    for pat in needles:
        counts[-1] += len(pat.findall(tail))
    total = counts[0]
    for i in range(1, len(counts)):
        total += max(counts[i], branch_max[i] if i < len(branch_max) else 0)
    return total


def _pushes(body, vm):
    """How many values this handler leaves on the stack.

    Both styles count: a call to the push helper, and a write to the register
    array at the pointer that is not the nil of a pop.
    """
    body = strip_flush(body)
    needles = []
    if vm.push:
        needles.append(re.compile(r"\b%s\(" % re.escape(vm.push)))
    if vm.regs and vm.sp:
        # a write to the slot at the pointer, excluding the nil of a pop
        needles.append(re.compile(r"%s\[%s\]\s*=\s*(?!nil)"
                                  % (re.escape(vm.regs), re.escape(vm.sp))))
    if not needles:
        return 0
    return _path_count(body, needles)


# Operations that leave a value. A handler that execution measured as producing
# nothing cannot be one of these, whatever its text looks like.
VALUE_OPS = {"INDEX", "GETVAR", "GETSLOT", "LOADK", "NEWTABLE", "LEN", "CALL",
             "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "CONCAT", "EQ", "NE",
             "LT", "LE", "GT", "GE", "NOT", "UNM"}


def classify(body, vm, produces=None):
    """What one handler body does, in terms the body itself states.

    `produces` is what execution measured: True if this opcode was seen leaving
    a value, False if it was seen leaving none, None if nothing settled it. A
    handler whose text reads as a value operation but which was measured to
    leave nothing is not that operation - the expression the reader found is
    working the value out, and what the handler DOES with it is the write at the
    end. Without this, the busiest store in two different builds read as an
    index: `v = v[1]` unboxes a variable, and unboxing is not the point of the
    handler.

    Two styles, because this family writes both: handlers that take values with a
    pop helper and hand the result to a push helper, and handlers that work on the
    register array directly after flushing the previous instruction's result. The
    second style was four fifths of the handlers in the sample this was written
    against, and reading only the first left them all unexplained.
    """
    body = strip_flush(body)
    pops = _path_count(body, [re.compile(r"=\s*%s\(\)" % re.escape(vm.pop))])
    # A handler that pushes something and THEN stores into a variable box is a
    # store: the push was part of working the value out. Reading the push first
    # named one opcode INDEX when what it does is write a variable, and that
    # reading was then withdrawn by a type check, so the opcode ended up with no
    # operation at all.
    if vm.row:
        store_at = None
        for m in re.finditer(r"\w+\[%s\[\d+\]\]\[1\]\s*=[^=]" % re.escape(vm.row),
                             body):
            store_at = m.start()
        push_at = None
        if vm.push:
            for m in re.finditer(r"\b%s\(" % re.escape(vm.push), body):
                push_at = m.start()
        if store_at is not None and (push_at is None or store_at > push_at):
            return "SETVAR", pops
    expr = _result(body, vm)
    if expr is None:
        expr = _result_regs(body, vm)
        if expr is not None and pops == 0 and vm.sp:
            # a register-style handler pops by stepping the pointer back
            pops = _path_count(body, [re.compile(r"%s\s*=\s*%s\s*-\s*1"
                                                 % (re.escape(vm.sp),
                                                    re.escape(vm.sp)))])
    # A write to the PROGRAM COUNTER is a jump, and it is the one operation this
    # reader had no name for. On the real sample the opcode that performs it ran
    # 710 times and its handler read as unclassifiable, which left every value
    # feeding a branch target unexplained.
    if vm.pc and re.search(r"\b%s\s*=(?!=)" % re.escape(vm.pc), body):
        # a conditional jump tests something first; an unconditional one does not
        if re.search(r"\bif\b", body):
            return "CJMP", pops
        return "JMP", pops
    if expr is None and re.search(r"\w+==-\d+\s+then", body) and vm.push \
       and re.search(r"%s\(" % re.escape(vm.push), body):
        # every push is inside a chain selecting one of the interpreter's named
        # slots by a negative operand: the handler reads one of those slots
        return "GETSLOT", pops
    if expr is None:
        # No result on the stack. A handler can still be an operation: this
        # family's stores end with a write to a variable box, to one of the
        # interpreter's named slots, or to a table - and reading only pushes left
        # every one of them unexplained.
        store = _store(body, vm)
        if store is not None:
            return store, pops
        return None, pops
    if produces is False:
        # measured to leave nothing. The write at the end is what it does.
        store = _store(body, vm)
        if store is not None:
            return store, pops
        return None, pops
    e = _trim(_chase(_trim(expr), body))
    # A variable box reached through an operand: `BOX[row[i]][1]`. This is the
    # shape that reads one of the program's own variables, and the single-level
    # pattern below cannot see it.
    if vm.row and re.fullmatch(r"\w+\[%s\[\d+\]\]\[1\]" % re.escape(vm.row), e):
        return "GETVAR", pops
    # an index chain of any depth is still an index
    if re.fullmatch(r"\w+(?:\[[^\[\]]+\])+", e) and e.count("[") > 1:
        return "INDEX", pops
    m = re.fullmatch(r"(\w+)\[(\w+)\]", e)
    if m:
        # Indexing a VARIABLE BOX is how this family reads one of the program's
        # own variables, and calling that INDEX put a table lookup in the report
        # where a variable read belongs.
        if vm.row and re.search(r"\b%s\[%s\[\d+\]\]" % (re.escape(m.group(1)),
                                                          re.escape(vm.row)),
                                body):
            return "GETVAR", pops
        return "INDEX", pops
    if re.fullmatch(r"\{\s*\}", e):
        return "NEWTABLE", pops
    m = re.fullmatch(r"(\w+)\((.*)\)", e, re.S)
    if m and m.group(1) not in (vm.pop, vm.push):
        if m.group(1) == vm.resolver:
            return "LOADK", pops
        return "CALL", pops
    # A bare name whose value was selected by a negative operand is one of the
    # interpreter's own slots, and pushing it is a read of that slot. Two opcodes
    # of the real sample do nothing else, and their handlers read as
    # unclassifiable because the name alone matches no pattern.
    if re.fullmatch(r"[A-Za-z_]\w*", e) and re.search(r"==-\d+\s+then", body):
        return "GETSLOT", pops
    # `#x` is an operation too, and the only unary one this family writes.
    if re.fullmatch(r"#\s*[\w\[\]\.\(\)]+", e):
        return "LEN", pops
    sym = _top_level_op(e)
    if sym:
        return OPS[sym], pops
    return None, pops


def style(body, vm):
    """Whether this handler takes its inputs through the pop helper.

    It matters for what may be CHECKED against it. The lifter's idea of what an
    instruction popped is a model built from arities; for a handler that calls
    the pop helper, that model is the handler's own inputs and a type check
    against it is meaningful. For a handler that works the register array
    directly, the popped list is a model and nothing more - and checking a
    reading against it withdrew the best-evidenced operation in the capture,
    because the preview it compared was never that handler's operand.
    """
    body = strip_flush(body)
    # MIXED counts as register style. A handler that calls the pop helper AND
    # reads the register array directly takes its operands from both, so the
    # order of the lifter's popped list is not the order of its inputs - which
    # is what a type check assumes. Three of the four most frequent opcodes of
    # the real sample are mixed, and treating them as stack handlers withdrew
    # their readings on previews that were never their operands.
    if vm.regs and vm.sp and re.search(r"%s\[%s" % (re.escape(vm.regs),
                                                   re.escape(vm.sp)), body):
        return "regs"
    if vm.pop and re.search(r"=\s*%s\(\)" % re.escape(vm.pop), body):
        return "stack"
    return "regs"


# Operators by precedence, lowest first: the operator that splits the expression
# is the lowest-precedence one at bracket depth zero. A pattern with both sides
# written as `[\w\[\]\.\(\)]+` cannot see it - `((a+b)%k)` has an operator in
# its left half, so the whole expression matched nothing and the handler read as
# unclassifiable.
_PRECEDENCE = ("==", "~=", "<=", ">=", "<", ">", "..", "+", "-", "*", "/", "%")


def _top_level_op(e):
    """The operator this expression is built around, or None."""
    depth = 0
    at = {}
    i = 0
    while i < len(e):
        ch = e[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0:
            two = e[i:i + 2]
            if two in OPS:
                at.setdefault(two, i)
                i += 2
                continue
            if ch in OPS and not (ch == "-" and (i == 0 or e[i - 1] in "([{,=<>~+-*/%")):
                at.setdefault(ch, i)
        i += 1
    for sym in _PRECEDENCE:
        if sym in at:
            left, right = e[:at[sym]].strip(), e[at[sym] + len(sym):].strip()
            if left and right:
                return sym
    return None


# The deferred flush this family opens a handler with. It is bookkeeping for the
# PREVIOUS instruction's result, so leaving it in makes every handler look like a
# write to the register array.
_FLUSH = re.compile(
    r"^\s*do\s+local\s+(\w+)\s*=\s*\w+;\s*"
    r"if\s+\1>=2\s+then\s+\w+\[\w+-1\]\s*=\s*\w+\s+end;\s*"
    r"if\s+\1>=1\s+then\s+\w+\[\w+\]\s*=\s*\w+\s+end;\s*"
    r"(?:\w+\s*=\s*nil;\s*)*(?:\w+\s*=\s*0;\s*)*")


def strip_flush(body):
    """A handler body without the flush that belongs to the instruction before it."""
    return _FLUSH.sub("", body, count=1)


def _result_regs(body, vm):
    """The expression a register-style handler leaves on the stack.

    These handlers do not call a push helper: they advance the stack pointer and
    write the array. The LAST such write is the handler's result, because an
    earlier one is an argument it is still building.
    """
    if not (vm.regs and vm.sp):
        return None
    pat = re.compile(r"%s\[%s\]\s*=\s*([^;]+)"
                     % (re.escape(vm.regs), re.escape(vm.sp)))
    # The FIRST write, not the last. A handler that returns more than one value
    # writes them in order, and the one that says what the handler DID is the
    # first: on one opcode the last was a boolean flag pushed beside the value,
    # and reading it named the handler EQ when it performs an index.
    # `ARR[SP] = nil` is a POP clearing the slot, not a result, and it comes
    # first in every handler that consumes values - so the first write that is
    # not nil is the one that says what the handler produced.
    for m in pat.finditer(body):
        value = _trim(m.group(1))
        if value != "nil" and value != "":
            return value
    return None


_TAIL = re.compile(r"\s*\b(end|do|then|return)\b.*$", re.S)


def _unwrap(e):
    """An expression without the parentheses wrapped around the whole of it.

    The minifier writes `(a+b)`, and every arithmetic pattern here matches the
    bare form, so a wrapped expression fell through all of them. Only a pair that
    encloses the WHOLE expression is removed: `(a+b)*(c+d)` keeps its own.
    """
    e = e.strip()
    while len(e) > 1 and e[0] == "(" and e[-1] == ")":
        depth = 0
        whole = True
        for i, ch in enumerate(e):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(e) - 1:
                    whole = False
                    break
        if not whole:
            return e
        e = e[1:-1].strip()
    return e


def _trim(expr):
    """The expression alone, without the Lua that closes the block around it."""
    return _unwrap(_TAIL.sub("", expr.strip()).strip())


def _balanced(text):
    """The argument of a call, up to its matching bracket."""
    depth, out = 1, []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return "".join(out)
        out.append(ch)
    return None


def apply(models, src, steps):
    """Name opcodes from the interpreter's handlers, checked against execution.

    `steps` gives what each opcode actually carried and moved, so a handler that
    reads an operand the instruction never had, or that takes a different number
    of values off the stack than was measured, is not this opcode's handler."""
    vm = discover(src)
    if not vm.ok:
        return vm, 0, {}
    hs = handlers(src, vm)
    carried = defaultdict(int)
    for st in steps:
        carried[st.op] = max(carried[st.op], len(st.operands))

    named, why = 0, {}
    for op, model in models.items():
        if model.operation or op not in hs:
            continue
        want = carried.get(op, 0) + 1
        cands, rejected = [], Counter()
        for body in hs[op]:
            used = _operands(body, vm.row)
            if used and max(used) > want:
                rejected["reads operand %d, the instruction carried %d"
                         % (max(used), want)] += 1
                continue                     # reads an operand it never had
            # What execution measured about whether this opcode leaves a
            # value. The handler's text is read against it rather than on its
            # own: the two are independent evidence and the measurement is the
            # harder of them to argue with.
            produces = None
            if model.pushes is not None:
                produces = model.pushes > 0
            elif model.delta is not None and model.delta < 0:
                produces = False
            sem, pops = classify(body, vm, produces)
            if sem is None:
                rejected["body not classified"] += 1
                continue
            # NET against NET. The handler's text gives how many values it takes
            # AND how many it leaves; execution gives the difference between two
            # stack pointers. Comparing the handler's pops against a pops that was
            # itself derived from a net delta rejected every handler that both
            # consumes and produces - which is most of them, and is why a hundred
            # opcodes with perfectly readable handlers kept their numbers.
            pushes = _pushes(body, vm)
            if model.delta is not None and (pops or pushes):
                # the whole body's net, or any one of its alternatives
                nets = {pushes - pops} | branch_nets(body, vm)
                if model.delta not in nets:
                    rejected["handler nets %+d, execution measured %+d"
                             % (pushes - pops, model.delta)] += 1
                    continue
            elif model.pops is not None and pops and pops != model.pops:
                rejected["handler takes %d off the stack, execution measured %d"
                         % (pops, model.pops)] += 1
                continue                     # not what execution measured
            cands.append((sem, pops, body, pushes))
        agreed = {c[0] for c in cands}
        if len(agreed) != 1:
            if agreed:
                why[op] = ("its %d handler(s) disagree (%s), so it keeps its "
                           "number" % (len(cands), ", ".join(sorted(agreed))))
            elif rejected:
                # Which gate rejected every candidate. Without this the report
                # said only that the operation was not known, and the reason - an
                # arity measured from four instances, or an operand list the
                # capture truncated - was invisible.
                why[op] = ("every handler was rejected: "
                           + "; ".join("%s (x%d)" % (k, n)
                                       for k, n in rejected.most_common(3)))
            continue
        sem = agreed.pop()
        model.operation = sem
        model.handler_style = style(cands[0][2], vm)
        # A jump produces no value. The arity pass had to guess that from the
        # value reported after the instruction, and after a jump that value is
        # the previous instruction's leftover - so a jump was modelled as
        # pushing one, and the reconstruction rendered thousands of lines of
        # `local t = OP_311(...)` for an instruction that only moves the counter.
        # The handler says what it does, and where the measured net agrees with
        # producing nothing, the handler wins.
        if sem in ("JMP", "CJMP") and (model.delta in (None, 0)):
            if model.pushes:
                model.fact.note(
                    "vmsrc.jump",
                    "its handler only writes the program counter, so it "
                    "produces no value; the %d it was modelled as pushing came "
                    "from the value reported after it, which a jump does not "
                    "set" % model.pushes, opcodes=(op,))
            model.pushes = 0
            model.pops = 0
        # The split, as the handler states it. A stack pointer before and a
        # stack pointer after give the NET only: 1->1 and 0->0 move the stack
        # by nothing and look identical from outside. The handler's text says
        # how many values it takes off and how many it leaves, so where the two
        # agree on the net the split is read from the source rather than guessed
        # from the value that happened to be pending afterwards. Nothing here
        # changes a net that was measured.
        hp = [c[3] for c in cands if c[3] is not None]
        if hp and len(set(hp)) == 1 and len({c[1] for c in cands}) == 1:
            model.handler_pops = cands[0][1]
            model.handler_pushes = hp[0]
        model.fact.evidence = "INFERRED" if model.pops is None else "OBSERVED"
        model.fact.note(
            "vmsrc.handler",
            "the interpreter's own handler for this opcode takes %d value(s) "
            "off the stack and performs %s%s"
            % (cands[0][1], sem,
               "" if model.pops is None else
               ", which matches the %d it was measured to consume" % model.pops),
            opcodes=(op,))
        why[op] = "read from the interpreter's handler"
        named += 1
    return vm, named, why


def variables(src, vm, models, steps):
    """Which opcodes read and write the program's variables.

    A VM keeps a Lua local in a one-element box so closures can share it, and
    reaches it through a table indexed by one of the instruction's operands. Both
    halves are visible in the handler: a read is `= TABLE[row[i]][1]` and a write
    is `TABLE[row[i]][1] =`. Reading them here is what makes variables recoverable
    from a run too short to prove them by correspondence alone.

    The operand is numbered as the interpreter numbers it, and the capture lists
    operands from the second onwards, so the index is shifted to match. If that
    shift is wrong for a build, the check in dataflow rejects the pair and
    nothing is asserted."""
    if not vm.ok:
        return {}, {}
    hs = handlers(src, vm)
    carried = defaultdict(int)
    for st in steps:
        carried[st.op] = max(carried[st.op], len(st.operands))
    rd = re.compile(r"=\s*(\w+)\[%s\[(\d+)\]\]\[1\]" % re.escape(vm.row))
    wr = re.compile(r"(\w+)\[%s\[(\d+)\]\]\[1\]\s*=[^=]" % re.escape(vm.row))
    reads, writes = {}, {}
    for op, bodies in hs.items():
        if op not in models:
            continue
        want = carried.get(op, 0) + 1
        r_idx, w_idx = set(), set()
        for body in bodies:
            used = _operands(body, vm.row)
            if used and max(used) > want:
                continue
            for m in wr.finditer(body):
                w_idx.add(int(m.group(2)))
            for m in rd.finditer(body):
                r_idx.add(int(m.group(2)))
        if len(w_idx) == 1:
            writes[op] = w_idx.pop() - 2
        if len(r_idx) == 1 and op not in writes:
            reads[op] = r_idx.pop() - 2
    return reads, writes


def revoke(models, lift, why=None):
    """Drop any reading the run contradicts.

    A handler read from the interpreter is a claim about every instance of that
    opcode, so it is tested against them. Where an operation can be recomputed -
    the arithmetic and the comparisons - one instance that comes out differently
    is enough to withdraw it: the obfuscator gives an opcode several bodies, and
    picking the wrong one has to cost the reading rather than be argued around.
    """
    import opsem
    why = why if why is not None else {}
    checked = Counter()
    bad = {}
    for st in lift.steps:
        m = models.get(st.op)
        if m is None or not m.operation or len(st.pushed) != 1:
            continue
        f = opsem.CANDIDATES.get(m.operation)
        if f is None or len(st.popped) != 2:
            continue
        a, b = st.popped[0].runtime, st.popped[1].runtime
        want = st.pushed[0].runtime
        if a is None or b is None or want is None:
            continue
        got = f(a, b)
        if got is None:
            continue
        checked[st.op] += 1
        if not opsem._same(got, want):
            bad.setdefault(st.op, (m.operation, a, b, got, want, st.pc))
    for op, (sem, a, b, got, want, pc) in bad.items():
        m = models[op]
        m.operation = None
        m.fact.note("vmsrc.revoked",
                    "the handler read as %s, but at pc %d it was given %s and "
                    "%s and produced %s, not the %s that reading requires, so "
                    "the reading is withdrawn" % (sem, pc, a, b, want, got),
                    opcodes=(op,))
        why[op] = ("read as %s from a handler, withdrawn: the values it "
                   "computed do not match" % sem)
    return len(bad), sum(checked.values())


def report(vm, named, total, why):
    L = ["OPCODE MEANING FROM THE INTERPRETER'S OWN HANDLERS",
         "=" * 56,
         "A script that runs straight through gives only a few instances of each",
         "opcode - enough to measure how many values it moves, not enough to",
         "prove which operation it performs. The interpreter states that itself,",
         "in the handler it runs for that opcode.", ""]
    if not vm.ok:
        L.append("  " + (vm.notes[0] if vm.notes else "not readable"))
        L.append("  The interpreter's source was not available or not in a shape")
        L.append("  this could read, so opcodes keep whatever execution proved.")
        return "\n".join(L)
    L.append("  interpreter primitives, found by shape: " + vm.describe())
    L.append("")
    L.append("  opcodes named from their handler: %d of %d" % (named, total))
    withdrawn = [(op, w) for op, w in why.items() if "withdrawn" in w]
    if withdrawn:
        L.append("")
        L.append("  withdrawn after checking against the run (%d): a handler is"
                 % len(withdrawn))
        L.append("  a claim about every instance, and these did not hold:")
        for op, w in sorted(withdrawn)[:15]:
            L.append("    OP_%-6d %s" % (op, w))
    L.append("")
    disagreed = [(op, w) for op, w in why.items() if "disagree" in w]
    if disagreed:
        L.append("  left unnamed because their handlers disagree (the obfuscator")
        L.append("  gives an opcode several bodies, and only one is real):")
        for op, w in sorted(disagreed)[:20]:
            L.append("    OP_%-6d %s" % (op, w))
        if len(disagreed) > 20:
            L.append("    ... %d more" % (len(disagreed) - 20))
    return "\n".join(L)
