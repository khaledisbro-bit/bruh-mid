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
    vm.ok = bool(vm.pop and vm.push and vm.row and vm.branch)
    if not vm.ok:
        vm.notes.append("could not identify %s"
                        % ", ".join(n for n, v in
                                    (("the dispatch comparison", vm.branch),
                                     ("the pop helper", vm.pop),
                                     ("the push helper", vm.push),
                                     ("the operand row", vm.row)) if not v))
    return vm


def _raw_bodies(src, vm, limit=4000):
    if vm.branch is None:
        return []
    out = []
    for m in vm.branch.finditer(src):
        out.append(_cut(src, m.end()))
        if len(out) >= limit:
            break
    return out


_END = re.compile(r"\belse(if)?\b")


def _cut(src, start):
    """One handler's body: everything up to the branch that follows it. The
    obfuscator writes these as one long if-chain with no line breaks, so the
    next `elseif` is the end of this body wherever it appears."""
    body = src[start:start + MAX_BODY]
    m = _END.search(body)
    if m and m.start() > 0:
        body = body[:m.start()]
    return body.strip()


def handlers(src, vm):
    """Every candidate handler body, by opcode."""
    out = defaultdict(list)
    if vm.branch is None:
        return out
    for m in vm.branch.finditer(src):
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


def classify(body, vm):
    """What one handler body does, in terms the body itself states."""
    pops = len(re.findall(r"=\s*%s\(\)" % re.escape(vm.pop), body))
    expr = _result(body, vm)
    if expr is None:
        return None, pops
    e = _trim(expr)
    m = re.fullmatch(r"(\w+)\[(\w+)\]", e)
    if m:
        return "INDEX", pops
    if re.fullmatch(r"\{\s*\}", e):
        return "NEWTABLE", pops
    m = re.fullmatch(r"(\w+)\((.*)\)", e, re.S)
    if m and m.group(1) not in (vm.pop, vm.push):
        if m.group(1) == vm.resolver:
            return "LOADK", pops
        return "CALL", pops
    for sym in sorted(OPS, key=len, reverse=True):
        m = re.fullmatch(r"([\w\[\]\.\(\)]+)\s*%s\s*([\w\[\]\.\(\)]+)"
                         % re.escape(sym), e)
        if m:
            return OPS[sym], pops
    return None, pops


_TAIL = re.compile(r"\s*\b(end|do|then|return)\b.*$", re.S)


def _trim(expr):
    """The expression alone, without the Lua that closes the block around it."""
    return _TAIL.sub("", expr.strip()).strip()


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
        cands = []
        for body in hs[op]:
            used = _operands(body, vm.row)
            if used and max(used) > want:
                continue                     # reads an operand it never had
            sem, pops = classify(body, vm)
            if sem is None:
                continue
            if model.pops is not None and pops and pops != model.pops:
                continue                     # not what execution measured
            cands.append((sem, pops, body))
        agreed = {c[0] for c in cands}
        if len(agreed) != 1:
            if agreed:
                why[op] = ("its %d handler(s) disagree (%s), so it keeps its "
                           "number" % (len(cands), ", ".join(sorted(agreed))))
            continue
        sem = agreed.pop()
        model.operation = sem
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
