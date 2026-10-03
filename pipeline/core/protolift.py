"""Where each instruction goes, for functions that never ran.

A decoded instruction says WHAT it does. It does not say what comes next, and in
this family that is the whole difference: control flow is flattened, so the
program is a few thousand instructions in 844 blocks and every block ends by
jumping to a number it computes. Read the instructions without the jumps and you
have a bag of operations in file order, which is not the program.

The jump target is computed, not stored. The interpreter's own resolver is four
lines of arithmetic over a table the prototype carries:

    x = operand XOR the function's jump key          (when that key is not 0)
    e = JUMPS[x]  or  {residue + x, -1, -1, -1, -1, -1, -1}
    a = (L2*48271 + x*7919 + L3) % 2147483647
    b = (L3*65599 + x*131 + a)  % 2147483647
    target = (e[1] - b) // L4 - a                   (one of four forms; L5 says
                                                     which)

L2..L7 are fields of the prototype, so they are read, not assumed, and the form
is chosen by what the prototype says rather than by what this file expects. The
`or {...}` matters: an operand the table has no entry for gets a target COMPUTED
from a base, and a computed target can land outside every block the interpreter
knows - which is how a build sends a tampered run nowhere.

Nothing here is believed on its own. The run executed some of these jumps and the
capture recorded where each one actually went, so every observed jump is resolved
again from its operand and compared. The report says how many agreed, and a
resolution that cannot reproduce what was observed is not used on what was not.

What that buys: the real control flow graph of every function, including the
parts no run reached, and from it the one question worth asking of a protected
build - which instructions can be reached from the entry at all, and which
cannot. The ones that cannot are not the program, whatever they look like.
"""
import re
from collections import defaultdict


MOD = 2147483647
SMALL = 1000003


class Function:
    """One prototype: its instructions, its jump table, its blocks."""

    __slots__ = ("pid", "key", "count", "jump_key", "lf", "jumps", "blocks",
                 "rows", "consts", "decoded", "targets", "reach", "notes")

    def __init__(self, pid):
        self.pid = pid
        self.key = None
        self.count = None
        self.jump_key = 0
        self.lf = {}
        self.jumps = {}
        self.blocks = {}
        self.rows = {}
        self.consts = {}
        self.decoded = {}
        self.targets = {}
        self.reach = set()
        self.notes = []


def _ints(text):
    out = {}
    for a, b in re.findall(r"(\d+)>(-?\d+)", text):
        out[int(a)] = int(b)
    return out


def read(capture_text):
    """Every prototype in a capture, with everything needed to walk it."""
    fns = {}

    def f(pid):
        if pid not in fns:
            fns[pid] = Function(pid)
        return fns[pid]

    for m in re.finditer(r"^p(\d+):#(\d+)=(-?\d+)$", capture_text, re.M):
        pid, k, v = int(m.group(1)), int(m.group(2)), int(m.group(3))
        g = f(pid)
        if k == 3:
            g.key = v
        elif k == 4:
            g.count = v
        elif k == 14:
            g.jump_key = v
    # the jump arithmetic's own numbers live in one field of the prototype
    for m in re.finditer(r"^p(\d+)~(\d+)\.#(\d+):(-?\d+)$", capture_text, re.M):
        pid, fld, k, v = (int(m.group(1)), int(m.group(2)), int(m.group(3)),
                          int(m.group(4)))
        f(pid).lf.setdefault(fld, {})[k] = v
    for m in re.finditer(r"^p(\d+)~(\d+)\.(\d+)\.(\d+):(.*)$", capture_text,
                         re.M):
        pid, fld, sub, key = (int(m.group(1)), int(m.group(2)),
                              int(m.group(3)), int(m.group(4)))
        f(pid).jumps.setdefault((fld, sub), {})[key] = _ints(m.group(5))
    for m in re.finditer(r"^p(\d+)~(\d+)\.(\d+):(.*)$", capture_text, re.M):
        pid, fld, sub = int(m.group(1)), int(m.group(2)), int(m.group(3))
        pairs = _ints(m.group(4))
        if pairs:
            f(pid).blocks.setdefault((fld, sub), {}).update(pairs)
    for m in re.finditer(r"^p(\d+)@2:(\d+):(.*)$", capture_text, re.M):
        pid, pc = int(m.group(1)), int(m.group(2))
        fields = {}
        for a, b in re.findall(r"(\d+)=(-?\d+)", m.group(3)):
            fields[int(a)] = int(b)
        if 1 in fields:
            f(pid).rows[pc] = fields
    # the constants, as the interpreter's own resolver gave them back
    for m in re.finditer(r"^p(\d+)!(\d+)\.(\d+)=(.*)$", capture_text, re.M):
        pid, fld, idx, val = (int(m.group(1)), int(m.group(2)),
                              int(m.group(3)), m.group(4))
        f(pid).consts.setdefault(fld, {})[idx] = _value(val)
    return fns


def _value(text):
    """One resolved constant, as the harness wrote it."""
    if text.startswith("s$"):
        hx = text[2:].split(":cut")[0]
        try:
            raw = bytes.fromhex(hx)
        except ValueError:
            return None
        try:
            return raw.decode("utf8")
        except UnicodeDecodeError:
            return raw.decode("latin1")
    if text.startswith("n="):
        try:
            return int(text[2:])
        except ValueError:
            try:
                return float(text[2:])
            except ValueError:
                return None
    if text.startswith("b="):
        return text[2:] == "true"
    return None


def pick_jump_field(fn):
    """Which field of the prototype holds the jump arithmetic.

    The one whose sub-table is keyed by large numbers and whose rows have seven
    entries - that is the shape the resolver reads. Picked by what is there, so a
    build that numbers its fields differently is read the same way.
    """
    best, best_n = None, -1
    for (fld, sub), entries in fn.jumps.items():
        if sub != 1:
            continue
        if len(entries) > best_n:
            best, best_n = fld, len(entries)
    return best


def pick_block_field(fn):
    """Which field holds the block table: start -> end, one per few pcs."""
    best, best_n = None, -1
    for (fld, sub), pairs in fn.blocks.items():
        if not pairs:
            continue
        # a block table's keys are program counters and its values are the pc
        # the block ends on, so every value is at or after its key and inside
        # the function
        n = len(pairs)
        if fn.count:
            ok = sum(1 for k, v in pairs.items()
                     if k <= v <= fn.count and k <= fn.count)
            if ok < n:
                continue
        if n > best_n:
            best, best_n = (fld, sub), n
    return best


def target(fn, operand, fld, residue=0):
    """Where a jump with this operand goes, by the interpreter's arithmetic."""
    lf = fn.lf.get(fld) or {}
    L2, L3, L4, L5 = lf.get(2), lf.get(3), lf.get(4), lf.get(5)
    if None in (L2, L3, L4, L5) or L4 == 0:
        return None, "the jump arithmetic's own numbers are not in the capture"
    x = operand ^ fn.jump_key if fn.jump_key else operand
    entries = fn.jumps.get((fld, 1)) or {}
    e = entries.get(x)
    z = e[1] if (e and 1 in e) else residue + x
    a = (L2 * 48271 + x * 7919 + L3) % MOD
    b = (L3 * 65599 + x * 131 + a) % MOD
    if L5 == 1:
        p = (z - a * 3 - b * 5) // L4
    elif L5 == 2:
        p = (z - b) ^ a
    elif L5 == 3:
        p = (z - b) // L4 - a
    else:
        p = (z - a - b) // L4
    return p + residue, ("looked up" if e else "computed from a base")


def _bodies(src, vm, window=1600):
    """Each opcode's handler body, cut where the next one starts.

    The fast path is a chain of `opcode == N then ... elseif opcode == M then`,
    so a fixed window runs into the next handler and gives it operands that are
    not its own. Cutting at the next comparison is what keeps `287` from being
    read as a jump because the handler after it is one.
    """
    if not (vm and vm.opvar):
        return {}
    pat = re.compile(r"%s\s*==\s*(\d+)\s+then" % re.escape(vm.opvar))
    hits = [(int(m.group(1)), m.end()) for m in pat.finditer(src)]
    out = defaultdict(list)
    for i, (op, at) in enumerate(hits):
        stop = hits[i + 1][1] if i + 1 < len(hits) else len(src)
        # back off to before the next comparison itself, not after it
        nxt = pat.search(src, at)
        if nxt:
            stop = min(stop, nxt.start())
        body = src[at:min(stop, at + window)]
        # the last handler in the chain is followed by the OTHER dispatch form -
        # a decision tree over the opcode's bits - and its leaves are handlers
        # too. Cutting at the first mention of that tree's own variable keeps
        # their operands from being read as this handler's.
        for nm in (vm.nl, vm.nu):
            if nm:
                i = body.find(nm)
                if i > 0:
                    body = body[:i]
        out[op].append(body)
    return out


def jump_operand_index(src, vm):
    """Which operand a jump reads, from the interpreter's own loop.

    The loop assigns its program counter from a call, and that call's first
    argument is the operand. Read rather than assumed, so an opcode that carries
    its target somewhere else is not mistaken for one that does not.
    """
    if not (vm and vm.pc and vm.row):
        return None
    m = re.search(r"%s\s*=\s*\w+\(\s*%s\[(\d+)\]"
                  % (re.escape(vm.pc), re.escape(vm.row)), src)
    return int(m.group(1)) if m else None


def _all_bodies(src, vm):
    """Every handler body, from both dispatch forms.

    This build dispatches eight opcodes from a plain chain and the other four
    hundred from a decision tree over the opcode's bits. Reading only the chain
    found three jumps out of twenty-two, and a control flow graph missing
    nineteen kinds of jump says almost nothing is reachable - which is how this
    was noticed.
    """
    out = defaultdict(list)
    for op, bodies in _bodies(src, vm).items():
        out[op].extend(bodies)
    try:
        import vmsrc
        for op, bodies in vmsrc.handlers(src, vm).items():
            for b in bodies:
                if b not in out[op]:
                    out[op].append(b)
    except Exception:
        pass
    return out


def jump_opcodes(src, vm):
    """Every opcode whose handler sets the program counter from a call."""
    if not (vm and vm.pc and vm.row):
        return {}
    out = {}
    for op, bodies in _all_bodies(src, vm).items():
        for body in bodies:
            j = re.search(r"%s\s*=\s*\w+\(\s*%s\[(\d+)\]"
                          % (re.escape(vm.pc), re.escape(vm.row)), body)
            if j:
                out[op] = int(j.group(1))
                break
    return out


def const_operands(src, vm):
    """Which operand of each opcode is a constant index.

    Read off the handlers: an operand handed to the constant resolver is an
    index into the constant table, and one that is not is a number in its own
    right. Nothing is guessed from the size of the number.
    """
    if not (vm and vm.resolver and vm.row and vm.opvar):
        return {}
    out = defaultdict(set)
    for op, bodies in _all_bodies(src, vm).items():
        for body in bodies:
            for k in re.findall(r"%s\(\s*%s\[(\d+)\]"
                                % (re.escape(vm.resolver), re.escape(vm.row)),
                                body):
                out[op].add(int(k))
    return dict(out)


def walk(fn, decoded, jumpers, fld, flow=None):
    """The control flow graph, and what the entry can reach.

    `decoded` is pc -> (opcode, number, operands). `jumpers` is opcode -> which
    operand carries the target. A jump whose target lands outside the function is
    recorded as such and leads nowhere, which is what the interpreter does with
    it too.
    """
    succ = {}
    for pc, (op, _num, ops) in decoded.items():
        nxt = []
        idx = jumpers.get(op)
        if idx is not None and len(ops) >= idx - 1:
            operand = ops[idx - 2]
            t, how = target(fn, operand, fld)
            if t is not None:
                fn.targets[pc] = (t, how)
                if t in decoded:
                    nxt.append(t)
        # an instruction that is not a jump, and a conditional jump, both carry
        # on to the next pc; an unconditional one does not. Which is which comes
        # from the handler: the ones that only ever set the counter have no
        # fall-through, and the capture cannot tell that apart from a branch
        # here, so both edges are kept and the report says so.
        # WHETHER THIS INSTRUCTION CARRIES ON. Measured, not assumed: for each
        # opcode, how often the instruction after it was the next pc. One that
        # never once did is a jump or a return and gets no fall-through edge; one
        # that sometimes did is a branch and gets both; one the run never
        # executed keeps the edge, because nothing established otherwise.
        f, t = (flow or {}).get(op, (1, 0))
        falls = not (t >= 8 and f == 0)
        if falls and pc + 1 in decoded:
            nxt.append(pc + 1)
        succ[pc] = nxt
    seen, stack = set(), [min(decoded)] if decoded else []
    while stack:
        pc = stack.pop()
        if pc in seen:
            continue
        seen.add(pc)
        for n in succ.get(pc, ()):
            if n not in seen:
                stack.append(n)
    fn.reach = seen
    return succ


def _trace_rows(capture_text, round_only=1):
    rows = []
    for line in capture_text.splitlines():
        if not line or not line[0].isdigit() or ";" not in line:
            continue
        parts = line.split(";", 5)
        if len(parts) < 6 or "rowop=" not in parts[5]:
            continue
        if round_only and ("round=%d" % round_only) not in parts[5]:
            continue
        try:
            rows.append((int(parts[0]), int(parts[1]), parts[2]))
        except ValueError:
            continue
    return rows


def fallthrough(capture_text, jumpers, fns=None):
    """Which jump opcodes carry on to the next instruction, measured.

    A conditional jump is followed by the next pc when it does not take its
    branch; an unconditional one never is. The source does not say which is which
    in a form this reads reliably, but the run does: for each jump opcode, how
    often the instruction after it was the next pc.

    One correction matters, and it changed the answer here. A jump whose target
    IS the next pc looks exactly like a fall-through from the outside, and this
    build has twelve of them. Counting those as fall-throughs made the one
    unconditional jump in the program look conditional, which put a second edge
    on seven hundred blocks and made almost everything reachable. So the target
    is resolved first, and a jump that went where it said it would is not a
    fall-through.

    An opcode the run never executed keeps both edges, because nothing
    established otherwise.
    """
    rows = _trace_rows(capture_text)
    fell = defaultdict(int)
    total = defaultdict(int)
    for i in range(len(rows) - 1):
        pc, op, ops = rows[i]
        idx = jumpers.get(op)
        total[op] += 1
        if rows[i + 1][0] != pc + 1:
            continue
        bits = ops.split(",")
        if fns and idx is not None and len(bits) >= idx - 1:
            try:
                operand = int(bits[idx - 2])
            except ValueError:
                operand = None
            if operand is not None and _resolve_any(fns, operand) == pc + 1:
                continue
        fell[op] += 1
    return {op: (fell[op], total[op]) for op in total}


def _resolve_any(fns, operand):
    """The target this operand resolves to, in whichever function owns it."""
    for fn in fns.values():
        fld = pick_jump_field(fn)
        if fld is None:
            continue
        if (operand ^ (fn.jump_key or 0)) in (fn.jumps.get((fld, 1)) or {}):
            return target(fn, operand, fld)[0]
    return None


def verify(fns, capture_text, jumpers):
    """Resolve every jump the run took, and compare with where it went.

    Returns how many were compared, how many agreed, how many carried an operand
    no function claims, and how many were branches that did not branch.
    """
    rows = []
    for line in capture_text.splitlines():
        if not line or not line[0].isdigit() or ";" not in line:
            continue
        parts = line.split(";", 5)
        if len(parts) < 6 or "rowop=" not in parts[5]:
            continue
        if "round=1" not in parts[5]:
            continue
        try:
            rows.append((int(parts[0]), int(parts[1]), parts[2]))
        except ValueError:
            continue
    checked = agreed = 0
    unknown = fell = 0
    for i in range(len(rows) - 1):
        pc, op, ops = rows[i]
        idx = jumpers.get(op)
        if idx is None:
            continue
        bits = ops.split(",")
        if len(bits) < idx - 1:
            continue
        try:
            operand = int(bits[idx - 2])
        except ValueError:
            continue
        went = rows[i + 1][0]
        hit = False
        for fn in fns.values():
            fld = pick_jump_field(fn)
            if fld is None:
                continue
            if operand ^ (fn.jump_key or 0) not in (fn.jumps.get((fld, 1)) or {}):
                continue
            t, _how = target(fn, operand, fld)
            hit = True
            if t != went and went == pc + 1:
                # A CONDITIONAL JUMP THAT DID NOT TAKE ITS BRANCH. The target it
                # carries is still the right target; the run simply went the
                # other way. Counting these as failures made six opcodes look
                # like a broken resolution when what they are is branches.
                fell += 1
                break
            checked += 1
            if t == went:
                agreed += 1
            break
        if not hit:
            unknown += 1
    return checked, agreed, unknown, fell


def constant_field(fn):
    """Which field of the prototype is the constant table.

    The one the resolver gave back the most values for. Picked by what came
    back, so a build that numbers its fields differently is read the same way.
    """
    best, best_n = None, -1
    for fld, entries in fn.consts.items():
        n = sum(1 for v in entries.values() if v is not None)
        if n > best_n:
            best, best_n = fld, n
    return best


def words(fn, decoded, const_ops, only=None):
    """Every constant the instructions in `only` actually name.

    `only` is a set of program counters, so this answers the question that
    matters about a protected build: of the words the function carries, which
    ones does the part you can reach from the entry use, and which ones belong
    only to the part you cannot.
    """
    fld = constant_field(fn)
    table = fn.consts.get(fld) or {}
    out = []
    for pc, (op, _num, ops) in sorted(decoded.items()):
        if only is not None and pc not in only:
            continue
        for idx in sorted(const_ops.get(op, ())):
            if len(ops) >= idx - 1:
                k = ops[idx - 2]
                v = table.get(k)
                if isinstance(v, str) and v:
                    out.append((pc, k, v))
    return out


def report(fns, decoded_by_pid, jumpers, const_ops, flow, checked, agreed,
           unknown, fell, names=None):
    """What the control flow says, and what it says about reachability."""
    T = ["WHERE EACH INSTRUCTION GOES, AND WHAT THE ENTRY CAN REACH",
         "=" * 58,
         "Control flow here is flattened: every block ends by jumping to a",
         "number it computes, so instructions in file order are not the",
         "program. The target is worked out by the interpreter's own",
         "arithmetic over a table the function carries, and that arithmetic is",
         "in its own source, so a jump can be resolved without running it.",
         ""]
    if checked:
        T += ["THE RESOLUTION, CHECKED",
              "-" * 58,
              "The run took some of these jumps and the capture recorded where",
              "each one actually went. The same jumps, resolved again from",
              "their operands:",
              "  %d compared, %d agreed (%d%%)"
              % (checked, agreed, 100 * agreed // max(1, checked)),
              "  %d were branches that did not branch, so the run went to the"
              % fell,
              "    next instruction instead of the target they carry",
              "  %d carried an operand no function's table claims" % unknown,
              ""]
        if agreed < checked:
            T += ["  They do not all agree, so this is not used on the jumps",
                  "  the run did not take either.", ""]
    else:
        T += ["No jump could be compared: the run took none of them.", ""]
    jumps = sum(len(f.targets) for f in fns.values())
    off = sum(1 for pid, f in fns.items()
              for _pc, (t, _h) in f.targets.items()
              if t not in (decoded_by_pid.get(pid) or {}))
    comp = sum(1 for f in fns.values()
               for _pc, (_t, h) in f.targets.items()
               if h == "computed from a base")
    T += ["AND A CHECK THAT NEEDS NO RUN AT ALL",
          "-" * 58,
          "A target is a program counter. One that lands outside the function",
          "it was read in is a resolution that cannot be right, whatever else",
          "agrees, and arithmetic that was merely plausible would scatter.",
          "  %d jump(s) resolved, %d landing outside their own function"
          % (jumps, off),
          "  %d carried an operand with no table entry, so their target was"
          % comp,
          "    computed from a base rather than looked up - which is what this",
          "    build does with a run it has decided against",
          ""]
    nf = [o for o, (f, t) in (flow or {}).items() if t >= 8 and f == 0]
    both = [o for o, (f, t) in (flow or {}).items() if t >= 8 and f > 0]
    T += ["WHICH INSTRUCTIONS CARRY ON, MEASURED",
          "-" * 58,
          "  never went to the next instruction (a jump or a return): %s"
          % (", ".join("OP_%d" % o for o in sorted(nf)) or "none"),
          "  sometimes did (a branch, so both edges are kept): %s"
          % (", ".join("OP_%d" % o for o in sorted(both)) or "none"),
          "  anything else the run did not execute often enough keeps its",
          "  edge, because nothing established otherwise",
          ""]
    T += ["PER FUNCTION", "-" * 58]
    tot = reach = 0
    for pid in sorted(decoded_by_pid):
        fn = fns.get(pid)
        dec = decoded_by_pid[pid]
        if fn is None:
            continue
        tot += len(dec)
        reach += len(fn.reach)
        T.append("  function %d: %d instruction(s), %d reachable from its "
                 "entry, %d not"
                 % (pid, len(dec), len(fn.reach), len(dec) - len(fn.reach)))
        gone = sorted(set(dec) - fn.reach)
        for a, b in _ranges(gone)[:6]:
            T.append("      unreachable: %d..%d" % (a, b) if a != b
                     else "      unreachable: %d" % a)
        if len(_ranges(gone)) > 6:
            T.append("      ... and %d more stretch(es)"
                     % (len(_ranges(gone)) - 6))
    T += ["",
          "  %d instruction(s) in all, %d reachable, %d not"
          % (tot, reach, tot - reach),
          ""]
    T += ["THE WORDS EACH PART USES",
          "-" * 58,
          "A constant is a value the instructions name. Split by whether the",
          "instruction naming it can be reached from the entry at all, because",
          "what the unreachable part says is not what the program does.",
          ""]
    for pid in sorted(decoded_by_pid):
        fn = fns.get(pid)
        dec = decoded_by_pid[pid]
        if fn is None:
            continue
        inn = {v for _pc, _k, v in words(fn, dec, const_ops, fn.reach)}
        out_ = {v for _pc, _k, v in words(fn, dec, const_ops,
                                         set(dec) - fn.reach)}
        if not inn and not out_:
            continue
        T.append("  function %d" % pid)
        if inn:
            T.append("    reachable:   " + ", ".join(sorted(inn)[:40]))
        only = sorted(out_ - inn)
        if only:
            T.append("    only in the unreachable part: "
                     + ", ".join(only[:40]))
    T.append("")
    return "\n".join(T)


def _ranges(nums):
    out = []
    for n in nums:
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return [tuple(x) for x in out]


def _selftest():
    # one function, two blocks: the first jumps over the second
    fn = Function(1)
    fn.key = 0
    fn.count = 4
    fn.jump_key = 0
    fn.lf = {5: {2: 1, 3: 1, 4: 1, 5: 4}}
    # with mode 4: target = (z - a - b) // 1, so z is chosen to give 4
    L2 = L3 = 1
    x = 7
    a = (L2 * 48271 + x * 7919 + L3) % MOD
    b = (L3 * 65599 + x * 131 + a) % MOD
    fn.jumps = {(5, 1): {x: {1: 4 + a + b}}}
    fn.consts = {17: {3: "hello"}}
    decoded = {1: (275, 0, [x]), 2: (99, 0, []), 3: (99, 0, []),
               4: (287, 0, [3])}
    probs = []
    t, how = target(fn, x, 5)
    if t != 4:
        probs.append("the target came out %r, not 4" % (t,))
    if how != "looked up":
        probs.append("a target with a table entry was called %r" % how)
    walk(fn, decoded, {275: 2}, 5, {275: (0, 20)})
    if fn.reach != {1, 4}:
        probs.append("the unconditional jump did not skip the middle: %r"
                     % (sorted(fn.reach),))
    walk(fn, decoded, {275: 2}, 5, {275: (3, 20)})
    if fn.reach != {1, 2, 3, 4}:
        probs.append("a branch that sometimes fell through lost its edge: %r"
                     % (sorted(fn.reach),))
    if constant_field(fn) != 17:
        probs.append("the constant table was not found")
    w = words(fn, decoded, {287: {2}}, {1, 4})
    if [v for _pc, _k, v in w] != ["hello"]:
        probs.append("the constant a reachable instruction names was not "
                     "read: %r" % (w,))
    txt = report({1: fn}, {1: decoded}, {275: 2}, {287: {2}},
                 {275: (0, 20)}, 1, 1, 0, 0)
    if "hello" not in txt:
        probs.append("the report does not mention the word it found")
    for p in probs:
        print("  PROBLEM: " + p)
    print("protolift selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()


def vocabulary(fns, decoded_by_pid):
    """Every value the program's functions carry, decrypted.

    A constant in this family is a small record holding a type tag, a seed and
    the value as ciphertext, so reading the instructions gives their shape and
    none of their words. These came back from the interpreter's own resolver,
    asked for every entry after the run - including the entries only an
    unreachable instruction names.

    This is the most direct thing a reader can use: the names a function touches
    say what it is for, whether or not any of it ran.
    """
    T = ["WHAT THE PROGRAM'S FUNCTIONS SAY",
         "=" * 58,
         "The values the instructions name, decrypted by the interpreter's own",
         "resolver rather than by a second implementation of its arithmetic.",
         "A function nothing called is read on the same terms as one that ran.",
         ""]
    any_ = False
    for pid in sorted(decoded_by_pid):
        fn = fns.get(pid)
        if fn is None:
            continue
        fld = constant_field(fn)
        table = fn.consts.get(fld) or {}
        strs = [(i, v) for i, v in sorted(table.items())
                if isinstance(v, str) and v]
        nums = [(i, v) for i, v in sorted(table.items())
                if isinstance(v, (int, float))]
        if not strs and not nums:
            continue
        any_ = True
        T.append("FUNCTION %d - %d instruction(s), %d value(s) in its table"
                 % (pid, len(decoded_by_pid[pid]), len(table)))
        if strs:
            T.append("  text (%d):" % len(strs))
            for i, v in strs:
                T.append("    [%4d] %s" % (i, _show(v)))
        if nums:
            T.append("  numbers (%d): %s" % (len(nums),
                     ", ".join(str(v) for _i, v in nums[:24])))
        T.append("")
    if not any_:
        T += ["No value came back: the interpreter's resolver was not in hand, "
              "so", "the constants stayed as the numbers the instructions "
              "carry.", ""]
    return "\n".join(T)


def _show(v):
    if len(v) > 120:
        return repr(v[:117] + "...")
    return repr(v)
