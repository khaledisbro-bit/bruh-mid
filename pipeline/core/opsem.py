#!/usr/bin/env python3
"""
opsem.py - work out what each opcode does, for this capture only.

This obfuscator renumbers its opcodes on every run and duplicates handlers, so
any fixed opcode table is wrong by construction. Meaning has to be measured from
the run in front of us, and it is measured in two independent steps.

STEP 1 - ARITY, from the stack pointer.
    Between two instructions that executed back to back, the change in the stack
    pointer is the first one's net effect. Whether it produced a value is a
    separate, directly visible fact: the VM reports the value an instruction left
    pending on the row that follows it. Those two facts together fix the arity,
    because net = pushes - pops:

        produced a value, net +1   ->  pops 0, pushes 1   (a load)
        produced a value, net  0   ->  pops 1, pushes 1   (a transform)
        produced a value, net -1   ->  pops 2, pushes 1   (a binary operation)
        produced a value, net -n   ->  pops n+1, pushes 1 (a call or n-ary op)
        no value,         net -1   ->  pops 1, pushes 0   (a store or a test)
        no value,         net  0   ->  pops 0, pushes 0   (a jump or a no-op)

    An opcode gets an arity only when its instances agree. Disagreement is kept
    as a disagreement; it is never averaged into a guess.

STEP 2 - OPERATION, from the values themselves.
    Once the lifter has built the value graph, every instance of a binary opcode
    has known inputs and a known result. Candidate operations are then tested
    against every instance, and one survives only if it explains all of them:

        a + b, a - b, a * b, a .. b, a < b, a == b, ...

    An opcode named this way was proved on real data from this run. An opcode
    that no candidate explains keeps its measured arity and no name. Nothing is
    renamed on a resemblance.
"""
from collections import Counter, defaultdict

from evidence import OBSERVED, INFERRED, UNKNOWN, Fact

LOAD = "LOAD"
TRANSFORM = "TRANSFORM"
BINARY = "BINARY"
NARY = "NARY"
STORE = "STORE"
NEUTRAL = "NEUTRAL"
SPREAD = "SPREAD"
UNSURE = "UNSURE"

AGREE = 0.8
MIN_SAMPLES = 2


def _is_value(v):
    return v is not None and v != "nil"


def measure(rows, machinery=None, agree=AGREE, min_samples=MIN_SAMPLES):
    """Measure every opcode's arity from the raw capture.

    `rows` must be the RAW rows in capture order, because whether an instruction
    produced a value is read from the record that physically follows it.

    The stack delta is taken between consecutive records. Passing the machinery
    pc set removes the interpreter's helper bursts from that sequence first,
    which is sound because a helper was already proved to give the stack pointer
    back untouched."""
    machinery = machinery or set()
    deltas = defaultdict(Counter)
    produces = defaultdict(Counter)
    operands = defaultdict(Counter)
    freq = Counter()

    for i, r in enumerate(rows):
        freq[r["opcode"]] += 1
        operands[r["opcode"]][len(r["operands"])] += 1
        nxt = rows[i + 1] if i + 1 < len(rows) else None
        # After a helper burst the reported value may be the helper's leftover,
        # so it says nothing about this instruction and is not counted.
        if nxt is not None and not r.get("burst_after"):
            produces[r["opcode"]][_is_value(nxt["value"])] += 1

    # Two records that follow each other in the capture have nothing between
    # them: the logger runs at the top of every dispatch, so no other
    # instruction executed in the gap. The difference in stack pointer across
    # that gap is therefore the first instruction's own effect, whatever its
    # successor's instruction number happens to be. Requiring the successor to
    # be the next instruction would only be measuring code that never jumps,
    # which throws away every branch, every loop edge and every call.
    prog = [r for r in rows if r["pc"] not in machinery]
    for a, b in zip(prog, prog[1:]):
        if a["sp"] is None or b["sp"] is None:
            continue
        deltas[a["opcode"]][b["sp"] - a["sp"]] += 1

    out = {}
    for op in freq:
        m = OpModel(op, freq[op])
        m.absorb(deltas.get(op), produces.get(op), operands.get(op),
                 agree, min_samples)
        out[op] = m
    return out


class OpModel:
    """What this run proves about one opcode."""

    def __init__(self, op, freq):
        self.op = op
        self.freq = freq
        self.delta = None
        self.delta_agreement = 0.0
        self.delta_samples = 0
        self.produces = None
        self.pops = None
        self.pushes = None
        self.role = UNSURE
        self.operation = None          # named only by value algebra
        # "stack" when the handler took its inputs through the pop helper, so a
        # type check against the lifter's popped values is meaningful; "regs"
        # when it worked the register array directly, where they are a model.
        self.handler_style = None
        self.operation_support = 0
        self.operand_arity = 0
        self.fact = Fact("opcode", UNKNOWN)
        self.conflicts = None

    # -- step 1 ---------------------------------------------------------------
    def absorb(self, dc, pc_, oc, agree, min_samples):
        if oc:
            self.operand_arity = oc.most_common(1)[0][0]
        if pc_:
            tot = sum(pc_.values())
            yes = pc_.get(True, 0)
            if yes >= tot * agree:
                self.produces = True
            elif (tot - yes) >= tot * agree:
                self.produces = False
        if not dc:
            self.fact.evidence = UNKNOWN
            self.fact.note("opsem.arity",
                           "no two instances of this opcode ran back to back "
                           "with a stack pointer on both sides, so its effect "
                           "was never measured", opcodes=(self.op,))
            return
        tot = sum(dc.values())
        self.delta_samples = tot
        d, n = dc.most_common(1)[0]
        self.delta_agreement = n / tot
        if tot < min_samples or n < tot * agree:
            self.conflicts = dict(dc)
            self.fact.evidence = UNKNOWN
            self.fact.note("opsem.arity",
                           "instances disagree on the stack effect (%s), so no "
                           "arity is assigned" % _fmt(dc), opcodes=(self.op,))
            return
        self.delta = d
        self._derive()

    def _derive(self):
        d = self.delta
        if self.produces is None:
            self.role = UNSURE
            self.fact.evidence = UNKNOWN
            self.fact.note("opsem.arity",
                           "net stack effect %+d is agreed, but instances "
                           "disagree on whether a value was produced" % d,
                           opcodes=(self.op,))
            return
        if self.produces:
            pushes = max(1, d)
            pops = pushes - d
        else:
            pushes = 0
            pops = -d
        if pops < 0:
            self.role = UNSURE
            self.fact.evidence = UNKNOWN
            self.fact.note("opsem.arity",
                           "net %+d with %s value cannot be expressed as "
                           "pushes-pops with non-negative pops"
                           % (d, "a" if self.produces else "no"),
                           opcodes=(self.op,))
            return
        self.pops, self.pushes = pops, pushes
        self.role = _role(pops, pushes)
        self.fact.evidence = INFERRED
        self.fact.note(
            "opsem.arity",
            "net stack effect %+d agreed by %d/%d adjacent instances, and it %s "
            "a value -> pops %d, pushes %d"
            % (d, round(self.delta_agreement * self.delta_samples),
               self.delta_samples,
               "produced" if self.produces else "produced no",
               pops, pushes),
            opcodes=(self.op,))

    # -- step 2 ---------------------------------------------------------------
    def name_operation(self, op_name, support, total):
        self.operation = op_name
        self.operation_support = support
        self.fact.evidence = OBSERVED
        self.fact.note("opsem.algebra",
                       "%s explains the result of all %d instance(s) whose "
                       "inputs and output were both known" % (op_name, total),
                       opcodes=(self.op,))

    def label(self):
        if self.operation:
            return self.operation
        if self.role == UNSURE:
            return "OP_%d" % self.op
        return self.role

    def describe(self):
        bits = ["OP_%d" % self.op, "x%d" % self.freq]
        if self.delta is not None:
            bits.append("net%+d" % self.delta)
        if self.pops is not None:
            bits.append("pops=%d pushes=%d" % (self.pops, self.pushes))
        bits.append(self.role)
        if self.operation:
            bits.append("= " + self.operation)
        return "  ".join(bits)


def _role(pops, pushes):
    if pushes == 0 and pops == 0:
        return NEUTRAL
    if pushes == 0:
        return STORE
    if pushes > 1:
        return SPREAD
    if pops == 0:
        return LOAD
    if pops == 1:
        return TRANSFORM
    if pops == 2:
        return BINARY
    return NARY


def _fmt(counter):
    return ", ".join("%+d x%d" % (k, v) for k, v in counter.most_common(4))


# --- step 2: candidate operations tested against observed values -------------

def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _str(v):
    if isinstance(v, str) and len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return None


def _eqnum(x, y, tol=1e-9):
    return x is not None and y is not None and abs(x - y) <= tol * max(1.0, abs(x), abs(y))


CANDIDATES = {
    "ADD": lambda a, b: _bin_num(a, b, lambda x, y: x + y),
    "SUB": lambda a, b: _bin_num(a, b, lambda x, y: x - y),
    "MUL": lambda a, b: _bin_num(a, b, lambda x, y: x * y),
    "DIV": lambda a, b: _bin_num(a, b, lambda x, y: x / y if y else None),
    "MOD": lambda a, b: _bin_num(a, b, lambda x, y: x % y if y else None),
    "CONCAT": lambda a, b: _bin_str(a, b),
    "LT": lambda a, b: _bin_cmp(a, b, lambda x, y: x < y),
    "LE": lambda a, b: _bin_cmp(a, b, lambda x, y: x <= y),
    "GT": lambda a, b: _bin_cmp(a, b, lambda x, y: x > y),
    "EQ": lambda a, b: _bool(a == b),
}


def _bin_num(a, b, f):
    x, y = _num(a), _num(b)
    if x is None or y is None:
        return None
    r = f(x, y)
    return None if r is None else _fmtnum(r)


def _bin_str(a, b):
    sa, sb = _str(a), _str(b)
    if sa is None:
        sa = a if _num(a) is not None else None
        if sa is not None:
            sa = _fmtnum(_num(sa))
    if sb is None:
        sb = b if _num(b) is not None else None
        if sb is not None:
            sb = _fmtnum(_num(sb))
    if sa is None or sb is None:
        return None
    return '"%s"' % (sa + sb)


def _bin_cmp(a, b, f):
    x, y = _num(a), _num(b)
    if x is None or y is None:
        sa, sb = _str(a), _str(b)
        if sa is None or sb is None:
            return None
        return _bool(f(sa, sb))
    return _bool(f(x, y))


def _bool(v):
    return "true" if v else "false"


def _fmtnum(r):
    if isinstance(r, float) and r.is_integer():
        return str(int(r))
    return repr(r)


def identify(models, instances, min_support=2):
    """Name binary opcodes from the values they actually computed.

    `instances` maps an opcode to a list of (input_values, result_value) taken
    from the lifted value graph, with concrete values only. A candidate must
    explain EVERY instance it can be evaluated on, and must cover at least
    `min_support` of them."""
    named = 0
    for op, rows in instances.items():
        m = models.get(op)
        if m is None or m.operation:
            continue
        usable = [(ins, out) for ins, out in rows
                  if out is not None and all(v is not None for v in ins)]
        if len(usable) < min_support:
            continue
        for name, f in CANDIDATES.items():
            hits = 0
            ok = True
            for ins, out in usable:
                if len(ins) != 2:
                    ok = False
                    break
                got = f(ins[0], ins[1])
                if got is None:
                    continue
                if _same(got, out):
                    hits += 1
                else:
                    ok = False
                    break
            if ok and hits >= min_support:
                m.name_operation(name, hits, len(usable))
                named += 1
                break
    return named


def _same(a, b):
    if a == b:
        return True
    na, nb = _num(_str(a) or a), _num(_str(b) or b)
    if na is not None and nb is not None:
        return _eqnum(na, nb)
    return False


def report(models):
    total = sum(m.freq for m in models.values())
    known = sum(m.freq for m in models.values() if m.role != UNSURE)
    named = [m for m in models.values() if m.operation]
    L = ["OPCODE SEMANTICS (measured from this run only)",
         "=" * 48,
         "Opcode numbers are randomised per run, so meaning is taken from the",
         "stack effect each opcode was observed to have and from the values it",
         "was observed to compute. An opcode that nothing proved keeps its",
         "number and no name.", "",
         "distinct opcodes: %d   arity established: %d   named by value algebra: %d"
         % (len(models), sum(1 for m in models.values() if m.role != UNSURE),
            len(named)),
         "coverage: %.0f%% of executed instructions have a measured arity"
         % (100.0 * known / max(total, 1)), "",
         "%-12s %8s %6s %6s %-10s %s"
         % ("opcode", "count", "net", "arity", "role", "operation / why")]
    for op, m in sorted(models.items(), key=lambda kv: -kv[1].freq):
        arity = ("%d->%d" % (m.pops, m.pushes)) if m.pops is not None else "-"
        L.append("%-12s %8d %6s %6s %-10s %s"
                 % ("OP_%d" % op, m.freq,
                    ("%+d" % m.delta) if m.delta is not None else "-",
                    arity, m.role, m.operation or ""))
    L.append("")
    L.append("why each arity was accepted:")
    for op, m in sorted(models.items(), key=lambda kv: -kv[1].freq):
        for line in m.fact.why():
            L.append("  OP_%-10d %s" % (op, line))
    return "\n".join(L)
