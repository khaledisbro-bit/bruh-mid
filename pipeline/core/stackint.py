#!/usr/bin/env python3
"""
stackint.py - lift the instruction stream into a value graph.

The VM is a stack machine, so the program's expressions are implicit in the
order values are pushed and popped. Replaying that stack symbolically turns the
flat instruction list back into a graph: every instruction consumes the values
its predecessors produced, and the edges of that graph are the program's
expressions.

Arity is decided per instruction, not per opcode. Every record carries the stack
pointer before the instruction ran and the value the instruction left pending, so
for that one instruction:

    pushes = 1 if it left a value, else 0
    pops   = pushes - (stack pointer after - stack pointer before)

The opcode-level model from opsem is used as a cross-check and as the fallback
when an instance has no measurement of its own. When the two disagree the
instruction is lifted from what was observed and both readings are recorded, so
the disagreement stays visible instead of being smoothed away.

The replay is checked against the VM as it goes: after each instruction the
simulated stack height must equal the stack pointer the VM reported next. Where
it does not, the lifter says so, resynchronises from the VM's own value, and
marks the values involved UNKNOWN. A silent desynchronisation would invent
expressions, which is the one thing this must never do.
"""
from evidence import OBSERVED, INFERRED, UNKNOWN, Fact

CONST = "const"
COMPUTED = "computed"
EXTERNAL = "external"


class Value:
    """One value produced by one instruction (an SSA definition)."""

    __slots__ = ("id", "kind", "op", "pc", "row", "inputs", "runtime",
                 "operands", "fact", "uses", "slot")

    def __init__(self, vid, kind, op=None, pc=None, row=None, inputs=(),
                 runtime=None, operands=()):
        self.id = vid
        self.kind = kind
        self.op = op
        self.pc = pc
        self.row = row
        self.inputs = list(inputs)
        self.runtime = runtime
        self.operands = list(operands)
        self.uses = []
        self.slot = None
        self.fact = Fact("value", UNKNOWN)

    def __repr__(self):
        return "v%d" % self.id


class Step:
    """One lifted instruction."""

    __slots__ = ("row", "pc", "op", "pops", "pushes", "popped", "pushed",
                 "operands", "sp", "net", "fact", "aligned", "fn", "depth",
                 "frame")

    def __init__(self, row, pc, op, operands, sp, fn=0, depth=0, frame=-1):
        self.row = row
        self.pc = pc
        self.fn = fn
        self.depth = depth
        self.frame = frame
        self.op = op
        self.operands = operands
        self.sp = sp
        self.pops = self.pushes = 0
        self.popped = []
        self.pushed = []
        self.net = None
        self.aligned = True
        self.fact = Fact("instruction", OBSERVED)

    def __repr__(self):
        return "fn%d:pc%d:OP_%d" % (self.fn, self.pc, self.op)

    def key(self):
        return (self.fn, self.pc)


class Lift:
    def __init__(self):
        self.values = []
        self.steps = []
        self.divergences = []
        self.externals = 0

    def new_value(self, *a, **kw):
        v = Value(len(self.values), *a, **kw)
        self.values.append(v)
        return v

    def instances(self):
        """Per-opcode (input runtime values, result runtime value), for the
        value-algebra pass in opsem."""
        out = {}
        for st in self.steps:
            if len(st.pushed) != 1:
                continue
            res = st.pushed[0].runtime
            ins = tuple(self.values[i].runtime for i in st.pushed[0].inputs)
            out.setdefault(st.op, []).append((ins, res))
        return out

    def consumers(self):
        c = {}
        for st in self.steps:
            for v in st.popped:
                c.setdefault(v.id, []).append(st)
        return c


def _is_value(v):
    return v is not None and v != "nil"


def lift(rows, program_rows, models):
    """Replay the program's stack symbolically.

    `rows` is the raw capture (needed to read the value each instruction left
    pending, which is reported on the record that follows it). `program_rows` is
    the same list with interpreter machinery removed."""
    nxt_value = {}
    nxt_sp = {}
    for i, r in enumerate(rows):
        if i + 1 < len(rows):
            nxt_value[r["i"]] = rows[i + 1]["value"]
    order = [r["i"] for r in program_rows]
    pos = {rid: k for k, rid in enumerate(order)}
    for k, r in enumerate(program_rows):
        if k + 1 < len(program_rows):
            nxt_sp[r["i"]] = program_rows[k + 1]["sp"]

    L = Lift()
    stack = []
    # What the run could possibly have pushed. Every instruction pushes a few
    # values at most, so several times the instruction count, plus room for a
    # short capture, is already far past any real stack. It exists to reject a
    # corrupt number, not to constrain a real one.
    depth_ceiling = 4 * len(program_rows) + 256
    for r in program_rows:
        rid = r["i"]
        st = Step(rid, r["pc"], r["opcode"], r["operands"], r["sp"],
                  r.get("fn", 0), r.get("depth", 0), r.get("frame", -1))
        product = nxt_value.get(rid)
        after = nxt_sp.get(rid)
        m = models.get(r["opcode"])

        if r.get("burst_after"):
            product = None
        pops, pushes, why, ev = _arity(r, product, after, m, depth_ceiling)
        st.pops, st.pushes, st.net = pops, pushes, (
            None if after is None or r["sp"] is None else after - r["sp"])

        # align the simulated stack with what the VM reported before this
        # instruction; a mismatch means an earlier arity was wrong.
        #
        # The depth is taken from the capture, and a capture can be damaged - a
        # run cut off mid-write, a field mangled in transit. A stack pointer
        # that reads as a billion used to be believed: the loop below inserts
        # one object per missing slot, so it allocated until the process was
        # killed. A hang and an out-of-memory death, from one bad field.
        #
        # No stack can be deeper than the run could have pushed, and every
        # instruction pushes a handful at most. A depth past that ceiling is
        # not a deep stack, it is a corrupt number, and the row is recorded as
        # unreadable rather than acted on.
        # A stack depth is a count. It cannot be negative, and it cannot be
        # deeper than this run could have filled. Either reading is a damaged
        # field rather than a deep stack, and acting on one is worse than
        # useless: a negative depth makes `len(stack) > sp` true forever, so
        # the resync below pops until the list is empty and then raises.
        if r["sp"] is not None and (r["sp"] < 0 or r["sp"] > depth_ceiling):
            L.divergences.append((rid, r["pc"], len(stack), r["sp"]))
            st.aligned = False
            st.sp = None
            st.fact.evidence = UNKNOWN
            st.fact.note("stackint.impossible_depth",
                         "the capture reports a stack depth of %s here, which "
                         "is %s. The number is not believed and this row is "
                         "not used to align the replay"
                         % (r["sp"],
                            "impossible: a depth is a count" if r["sp"] < 0
                            else ("past anything %d instruction(s) could have "
                                  "built (ceiling %d)"
                                  % (len(program_rows), depth_ceiling))),
                         pcs=(r["pc"],), steps=(rid,))
        elif r["sp"] is not None and len(stack) != r["sp"]:
            L.divergences.append((rid, r["pc"], len(stack), r["sp"]))
            st.aligned = False
            while len(stack) < r["sp"]:
                ext = L.new_value(EXTERNAL, pc=r["pc"], row=rid)
                ext.fact.evidence = UNKNOWN
                ext.fact.note("stackint.resync",
                              "the VM reported a deeper stack than the replay "
                              "had built, so this slot was produced by an "
                              "instruction the capture does not cover",
                              pcs=(r["pc"],), steps=(rid,))
                L.externals += 1
                stack.insert(0, ext)
            while len(stack) > r["sp"]:
                stack.pop()

        popped = []
        for _ in range(pops):
            if stack:
                popped.append(stack.pop())
            else:
                ext = L.new_value(EXTERNAL, pc=r["pc"], row=rid)
                ext.fact.evidence = UNKNOWN
                ext.fact.note("stackint.underflow",
                              "consumed a value the traced window never saw "
                              "produced", pcs=(r["pc"],), steps=(rid,))
                L.externals += 1
                popped.append(ext)
        popped.reverse()
        st.popped = popped

        for n in range(pushes):
            kind = CONST if (pops == 0 and _is_value(product)) else COMPUTED
            shown = nxt_value.get(rid) if r.get("burst_after") else product
            v = L.new_value(kind, op=r["opcode"], pc=r["pc"], row=rid,
                            inputs=[p.id for p in popped],
                            runtime=(shown if n == pushes - 1 else None),
                            operands=r["operands"])
            v.fact.evidence = ev
            v.fact.note("stackint.lift", why, pcs=(r["pc"],),
                        opcodes=(r["opcode"],), steps=(rid,),
                        inputs=tuple(p.id for p in popped))
            if r.get("burst_after") and v.runtime is not None:
                v.fact.evidence = UNKNOWN
                v.fact.note("stackint.burst",
                            "a decryptor ran inside this instruction, so the "
                            "value reported next may be its leftover rather "
                            "than this instruction's result",
                            pcs=(r["pc"],), steps=(rid,))
            stack.append(v)
            st.pushed.append(v)

        # How well the arity is known belongs on the instruction, not only on
        # the values it produced. Without it a later pass cannot tell an arity
        # that was measured from one that is merely the shape the numbers
        # allowed, and the decoy pass was condemning instructions on the
        # strength of the second.
        if ev == UNKNOWN and st.fact.evidence != UNKNOWN:
            st.fact.evidence = UNKNOWN
        st.fact.note("stackint.arity", why, pcs=(r["pc"],),
                     opcodes=(r["opcode"],), steps=(rid,))
        L.steps.append(st)

    for st in L.steps:
        for v in st.popped:
            v.uses.append(st.row)
    return L


def _arity(row, product, after, model, ceiling=None):
    """Decide how many values this one instruction consumed and produced.

    The stack movement comes from two numbers the capture reported, and a
    capture can be damaged - a run cut off mid-write, a field mangled in
    transit. A stack pointer that reads as a billion makes this compute a
    movement of a billion, and the caller then loops that many times building a
    value for each: the analysis hangs and the process is killed. That is one
    bad field turning into an out-of-memory death.

    No instruction moves the stack further than the run could have filled it.
    Past that ceiling the two numbers are not describing a stack effect, so the
    movement is discarded and the opcode's own measured effect is used instead,
    which is what already happens when no stack pointer follows at all."""
    produced = _is_value(product)
    net = None
    if after is not None and row["sp"] is not None:
        net = after - row["sp"]
        if ceiling is not None and abs(net) > ceiling:
            return (0, 1 if produced else 0,
                    "the capture reports the stack moving %+d here, which is "
                    "past anything this run could have built (ceiling %d). "
                    "Those numbers are not believed, and no stack effect is "
                    "taken from them" % (net, ceiling),
                    UNKNOWN)

    # A helper ran inside this instruction's handler, so the value reported next
    # may be the helper's leftover. Whether this instruction produced anything
    # is taken from what the same opcode did where no helper intervened.
    if row.get("burst_after") and model is not None and model.produces is not None:
        produced = model.produces
        if net is not None:
            pushes = max(1, net) if produced else max(0, net)
            pops = pushes - net
            if pops >= 0:
                return (pops, pushes,
                        "stack pointer moved %+d, and a decryptor ran inside "
                        "this instruction, so whether it produced a value is "
                        "taken from OP_%d where none did -> consumed %d, "
                        "produced %d" % (net, row["opcode"], pops, pushes),
                        INFERRED)

    if net is not None:
        # A decryptor ran inside this instruction, so the value reported next is
        # the decryptor's and not this instruction's - which is why `product`
        # was cleared. That means "left nothing pending" was never observed
        # here, it is what is left when nothing could be seen. If the opcode's
        # other instances did not settle it either (they all had a burst too),
        # then whether this produces a value is simply not established.
        #
        # It used to fall through to `produced = False` and report OBSERVED,
        # and an instruction that moves the stack by nothing and produces
        # nothing is one the decoy pass calls dead. So a name lookup whose
        # every execution happened to trigger a decryptor was reported as code
        # nothing could depend on.
        unsettled = bool(row.get("burst_after")) and not produced and (
            model is None or model.produces is None)
        pushes = max(1, net) if produced else max(0, net)
        pops = pushes - net
        if pops < 0:
            pushes, pops = max(net, 0), 0
        why = ("stack pointer moved %+d and the instruction left %s pending, so "
               "it consumed %d and produced %d"
               % (net, "a value" if produced else "nothing", pops, pushes))
        ev = OBSERVED
        if unsettled:
            why = ("stack pointer moved %+d, and a decryptor ran inside this "
                   "instruction so what it left pending could not be seen. No "
                   "other instance of OP_%d settled it either, so whether it "
                   "produces a value is not established and %d->%d is the "
                   "shape the movement allows, not a measurement"
                   % (net, row["opcode"], pops, pushes))
            ev = UNKNOWN
        if model is not None and model.pops is not None and \
                (model.pops, model.pushes) != (pops, pushes):
            why += ("; this run of OP_%d disagrees with the opcode's usual "
                    "%d->%d, so the measurement here is used"
                    % (row["opcode"], model.pops, model.pushes))
            ev = UNKNOWN
        return pops, pushes, why, ev

    if model is not None and model.pops is not None:
        return (model.pops, model.pushes,
                "no stack pointer follows this instruction, so OP_%d's measured "
                "%d->%d is used" % (row["opcode"], model.pops, model.pushes),
                INFERRED)

    return (0, 1 if produced else 0,
            "neither this instruction nor OP_%d has a measured stack effect; "
            "assumed to consume nothing" % row["opcode"], UNKNOWN)


def report(L, models):
    L2 = ["VALUE GRAPH (symbolic replay of the VM stack)",
          "=" * 46,
          "Each instruction was replayed against the stack pointer the VM itself",
          "reported. Arity is taken from that measurement per instruction, not",
          "from an opcode table.", "",
          "instructions lifted: %d" % len(L.steps),
          "values defined: %d" % len(L.values),
          "values consumed from outside the traced window: %d" % L.externals,
          "stack desynchronisations: %d" % len(L.divergences)]
    if L.divergences:
        L2.append("")
        L2.append("where the replay disagreed with the VM (resynchronised from")
        L2.append("the VM, values there marked UNKNOWN):")
        for rid, pc, got, want in L.divergences[:20]:
            L2.append("  row %-6d pc %-6d replay had %d slot(s), VM reported %d"
                      % (rid, pc, got, want))
        if len(L.divergences) > 20:
            L2.append("  ... %d more" % (len(L.divergences) - 20))
    return "\n".join(L2)
