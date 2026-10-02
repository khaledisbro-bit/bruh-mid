"""Every recomputation that did not agree, traced back through the graph.

A reconstruction that explains nine instructions in ten and contradicts the
machine on the tenth is not nine tenths right. The contradiction is the finding:
either the reading of that instruction is wrong, or the value it was compared
against was never that instruction's value. Both have to be said out loud, with
the chain that leads to them, because a disagreement folded into "unknown" is a
disagreement nobody will look for again.

This module takes each failed recomputation and walks backwards: the value, the
instruction that produced it, the values it consumed, and where each of those
came from. Then it says which of the reasons below holds, and each reason is a
test over the capture, not a preference:

  NOT A READING      the operation cannot produce nil in Lua - arithmetic on
                     numbers, a comparison, a length, a table constructor - and
                     nil is what the pending slot read. The slot was empty, so
                     nothing was reported for this instruction. That is the
                     absence of a reading and not a reading of nil.
  WENT TO A REGISTER the handler writes its result into the interpreter's
                     register file instead of leaving it on the stack, so the
                     pending slot never holds it. What the slot held belongs to
                     another instruction.
  ANOTHER TYPE       the reported value is a table, a function or a string where
                     the operation yields a number. A number operation cannot
                     return a table; the value reported is another
                     instruction's.
  UNALIGNED          the replay and the machine disagreed about the stack depth
                     at or before this instruction, or an input was consumed
                     from outside the traced window. The inputs are then not
                     established, so neither is the comparison.
  ORDER NOT PROVEN   the handler computes through registers, so which value it
                     took first is not fixed by the order they came off the
                     stack. An asymmetric operation read with its inputs
                     swapped disagrees for that reason alone.
  THE READING IS WRONG
                     none of the above. Both values were reported, the inputs
                     are established, the stack was aligned, and the arithmetic
                     still does not come out. The operation read for this
                     instruction does not describe it.

Only the last one is evidence against the reading itself. The others are
evidence about what the capture can and cannot compare, and each one names the
instruction it applies to so the claim can be checked by hand.
"""
import opsem
from evidence import OBSERVED


# Operations whose result cannot be nil in Lua. Arithmetic on two numbers is a
# number or an error, never nil; a comparison is a boolean; a length is a
# number; a table constructor is a table. This is the language, not this build.
NEVER_NIL = {"ADD", "SUB", "MUL", "DIV", "MOD", "POW", "IDIV", "UNM",
             "CONCAT", "LEN", "NEWTABLE",
             "EQ", "NE", "LT", "LE", "GT", "GE", "NOT"}
# Operations whose result is a number. A table or a function reported for one of
# these is not its result.
NUMERIC = {"ADD", "SUB", "MUL", "DIV", "MOD", "POW", "IDIV", "UNM", "LEN"}
# Operations where the order of the two inputs changes the answer.
ORDERED = {"SUB", "DIV", "MOD", "POW", "IDIV", "CONCAT", "LT", "LE", "GT", "GE"}

NOT_A_READING = "the pending slot was empty, so nothing was reported"
REGISTER = "the handler writes its result into a register"
ANOTHER_TYPE = "the value reported is of a type this operation cannot return"
UNALIGNED = "the stack was not aligned here, so the inputs are not established"
ORDER = "the handler's input order is not fixed by the stack order"
WRONG = "the reading is wrong"


class Finding:
    __slots__ = ("value", "step", "op", "operation", "style", "inputs",
                 "recomputed", "reported", "cause", "why", "pend",
                 "withdrawn")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))
        self.withdrawn = bool(kw.get("withdrawn"))

    def comparable(self):
        """Whether this is a disagreement about the program or about what the
        capture could see."""
        return self.cause in (WRONG, ORDER)


def _is_nil(x):
    return x is None or x == "nil"


def _typeish(x):
    """What the capture's text says the value was."""
    if x is None:
        return "not reported"
    s = str(x)
    if s == "nil":
        return "nil"
    if s.startswith("table:") or s == "table" or s == "{}":
        return "table"
    if s.startswith("function:"):
        return "function"
    if s.startswith('"'):
        return "string"
    if opsem._num(s) is not None:
        return "number"
    return "other"


def find(L, models, rows=()):
    """Every value whose named producer recomputes to something else."""
    pend = {}
    order = [r["i"] for r in rows]
    at = {rid: k for k, rid in enumerate(order)}
    for k, r in enumerate(rows):
        # The pending count is read at the top of the loop, so the count on a
        # record describes what the instruction BEFORE it left pending.
        if k + 1 < len(rows):
            pend[r["i"]] = rows[k + 1].get("pend")
    unaligned_rows = {d[0] for d in L.divergences}
    step_by_row = {st.row: st for st in L.steps}

    out = []
    for v in L.values:
        m = models.get(v.op)
        if m is None or not m.operation or len(v.inputs) != 2:
            continue
        f = opsem.CANDIDATES.get(m.operation)
        if f is None:
            continue
        ins = [L.values[i] for i in v.inputs]
        a, b = ins[0].runtime, ins[1].runtime
        if a is None or b is None:
            continue
        got = f(a, b)
        if got is None:
            continue
        if v.runtime is not None and opsem._same(got, v.runtime):
            continue
        swapped = f(b, a)
        st = step_by_row.get(v.row)
        style = getattr(m, "handler_style", None)
        cause = WRONG
        if _is_nil(v.runtime) and m.operation in NEVER_NIL:
            cause = NOT_A_READING
        elif style == "regs":
            cause = REGISTER
        elif m.operation in NUMERIC and _typeish(v.runtime) in (
                "table", "function", "string"):
            cause = ANOTHER_TYPE
        elif (v.row in unaligned_rows
                or (st is not None and not st.aligned)
                or any(x.kind == "external" for x in ins)
                or any(x.fact.evidence != OBSERVED for x in ins)):
            cause = UNALIGNED
        elif (m.operation in ORDERED and swapped is not None
                and v.runtime is not None
                and opsem._same(swapped, v.runtime)):
            cause = ORDER
        out.append(Finding(
            value=v, step=st, op=v.op, operation=m.operation, style=style,
            inputs=ins, recomputed=got, reported=v.runtime, cause=cause,
            pend=pend.get(v.row),
            why=None))
    return out


def withdraw(models, findings):
    """Drop every reading the machine contradicted.

    A reading that recomputes to the wrong number is wrong wherever that opcode
    appears, not only at the instruction where it was caught. The opcode keeps
    its arity - the stack movement was measured and is not in question - and
    loses its name, so the output writes the opcode's number instead of an
    expression that does not hold. An unresolved instruction is a worse-looking
    answer and a truer one.
    """
    taken = {}
    for f in findings:
        if not f.comparable():
            continue
        taken.setdefault(f.op, []).append(f)
    for op, fs in taken.items():
        m = models.get(op)
        if m is None or not m.operation:
            continue
        f = fs[0]
        swapped = any(x.cause == ORDER for x in fs)
        m.fact.note(
            "disagree.withdrawn",
            "read as %s, and recomputing it that way contradicts the machine: "
            "at pc %s it gives %s where the machine reported %s, with both "
            "inputs reported and the stack aligned%s. The reading is withdrawn "
            "and this opcode keeps its number; its arity stands, because the "
            "stack movement was measured and is not what is in doubt"
            % (m.operation, f.value.pc, f.recomputed, f.reported,
               ". Its inputs in the other order do agree, so the handler takes "
               "them in an order the stack does not fix" if swapped else ""),
            opcodes=(op,))
        m.operation = None
        m.operation_support = 0
        for x in fs:
            x.withdrawn = True
            # the value is still there and still did something; what it holds
            # is no longer claimed
            x.value.runtime = None
    return taken


def unproven_values(L, findings):
    """Values whose content the capture could not compare, so nothing is claimed
    about what they held. The instruction stays: it ran."""
    n = 0
    for f in findings:
        if f.comparable():
            continue
        if f.cause in (ANOTHER_TYPE, UNALIGNED):
            if f.value.runtime is not None:
                f.value.runtime = None
                f.value.fact.note(
                    "disagree.not_this_value",
                    "the value reported here is %s, which the operation read "
                    "for this instruction cannot produce, so it is another "
                    "instruction's value and nothing is claimed about what "
                    "this one held" % _typeish(f.reported),
                    pcs=(f.value.pc,), opcodes=(f.op,))
                n += 1
    return n


def _chain(L, v, depth=0, seen=None):
    """Where a value came from, one line per step back."""
    seen = seen or set()
    if v.id in seen or depth > 6:
        return []
    seen.add(v.id)
    bit = "    " * (depth + 1)
    where = ("external to the capture" if v.kind == "external"
             else "OP_%s at pc %s" % (v.op, v.pc))
    line = "%s<- v%d  %s  value %s  [%s]" % (
        bit, v.id, where,
        "not reported" if v.runtime is None else v.runtime,
        v.fact.evidence)
    out = [line]
    for i in v.inputs:
        out += _chain(L, L.values[i], depth + 1, seen)
    return out


def report(L, models, findings, rows=()):
    real = [f for f in findings if f.comparable()]
    counts = {}
    for f in findings:
        counts[f.cause] = counts.get(f.cause, 0) + 1
    T = ["DISAGREEMENTS - where the reconstruction and the machine differ",
         "=" * 62,
         "Each one is a value this analysis can recompute from its own reading",
         "of the instruction that produced it, where the recomputation and the",
         "value the machine reported are not the same number.",
         "",
         "Coverage says how much was explained. This says where what was",
         "explained is contradicted, which is the more important number of the",
         "two: one contradiction is a wrong reading, and a wrong reading is",
         "wrong everywhere that opcode appears.",
         "",
         "%d disagreement(s), of which %d are about the program and %d are "
         "about what the capture could compare." % (len(findings), len(real),
                                                    len(findings) - len(real)),
         ""]
    for cause, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        T.append("  %-4d %s" % (n, cause))
    T.append("")
    if real:
        T += ["AGAINST THE PROGRAM",
              "-" * 62,
              "These are the ones that say the reading is wrong. Nothing here",
              "is excused by what the capture could not see.",
              ""]
        for f in real:
            T += _one(L, f)
        T += ["  Every reading above was withdrawn. The opcodes keep their",
              "  numbers in the output and their measured arity, and no",
              "  expression is written for them.",
              ""] if all(f.withdrawn for f in real) else []
    other = [f for f in findings if not f.comparable()]
    if other:
        T += ["ABOUT WHAT THE CAPTURE COULD COMPARE",
              "-" * 62,
              "The reading is not contradicted here: the value it was compared",
              "against was not this instruction's value. The test that decided",
              "that is named on each one.",
              ""]
        for f in other[:60]:
            T += _one(L, f)
        if len(other) > 60:
            T.append("  ... %d more" % (len(other) - 60))
    return "\n".join(T)


def _one(L, f):
    v = f.value
    st = f.step
    T = ["  v%d  %s" % (v.id, f.cause),
         "    instruction      %s"
         % ("fn%d pc %d (capture row %d)" % (st.fn, st.pc, st.row)
            if st is not None else "pc %s (capture row %s)" % (v.pc, v.row)),
         "    opcode           OP_%s, read as %s%s"
         % (f.op, f.operation,
            "" if not f.style else " (handler computes through %s)" % f.style),
         "    operands carried %s" % (list(v.operands) or "none"),
         "    inputs           %s"
         % ", ".join("v%d=%s" % (x.id, "not reported" if x.runtime is None
                                 else x.runtime) for x in f.inputs),
         "    recomputed       %s" % f.recomputed,
         "    machine reported %s  (%s)"
         % ("nothing" if f.reported is None else f.reported,
            _typeish(f.reported)),
         "    pending slots    %s"
         % ("not recorded" if f.pend is None else f.pend),
         "    diverges at      the result of this instruction; its inputs "
         "agree with the capture"]
    T += ["    where its inputs came from:"]
    for x in f.inputs:
        T += _chain(L, x)
    T.append("")
    return T


def _selftest():
    """A wrong reading must be reported as wrong, and a value the capture never
    reported must not be reported as a disagreement at all."""
    import stackint
    from evidence import OBSERVED as OBS

    class M:
        def __init__(self, operation, style=None):
            self.operation = operation
            self.handler_style = style

    L = stackint.Lift()
    a = L.new_value("const", op=1, pc=1, row=1, runtime="2")
    b = L.new_value("const", op=1, pc=2, row=2, runtime="3")
    a.fact.evidence = b.fact.evidence = OBS
    # a reading that is simply wrong: 2+3 is not 9
    bad = L.new_value("computed", op=7, pc=3, row=3, inputs=[a.id, b.id],
                      runtime="9")
    # the pending slot was empty; an ADD cannot have returned nil
    empty = L.new_value("computed", op=7, pc=4, row=4, inputs=[a.id, b.id],
                        runtime="nil")
    # a table reported for an ADD is another instruction's value
    other = L.new_value("computed", op=7, pc=5, row=5, inputs=[a.id, b.id],
                        runtime="table: 0x1")
    # the order the handler took its inputs in is not fixed
    sub = L.new_value("computed", op=8, pc=6, row=6, inputs=[a.id, b.id],
                      runtime="1")
    models = {1: M(None), 7: M("ADD"), 8: M("SUB", "regs")}
    fs = {f.value.id: f for f in find(L, models, rows=())}
    probs = []
    if fs.get(bad.id) is None or fs[bad.id].cause != WRONG:
        probs.append("a wrong reading was not reported as wrong")
    if fs.get(empty.id) is None or fs[empty.id].cause != NOT_A_READING:
        probs.append("an empty pending slot was read as a value")
    if fs.get(other.id) is None or fs[other.id].cause != ANOTHER_TYPE:
        probs.append("a table reported for an ADD was not recognised")
    if fs.get(sub.id) is None or fs[sub.id].cause != REGISTER:
        probs.append("a register-style handler was not recognised")
    if not report(L, models, list(fs.values())).strip():
        probs.append("the report came out empty")
    for p in probs:
        print("  PROBLEM: " + p)
    print("disagree selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()
