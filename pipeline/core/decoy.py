#!/usr/bin/env python3
"""
decoy.py - decide what actually affects the program, and what only pretends to.

These samples carry deliberate decoy work: instructions that execute, look busy,
and change nothing the program does. Separating them is where a deobfuscator is
easiest to fool, in both directions, so two tempting shortcuts are refused here.

  Complicated does not mean decoy, and simple does not mean real. Nothing is
  judged by how it looks.

  Not appearing in a trace does not mean decoy. An instruction that never ran is
  missing evidence, not proof of irrelevance, and it is never classified from
  absence.

The decision is made on influence, computed backwards from the points where the
program is observable: the arguments and receivers of calls it made, the
conditions it branched on, the values it returned, and the variables it later
read. Anything those depend on, transitively, is real. An instruction that
executed, produced something, and reaches none of them influenced nothing on
this path.

Even then the verdict is held back when the evidence is incomplete. If an
instruction's result could still be consumed on a branch this capture never
entered, it stays a candidate with both readings recorded rather than being
called a decoy, because the run that settles it has not happened yet.
"""
from evidence import OBSERVED, UNKNOWN, DECOY


class Verdict:
    __slots__ = ("pc", "verdict", "why", "alternative")

    def __init__(self, pc, verdict, why, alternative=None):
        self.pc = pc
        self.verdict = verdict
        self.why = why
        self.alternative = alternative


# Operations whose handler performs something the program cannot take back: a
# call, a store, or a jump. The trace shows which way a jump went, so its target
# and its condition mattered on the path that ran.
_EFFECT_OPS = {"CALL", "SETINDEX", "SETVAR", "SETSLOT", "JMP", "CJMP"}


def sinks(L, calls, g, slots, env_ops=(), models=None):
    """The values the program's observable behaviour depends on."""
    out, why = set(), {}

    def mark(vid, reason):
        out.add(vid)
        why.setdefault(vid, reason)

    for c in calls:
        if c.recv_value is not None:
            mark(c.recv_value.id, "receiver of the recorded call %s"
                 % c.record.get("raw", ""))
        for a in c.arg_values:
            mark(a.id, "argument of the recorded call %s"
                 % c.record.get("raw", ""))
    for b in g.branches:
        st = next((s for s in L.steps if s.key() == b["pc"] and s.popped), None)
        if st is not None:
            mark(st.popped[0].id, "the condition the branch at fn%d:%d tested"
                 % b["pc"])
    last = next((st for st in reversed(L.steps)
                 if st.pops >= 1 and st.pushes == 0), None)
    if last is not None and last.popped:
        mark(last.popped[0].id, "the value handed back when execution ended")
    read_slots = set(slots.reads.values())
    for st in L.steps:
        key = slots.writes.get(st.row)
        if key is not None and key in read_slots and st.popped:
            mark(st.popped[0].id,
                 "stored into variable slot%s, which the program reads again"
                 % (key[1] if isinstance(key, tuple) else key,))
            continue
        # An instruction that consumes values and produces none has an effect we
        # cannot see. Its inputs are therefore not provably irrelevant, so they
        # count as observable. Claiming otherwise is exactly the mistake this
        # module exists to avoid.
        if st.pushes == 0 and st.pops >= 1 and key is None:
            for v in st.popped:
                mark(v.id, "consumed by the instruction at fn%d:%d, whose "
                           "effect this capture cannot observe"
                     % (st.fn, st.pc))
    # An instruction whose own handler PERFORMS a call or a store has an effect
    # by definition, whether or not the environment recorded it.
    #
    # Reading the interpreter's handlers says which opcodes those are. Before
    # this, a call the environment did not happen to log, and every store into a
    # table the program built, counted for nothing - so the values feeding them
    # were "produced and never used", and the instructions that computed them
    # were unexplained. That is not a fact about the program; it is this analysis
    # declining to use what it had already read.
    models = models or {}
    # A jump belongs here too: the trace shows which way it went, so the value
    # it tested or the target it computed had an effect on the path that ran.
    for st in L.steps:
        m = models.get(st.op)
        if m is None or m.operation not in _EFFECT_OPS:
            continue
        for v in st.popped:
            mark(v.id, "consumed by the %s the interpreter's own handler for "
                       "opcode %d performs" % (m.operation, st.op))
    # A call whose callee was resolved from a name is a call even when the
    # environment did not record it, so its arguments are observable too.
    for st in L.steps:
        if st.pushes != 1 or not st.popped:
            continue
        head = st.popped[0]
        if head.op in env_ops:
            for v in st.popped[1:]:
                mark(v.id, "argument of the call made at fn%d:%d"
                     % (st.fn, st.pc))
            mark(head.id, "the thing called at fn%d:%d" % (st.fn, st.pc))
    return out, why


def influence(L, seeds, amap):
    """Everything the observable behaviour depends on, transitively."""
    live, stack = set(), list(seeds)
    while stack:
        vid = stack.pop()
        if vid in live:
            continue
        live.add(vid)
        v = L.values[vid]
        stack.extend(v.inputs)
        if vid in amap:
            stack.append(amap[vid])
    return live


def classify(L, g, calls, slots, amap, env_ops=(), models=None,
             register_file=False):
    """Verdict per program counter, with the evidence behind it.

    `register_file` says whether this build was observed keeping the program's
    values somewhere other than the stack. It decides what "it moved nothing on
    the stack" is worth: in a stack machine that is the whole story, and in a
    register machine it is not even half of it.
    """
    seeds, why_seed = sinks(L, calls, g, slots, env_ops, models)
    live = influence(L, seeds, amap)
    call_rows = {c.step.row for c in calls}
    jumps = {a.key() for a, b in zip(L.steps, L.steps[1:])
             if b.key() != (a.fn, a.pc + 1)}
    unexplored_from = {b["pc"] for b in g.branches if b["untaken"]}
    reachable_unknown = bool(g.unexplored)

    out = {}
    for st in L.steps:
        if st.key() in out:
            continue
        if st.row in call_rows:
            out[st.key()] = Verdict(
                st.key(), OBSERVED,
                                 "makes a call the environment recorded")
            continue
        if any(v.id in live for v in st.pushed):
            reason = next((why_seed[v.id] for v in st.pushed
                           if v.id in why_seed), None)
            out[st.key()] = Verdict(
                st.key(), OBSERVED,
                reason or "its result is used, directly or through other "
                          "instructions, by something the program observably did")
            continue
        if st.pushes == 0 and st.pops == 0:
            # "It moved nothing" is only evidence when the movement was
            # measured. Where the arity could not be established - a decryptor
            # ran inside every execution of this opcode, so what it left
            # pending was never visible - 0->0 is the shape the numbers allow,
            # not something the run showed. Calling that dead condemns an
            # instruction for being unobservable.
            if st.fact.evidence == UNKNOWN:
                out[st.key()] = Verdict(
                    st.key(), UNKNOWN,
                    "it appears to move nothing on the stack, but its arity "
                    "was never established - a decryptor ran inside it and "
                    "nothing else settled what this opcode produces - so "
                    "there is no evidence either way")
                continue
            if (st.key() in jumps or st.key() in unexplored_from
                    or any(b["pc"] == st.key() for b in g.branches)):
                out[st.key()] = Verdict(
                st.key(), OBSERVED,
                                     "control did not fall through after it, so "
                                     "it decides where execution goes")
                continue
            # "It moved nothing on the stack" is only a proof of no effect
            # if the stack is the only place it could have written. This build
            # keeps the program's values in a register file and most of its
            # handlers write there, which moves no stack pointer and leaves
            # nothing pending - exactly what this case looks like from outside.
            #
            # So the handler has to have been read before this can be called
            # dead. Where it was and it only computes on the stack, nothing can
            # depend on an instruction that moved nothing. Where it was not
            # read, this is an instruction whose effect was not observable, and
            # that is an unknown, not a decoy. Proving it dead is what earns
            # the word.
            m0 = (models or {}).get(st.op)
            style0 = getattr(m0, "handler_style", None) if m0 else None
            if style0 is None and register_file:
                out[st.key()] = Verdict(
                    st.key(), UNKNOWN,
                    "it executed, moved nothing on the stack and produced no "
                    "value, and its handler was not read. This build was "
                    "observed keeping the program's values outside the stack, "
                    "in the interpreter's own registers, and a handler that "
                    "writes one of those moves no stack pointer and leaves "
                    "nothing pending - which is exactly what this looks like "
                    "from outside. Nothing here proves it has no effect, so "
                    "nothing is claimed")
                continue
            if style0 is None:
                out[st.key()] = Verdict(
                    st.key(), DECOY,
                    "it executed, moved nothing on the stack, produced no value "
                    "and made no recorded call. Its handler was not read, but "
                    "nothing in this capture shows this build keeping the "
                    "program's values anywhere but the stack, so the stack was "
                    "the only place it could have written and nothing can "
                    "depend on it")
                continue
            if style0 != "stack":
                out[st.key()] = Verdict(
                    st.key(), UNKNOWN,
                    "it executed and moved nothing on the stack, but its "
                    "handler computes through the interpreter's registers, so "
                    "the stack is not the only place it could have written and "
                    "moving nothing there proves nothing")
                continue
            out[st.key()] = Verdict(
                st.key(), DECOY,
                "it executed, moved nothing on the stack, produced no value and "
                "made no recorded call, and its handler was read and only ever "
                "computes on the stack - so there was nowhere else for it to "
                "write and nothing about the program can depend on it")
            continue
        # An instruction whose own handler performs a call, a store or a jump had
        # an effect, and it ran. "What it did with them was not observable" was
        # the verdict on 737 steps of the real sample, 658 of them an opcode the
        # interpreter's own handler shows calling what it was given - which is
        # as observable as anything in this capture gets.
        m = (models or {}).get(st.op)
        if m is not None and m.operation in _EFFECT_OPS:
            out[st.key()] = Verdict(
                st.key(), OBSERVED,
                "the interpreter's own handler for opcode %d performs a %s, so "
                "this instruction had an effect when it ran"
                % (st.op, m.operation))
            continue
        if not st.pushed:
            out[st.key()] = Verdict(
                st.key(), UNKNOWN,
                "it consumed values and produced none; what it did with them was "
                "not observable, so its effect is unproven either way")
            continue
        # Everything that is left produced something nothing used. That is a
        # fact about the path that ran, and on its own it is not enough to call
        # an instruction a decoy: the verdict is withheld and both readings are
        # recorded. Only an instruction that can have no effect at all - which
        # was decided above - is named a decoy outright.
        extra = (" this capture also left %d branch target(s) unexplored, so a "
                 "path that was not taken may consume it" % len(g.unexplored)
                 ) if reachable_unknown else ""
        out[st.key()] = Verdict(
                st.key(), UNKNOWN,
            "it produced a value that nothing consumed on the path that ran;" +
            (extra or " whether anything consumes it elsewhere is not settled "
                      "by this capture"),
            "decoy: on the evidence available its result influences nothing")
    return out


def readable(verdicts, L, R, calls, models):
    """The same verdicts, said in terms of what the code does.

    An instruction number tells a reader nothing. This lists each verdict
    alongside what the instruction actually is - the call it makes, the value it
    computes, the constant it loads - so the split between what matters and what
    does not can be read rather than cross-referenced."""
    by_step = {c.step.row: c for c in calls}
    real, unproven, dec = [], [], []
    for st in L.steps:
        v = verdicts.get(st.key())
        if v is None:
            continue
        if st.row in by_step:
            text = R.call_text(by_step[st.row])
        elif st.pushed:
            text = R.value(st.pushed[0].id)
        elif st.popped:
            text = "OP_%d(%s)" % (st.op, ", ".join(
                R.value(p.id) for p in st.popped))
        else:
            text = "OP_%d" % st.op
        row = (st.pc, text, v.why)
        if v.verdict == OBSERVED:
            real.append(row)
        elif v.verdict == DECOY:
            dec.append(row)
        else:
            unproven.append(row)

    def rank(row):
        """Readable first. A call with its arguments, a string the program used,
        a piece of arithmetic - these say something. A bare opcode number says
        only that an instruction ran, so it goes last."""
        t = row[1]
        if "(" in t and not t.startswith("OP_"):
            return 0
        if '"' in t:
            return 1
        if any(op in t for op in (" + ", " - ", " * ", " .. ", " < ", " == ")):
            return 2
        if t.startswith("OP_") and "(" not in t:
            return 5
        if t in ("nil", "{}", "true", "false"):
            return 4
        return 3

    def block(title, rows, note, limit=200):
        out = ["", title, "-" * len(title), note, ""]
        seen = set()
        shown = 0
        for pc, text, why in sorted(rows, key=rank):
            t = text.strip()
            if not t or t in seen:
                continue
            seen.add(t)
            out.append("  %s" % t)
            out.append("      why: %s" % why)
            shown += 1
            if shown >= limit:
                out.append("  ... %d more, all in the machine-readable list above"
                           % (len(rows) - shown))
                break
        if not shown:
            out.append("  (none)")
        return out

    LL = ["WHAT MATTERS AND WHAT DOES NOT, IN THE CODE'S OWN TERMS",
          "=" * 58,
          "The same verdicts as above, each shown as what the instruction is",
          "rather than where it sits. Repeats are collapsed."]
    LL += block("REAL - the program's behaviour depends on these", real,
                "Each of these feeds something the program was observed to do: a\n"
                "call it made, a condition it tested, the value it returned, or a\n"
                "variable it read again.")
    LL += block("DECOY - proven unable to affect anything", dec,
                "These executed and can have no effect at all: nothing moves on\n"
                "the stack, no value is produced, no call is recorded, and control\n"
                "does not depend on them.")
    LL += block("UNPROVEN - not settled either way", unproven,
                "These produced a value nothing consumed on the path that ran.\n"
                "That is not enough to call them decoys, so both readings are\n"
                "kept. A run that enters the branches this one did not is what\n"
                "would settle them.")
    return "\n".join(LL)


def report(verdicts, g):
    order = {OBSERVED: 0, UNKNOWN: 1, DECOY: 2}
    rows = sorted(verdicts.values(),
                  key=lambda v: (order.get(v.verdict, 3), v.pc))
    n = {}
    for v in rows:
        n[v.verdict] = n.get(v.verdict, 0) + 1
    L = ["WHAT MATTERS AND WHAT DOES NOT",
         "=" * 46,
         "Verdicts computed backwards from what the program was observed to do:",
         "the calls it made, the conditions it tested, the value it returned and",
         "the variables it read again. Nothing is judged by how complicated it",
         "looks, and nothing is called a decoy for being absent from a trace.",
         "",
         "real: %d   unproven: %d   decoy: %d   unexplored branch targets: %d"
         % (n.get(OBSERVED, 0), n.get(UNKNOWN, 0), n.get(DECOY, 0),
            len(g.unexplored)),
         ""]
    if g.unexplored:
        L.append("Because branch targets were left unexplored, instructions whose")
        L.append("result is unused are reported as unproven rather than as decoys.")
        L.append("Driving those branches in another run is what would settle them.")
        L.append("")
    for v in rows:
        L.append("  %-12s %-9s %s"
                 % ("fn%d:%d" % v.pc if isinstance(v.pc, tuple) else v.pc,
                    v.verdict, v.why))
        if v.alternative:
            L.append("  %-8s %-9s rival reading kept: %s" % ("", "", v.alternative))
    return "\n".join(L)


def apply_predicates(verdicts, predicates, g=None):
    """Record what constant propagation settled about each branch.

    A branch whose condition is the same constant on every path that reaches it
    cannot go the other way. That is worth saying, and it is said - on the
    branch and on the target that was never entered.

    What it is NOT is a licence to delete. "The other side cannot be reached"
    is a statement about reachability, not about who wrote the code: a
    programmer's own `if n < 10` with n fixed at 3 reads exactly the same way
    as an obfuscator's opaque predicate, and this pass cannot tell them apart.
    So the verdict on the instruction is left alone and nothing is removed from
    the reconstruction. The finding is attached to the branch, where a reader
    can weigh it, and counted.

    Returns how many branches were settled this way.
    """
    n = 0
    for pc, d in (predicates or {}).items():
        if d.get("verdict") != DECOY:
            continue
        n += 1
        v = verdicts.get(pc)
        if v is not None and v.alternative is None:
            v.alternative = d["why"]
    if g is not None:
        settled = {pc for pc, d in (predicates or {}).items()
                   if d.get("verdict") == DECOY}
        for b in g.branches:
            if b["pc"] in settled:
                b["settled"] = (predicates or {})[b["pc"]]["why"]
        g.unexplored = [(a, t, why + "  -- and: " +
                         (predicates or {})[a]["why"] if a in settled else why)
                        for a, t, why in g.unexplored]
    return n
