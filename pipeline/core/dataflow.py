#!/usr/bin/env python3
"""
dataflow.py - recover variables, and follow values through them.

The stack replay gives expressions, but a program's shape comes from its
variables, and the VM's instructions do not say which of them read or write one.
That has to be discovered, and it can be discovered exactly, because a variable
leaves a signature nothing else does: whatever a slot was last given is what the
next read of that slot returns.

So the pass proposes every pair of opcodes that could be a write and a read - one
that consumes a value and carries an operand, one that produces a value and
carries an operand - and then tests the pair against the whole run. Replaying the
slots for a candidate pair, every read must return the value the last write to
that slot put there. One counter-example is enough to reject the pair. A pair
that survives is not a guess: it is the only reading consistent with every
instance in the capture.

From there the rest follows on the graph that is now complete:

  REACHING DEFINITIONS   which write each read sees,
  LIVENESS               whether anything ever reads what an instruction wrote,
  DEPENDENCIES           the transitive inputs of a value, used to tell code that
                         matters from code that nothing depends on.
"""
from collections import defaultdict

from evidence import OBSERVED, INFERRED, UNKNOWN

MIN_WITNESSES = 3


class Slots:
    """The variable model this capture supports."""

    def __init__(self):
        self.write_ops = set()
        self.read_ops = set()
        self.index = {}          # (opcode, 'r'|'w') -> operand position
        self.reads = {}          # step row -> slot key
        self.writes = {}         # step row -> slot key
        self.reaching = {}       # read step row -> value id written
        self.witnesses = 0
        self.why = ""

    def active(self):
        return bool(self.write_ops and self.read_ops)


def _operand_positions(step):
    return range(len(step.operands))


def env_slots(L, reads):
    """Name the stored slots the program reads.

    Some opcodes fetch a value the interpreter keeps in a boxed slot, indexed by
    one of the instruction's operands - the handler says so outright. Those are
    the program's captured values, and without naming them every read of the same
    slot renders as a separate unnamed opcode, hiding that one object is being
    used over and over.

    They cannot be checked the way a variable is, because nothing in this capture
    writes them, so the check available is consistency: two reads of one slot,
    with no write between, must return the same value. The rate is reported and
    the naming is marked inferred, never observed."""
    seen, agree, differ = {}, 0, 0
    keys = {}
    for st in L.steps:
        i = reads.get(st.op)
        if i is None or not (0 <= i < len(st.operands)) or not st.pushed:
            continue
        key = st.operands[i]
        keys[st.row] = key
        got = st.pushed[0].runtime
        if got is None:
            continue
        if key in seen:
            if seen[key] == got:
                agree += 1
            else:
                differ += 1
        seen[key] = got
    order, names = [], {}
    for row in sorted(keys):
        k = keys[row]
        if k not in names:
            names[k] = "u%d" % len(names)
        order.append(k)
    total = agree + differ
    why = ("%d opcode(s) read a stored slot, naming %d slot(s). Of the repeat "
           "reads, %d of %d returned the same value as the read before it"
           % (len(reads), len(names), agree, total))
    return keys, names, why, agree, total


def slots_from_source(L, reads, writes):
    """Build the variable model the interpreter's handlers describe, and check it.

    The handlers say which opcode reads a variable and which writes one, and at
    which operand. That is a claim, so it is put through the same test a guessed
    pair has to pass: every read must return what the last write to its slot
    stored. The rate is reported; a model that fails it is not used."""
    S = Slots()
    if not reads or not writes:
        S.why = "the interpreter's handlers did not describe a variable access"
        return S, 0, 0
    env, hits, misses = {}, 0, 0
    for st in L.steps:
        if st.op in writes:
            i = writes[st.op]
            if 0 <= i < len(st.operands) and st.popped:
                key = (st.frame, st.operands[i])
                env[key] = st.popped[0]
                S.writes[st.row] = key
        elif st.op in reads:
            i = reads[st.op]
            if not (0 <= i < len(st.operands)) or not st.pushed:
                continue
            key = (st.frame, st.operands[i])
            S.reads[st.row] = key
            src = env.get(key)
            if src is None:
                continue
            S.reaching[st.row] = src.id
            got, want = st.pushed[0].runtime, src.runtime
            if got is None or want is None:
                continue
            if got == want:
                hits += 1
            else:
                misses += 1
    S.write_ops = set(writes)
    S.read_ops = set(reads)
    S.witnesses = hits
    total = hits + misses
    S.why = ("taken from the interpreter's handlers: %d opcode(s) write a "
             "variable and %d read one. Of the reads that could be checked, "
             "%d of %d returned exactly what the last write to the same slot "
             "stored" % (len(writes), len(reads), hits, total))
    if total and hits < total * 0.9:
        S.why += " - too many disagreed, so this model is not used"
        return Slots(), hits, total
    _mark(L, S)
    return S, hits, total


def _mark(L, S):
    for st in L.steps:
        if st.row in S.reads:
            src = S.reaching.get(st.row)
            for v in st.pushed:
                v.slot = S.reads[st.row]
                v.fact.evidence = OBSERVED if src is not None else UNKNOWN
                v.fact.note(
                    "dataflow.slot",
                    ("reads variable %s, last written by v%s"
                     % (_name(S.reads[st.row]), src)) if src is not None else
                    ("reads variable %s, never written inside the capture"
                     % _name(S.reads[st.row])),
                    pcs=(st.pc,), steps=(st.row,),
                    inputs=((src,) if src is not None else ()))


def infer_slots(L, min_witnesses=MIN_WITNESSES):
    """Find the opcodes that write and read local variables."""
    writers = defaultdict(list)
    readers = defaultdict(list)
    for st in L.steps:
        if not st.operands:
            continue
        if st.pushes == 0 and st.pops == 1:
            writers[st.op].append(st)
        elif st.pops == 0 and st.pushes == 1:
            readers[st.op].append(st)

    survivors = []
    for wop, wsteps in writers.items():
        for rop, rsteps in readers.items():
            for wi in _operand_positions(wsteps[0]):
                for ri in _operand_positions(rsteps[0]):
                    res = _test_pair(L, wop, wi, rop, ri)
                    if res is not None:
                        survivors.append((res[0], wop, wi, rop, ri, res[1]))
    # A candidate needs enough witnesses to stand on its own. When only one
    # candidate survives the whole run there is nothing else it could be, so a
    # shorter run still settles it - the test that rejected every rival is the
    # evidence, not the count.
    need = min_witnesses if len(survivors) > 1 else 2
    survivors = [c for c in survivors if c[0] >= need]
    best = max(survivors, key=lambda c: c[0]) if survivors else None

    S = Slots()
    if best is None:
        S.why = ("no pair of opcodes behaved like a variable write and read: no "
                 "candidate returned the last value written to its slot on every "
                 "instance")
        return S
    hits, wop, wi, rop, ri, slots = best
    S.write_ops = {wop}
    S.read_ops = {rop}
    S.index[(wop, "w")] = wi
    S.index[(rop, "r")] = ri
    S.reads, S.writes, S.reaching = slots["reads"], slots["writes"], slots["reaching"]
    S.witnesses = hits
    S.why = ("OP_%d (consumes one value, operand %d) and OP_%d (produces one "
             "value, operand %d) behave as a variable write and read: %d read(s) "
             "returned exactly what the last write to the same slot stored, with "
             "no counter-example" % (wop, wi, rop, ri, hits))

    _mark(L, S)
    return S


def _test_pair(L, wop, wi, rop, ri):
    """Replay the run treating (wop, operand wi) as a write and (rop, operand ri)
    as a read. Every read must return what the last write to that slot stored."""
    env = {}
    hits = 0
    reads, writes, reaching = {}, {}, {}
    for st in L.steps:
        if st.op == wop:
            if wi >= len(st.operands) or not st.popped:
                return None
            key = (st.frame, st.operands[wi])
            env[key] = st.popped[0]
            writes[st.row] = key
        elif st.op == rop:
            if ri >= len(st.operands) or not st.pushed:
                return None
            key = (st.frame, st.operands[ri])
            reads[st.row] = key
            src = env.get(key)
            if src is None:
                continue
            reaching[st.row] = src.id
            got = st.pushed[0].runtime
            want = src.runtime
            if got is None or want is None:
                continue
            if got != want:
                return None
            hits += 1
    if not hits:
        return None
    return hits, {"reads": reads, "writes": writes, "reaching": reaching}


def _name(key):
    if isinstance(key, tuple):
        return "slot%s" % (key[1],)
    return "slot%s" % key


def alias(L, slots):
    """Point every variable read at the definition it returns, so expressions can
    be followed across a variable without losing where the value came from."""
    amap = {}
    for st in L.steps:
        if st.row in slots.reaching and st.pushed:
            amap[st.pushed[0].id] = slots.reaching[st.row]
    return amap


def liveness(L):
    """Value ids that nothing ever consumes. A value with no consumer did not
    feed the program's result on this path; that is a fact about this path, not a
    licence to delete the instruction that made it."""
    used = set()
    for st in L.steps:
        for v in st.popped:
            used.add(v.id)
    return {v.id for v in L.values if v.id not in used}


def dependencies(L, amap=None):
    """Transitive inputs of every value."""
    amap = amap or {}
    deps = {}

    def walk(vid, seen):
        if vid in deps:
            return deps[vid]
        if vid in seen:
            return set()
        seen.add(vid)
        v = L.values[vid]
        out = set()
        srcs = list(v.inputs)
        if vid in amap:
            srcs.append(amap[vid])
        for i in srcs:
            out.add(i)
            out |= walk(i, seen)
        deps[vid] = out
        return out

    for v in L.values:
        walk(v.id, set())
    return deps


def report(L, slots):
    dead = liveness(L)
    lines = ["VARIABLES AND DATA FLOW",
             "=" * 46,
             "Variables are not declared by the instruction set, so the write and",
             "read opcodes were found by testing candidates against the whole run:",
             "a pair is accepted only if every read returned what the last write",
             "to that slot stored.", ""]
    if not slots.active():
        lines.append("  " + slots.why)
    else:
        lines.append("  " + slots.why)
        keys = sorted(set(slots.reads.values()) | set(slots.writes.values()),
                      key=lambda k: (str(type(k)), k))
        lines.append("")
        lines.append("  variables found: %d" % len(keys))
        for k in keys:
            w = sum(1 for kk in slots.writes.values() if kk == k)
            r = sum(1 for kk in slots.reads.values() if kk == k)
            lines.append("    %-10s written %d time(s), read %d time(s)"
                         % (_name(k), w, r))
    lines.append("")
    lines.append("values never consumed on this path: %d of %d"
                 % (len(dead), len(L.values)))
    lines.append("  (recorded, not removed: a value unused on the path that ran")
    lines.append("   may be consumed on a path that did not)")
    return "\n".join(lines)


class Tables:
    """Opcodes proved to store into and read back from a keyed container."""

    def __init__(self):
        self.store_op = None
        self.load_op = None
        self.witnesses = 0
        self.stores = {}     # step row -> (container value, key text)
        self.loads = {}
        self.why = "no pair of opcodes behaved like a keyed store and load"

    def active(self):
        return self.store_op is not None


def infer_tables(L, min_witnesses=2):
    """Find the instructions that write and read a field of a container.

    The proof is the same one that finds variables, applied to a pair of values
    instead of a slot number: if an opcode stores three values and another
    opcode, given back the same container and the same key, returns exactly what
    was stored, the pair is a keyed write and read. One mismatch rejects it."""
    stores = [st for st in L.steps if st.pushes == 0 and st.pops == 3]
    loads = [st for st in L.steps if st.pushes == 1 and st.pops == 2]
    T = Tables()
    if not stores or not loads:
        return T
    best = None
    for sop in {st.op for st in stores}:
        for lop in {st.op for st in loads}:
            res = _test_container(L, sop, lop)
            if res is None:
                continue
            hits, rec = res
            if hits >= min_witnesses and (best is None or hits > best[0]):
                best = (hits, sop, lop, rec)
    if best is None:
        return T
    hits, sop, lop, rec = best
    T.store_op, T.load_op, T.witnesses = sop, lop, hits
    T.stores, T.loads = rec["stores"], rec["loads"]
    T.why = ("OP_%d (stores three values) and OP_%d (returns one from two) "
             "behave as a keyed write and read: %d read(s) returned exactly what "
             "the last write with the same container and key stored, with no "
             "counter-example" % (sop, lop, hits))
    return T


def _test_container(L, sop, lop):
    env, hits = {}, 0
    stores, loads = {}, {}
    for st in L.steps:
        if st.op == sop:
            if len(st.popped) != 3:
                return None
            c, k, v = st.popped
            env[(c.id, k.runtime)] = v
            stores[st.row] = (c.id, k.runtime)
        elif st.op == lop:
            if len(st.popped) != 2 or not st.pushed:
                return None
            c, k = st.popped
            loads[st.row] = (c.id, k.runtime)
            src = env.get((c.id, k.runtime))
            if src is None:
                continue
            got, want = st.pushed[0].runtime, src.runtime
            if got is None or want is None:
                continue
            if got != want:
                return None
            hits += 1
    if not hits:
        return None
    return hits, {"stores": stores, "loads": loads}
