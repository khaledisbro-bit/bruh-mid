#!/usr/bin/env python3
"""
exprs.py - turn the value graph back into expressions, and find the calls.

Two things happen here.

FINDING CALLS. The harness watched the program through a proxied environment, so
it holds a record of every call the program made, with the receiver, the method
and the real arguments. Those records are in execution order, and so are the
instructions. A record is matched to the instruction that made it by requiring
both: the instruction must have consumed a value equal to the method name in the
record, and the matches must stay in order. A record that cannot be matched that
way is reported unmatched rather than attached to a plausible-looking
instruction.

RENDERING. Once calls are matched, every value has a reading:

  a constant           the literal the VM decrypted
  a variable read      the variable's name
  a proved operation   its inputs joined by the operator that value algebra
                       proved for that opcode
  a matched call       receiver, method and arguments from the record
  anything else        the opcode and its inputs, unnamed

Nothing is rendered that the graph does not contain. An expression whose parts
are not all known is rendered with the unknown parts left visible, never
completed by guesswork.
"""
import re

from evidence import OBSERVED, INFERRED, UNKNOWN, DECOY

_LIT = re.compile(r'^(".*"|-?\d+(?:\.\d+)?|true|false|nil)$')


class Call:
    __slots__ = ("record", "step", "recv_value", "name_value", "arg_values",
                 "evidence", "why")

    def __init__(self, record, step, recv_value, name_value, arg_values,
                 evidence, why):
        self.record = record
        self.step = step
        self.recv_value = recv_value
        self.name_value = name_value
        self.arg_values = arg_values
        self.evidence = evidence
        self.why = why


def _unq(v):
    if v and len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def match_calls(L, records):
    """Attach each observed call record to the instruction that made it.

    The environment recorded what the program called; the capture recorded which
    instructions ran. Joining them needs an anchor that appears in both, and
    which anchor survives depends on the build, so several are tried in order of
    how much they prove. All of them keep execution order, so a match can never
    jump backwards past one already made.

      1. the call instruction itself consumed the method name
      2. the method name appears as a value in the graph, and an instruction
         downstream of it consumes it
      3. the receiver's name appears the same way
      4. an argument value appears the same way

    The first anchor is proof; the later ones place the call by a value it
    demonstrably used, which is weaker and is marked as inferred. A record no
    anchor reaches is reported unmatched rather than attached to whatever
    instruction happened to be nearby."""
    matched, unmatched = [], []
    cursor = 0
    consumers = L.consumers()
    for rec in records:
        found = None
        for tier, anchor, strength, note in _anchors(rec):
            found = _find(L, consumers, cursor, anchor)
            if found is not None:
                k, st, namev = found
                cursor = k + 1
                matched.append(_build(rec, st, namev, strength, note, anchor))
                break
        if found is None:
            unmatched.append(rec)
    return matched, unmatched


def _anchors(rec):
    name = rec.get("method")
    out = []
    if name:
        out.append(("name", '"%s"' % name, OBSERVED,
                    "the instruction consumed the method name %r" % name))
    if rec.get("recv"):
        out.append(("recv", '"%s"' % rec["recv"], INFERRED,
                    "the instruction is downstream of the receiver name %r"
                    % rec["recv"]))
    for a in rec.get("args") or ():
        if a.startswith('"') and len(a) > 2:
            out.append(("arg", a, INFERRED,
                        "the instruction consumed the argument %s" % a))
    return out


def _find(L, consumers, cursor, anchor):
    """The first instruction at or after `cursor` that consumes a value equal to
    `anchor`, or failing that the instruction that produced one."""
    for k in range(cursor, len(L.steps)):
        st = L.steps[k]
        hit = [v for v in st.popped if v.runtime == anchor]
        if hit:
            return k, st, hit[0]
    producer = None
    for v in L.values:
        if v.runtime == anchor and v.row is not None:
            producer = v
            break
    if producer is None:
        return None
    for k in range(cursor, len(L.steps)):
        st = L.steps[k]
        if st.row < producer.row:
            continue
        users = consumers.get(producer.id) or []
        if users and st.row == users[0].row:
            return k, st, producer
        if st.row == producer.row and not users:
            return k, st, producer
    return None


def _build(rec, st, namev, strength, note, anchor):
    if namev in st.popped:
        idx = st.popped.index(namev)
        recv = st.popped[idx - 1] if idx >= 1 else None
        args = st.popped[idx + 1:]
    else:
        recv = st.popped[0] if st.popped else None
        args = st.popped[1:]
    st.fact.evidence = strength
    st.fact.note("exprs.call", "makes the recorded call %s; %s"
                 % (rec.get("raw", ""), note),
                 pcs=(st.pc,), steps=(st.row,), records=(rec.get("raw", ""),))
    return Call(rec, st, recv, namev, args, strength,
                "the environment recorded %s and %s at the matching point in "
                "execution order" % (rec.get("raw", ""), note))


def identify_env(L, models, calls, slots):
    """Find the instruction that turns a name into the thing it names.

    A VM looks a global up by pushing its name and then indexing the environment
    with it. That instruction can be identified without assuming anything: take
    an opcode that consumes one value and produces one, and look for a case where
    its input was a string and its output was then used as the receiver of a call
    the environment recorded under exactly that name. When the recorded receiver
    matches the consumed string, the instruction demonstrably resolved that name,
    and any counter-example rules the opcode out."""
    by_value = {}
    for c in calls:
        if c.recv_value is not None:
            by_value.setdefault(c.recv_value.id, []).append(c)
    support, against = {}, set()
    for st in L.steps:
        if st.pops != 1 or st.pushes != 1 or st.op in slots.read_ops:
            continue
        src = st.popped[0]
        name = _unq(src.runtime) if src.runtime else None
        if name is None or not (src.runtime or "").startswith('"'):
            continue
        for c in by_value.get(st.pushed[0].id, []):
            if c.record.get("recv") == name:
                support[st.op] = support.get(st.op, 0) + 1
            else:
                against.add(st.op)
    ops = {op for op, n in support.items() if n >= 1 and op not in against}
    why = {op: ("OP_%d resolved a name %d time(s): the value it produced was the "
                "receiver of a call the environment recorded under exactly the "
                "string it consumed" % (op, support[op])) for op in ops}
    return ops, why


class Renderer:
    def __init__(self, L, models, slots, amap, calls, bound=None, env_ops=None):
        self.bound = bound if bound is not None else {}
        self.env_ops = env_ops or set()
        self.L = L
        self.models = models
        self.slots = slots
        self.amap = amap or {}
        self.by_step = {c.step.row: c for c in calls}
        self.names = {}
        self._assign_names()
        self._cache = {}

    def _assign_names(self):
        """A variable is named per function and slot, so the same local seen on
        two calls of one function reads as one variable, while the same slot
        number in a different function does not."""
        order, byfn = [], {}
        for st in self.L.steps:
            key = self.slots.writes.get(st.row, self.slots.reads.get(st.row))
            if key is None:
                continue
            group = (st.fn, key[1] if isinstance(key, tuple) else key)
            if group not in byfn:
                byfn[group] = "v%d" % len(byfn)
            order.append((key, group))
        for key, group in order:
            self.names[key] = byfn[group]

    def var(self, key):
        if key in self.names:
            return self.names[key]
        return "slot%s" % (key[1] if isinstance(key, tuple) else key,)

    def value(self, vid, depth=0):
        if vid in self.bound:
            return self.bound[vid]
        if vid in self._cache:
            return self._cache[vid]
        if depth > 24:
            return "v%d" % vid
        v = self.L.values[vid]
        out = self._render(v, depth)
        self._cache[vid] = out
        return out

    def _render(self, v, depth):
        if v.id in self.bound:
            return self.bound[v.id]
        if v.slot is not None and v.kind != "external":
            return self.var(v.slot)
        call = self.by_step.get(v.row)
        if call is not None and v in call.step.pushed:
            return self.call_text(call, depth)
        if v.op in self.env_ops and len(v.inputs) == 1:
            src = self.L.values[v.inputs[0]]
            if src.runtime and src.runtime.startswith('"'):
                return _unq(src.runtime)
        m = self.models.get(v.op)
        if m is not None and m.operation and len(v.inputs) == 2:
            a = self.value(v.inputs[0], depth + 1)
            b = self.value(v.inputs[1], depth + 1)
            sym = {"ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/", "MOD": "%",
                   "CONCAT": "..", "LT": "<", "LE": "<=", "GT": ">",
                   "EQ": "=="}.get(m.operation)
            if sym:
                return "(%s %s %s)" % (a, sym, b)
        if v.inputs and v.op not in self.env_ops:
            head = self.L.values[v.inputs[0]]
            if head.op in self.env_ops and len(head.inputs) == 1:
                callee = self.value(head.id, depth + 1)
                rest = [self.value(i, depth + 1) for i in v.inputs[1:]]
                return "%s(%s)" % (callee, ", ".join(rest))
        if v.kind == "external":
            return "<unknown value>"
        if v.runtime and _LIT.match(v.runtime):
            if v.runtime not in ("table", "{}"):
                return v.runtime
        if not v.inputs:
            return "OP_%d()" % v.op if v.op is not None else "<unknown value>"
        return "OP_%d(%s)" % (v.op, ", ".join(
            self.value(i, depth + 1) for i in v.inputs))

    def call_text(self, call, depth=0):
        rec = call.record
        name = rec.get("method") or "?"
        if call.recv_value is not None:
            recv = self.value(call.recv_value.id, depth + 1)
            if recv in ("<unknown value>", "table", "{}") or recv.startswith("OP_"):
                recv = rec.get("recv") or recv
        else:
            recv = rec.get("recv") or "?"
        args = [self.value(a.id, depth + 1) for a in call.arg_values]
        if not args and rec.get("args"):
            args = list(rec["args"])
        if rec.get("recv") is None:
            return "%s(%s)" % (name, ", ".join(args))
        return "%s:%s(%s)" % (recv, name, ", ".join(args))


def evidence_of(L, vid, amap):
    """The weakest evidence anywhere under a value: an expression is only as
    certain as the least certain thing it is built from."""
    worst = OBSERVED
    rank = {OBSERVED: 3, INFERRED: 2, UNKNOWN: 1, DECOY: 0}
    seen, stack = set(), [vid]
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        seen.add(i)
        v = L.values[i]
        if rank.get(v.fact.evidence, 1) < rank[worst]:
            worst = v.fact.evidence
        stack.extend(v.inputs)
        if i in amap:
            stack.append(amap[i])
    return worst
