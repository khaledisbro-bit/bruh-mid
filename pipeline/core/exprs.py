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


_PLAIN = re.compile(r"^(-?\d+(\.\d+)?|true|false|nil|table|function)$")


def _as_written(arg):
    """An argument the environment recorded as bare text is a string unless it
    reads as one of the values that are written without quotes."""
    a = arg.strip()
    if a.startswith(('"', "{", "[")) or _PLAIN.match(a):
        return a
    return '"%s"' % a


_NAME = re.compile(r"^[A-Za-z_]\w*$")
_RISKY = re.compile(r"(^|[^\w.])nil\s*[\[.(]|^\s*-?\d+\s*\(|nil\s*[-+*/%]|"
                    r"[-+*/%]\s*nil|\{\}\s*[-+*/%]|[-+*/%]\s*\{\}")


def _risky(text):
    """A rendering that loads but would stop the run: indexing or calling nil,
    calling a number, arithmetic on nil or on a table. These come from a reading
    that is wrong somewhere, and in a script they end the comparison at the first
    one instead of letting the proven part run."""
    return bool(_RISKY.search(text))


def is_literal(text):
    """A rendering that costs nothing to repeat: a value, or a name that already
    stands for one. Giving either its own line adds a rename, not information."""
    t = text.strip()
    return bool(_LIT.match(t) or _NAME.match(t))


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
                matched.append(_build(rec, st, namev, strength, note, tier))
                break
        if found is None:
            unmatched.append(rec)
    return matched, unmatched


def _anchors(rec):
    """What to look for in the value graph to find the instruction that made a
    recorded call, best evidence first.

    An argument is worth as much as a method name and often more. A VM resolves
    the name of a host function through its import table, so the name itself
    never appears as a value, while the argument the program passed is a
    constant it decrypted and pushed - and that does appear. The environment
    records an argument as text, quoted or not depending on its type, so a plain
    word is also tried as the string it stands for."""
    out = []
    name = rec.get("method")
    if name:
        out.append(("name", '"%s"' % name, OBSERVED,
                    "the instruction consumed the method name %r" % name))
    if rec.get("recv"):
        out.append(("recv", '"%s"' % rec["recv"], INFERRED,
                    "the instruction is downstream of the receiver name %r"
                    % rec["recv"]))
    for a in rec.get("args") or ():
        a = a.strip()
        if not a:
            continue
        if a.startswith('"'):
            out.append(("arg", a, INFERRED,
                        "the instruction consumed the argument %s" % a))
        elif not a.startswith(("{", "[")):
            out.append(("arg", '"%s"' % a, INFERRED,
                        "the instruction consumed the argument %r, which the "
                        "environment recorded without quoting" % a))
            out.append(("argraw", a, INFERRED,
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


def _build(rec, st, namev, strength, note, tier):
    """Split the instruction's inputs into a receiver and arguments, using where
    the anchor sat among them. A stack machine pushes the callee, then the name,
    then the arguments, so the anchor's position says which is which - and the
    anchor is not always the name."""
    if namev in st.popped:
        idx = st.popped.index(namev)
        if tier in ("arg", "argraw"):
            args = st.popped[idx:]
            recv = st.popped[0] if idx > 0 else None
        elif tier == "recv":
            recv = namev
            args = st.popped[idx + 1:]
        else:
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
    def __init__(self, L, models, slots, amap, calls, bound=None, env_ops=None,
                 env_slots=None, env_names=None, runnable=False, webs=None):
        self.webs = webs
        self.env_slots = env_slots or {}
        self.env_names = env_names or {}
        # In runnable mode everything unproven is rendered as a call to a stub,
        # so the file loads and the parts that ARE proven can be executed and
        # compared. A report may say "OP_19" or "<constant>"; a script cannot.
        self.runnable = runnable
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
        number in a different function does not.

        Where the reaching-definition pass ran, the name goes on the variable
        rather than on the slot. A compiler reuses a slot, so one slot can hold
        two things that no read connects; naming per slot writes them as one
        variable and claims an assignment the program never made."""
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
        self.by_web = {}
        if self.webs is not None and self.webs.active():
            per_group = {}
            for st in self.L.steps:
                wid = self.webs.of_row(st.row)
                if wid is None:
                    continue
                key = self.slots.writes.get(st.row, self.slots.reads.get(st.row))
                if key is None:
                    continue
                base = self.names.get(key)
                if base is None:
                    continue
                if wid in self.by_web:
                    continue
                n = per_group.get(base, 0)
                per_group[base] = n + 1
                # the first variable on a slot keeps the slot's name, so a slot
                # that was never reused reads exactly as it did before
                self.by_web[wid] = base if n == 0 else "%s_%d" % (base, n + 1)

    def var(self, key, row=None):
        if row is not None and self.webs is not None:
            wid = self.webs.of_row(row)
            if wid is not None and wid in getattr(self, "by_web", {}):
                return self.by_web[wid]
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
        if v.row in self.env_slots:
            key = self.env_slots[v.row]
            if key in self.env_names:
                return self.env_names[key]
        if v.slot is not None and v.kind != "external":
            return self.var(v.slot, getattr(v, "row", None))
        call = self.by_step.get(v.row)
        if call is not None and v in call.step.pushed:
            return self.call_text(call, depth)
        if v.op in self.env_ops and len(v.inputs) == 1:
            src = self.L.values[v.inputs[0]]
            if src.runtime and src.runtime.startswith('"'):
                return _unq(src.runtime)
        m = self.models.get(v.op)
        if m is not None and m.operation:
            out = self._operation(v, m.operation, depth)
            if out is not None:
                if self.runnable and _risky(out):
                    return self._stub(v, depth)
                return out
        if v.inputs and v.op not in self.env_ops:
            head = self.L.values[v.inputs[0]]
            if head.op in self.env_ops and len(head.inputs) == 1:
                callee = self.value(head.id, depth + 1)
                rest = [self.value(i, depth + 1) for i in v.inputs[1:]]
                return "%s(%s)" % (callee, ", ".join(rest))
        if v.kind == "external":
            return self._stub(v, depth) if self.runnable else "<unknown value>"
        if v.runtime and _LIT.match(v.runtime):
            if v.runtime not in ("table", "{}"):
                return v.runtime
        if self.runnable:
            return self._stub(v, depth)
        if not v.inputs:
            return "OP_%d()" % v.op if v.op is not None else "<unknown value>"
        return "OP_%d(%s)" % (v.op, ", ".join(
            self.value(i, depth + 1) for i in v.inputs))

    def _stub(self, v, depth):
        """An operation this analysis has not established, written so the file
        still loads: the opcode's number and its inputs handed to a stub."""
        args = [self.value(i, depth + 1) for i in v.inputs]
        return "OP(%s%s)" % (v.op if v.op is not None else -1,
                             (", " + ", ".join(args)) if args else "")

    SYMBOLS = {"ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/", "MOD": "%",
               "CONCAT": "..", "LT": "<", "LE": "<=", "GT": ">", "GE": ">=",
               "EQ": "==", "NE": "~="}

    def _operation(self, v, op, depth):
        """Render an operation the interpreter's handler named."""
        args = [self.value(i, depth + 1) for i in v.inputs]
        sym = self.SYMBOLS.get(op)
        if sym and len(args) == 2:
            return "(%s %s %s)" % (args[0], sym, args[1])
        if op == "INDEX" and len(args) == 2:
            base = args[0]
            if not _NAME.match(base.strip()):
                base = "(%s)" % base          # a table constructor or an
                                              # expression cannot be indexed bare
            key = _unq(args[1]) if args[1].startswith('"') else None
            if key and re.fullmatch(r"[A-Za-z_]\w*", key):
                return "%s.%s" % (base, key)
            return "%s[%s]" % (base, args[1])
        if op == "NEWTABLE" and not args:
            return "{}"
        if op == "LOADK":
            if v.runtime:
                return v.runtime
            return "nil" if self.runnable else "<constant>"
        if op == "CALL" and args:
            if self.runnable and not _NAME.match(args[0].strip()):
                return None       # calling something that is not a name would
                                  # not run; the stub below says so instead
            return "%s(%s)" % (args[0], ", ".join(args[1:]))
        return None

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
        # The instruction may leave more on the stack than the call took. The
        # environment recorded how many arguments there were, so anything past
        # that is not an argument and is dropped rather than printed.
        want = len(rec.get("args") or ())
        if want and len(args) > want:
            args = args[:want]
        if not args and rec.get("args"):
            args = [_as_written(a) for a in rec["args"]]
        if rec.get("recv") is None:
            return "%s(%s)" % (name, ", ".join(args))
        # a method call needs something a method can be taken from: a literal or
        # an expression has to be parenthesised, or the line will not load
        if not _NAME.match(recv.strip()) and not recv.strip().startswith("("):
            recv = "(%s)" % recv
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
