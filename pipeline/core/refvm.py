#!/usr/bin/env python3
"""
refvm.py - TEST INFRASTRUCTURE ONLY. A small stack VM that produces captures in
the same shape as the real harness, from programs whose source we know.

It exists so every analysis stage can be checked against ground truth instead of
being eyeballed, and it deliberately reproduces the properties that make the real
samples hard:

  * opcode numbers are RANDOMISED per run, so nothing downstream may depend on a
    fixed opcode table,
  * names are not baked into instructions: a name is pushed as a constant and
    then consumed by a generic index operation, exactly as a real VM does, so the
    analyser has to recover it through data flow,
  * an instruction's result is reported one record LATE, because the VM leaves it
    pending until the next instruction runs,
  * interpreter machinery runs in bursts between program instructions and gives
    the stack pointer back untouched,
  * decoy instructions execute, touch nothing and feed nothing.

It contains no knowledge of any real sample. The fixture sources below are ground
truth for the round-trip test; the analysis engine never reads them, it only ever
sees the emitted capture text.
"""
import random

# name: (pops, pushes); "n+k" means the count comes from the instruction operand
ISA = {
    "PUSHK":    (0, 1),    # push constant[k]
    "GETENV":   (1, 1),    # name -> the global it names
    "INDEX":    (2, 1),    # table, key -> value
    "SETINDEX": (3, 0),    # table, key, value ->
    "NEWTABLE": (0, 1),
    "GETLOCAL": (0, 1),
    "SETLOCAL": (1, 0),
    "ADD":      (2, 1),
    "SUB":      (2, 1),
    "MUL":      (2, 1),
    "CONCAT":   (2, 1),
    "LT":       (2, 1),
    "CALL":     ("n+1", 1),   # callee, args... -> result
    "SELFCALL": ("n+2", 1),   # object, name, args... -> result
    # CALLP only transfers control. The value the call produces is left by the
    # callee's RETURN, so the calling instruction itself moves nothing, and that
    # is what a trace shows.
    "CALLP":    (0, 0),
    "JMP":      (0, 0),
    "JMPIFNOT": (1, 0),
    "RETURN":   (1, 0),   # at the root; see CONTEXTUAL
    "DECOY":    (0, 0),
}

# Instructions whose stack effect depends on where they run rather than on
# what they are. RETURN drops a value at the end of the program, but hands one
# to the caller when a call is waiting, so there is no single right answer to
# check a measurement against.
CONTEXTUAL = {"RETURN"}

_CONSTUSERS = ("PUSHK", "INDEX", "SETINDEX", "SELFCALL", "GETENV")


class Program:
    """A program is one or more functions. Each function numbers its own
    instructions from zero, exactly as a real VM does, so instruction 2 of one
    function and instruction 2 of another are different instructions that look
    identical in a trace."""

    def __init__(self, source, code, consts, protos=None):
        self.source = source
        self.protos = [code] + list(protos or [])
        self.code = code
        self.consts = consts


class Emitter:
    def __init__(self, seed=0):
        self.rng = random.Random(seed)
        self.opnum = {}
        self.rows, self.resolved, self.calls, self.prints = [], [], [], []
        self.mach_pcs = [9000 + i for i in range(6)]
        self._pending = "nil"
        self.code_rows = []

    def op(self, name):
        if name not in self.opnum:
            self.opnum[name] = self.rng.randrange(1000, 2 ** 31 - 1)
        return self.opnum[name]

    def emit(self, pc, name, operands, sp):
        self.rows.append("%d;%d;%s;%d;%s" % (
            pc, self.op(name), ",".join(str(o) for o in operands), sp,
            self._pending))
        self._pending = "nil"

    def produce(self, value):
        self._pending = preview(value)

    def machinery(self, sp):
        for k in range(self.rng.randrange(4, 9)):
            self.emit(self.mach_pcs[k % len(self.mach_pcs)],
                      "MACH%d" % (k % 3), [], sp)
            self.produce(self.rng.randrange(1 << 40, 1 << 52))

    def text(self):
        out = ["loaded: true", "run_ok: true  return_type: nil",
               "mode: reference", "---PRINTS---"]
        out += ["PRINT: " + p for p in self.prints]
        out.append("---BEHAVIOR---")
        out += self.calls
        out.append("---RESOLVED---")
        out += self.resolved
        out.append("---OPCODES---")
        out += self.rows
        if self.code_rows:
            # The whole instruction array, the way the real harness dumps it
            # from inside the dispatch loop. Without this the round-trip test
            # can only ever measure coverage against the instructions that ran,
            # and a branch whose untaken side was never reached is invisible:
            # its instructions have no numbers in the trace, so nothing knows
            # they exist. That is the one thing this section makes testable.
            out.append("---CODE---")
            out += self.code_rows
        return "BEGIN_UNOBF_RESULT\n" + "\n".join(out) + "\nEND_UNOBF_RESULT"

    def dump_code(self, protos):
        """Every instruction of every function, as `pc:operands` rows.

        The slot one past the last instruction is included. A real
        interpreter's array carries its own terminator there and the run stops
        on it, so leaving it out would make the halt look like an instruction
        that ran without being in the program."""
        for code in protos:
            for pc, ins in enumerate(code):
                # The real harness dumps every field of the instruction row:
                # the instruction's own word first, then its operands. Writing
                # only the operands here made the fixture a different shape from
                # anything the engine sees in practice, and the pass that lines
                # the trace up against the array had nothing to match on.
                ops = [str(self.op(ins[0]))] + [str(o) for o in ins[1:]]
                self.code_rows.append("%d:%s" % (pc, ",".join(ops)))
            self.code_rows.append("%d:" % len(code))


class Proxy:
    """Stands in for a host object; every call through it is logged the way the
    real harness proxy logs one."""

    def __init__(self, em, ns):
        self.em, self.ns = em, ns

    def call(self, method, args):
        self.em.calls.append("%s:%s(%s)" % (
            self.ns, method, ", ".join(preview(a) for a in args)))
        return Proxy(self.em, "%s.%s" % (self.ns, method))


def preview(v):
    if isinstance(v, Proxy):
        return "table"
    if isinstance(v, str):
        return '"%s"' % (v[:60] + ".." if len(v) > 60 else v)
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "nil"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, dict):
        return "{}"
    return "table"


def _s(v):
    if isinstance(v, Proxy):
        return v.ns
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "nil"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def run(prog, seed=0, mach_every=2, dump_code=True):
    em = Emitter(seed)
    if dump_code:
        em.dump_code(prog.protos)
    for idx in sorted(prog.consts):
        v = prog.consts[idx]
        em.resolved.append(("S:%s" if isinstance(v, str) else "N:%s") % (v,))

    stack, glob = [], {}
    locals_stack = [{}]
    frames = []
    cur = 0
    pc, steps = 0, 0
    while 0 <= pc < len(prog.protos[cur]):
        local = locals_stack[-1]
        ins = prog.protos[cur][pc]
        name, operands = ins[0], list(ins[1:])
        em.emit(pc, name, operands, len(stack))
        steps += 1
        produced, nxt = None, pc + 1

        if name == "PUSHK":
            v = prog.consts[operands[0]]; stack.append(v); produced = v
        elif name == "GETENV":
            nm = stack.pop()
            v = glob.get(nm)
            if v is None:
                v = Proxy(em, nm); glob[nm] = v
            stack.append(v); produced = v
        elif name == "INDEX":
            k = stack.pop(); t = stack.pop()
            v = (t.call(k, []) if isinstance(t, Proxy)
                 else (t.get(k) if isinstance(t, dict) else None))
            stack.append(v); produced = v
        elif name == "SETINDEX":
            v = stack.pop(); k = stack.pop(); t = stack.pop()
            if isinstance(t, dict):
                t[k] = v
        elif name == "NEWTABLE":
            t = {}; stack.append(t); produced = t
        elif name == "GETLOCAL":
            v = local.get(operands[0]); stack.append(v); produced = v
        elif name == "SETLOCAL":
            local[operands[0]] = stack.pop()
        elif name in ("ADD", "SUB", "MUL", "LT", "CONCAT"):
            b = stack.pop(); a = stack.pop()
            v = {"ADD": lambda: (a or 0) + (b or 0),
                 "SUB": lambda: (a or 0) - (b or 0),
                 "MUL": lambda: (a or 0) * (b or 0),
                 "LT": lambda: (a or 0) < (b or 0),
                 "CONCAT": lambda: "%s%s" % (_s(a), _s(b))}[name]()
            stack.append(v); produced = v
        elif name == "CALL":
            n = operands[0]
            args = [stack.pop() for _ in range(n)][::-1]
            fn = stack.pop()
            if isinstance(fn, Proxy):
                v = fn.call("__call", args)
            else:
                em.prints.append(" ".join(_s(a) for a in args)); v = None
            stack.append(v); produced = v
        elif name == "SELFCALL":
            n = operands[0]
            args = [stack.pop() for _ in range(n)][::-1]
            k = stack.pop(); obj = stack.pop()
            v = obj.call(k, args) if isinstance(obj, Proxy) else None
            stack.append(v); produced = v
        elif name == "JMP":
            nxt = operands[0]
        elif name == "JMPIFNOT":
            if not stack.pop():
                nxt = operands[0]
        elif name == "CALLP":
            frames.append((cur, pc + 1))
            locals_stack.append({})
            cur = operands[0]
            nxt = 0
        elif name == "RETURN":
            v = stack.pop()
            if frames:
                cur, nxt = frames.pop()
                locals_stack.pop()
                stack.append(v)
                produced = v
            else:
                break
        elif name == "DECOY":
            pass
        else:
            raise ValueError("reference VM: unknown %s" % name)

        # The decryptor runs INSIDE the handler of the instruction that needed a
        # constant, so its records come before that instruction leaves its own
        # result pending - which is what a real interpreter's trace looks like,
        # and what the analysis has to read correctly.
        if name in _CONSTUSERS and steps % mach_every == 0:
            em.machinery(len(stack))
        if produced is not None:
            em.produce(produced)
        pc = nxt
        if steps > 40000:
            break
    em.emit(len(prog.protos[cur]), "HALT", [], len(stack))
    return em.text(), em


def asm(items):
    """Tiny assembler: items are instruction tuples or "label:" marker strings;
    a jump operand written as a label is resolved to its index."""
    labels, code = {}, []
    for it in items:
        if isinstance(it, str):
            labels[it] = len(code)
        else:
            code.append(list(it))
    for ins in code:
        for k, o in enumerate(ins):
            if isinstance(o, str) and k > 0:
                ins[k] = labels[o]
    return [tuple(i) for i in code]


# --- fixtures: ground truth for the round-trip test --------------------------

def fixture_calls():
    c = {1: "game", 2: "GetService", 3: "Players", 4: "print",
         5: "Workspace", 6: "Name", 7: "hello "}
    code = asm([
        ("PUSHK", 1), ("GETENV",), ("PUSHK", 2), ("PUSHK", 3), ("SELFCALL", 1),
        ("SETLOCAL", 0),
        ("DECOY",),
        ("PUSHK", 5), ("GETENV",), ("PUSHK", 6), ("INDEX",),
        ("SETLOCAL", 1),
        ("PUSHK", 4), ("GETENV",), ("PUSHK", 7), ("GETLOCAL", 1), ("CONCAT",),
        ("CALL", 1),
        ("PUSHK", 3), ("RETURN",),
    ])
    src = ('local v0 = game:GetService("Players")\n'
           'local v1 = Workspace.Name\n'
           'print("hello " .. v1)\n'
           'return "Players"\n')
    return Program(src, code, c)


def fixture_loop():
    c = {1: 0, 2: 1, 3: 5, 4: "print", 5: "total="}
    code = asm([
        ("PUSHK", 1), ("SETLOCAL", 0),
        ("PUSHK", 1), ("SETLOCAL", 1),
        "top",
        ("GETLOCAL", 1), ("PUSHK", 3), ("LT",), ("JMPIFNOT", "done"),
        ("GETLOCAL", 0), ("GETLOCAL", 1), ("ADD",), ("SETLOCAL", 0),
        ("GETLOCAL", 1), ("PUSHK", 2), ("ADD",), ("SETLOCAL", 1),
        ("JMP", "top"),
        "done",
        ("PUSHK", 4), ("GETENV",), ("PUSHK", 5), ("GETLOCAL", 0), ("CONCAT",),
        ("CALL", 1),
        ("PUSHK", 1), ("RETURN",),
    ])
    src = ('local acc = 0\n'
           'local i = 0\n'
           'while i < 5 do\n'
           '    acc = acc + i\n'
           '    i = i + 1\n'
           'end\n'
           'print("total=" .. acc)\n'
           'return 0\n')
    return Program(src, code, c)


def fixture_rich():
    """Exercises every operation many times, so each opcode has enough instances
    for its arity and its operation to be measured."""
    c = {1: 0, 2: 1, 3: 12, 4: 2, 5: "x", 6: "", 7: "count",
         8: "Service", 9: "report", 10: "print", 11: "done "}
    code = asm([
        ("PUSHK", 1), ("SETLOCAL", 0),
        ("PUSHK", 6), ("SETLOCAL", 1),
        ("NEWTABLE",), ("SETLOCAL", 2),
        ("PUSHK", 1), ("SETLOCAL", 3),
        "top",
        ("GETLOCAL", 3), ("PUSHK", 3), ("LT",), ("JMPIFNOT", "done"),
        ("GETLOCAL", 0), ("GETLOCAL", 3), ("PUSHK", 4), ("MUL",), ("ADD",),
        ("SETLOCAL", 0),
        ("GETLOCAL", 1), ("PUSHK", 5), ("CONCAT",), ("SETLOCAL", 1),
        ("GETLOCAL", 2), ("PUSHK", 7), ("GETLOCAL", 0), ("SETINDEX",),
        ("PUSHK", 8), ("GETENV",), ("PUSHK", 9), ("GETLOCAL", 0),
        ("SELFCALL", 1), ("SETLOCAL", 4),
        ("GETLOCAL", 3), ("PUSHK", 2), ("ADD",), ("SETLOCAL", 3),
        ("JMP", "top"),
        "done",
        ("PUSHK", 10), ("GETENV",), ("PUSHK", 11), ("GETLOCAL", 0),
        ("CONCAT",), ("CALL", 1),
        ("GETLOCAL", 0), ("RETURN",),
    ])
    src = ('local acc = 0\n'
           'local msg = ""\n'
           'local t = {}\n'
           'local i = 0\n'
           'while i < 12 do\n'
           '    acc = acc + i * 2\n'
           '    msg = msg .. "x"\n'
           '    t.count = acc\n'
           '    local v4 = Service:report(acc)\n'
           '    i = i + 1\n'
           'end\n'
           'print("done " .. acc)\n'
           'return acc\n')
    return Program(src, code, c)


def fixture_funcs():
    """Two helper functions called from several places. Each numbers its own
    instructions from zero, so their instruction numbers collide with the main
    function's and with each other's - which is what a trace of a real program
    looks like, and what the frame reconstruction has to undo."""
    c = {1: 2, 2: 3, 3: 10, 4: "Service", 5: "report", 6: 0, 7: 1}
    double = asm([
        ("GETLOCAL", 0), ("GETLOCAL", 0), ("ADD",), ("RETURN",),
    ])
    shout = asm([
        ("PUSHK", 4), ("GETENV",), ("PUSHK", 5), ("GETLOCAL", 0),
        ("SELFCALL", 1), ("RETURN",),
    ])
    main = asm([
        ("PUSHK", 1), ("SETLOCAL", 0),
        ("PUSHK", 6), ("SETLOCAL", 1),
        "top",
        ("GETLOCAL", 1), ("PUSHK", 2), ("LT",), ("JMPIFNOT", "done"),
        ("GETLOCAL", 0), ("SETLOCAL", 0),
        ("CALLP", 1), ("SETLOCAL", 2),
        ("CALLP", 2), ("SETLOCAL", 3),
        ("GETLOCAL", 1), ("PUSHK", 7), ("ADD",), ("SETLOCAL", 1),
        ("JMP", "top"),
        "done",
        ("GETLOCAL", 0), ("RETURN",),
    ])
    src = ('local function double(x) return x + x end\n'
           'local function shout(x) return Service:report(x) end\n'
           'local acc = 2\n'
           'local i = 0\n'
           'while i < 3 do\n'
           '    local a = double(acc)\n'
           '    local b = shout(acc)\n'
           '    i = i + 1\n'
           'end\n'
           'return acc\n')
    return Program(src, main, c, protos=[double, shout])


def fixture_branch():
    """A branch where one side never runs on this input, so the analyser must
    report the untaken side as unknown rather than delete it."""
    c = {1: 3, 2: 10, 3: "big", 4: "small", 5: "print", 6: 0}
    code = asm([
        ("PUSHK", 1), ("SETLOCAL", 0),
        ("GETLOCAL", 0), ("PUSHK", 2), ("LT",), ("JMPIFNOT", "else"),
        ("PUSHK", 4), ("SETLOCAL", 1),
        ("JMP", "done"),
        "else",
        ("PUSHK", 3), ("SETLOCAL", 1),
        "done",
        ("PUSHK", 5), ("GETENV",), ("GETLOCAL", 1), ("CALL", 1),
        ("PUSHK", 6), ("RETURN",),
    ])
    src = ('local n = 3\n'
           'local label\n'
           'if n < 10 then\n'
           '    label = "small"\n'
           'else\n'
           '    label = "big"\n'
           'end\n'
           'print(label)\n'
           'return 0\n')
    return Program(src, code, c)


FIXTURES = {"calls": fixture_calls, "loop": fixture_loop,
            "rich": fixture_rich, "branch": fixture_branch,
            "funcs": fixture_funcs}


if __name__ == "__main__":
    import sys
    which = sys.argv[1] if len(sys.argv) > 1 else "rich"
    print(run(FIXTURES[which]())[0])
