"""Reading the instructions of functions that never ran.

The prototypes handed over by the interpreter hold their instructions masked.
The interpreter unmasks a block of them when the program counter enters it, and
the arithmetic it uses is in its own source:

    word   = the number in field 1 of the row
    Ro     = bxor(word, the prototype's own key) - (R*R + pc*845493 + 520175)
             mod 1000003,  where R = (pc*314961 + 587922) mod 1000003
    opcode = D[Ro]

- with D the table the interpreter is handed, which turns an unmasked number
into an opcode. A block whose descriptor carries extra key material is masked
further; this reads what the descriptors say rather than assuming, and a block
it cannot account for is left undecoded and counted.

Nothing here is taken on trust. Every instruction the run DID execute was
recorded with its unmasked number, so the same rows are decoded again from
their masked form and compared. The report says how many agreed. A decode that
cannot reproduce what was observed is not used on what was not.

D is learned the same way: from the pairs the run showed, each unmasked number
with the opcode it turned out to be. An instruction whose number was never seen
decodes to a number and no name, and is counted apart - it is not guessed at.
"""
import re
from collections import defaultdict


def _masks(pc):
    r = (pc * 314961 + 587922) % 1000003
    return (r * r + pc * 845493 + 520175) % 1000003


def unmask(word, key, pc):
    """One instruction word, as the interpreter unmasks it."""
    return (word ^ key) - _masks(pc)


class Program:
    """Every function the interpreter was handed, with its instructions."""

    def __init__(self):
        self.protos = {}        # pid -> {pc: {field: value}}
        self.keys = {}          # pid -> the prototype's own key
        self.decoded = {}       # pid -> {pc: (opcode or None, number, operands)}
        self.table = {}         # unmasked number -> opcode
        self.checked = 0
        self.agreed = 0
        self.unknown_word = 0
        self.total = 0

    def distinct(self):
        """The prototypes that are not copies of one another.

        The ladder runs the payload again per round, so the same function is
        handed over several times. Two with the same instructions are one.
        """
        seen, out = {}, []
        for pid in sorted(self.decoded):
            rows = self.decoded[pid]
            key = (len(rows), tuple(sorted(rows))[:8],
                   tuple(v[1] for _k, v in sorted(rows.items())[:16]))
            if key in seen:
                continue
            seen[key] = pid
            out.append(pid)
        return out


def learn(capture_text):
    """The table that turns an unmasked number into an opcode, from the run."""
    table = {}
    for m in re.finditer(r"^\d+;(\d+);[^;]*;[^;]*;[^;]*;.*?field1=(-?\d+)",
                         capture_text, re.M):
        table.setdefault(int(m.group(2)), int(m.group(1)))
    return table


def read(capture_text):
    """The prototypes and their masked instructions, out of a capture."""
    P = Program()
    for m in re.finditer(r"^p(\d+):#3=(-?\d+)$", capture_text, re.M):
        P.keys[int(m.group(1))] = int(m.group(2))
    for m in re.finditer(r"^p(\d+)@2:(\d+):(.*)$", capture_text, re.M):
        fields = {}
        for a, b in re.findall(r"(\d+)=(-?\d+)", m.group(3)):
            fields[int(a)] = int(b)
        if 1 in fields:
            P.protos.setdefault(int(m.group(1)), {})[int(m.group(2))] = fields
    P.table = learn(capture_text)
    return P


def decode(P):
    """Unmask every instruction, and name the ones whose number the run saw."""
    for pid, rows in P.protos.items():
        key = P.keys.get(pid)
        if key is None:
            continue
        out = {}
        for pc, fields in rows.items():
            number = unmask(fields[1], key, pc)
            op = P.table.get(number)
            operands = [fields[i] for i in sorted(fields) if i >= 2]
            out[pc] = (op, number, operands)
            P.total += 1
            if op is None:
                P.unknown_word += 1
        P.decoded[pid] = out
    return P


def verify(P, capture_text):
    """Decode the instructions the run executed, and compare.

    The run recorded each instruction it executed with the number the
    interpreter unmasked it to. Those same instructions are in the prototypes
    in masked form, so decoding them again is a check with an answer.
    """
    seen = set()
    for m in re.finditer(r"^\d+;(\d+);[^;]*;[^;]*;[^;]*;.*?field1=(-?\d+)",
                         capture_text, re.M):
        seen.add((int(m.group(2)), int(m.group(1))))
    by_number = {}
    for number, op in seen:
        by_number.setdefault(number, set()).add(op)
    for pid, rows in P.decoded.items():
        for pc, (op, number, _ops) in rows.items():
            if number in by_number:
                P.checked += 1
                if op in by_number[number]:
                    P.agreed += 1
    return P


def report(P):
    pids = P.distinct()
    named = sum(1 for rows in (P.decoded[p] for p in pids)
                for v in rows.values() if v[0] is not None)
    total = sum(len(P.decoded[p]) for p in pids)
    T = ["THE PROGRAM'S INSTRUCTIONS, INCLUDING WHAT NEVER RAN",
         "=" * 58,
         "The interpreter masks its instructions and unmasks a block when the",
         "program counter enters it. The arithmetic is in its own source, so",
         "the instructions of a function nothing called can be read the same",
         "way - without running it, and without the checks that stop it.",
         ""]
    if not pids:
        T += ["No prototype was handed over, so there is nothing to decode.",
              ""]
        return "\n".join(T)
    T += ["%d function(s), %d instruction(s) in all" % (len(pids), total),
          "%d of them decode to an operation this run also performed (%d%%)"
          % (named, (100 * named // max(1, total))),
          "%d carry a number the run never saw, so they keep the number and no"
          % (total - named),
          "  name - nothing is guessed from the number alone",
          ""]
    if P.checked:
        T += ["THE DECODE, CHECKED",
              "-" * 58,
              "The run recorded every instruction it executed with the number",
              "the interpreter unmasked it to. The same instructions, decoded",
              "again here from their masked form:",
              "  %d compared, %d agreed (%d%%)"
              % (P.checked, P.agreed, 100 * P.agreed // max(1, P.checked)),
              ""]
        if P.agreed < P.checked:
            T += ["  They do not all agree, so this decode is not used on what",
                  "  the run did not execute either.", ""]
    else:
        T += ["Nothing could be compared: the run executed none of these.", ""]
    T += ["PER FUNCTION", "-" * 58]
    for pid in pids:
        rows = P.decoded[pid]
        kn = sum(1 for v in rows.values() if v[0] is not None)
        ops = defaultdict(int)
        for v in rows.values():
            if v[0] is not None:
                ops[v[0]] += 1
        common = ", ".join("OP_%d x%d" % (o, n) for o, n in
                           sorted(ops.items(), key=lambda kv: -kv[1])[:6])
        T.append("  function %d: %d instruction(s), %d named" % (pid, len(rows), kn))
        if common:
            T.append("      most used: " + common)
    T.append("")
    return "\n".join(T)


def _selftest():
    # a capture with one executed instruction and one that never ran, both in
    # the prototype: the decode has to reproduce the first and read the second
    key, pc1, pc2 = 12345, 1, 2
    n1, n2 = 7696879, 4242424
    w1 = (n1 + _masks(pc1)) ^ key
    w2 = (n2 + _masks(pc2)) ^ key
    text = (
        "1;272;;0;nil;rowop=272|field1=%d\n" % n1 +
        "p1:#3=%d\n" % key +
        "p1@2:%d:1=%d 2=5\n" % (pc1, w1) +
        "p1@2:%d:1=%d\n" % (pc2, w2))
    P = decode(read(text))
    verify(P, text)
    probs = []
    rows = P.decoded.get(1) or {}
    if rows.get(pc1, (None,))[0] != 272:
        probs.append("the executed instruction did not decode back to its "
                     "opcode: %r" % (rows.get(pc1),))
    if rows.get(pc2, (0,))[0] is not None:
        probs.append("an instruction whose number the run never saw was given "
                     "a name")
    if rows.get(pc2, (0, 0))[1] != n2:
        probs.append("the unmasking is wrong: %r" % (rows.get(pc2),))
    if rows.get(pc1, (0, 0, []))[2] != [5]:
        probs.append("the operands were lost")
    if P.checked != 1 or P.agreed != 1:
        probs.append("the check counted %d/%d" % (P.agreed, P.checked))
    if not report(P).strip():
        probs.append("the report came out empty")
    for p in probs:
        print("  PROBLEM: " + p)
    print("protodecode selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()
