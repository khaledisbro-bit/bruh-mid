#!/usr/bin/env python3
"""
evidence.py - the evidence model every recovered fact carries.

Nothing in this pipeline is allowed to exist without a reason. A value, a
statement or a block is created only by a rule that can name the instructions
and the data-flow relationships that forced it. That reason travels with the
fact as a Provenance record, and the fact's confidence is one of four classes:

  OBSERVED  the VM did this at runtime. We saw the instruction execute, or we
            saw the value on its stack / in a proxied call.
  INFERRED  not directly seen, but forced by data flow over observed facts
            (a def-use edge, a constant that propagated, an arity that the
            measured stack effect fixes).
  UNKNOWN   present in the program but not resolved on the evidence we have -
            an unexecuted branch, an opcode whose effect never stabilised, a
            value whose producer is outside the trace. Kept, never deleted:
            one execution path is not the program.
  STANDIN   observed, but against a stand-in environment rather than a real
            host. The instruction ran and the value was on the stack; what fed
            it was this tool's answer for a host object it had to stand in for.
            So it is evidence about the program under THIS environment, and not
            yet evidence about what the program does on a real client.
  DECOY     anti-analysis material, and we can say which signals made it so.

A fact may hold several candidate readings. It stays multi-candidate until the
evidence picks one; it is never collapsed just to look tidy.
"""
from dataclasses import dataclass, field


OBSERVED = "OBSERVED"
STANDIN = "STANDIN"
INFERRED = "INFERRED"
UNKNOWN = "UNKNOWN"
DECOY = "DECOY"

_RANK = {OBSERVED: 4, STANDIN: 3, INFERRED: 2, UNKNOWN: 1, DECOY: 0}

TAG = {OBSERVED: "O", STANDIN: "S", INFERRED: "I", UNKNOWN: "U",
       DECOY: "D"}


def strongest(*classes):
    """Merge evidence classes from several runs/derivations: the best wins.
    A fact OBSERVED on any path is OBSERVED; DECOY only survives alone."""
    real = [c for c in classes if c]
    if not real:
        return UNKNOWN
    return max(real, key=lambda c: _RANK.get(c, 0))


@dataclass
class Provenance:
    """Why a fact exists. `rule` names the analysis that produced it, `because`
    is one human sentence, and the rest pins it to concrete evidence."""
    rule: str
    because: str
    steps: tuple = ()          # trace step indices that caused it
    pcs: tuple = ()            # VM program counters of those steps
    opcodes: tuple = ()        # opcode numbers involved
    inputs: tuple = ()         # ids of the facts this one derives from
    records: tuple = ()        # raw evidence lines (behaviour log, constants)

    def cite(self):
        bits = []
        if self.pcs:
            pcs = list(self.pcs)
            bits.append("pc=" + ",".join(str(p) for p in pcs[:4]) +
                        ("+%d" % (len(pcs) - 4) if len(pcs) > 4 else ""))
        if self.opcodes:
            ops = sorted(set(self.opcodes))
            bits.append("op=" + ",".join("OP_%d" % o for o in ops[:4]) +
                        ("+%d" % (len(ops) - 4) if len(ops) > 4 else ""))
        if self.steps:
            st = list(self.steps)
            bits.append("step=" + ",".join(str(s) for s in st[:3]) +
                        ("+%d" % (len(st) - 3) if len(st) > 3 else ""))
        if self.inputs:
            bits.append("from=" + ",".join(str(i) for i in self.inputs[:4]))
        return "%s: %s%s" % (self.rule, self.because,
                             ("  [" + "; ".join(bits) + "]") if bits else "")


@dataclass
class Fact:
    """A recovered thing (value, statement, block) with its evidence."""
    kind: str
    evidence: str = UNKNOWN
    prov: list = field(default_factory=list)
    candidates: list = field(default_factory=list)   # rival readings, kept

    def note(self, rule, because, **kw):
        self.prov.append(Provenance(rule, because, **kw))
        return self

    def add_candidate(self, text, evidence, why):
        for c in self.candidates:
            if c[0] == text:
                return self
        self.candidates.append((text, evidence, why))
        return self

    def tag(self):
        return TAG.get(self.evidence, "?")

    def why(self):
        return [p.cite() for p in self.prov]
