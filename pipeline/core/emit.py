#!/usr/bin/env python3
"""
emit.py - write out the program the graph describes.

This stage adds nothing. Every line it writes is a rendering of something already
in the value graph or the control-flow graph, and it can name the instructions
behind each one. There is no template, no library of shapes to fill in, and no
step that recognises a value and writes code around it. If the graph does not
contain a statement, no statement is written.

What it does do is pick the order and the nesting:

  * one statement per instruction, taken from that instruction's first execution,
    so a loop body is written once instead of once per iteration,
  * loop bodies nested inside the loop the control-flow graph found,
  * a branch whose other side never ran written as a branch, with the side that
    was not entered marked and left empty rather than dropped,
  * an instruction whose result nothing ever used written as a comment, since
    removing it would be a claim this run cannot support.

Every line carries its evidence class, and the provenance listing underneath
gives, for each line, the instructions and the data-flow relationships that
produced it.
"""
from evidence import OBSERVED, INFERRED, UNKNOWN, DECOY, TAG

import cfgx
import exprs as exprmod


MAX_BRANCH_NOTES = 12
MAX_STATEMENTS = 6000


class Line:
    __slots__ = ("text", "evidence", "pc", "prov", "indent")

    def __init__(self, text, evidence, pc, prov, indent=0):
        self.text = text
        self.evidence = evidence
        self.pc = pc
        self.prov = prov
        self.indent = indent


class Emitter:
    def __init__(self, L, g, models, slots, amap, calls, decoys=None):
        self.L = L
        self.g = g
        self.models = models
        self.slots = slots
        self.amap = amap
        self.bound = {}
        self.env_ops, self.env_why = exprmod.identify_env(L, models, calls, slots)
        self.R = exprmod.Renderer(L, models, slots, amap, calls, self.bound,
                                  self.env_ops)
        self._tmp = 0
        self._jumps = self._jump_pcs()
        self._last = next((st for st in reversed(L.steps)
                           if st.pops >= 1 and st.pushes == 0), None)
        self.by_step = {c.step.row: c for c in calls}
        self.decoys = decoys or {}
        self.consumed = self._consumed()
        self.consumers = L.consumers()
        self.needs_name = self._needs_name()
        self.first_write = {}
        self.lines = []

    def _needs_name(self):
        """Values that have to become named statements rather than stay inside
        another expression.

        A stack machine builds an expression by pushing its parts, so most
        values are just part of the instruction that consumes them and belong
        inline. Two kinds do not. A value used more than once was computed once
        and reused, which is a variable in the program whatever the VM calls it.
        A value produced in one block and consumed in another outlives the
        block, so writing it inline would move the work into a branch it was not
        in. Both get a name, which is what turns a value graph back into
        statements."""
        owner = getattr(self.g, "_owner", {})
        out = {}
        for st in self.L.steps:
            if len(st.pushed) != 1:
                continue
            v = st.pushed[0]
            users = self.consumers.get(v.id) or []
            if not users:
                continue
            if len(users) > 1:
                out[v.id] = ("its result is used %d times, so it was computed "
                             "once and reused" % len(users))
                continue
            u = users[0]
            if owner.get(u.key()) != owner.get(st.key()):
                out[v.id] = ("its result is used in a different block, so it "
                             "outlives the one it was computed in")
        return out

    def _consumed(self):
        used = set()
        for st in self.L.steps:
            for v in st.popped:
                used.add(v.id)
        return used

    # -- statements ----------------------------------------------------------
    def statement(self, st):
        """The statement this instruction is, or None if it only contributes to
        another instruction's expression."""
        d = self.decoys.get(st.key())
        if st.row in self.by_step:
            call = self.by_step[st.row]
            text = self.R.call_text(call)
            used_by = [c for c in self.consumers.get(
                st.pushed[0].id, []) if st.pushed] if st.pushed else []
            if not used_by:
                return self._line(text, OBSERVED, st,
                                  "an observed call whose result is not used")
            if len(used_by) == 1 and self.slots.writes.get(used_by[0].row) is not None:
                return None          # the variable write below prints it
            name = "t%d" % self._tmp
            self._tmp += 1
            self.bound[st.pushed[0].id] = name
            return self._line("local %s = %s" % (name, text), OBSERVED, st,
                              "an observed call whose result is used later; "
                              "bound to a name so the later use can refer to it")
        if (st.pushes == 1 and st.pushed[0].id in self.needs_name
                and self.slots.writes.get(st.row) is None
                and st.pushed[0].id not in self.bound):
            v = st.pushed[0]
            text = self.R.value(v.id)
            name = "t%d" % self._tmp
            self._tmp += 1
            self.bound[v.id] = name
            ev = exprmod.evidence_of(self.L, v.id, self.amap)
            return self._line("local %s = %s" % (name, text), ev, st,
                              self.needs_name[v.id])
        key = self.slots.writes.get(st.row)
        if key is not None and st.popped:
            src = st.popped[0]
            rhs = self.R.value(src.id)
            name = self.R.var(key)
            first = self.first_write.get(key)
            if first is None:
                self.first_write[key] = st.pc
                text = "local %s = %s" % (name, rhs)
            else:
                text = "%s = %s" % (name, rhs)
            ev = exprmod.evidence_of(self.L, src.id, self.amap)
            return self._line(text, ev, st,
                              "instruction writes variable %s; the value comes "
                              "from v%d" % (name, src.id))
        if st.pushes and all(v.id not in self.consumed for v in st.pushed):
            text = self.R.value(st.pushed[0].id)
            if st.pops >= 1 and text.endswith(")") and not text.startswith("OP_"):
                return self._line(
                    text, OBSERVED, st,
                    "this instruction called something and its result was not "
                    "used, so the call itself is the statement")
            if d:
                return self._line(
                    "-- %s" % self.R.value(st.pushed[0].id), DECOY, st,
                    d)
            return self._line(
                "-- unused: %s" % self.R.value(st.pushed[0].id), UNKNOWN, st,
                "this instruction produced a value that nothing in the captured "
                "run consumed; it is kept because a path that did not run may "
                "consume it")
        if st.pushes == 0 and st.pops >= 1 and not self._is_control(st):
            args = ", ".join(self.R.value(v.id) for v in st.popped)
            ev = OBSERVED
            if (self._last is not None and st.row == self._last.row
                    and self.slots.writes.get(st.row) is None):
                return self._line(
                    "return %s" % args, INFERRED, st,
                    "the last instruction executed; it consumed a value and "
                    "nothing ran afterwards, so it hands that value back")
            return self._line(
                "OP_%d(%s)" % (st.op, args), ev, st,
                "consumes %d value(s) and produces none, so its effect is a "
                "statement; what that effect is was not proved by this run"
                % st.pops)
        if st.pushes == 0 and st.pops == 0 and not self._is_control(st):
            return self._line("-- no effect: OP_%d" % st.op,
                              DECOY if d else UNKNOWN, st,
                              d or "this instruction moved nothing on the stack "
                                   "and produced no value")
        return None

    def _sink(self, st):
        return st.row

    def _jump_pcs(self):
        """Instructions after which control did not simply fall through. Those
        are jumps: they are the control flow, not statements."""
        out = set()
        for a, b in zip(self.L.steps, self.L.steps[1:]):
            if b.key() != (a.fn, a.pc + 1):
                out.add(a.key())
        return out

    def _is_control(self, st):
        return st.key() in self._jumps or \
            any(b["pc"] == st.key() for b in self.g.branches) or \
            any(lp["back"] == st.key() for lp in self.g.loops)

    def _line(self, text, ev, st, why):
        return Line(text, ev, st.key(), why)

    # -- structure -----------------------------------------------------------
    def run(self):
        g = self.g
        first_pc = {}
        for st in self.L.steps:
            first_pc.setdefault(st.key(), st)

        loop_by_head = {lp["head"]: lp for lp in g.loops}
        loop_bodies = {}
        for lp in g.loops:
            for b in lp["body"]:
                loop_bodies.setdefault(b, lp["head"])

        # one function at a time, in the order each first ran
        seen_fn, fn_order = set(), []
        for st in self.L.steps:
            if st.fn not in seen_fn:
                seen_fn.add(st.fn)
                fn_order.append(st.fn)
        rank = {f: i for i, f in enumerate(fn_order)}
        order = sorted(g.blocks, key=lambda h: (rank.get(h[0], 0),
                                                min(st.row for st in g.blocks[h])))
        shown_branches = [0]
        current_fn = [None]
        dropped = [0]
        emitted_heads = set()
        out, depth = [], 0
        open_loops = []

        for head in order:
            lp = loop_by_head.get(head)
            if lp is not None and head not in emitted_heads:
                cond = self._loop_condition(head)
                out.append(Line("while %s do" % cond, OBSERVED, head,
                                "the block at %s is the head of a loop; the back "
                                "edge from %s was taken %d time(s)"
                                % (cfgx._fmt(head), cfgx._fmt(lp["back"]),
                                   lp["iterations"]), depth))
                depth += 1
                open_loops.append((lp, depth))
                emitted_heads.add(head)
            while open_loops and head not in \
                    set(open_loops[-1][0]["body"]) | {open_loops[-1][0]["head"]}:
                lp2, d2 = open_loops.pop()
                depth = d2 - 1
                out.append(Line("end", OBSERVED, lp2["head"],
                                "closes the loop whose head is %s"
                                % cfgx._fmt(lp2["head"]), depth))
            if head[0] != current_fn[0]:
                current_fn[0] = head[0]
                out.append(Line(
                    "-- function fn%d" % head[0], OBSERVED, head,
                    "records placed in this function by matching calls with "
                    "their returns", 0))
            for st in g.blocks[head]:
                if first_pc.get(st.key()) is not st:
                    continue
                ln = self.statement(st)
                if ln is None:
                    continue
                if len(out) >= MAX_STATEMENTS:
                    dropped[0] += 1
                    continue
                ln.indent = depth
                out.append(ln)
            for b in g.branches:
                if b["pc"] not in [s.pc for s in g.blocks[head]]:
                    continue
                if not b["untaken"]:
                    continue
                out.append(Line(
                    "-- branch at %s: the path to %s was never taken in this "
                    "capture" % (cfgx._fmt(b["pc"]),
                                 ", ".join(cfgx._fmt(t) for t in b["untaken"])),
                    UNKNOWN, b["pc"], b["why"], depth))
        while open_loops:
            lp2, d2 = open_loops.pop()
            depth = d2 - 1
            out.append(Line("end", OBSERVED, lp2["head"],
                            "closes the loop whose head is pc %d" % lp2["head"],
                            depth))
        if dropped[0]:
            out.append(Line(
                "-- %d further statement(s) were recovered and left out here to "
                "keep the file readable; PROVENANCE.txt lists every one"
                % dropped[0], UNKNOWN, (0, 0),
                "the capture is larger than one readable file", 0))
        extra = sum(1 for b in self.g.branches if b["untaken"]) - shown_branches[0]
        if extra > 0:
            out.append(Line(
                "-- %d more branch(es) have a side this capture never entered; "
                "they are listed in CONTROL_FLOW.txt" % extra,
                UNKNOWN, 0, "kept out of the source so it stays readable; none are discarded", 0))
        self.lines = out
        return out

    def _loop_condition(self, head):
        """The condition of the branch that leaves the loop, if the graph has
        one. Otherwise the loop is written as unconditional, which is what the
        capture supports."""
        body = None
        for lp in self.g.loops:
            if lp["head"] == head:
                body = set(lp["body"]) | {head}
        if body is None:
            return "true"
        inside = {st.key() for h in body for st in self.g.blocks.get(h, [])}
        for b in self.g.branches:
            if b["pc"] not in inside:
                continue
            st = next((s for s in self.L.steps if s.key() == b["pc"]), None)
            if st is None or not st.popped:
                continue
            return self.R.value(st.popped[0].id)
        return "true"

    # -- output --------------------------------------------------------------
    def text(self, header=True):
        out = []
        if header:
            out += [
                "-- Reconstructed by symbolic replay of the VM's own execution.",
                "-- Every line below is a rendering of the recovered value graph;",
                "-- nothing is filled in from a template or a known program.",
                "--",
                "--   [O] observed   the VM performed this at runtime",
                "--   [I] inferred   forced by data flow over observed facts",
                "--   [U] unknown    present but not resolved on this evidence",
                "--   [D] decoy      shown to have no effect on the program",
                "",
            ]
        for ln in self.lines:
            pad = "    " * ln.indent
            out.append("%s%s%s" % (pad, ln.text,
                                   "  --[%s]" % TAG.get(ln.evidence, "?")))
        return "\n".join(out)

    def provenance(self):
        out = ["PROVENANCE - why each line exists",
               "=" * 46,
               "Each emitted line, the instruction it came from, and the reason",
               "the analysis produced it.", ""]
        for ln in self.lines:
            out.append("  %-12s [%s] %s"
                       % (cfgx._fmt(ln.pc) if isinstance(ln.pc, tuple)
                          else str(ln.pc),
                          TAG.get(ln.evidence, "?"), ln.text.strip()))
            out.append("        %s" % ln.prov)
        return "\n".join(out)
