#!/usr/bin/env python3
"""
driver.py - run the whole analysis over one or more captures.

Each capture is analysed on its own, from scratch. Nothing measured in one
sample is carried into another: opcode numbering, variable slots, machinery
boundaries and operation meanings are all properties of the run they were
measured in, and reusing them across samples would be assuming the answer.

Where several captures of the SAME program are given, they are merged at the
level of facts rather than text. The obfuscator takes a different path each run,
so a later run can only ever add: an instruction explained in any run counts as
explained, and a branch target counts as unexplored only when no run took it.
A fact is never weakened by a run that did not reach it.

    python3 driver.py capture.txt [more.txt ...] -o out
    python3 driver.py --selftest
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import cfgx            # noqa: E402
import dataflow        # noqa: E402
import decoy           # noqa: E402
import actions         # noqa: E402
import antitamper      # noqa: E402
import branches        # noqa: E402
import disagree        # noqa: E402
import emit            # noqa: E402
import evidence        # noqa: E402
import exposure        # noqa: E402
import exprs           # noqa: E402
import frames          # noqa: E402
import dispatch        # noqa: E402
import induct          # noqa: E402
import metatab         # noqa: E402
import naming          # noqa: E402
import noise           # noqa: E402
import opsem           # noqa: E402
import plain           # noqa: E402
import probes         # noqa: E402
import protodecode     # noqa: E402
import protolift       # noqa: E402
import gate            # noqa: E402
import render          # noqa: E402
import story           # noqa: E402
import source          # noqa: E402
import sccp           # noqa: E402
import stackint        # noqa: E402
import staticcode      # noqa: E402
import tracefmt        # noqa: E402
import types_ as typecheck  # noqa: E402
import vmsrc           # noqa: E402
import webs            # noqa: E402
import verify          # noqa: E402
import version         # noqa: E402


def _protos_report(capture):
    """The program's own functions, as the interpreter was handed them.

    This is not what ran. It is what the program IS: every function the
    interpreter built a closure for, whether or not anything called it. A build
    that routes execution past its payload still hands the payload over here,
    which is the only way a one-run analysis sees the part it never reaches.
    """
    protos = getattr(capture, "protos", None) or {}
    T = ["THE PROGRAM'S OWN FUNCTIONS",
         "=" * 46,
         "Taken where the interpreter builds a closure, not where it runs one.",
         "A function nothing called is here on the same terms as one that ran.",
         ""]
    if not protos:
        T += ["No function was handed over in this capture. That happens when",
              "the interpreter's own source could not be prepared - the report",
              "says why where it was tried - or when this build hands its",
              "functions over some other way.", ""]
        return "\n".join(T)
    # the same function appears once per round of the ladder; group by shape
    shapes = {}
    for pid, fields in sorted(protos.items()):
        key = tuple(sorted((f, len(v)) for f, v in fields.items()))
        shapes.setdefault(key, []).append(pid)
    T.append("%d function(s) handed over, %d distinct"
             % (len(protos), len(shapes)))
    T.append("")
    for key, pids in sorted(shapes.items(), key=lambda kv: -max(
            n for _f, n in kv[0])):
        fields = protos[pids[0]]
        scalars = {f: v[0] for f, v in fields.items()
                   if f.startswith("#") and len(v) == 1}
        arrays = {f: len(v) for f, v in fields.items() if not f.startswith("#")}
        T.append("  function %s%s"
                 % (", ".join("#%d" % p for p in pids[:4]),
                    " and %d more" % (len(pids) - 4) if len(pids) > 4 else ""))
        if arrays:
            T.append("      arrays:  " + ", ".join(
                "field %s holds %d number(s)" % (f, n)
                for f, n in sorted(arrays.items())))
        if scalars:
            T.append("      numbers: " + ", ".join(
                "field %s = %s" % (f[1:], v)
                for f, v in sorted(scalars.items())))
        T.append("")
    T += ["What is NOT done with them yet: the instruction stream is encoded,",
          "and which field holds what is read from the interpreter rather than",
          "assumed. Decoding these into instructions is the next step, and it",
          "is what turns a function nothing called into source.", ""]
    return "\n".join(T)


class Analysis:
    """Everything one capture supports, and the reports that explain it."""

    def __init__(self, capture, vm_source=None):
        self.capture = capture
        self.vm_source = vm_source
        # Instruction numbers restart in every function, so records are placed
        # in the function they belong to before anything is measured. Without
        # this, code from unrelated functions shares an address.
        self.machinery, self.regions = noise.analyse(capture.rows)
        # The program's records read as a sequence once the interpreter's
        # bursts are out of the way: each one then reports the result and the
        # stack effect of the instruction before it, with the decryption that
        # instruction triggered already collapsed into it.
        self.program, self.bursts = noise.split(capture.rows, self.machinery)
        # Frames are recovered from the program's records, not the capture's:
        # the interpreter's helpers jump constantly and would drown the
        # program's own calls. Where instruction numbers already identify an
        # instruction, no frames are needed and none are invented.
        self.frames, self.frames_ok = frames.reconstruct(self.program)
        self.models = opsem.measure(self.program)
        self.lift = stackint.lift(self.program, self.program, self.models)
        self.named = opsem.identify(self.models, self.lift.instances())
        # Naming happens after the replay, so the operands that the newly named
        # operations prove could not have been nil are cleared now rather than
        # staying in the graph as a nil the program never had.
        self.impossible_nils = stackint.clear_impossible_nils(
            self.lift, self.models)
        # The interpreter states what its opcodes do; a short run cannot.
        self.vm, self.from_handlers, self.handler_why = (None, 0, {})
        self.relifted = False
        self.arity_corrected = []
        self.withdrawn_ops = {}
        self.unclaimed_values = 0
        if vm_source:
            # What the stack reading assumed before the interpreter's own
            # handlers were read. Kept so the reading can be redone if the
            # handlers disagree: an instruction read as taking two values and
            # returning one, which the handler shows only jumps, was lifted
            # into a call with arguments that do not exist.
            before = {op: (m.pops, m.pushes,
                           m.handler_pops, m.handler_pushes)
                      for op, m in self.models.items()}
            self.vm, self.from_handlers, self.handler_why = vmsrc.apply(
                self.models, vm_source, self.lift.steps)
            dropped, _checked = vmsrc.revoke(self.models, self.lift,
                                             self.handler_why)
            self.from_handlers -= dropped
            # Value algebra can only test a reading it can recompute. A reading
            # it cannot is still testable against the types the values had: an
            # index of nothing or a call of a number is impossible whatever the
            # program was doing, and the reading that produced it is wrong.
            # An operation the values make impossible is usually a wrong
            # reading, and sometimes a metatable. Ask which before withdrawing.
            self.meta = metatab.find(self.models, self.lift)
            # Which opcodes the environment was watching when it answered a
            # call. Taken from the capture rather than from the matched calls,
            # because matching happens later and this check runs now: each
            # recorded call carries the capture row it happened at, and the row
            # carries the opcode that was executing.
            by_row = {r["i"]: r["opcode"] for r in capture.rows}
            observed_call_ops = set()
            for rec in (capture.calls or []):
                at = rec.get("row")
                if at is None:
                    continue
                op = by_row.get(at)
                if op is None:
                    lower = [i for i in by_row if i <= at]
                    op = by_row[max(lower)] if lower else None
                if op is not None:
                    observed_call_ops.add(op)
            bad, examined, why = typecheck.check(
                self.models, self.lift, metatab.rescued(self.meta),
                observed_call_ops)
            self.type_withdrawn, self.type_examined = bad, examined
            self.handler_why.update(why)
            self.from_handlers -= bad
            # The first reading had to guess how many values each instruction
            # took and left, because a trace shows the stack moving and not
            # why. The handlers say it outright. Where the two disagree the
            # handler wins, and everything built on the guess has to be built
            # again: the values an instruction consumed, which expression each
            # one came from, and the statements written from them. Nothing is
            # re-measured here, only re-read with the arities the interpreter
            # itself states.
            changed = sorted(op for op, was in before.items()
                             if op in self.models
                             and was != (self.models[op].pops,
                                         self.models[op].pushes,
                                         self.models[op].handler_pops,
                                         self.models[op].handler_pushes))
            self.arity_corrected = changed
            if changed:
                self.lift = stackint.lift(self.program, self.program,
                                          self.models)
                self.named = opsem.identify(self.models,
                                            self.lift.instances())
                self.impossible_nils += stackint.clear_impossible_nils(
                    self.lift, self.models)
                self.relifted = True
                # Now that both the arities and the values are read with the
                # handlers' own numbers, every named operation is recomputed
                # and compared with what the machine reported. A reading that
                # contradicts the machine is withdrawn here, before anything is
                # rendered from it: an unresolved instruction in the output is
                # better than an expression that does not hold.
                self.differences = disagree.find(self.lift, self.models,
                                                 capture.rows)
                self.withdrawn_ops = disagree.withdraw(self.models,
                                                       self.differences)
                self.unclaimed_values = disagree.unproven_values(
                    self.lift, self.differences)
                self.from_handlers -= len(self.withdrawn_ops)
                # The metatable question was asked against the old reading.
                # It is asked again below, against this one.
                if hasattr(self, "meta"):
                    del self.meta
        # The interpreter's handlers say which opcodes touch a variable. That
        # is checked the same way a guessed pair is, and only used if it holds.
        self.slots, self.slot_hits, self.slot_checks = (None, 0, 0)
        if vm_source and self.vm is not None and self.vm.ok:
            rd, wr = vmsrc.variables(vm_source, self.vm, self.models,
                                     self.lift.steps)
            self.slots, self.slot_hits, self.slot_checks = \
                dataflow.slots_from_source(self.lift, rd, wr)
        if self.slots is None or not self.slots.active():
            self.slots = dataflow.infer_slots(self.lift)
        # Slots the program reads but this capture never writes: the interpreter
        # keeps them boxed, and naming them shows one object used repeatedly
        # instead of a different unnamed opcode each time.
        self.env_rows, self.env_names, self.env_why = {}, {}, ""
        if vm_source and self.vm is not None and self.vm.ok:
            rd, _wr = vmsrc.variables(vm_source, self.vm, self.models,
                                      self.lift.steps)
            self.env_rows, self.env_names, self.env_why, _a, _t = \
                dataflow.env_slots(self.lift, rd)
        self.alias = dataflow.alias(self.lift, self.slots)
        self.tables = dataflow.infer_tables(self.lift)
        self.calls, self.unmatched = exprs.match_calls(
            self.lift, capture.calls)
        # Metatables, where the interpreter's source was not read: the same
        # test still applies, it just has fewer named operations to apply to.
        if not hasattr(self, "meta"):
            self.meta = metatab.find(self.models, self.lift)
        # One call instruction is not one target. A site that reached several
        # is dispatch, and writing one name for it describes a program that
        # does not exist.
        self.sites = dispatch.find(self.lift, self.calls, self.models)
        # The instruction array, where the capture carries it, is what lets a
        # branch have a side that was never entered. The side that did not run
        # has no numbers in the trace, so without the array nothing knows those
        # instructions exist and the branch looks unconditional.
        #
        # It is only safe to use when instruction numbers already identify an
        # instruction. The array numbers each function from zero, so if two
        # functions share numbers, feeding it in would invent fall-through
        # targets in whichever function happens to own that number - phantom
        # branches, which is the failure this project has already been through
        # once. When numbers collide, the array is left for the coverage
        # report, which does not need to place it in a function.
        universe = None
        if self.capture.code and self.frames.get("unique_addresses"):
            fns = {st.fn for st in self.lift.steps}
            if len(fns) == 1:
                fn = next(iter(fns))
                # in the trace's own numbering: the array counts its rows the
                # way the interpreter stores them, which is not obliged to be
                # the way the program counter reports them. Handing the graph
                # the raw indices offers it fall-through targets that are one
                # instruction out - phantom branches, from arithmetic.
                code, _k, _n, _w = staticcode.aligned(self.capture.code,
                                                      self.program)
                universe = {(fn, pc) for pc in code}
                universe |= {st.key() for st in self.lift.steps}
        self.cfg = cfgx.build(self.lift, self.slots, universe)
        # One slot is not one variable. A compiler reuses a slot, so the reads
        # and writes of a slot are grouped by what can reach what, and each
        # group is named on its own. Without this, two unrelated values written
        # to one slot read as one variable being reassigned.
        self.webs = webs.build(self.cfg, self.lift, self.slots)
        # Facts that hold on EVERY path into a point, not just on the path this
        # run took. This is what separates a condition that was decided before
        # it was tested from one that really depends on something.
        self.facts = sccp.propagate(self.cfg, self.lift, self.slots)
        self.predicates = sccp.decide_branches(
            self.facts, self.cfg, self.lift, self.slots)
        # A loop written as "go round 4 times" states a property of the input,
        # not of the program. Where a variable advanced by a fixed amount and
        # something compared it against a value that held still, the loop has a
        # bound the capture actually showed, and that is what gets written.
        self.counters = induct.counters(self.lift, self.slots, self.webs,
                                        self.cfg, self.models)
        # Calls made over and over with the same arguments whose answer nothing
        # ever took. Reported as that fact and nothing more - no name is
        # matched against a table, and nothing is removed on this evidence.
        self.probes = probes.find(self.lift, self.calls, capture.calls)
        # a different question from the stored slots above, and a different
        # answer: keep them apart, or the explanation of one overwrites the
        # explanation of the other and the report prints a dictionary
        self.env_ops, self.env_op_why = exprs.identify_env(
            self.lift, self.models, self.calls, self.slots)
        # Whether this build keeps the program's values outside the stack. It
        # decides whether "it moved nothing on the stack" can be a proof of no
        # effect, and it is read off what the analysis established rather than
        # assumed either way.
        has_registers = bool(self.slots is not None and self.slots.active())
        self.verdicts = decoy.classify(
            self.lift, self.cfg, self.calls, self.slots, self.alias,
            self.env_ops, self.models, has_registers)
        # A branch whose condition is one constant on every path that reaches
        # it can only ever go one way. That is recorded against the branch and
        # against the target that was never entered. It does not delete
        # anything: a programmer's own always-true test reads the same way as
        # an obfuscator's, and this pass cannot tell which it is looking at.
        self.opaque = decoy.apply_predicates(self.verdicts, self.predicates,
                                             self.cfg)
        # Why each untaken side was not taken, in four groups. The first of
        # them - a condition the environment decided - is the one the stand-in
        # makes, not the program, and it has to be separated from the rest or
        # the report claims a property of the program that belongs to this
        # machine.
        # Which operands a branch handler reads its condition from, where the
        # handler names them. Without this every untaken side of a build that
        # tests registers reads as unresolved.
        cond_ops = {}
        if vm_source and self.vm is not None and self.vm.ok:
            try:
                hs = vmsrc.handlers(vm_source, self.vm)
                for op, bodies in hs.items():
                    for body in bodies:
                        reads, sense = vmsrc.condition_reads(body, self.vm)
                        if reads:
                            cond_ops[op] = (reads, sense)
                            break
            except Exception:
                cond_ops = {}
        self.branch_why = branches.classify(
            self.cfg, self.lift, self.predicates,
            call_rows=[r.get("row") for r in (capture.calls or [])],
            fiction_row=getattr(capture, "fiction_at_row", None),
            models=self.models, cond_ops=cond_ops)
        # Which instructions worked on a value the stand-in answered for. The
        # same walk the branch classifier uses: back through the value graph to
        # the row where the environment answered, so the mark is carried by
        # evidence and not by a guess about which names look like host objects.
        self.standin_pcs = branches.standin_instructions(
            self.lift, [r.get("row") for r in (capture.calls or [])],
            self.calls)
        self.emitter = emit.Emitter(
            self.lift, self.cfg, self.models, self.slots, self.alias,
            self.calls, {pc: v.why for pc, v in self.verdicts.items()
                         if v.verdict == evidence.DECOY},
            self.env_rows, self.env_names, False, self.unmatched, self.webs,
            self.counters, self.standin_pcs)
        self.emitter.run()
        self.source = self.emitter.text()
        # a second rendering, this one made to load and run, for the behaviour
        # comparison in the executor
        self.runner = emit.Emitter(
            self.lift, self.cfg, self.models, self.slots, self.alias,
            self.calls, {pc: v.why for pc, v in self.verdicts.items()
                         if v.verdict == evidence.DECOY},
            self.env_rows, self.env_names, runnable=True, webs=self.webs,
            counters=self.counters)
        self.runner.run()
        self.runnable = self.runner.runnable_text()
        # The same program with everything this analysis cannot stand behind
        # taken out: the instructions shown to have no effect, and the ones
        # whose value nothing on this path consumed. Removing them is a claim,
        # and the claim is tested by running both and comparing their calls.
        self.cleaned = self.runner.runnable_text(only_proven=True)
        # Names derived from the values the variables hold. Applied to BOTH
        # renderings with the same substitution, so the readable one and the one
        # the behaviour comparison actually executes stay the same program - a
        # rename that landed on only one of them would make the comparison
        # measure the rename.
        self.source, self.names = naming.rename(self.source)
        self.runnable, _ = naming.rename(self.runnable)
        self.cleaned, _ = naming.rename(self.cleaned)
        # The same run said another way: what the program did to its host, in
        # order, as Luau that runs. The full rendering is the machine; this is
        # the effects, which for a script of this kind is what a reader wants.
        self.actions_text, self.actions_n = actions.build(capture.calls)
        # Where the reading and the machine differ, traced back through the
        # graph. This runs before the verification summary so the summary can
        # say how many of the differences are about the program and how many
        # are about what the capture could compare.
        if not hasattr(self, "differences"):
            self.differences = disagree.find(self.lift, self.models,
                                             capture.rows)
        self.verification, self.consistent = verify.report(
            self.lift, self.models, self.verdicts, capture.calls, self.calls,
            (getattr(self, "type_withdrawn", 0),
             getattr(self, "type_examined", 0)))
        self.decode_program()
        (_f, self.in_step, self.unaccounted, self.accounted,
         self.accounted_share) = verify.fidelity(
            capture.calls, self.calls)

    def decode_program(self):
        """The instructions of every function the interpreter was handed.

        This is the part a run cannot reach: a function the checks route past
        is still handed over, and its instructions are masked the same way as
        the ones that ran - so the same arithmetic reads them.
        """
        self.program_decoded = None
        self.program_text = ""
        self.flow_text = ""
        self.vocab_text = ""
        self.gate_text = ""
        self.story_text = ""
        self.source_text = ""
        self.listing_text = ""
        self.split_text = ""
        raw = getattr(self.capture, "raw", "") or ""
        if "---PROTOS---" not in raw:
            self.program_text = protodecode.report(protodecode.Program())
            return
        P = protodecode.decode(protodecode.read(raw))
        protodecode.verify(P, raw)
        self.program_decoded = P
        self.program_text = protodecode.report(P)
        self.flow_text = self._decode_flow(raw, P)
        # THE GATE. The most useful thing in a capture of this family: the key
        # the payload is decrypted with, what the decryption produced, every
        # slice in the table rather than only the ones the run asked for, and
        # what the digests it carries are digests OF. All of it was already in
        # the capture and none of it was in any report.
        try:
            g = gate.read(self.capture)
            self.gate_text = gate.report(g)
            # AND THE SAME THING IN WORDS. The listing is accurate and
            # unreadable; a reader wants to know what the script does.
            self.story_text = story.report(self.capture, g)
            # AND AS LUA. The transcript is ordered, so the layer that runs can
            # be written back out as source a person can read.
            self.source_text = source.write(self.capture)
        except Exception as exc:
            self.gate_text = ("The gate could not be read (%s: %s).\n"
                              % (exc.__class__.__name__, exc))

    def _decode_flow(self, raw, P):
        """Where each of those instructions goes, and what the entry reaches.

        Instructions in file order are not the program: control flow here is
        flattened and every block ends by jumping to a number it computes. The
        arithmetic that computes it is in the interpreter's own source, so the
        jumps resolve without running any of them - and then the one question
        worth asking of a protected build has an answer: which instructions can
        be reached from the entry at all.
        """
        vm = getattr(self, "vm", None)
        src = getattr(self, "vm_source", "") or ""
        if not (vm and getattr(vm, "ok", False) and src):
            return ("Where each instruction goes could not be worked out: the "
                    "interpreter's own source is not in hand, and the jump "
                    "arithmetic is in it.\n")
        try:
            jumpers = protolift.jump_opcodes(src, vm)
            consts = protolift.const_operands(src, vm)
            fns = protolift.read(raw)
            flow = protolift.fallthrough(raw, jumpers, fns)
            dist = [p for p in P.distinct() if p in fns]
            dec = {p: P.decoded[p] for p in dist}
            for pid in dist:
                protolift.walk(fns[pid], dec[pid], jumpers,
                               protolift.pick_jump_field(fns[pid]), flow)
            ck, ag, unk, fell = protolift.verify(fns, raw, jumpers)
            self.program_flow = (fns, dec, jumpers, consts)
            self.vocab_text = protolift.vocabulary(
                {p: fns[p] for p in dist}, dec)
            # THE PROGRAM AS TEXT, both parts. The names come from the
            # interpreter's own handlers, so an operation is what the handler
            # does rather than what its number suggests.
            names = {}
            for op, m in (self.models or {}).items():
                nm = getattr(m, "operation", None)
                if nm:
                    names[op] = nm
            # BY COUNTER AND OPCODE, not by counter. Every function starts at
            # 1, so a counter on its own marks the same instruction in all of
            # them: it reported three thousand executed instructions out of
            # three thousand, from a trace with a fraction of that in it.
            ran = set()
            for rec in (getattr(self.capture, "rows", None) or []):
                if not isinstance(rec, dict):
                    continue
                pc, op = rec.get("pc"), rec.get("opcode")
                if isinstance(pc, int) and isinstance(op, int):
                    ran.add((pc, op))
            these = {p: fns[p] for p in dist}
            self.listing_text = render.listing(these, dec, jumpers, consts,
                                               names, ran)
            self.split_text = render.split(these, dec, jumpers, consts,
                                           names, ran)
            return protolift.report({p: fns[p] for p in dist}, dec, jumpers,
                                    consts, flow, ck, ag, unk, fell)
        except Exception as exc:
            return ("Where each instruction goes could not be worked out (%s: "
                    "%s).\n" % (exc.__class__.__name__, exc))

    def _harness_age_lines(self):
        """Which harness wrote this capture, said before anything is read from it.

        A report that does not say this invites the reader - me included - to
        treat an old capture as evidence about the current code.
        """
        note = tracefmt.which_harness(self.capture, version.VERSION)
        if not note:
            return []
        return ["WHICH HARNESS WROTE THIS", "  " + note, ""]

    def _early_stop_lines(self):
        """The warning that the rows below are not a whole program.

        Two different captures need it and only one used to get it. A capture
        whose traced run died says so in its headline. A capture whose UNTRACED
        retry then finished says run_ok: true in its headline - while every
        instruction row in it still came from the attempt that died. Keying this
        off the headline alone would drop the warning from exactly the capture
        that needs it most.
        """
        cap = self.capture
        err = getattr(cap, "run_error", None)
        from_failed = getattr(cap, "rows_from_failed_run", False)
        if not err and not from_failed:
            return []
        if not err:
            att = [a for a in (getattr(cap, "attempts", None) or [])
                   if a["instructions"] > 0 and not a["ok"]]
            err = (att[0]["error"] if att and att[0]["error"]
                   else "the run that produced these instructions raised")
        L = ["THE SCRIPT STOPPED EARLY",
             "  %s" % err,
             "  Everything below describes the %d instruction(s) that ran "
             "before" % len(cap.rows),
             "  that, which is not the program.",
             ""]
        if from_failed and getattr(cap, "run_error", None) is None:
            L[4:4] = ["  A later attempt in the same capture DID finish, "
                      "without the trace hook.",
                      "  It logged no instructions, so it does not extend the "
                      "rows below."]
        note = tracefmt.stopped_under_the_trace(cap)
        if note:
            L += ["  " + note, ""]
        # Whether the interpreter stopped the run on purpose, and what it was
        # holding when it did. Both come from the harness's own watches, so this
        # says a cause where the report used to say a symptom.
        for fn in (tracefmt.the_program_ended_itself,
                   tracefmt.what_the_interpreter_had,
                   tracefmt.the_standin_answered):
            text = fn(cap)
            if text:
                L += ["  " + x for x in text.split("\n")] + [""]
        # Where the run happened, before anything is read from it.
        for ln in tracefmt.taken_against_a_standin(cap):
            L += ["  " + ln, ""]
        # What the instruction arrays did, and what the environment did not have.
        # The report used to stop at "the program, or the environment" and then
        # say nothing about either, while the capture carried the answer.
        for ln in tracefmt.what_the_arrays_did(cap):
            L += ["  " + ln, ""]
        # Whether the instructions grouped under one opcode really are one. This
        # belongs BEFORE anything measured per opcode is read, because every
        # number below inherits that grouping.
        # Whether these instructions are the ones that ran, or the subset that
        # missed every handler. This goes first: it decides how to read every
        # number that follows.
        filt = tracefmt.trace_was_filtered(cap)
        if filt:
            L += ["  " + x for x in filt] + [""]
        doubt = tracefmt.opcode_grouping_doubt(cap)
        if doubt:
            L += ["  " + x for x in doubt] + [""]
        env = tracefmt.env_did_not_have(cap)
        if env:
            L += ["  " + x for x in env] + [""]
        return L

    def _retry_records_lines(self):
        """What the second run recorded, said rather than folded in.

        The retry runs the same payload again, so its calls land in the same
        behaviour log. They are kept out of the call comparison, because
        counting one run's records against another's reconstruction twice is not
        a fidelity measurement. But they are the records of the run that
        FINISHED, which makes them the better account of what the program does,
        and dropping them silently would be worse than either.
        """
        later = getattr(self.capture, "calls_after_retry", None) or []
        if not later:
            return []
        # "what the run that finished did" was printed for a capture where no
        # round finished. The later rounds are worth reporting either way, but
        # only the ones that happened may be described.
        rounds = getattr(self.capture, "attempts", None) or []
        finished = [r for r in rounds if r["ok"]]
        L = ["A LATER ROUND RECORDED MORE",
             "  The harness ran the payload again with one of its own edits "
             "removed.",
             "  That round made %d call(s) of its own. They are not counted "
             "against the" % len(later),
             "  reconstruction below, which describes the instructions from the "
             "round that",
             "  logged them%s:"
             % (" - but they are what the round that finished did"
                if finished else
                ", and no round of this capture finished")]
        for c in later[:40]:
            L.append("    %s" % c["raw"])
        if len(later) > 40:
            L.append("    ... %d more" % (len(later) - 40))
        L.append("")
        return L

    def summary(self):
        cov, explained, total = verify.coverage(self.lift, self.verdicts)
        named = sum(1 for m in self.models.values() if m.operation)
        arity = sum(1 for m in self.models.values() if m.pops is not None)
        counts = {}
        for v in self.verdicts.values():
            counts[v.verdict] = counts.get(v.verdict, 0) + 1
        L = ["SUMMARY - %s" % self.capture.name,
             "=" * 46,
             "produced by %s" % version.banner(),
             "",
             ] + self._harness_age_lines() + self._early_stop_lines() + [
             ] + self._retry_records_lines() + [
             "captured instructions      %d" % len(self.capture.rows),
             "interpreter machinery      %d record(s) folded away"
             % (len(self.capture.rows) - len(self.program)),
             "program instructions       %d" % len(self.program),
             "distinct opcodes           %d, arity measured for %d, operation "
             "known for %d (%d read from the interpreter's handlers)"
             % (len(self.models), arity, named, self.from_handlers),
             ] + ([
             "arities corrected          %d opcode(s) the handlers read "
             "differently from the stack; the values and the code were read "
             "again with the handlers' numbers"
             % len(self.arity_corrected),
             ] if self.relifted else []) + ([
             "readings withdrawn         %d opcode(s) whose named operation "
             "recomputed to something the machine did not report; the opcode "
             "keeps its number and nothing is written for it"
             % len(self.withdrawn_ops),
             ] if self.withdrawn_ops else []) + ([
             "values left unclaimed      %d value(s) where the machine "
             "reported something this operation cannot produce, so it was "
             "another instruction's value" % self.unclaimed_values,
             ] if self.unclaimed_values else []) + [
             "values recovered           %d (%d consumed from outside the "
             "capture)" % (len(self.lift.values), self.lift.externals),
             "stack desynchronisations   %d" % len(self.lift.divergences),
             "stored slots named         %s"
             % (len(self.env_names) if self.env_names else "none"),
             "variables                  %s"
             % (len(set(list(self.slots.reads.values()) +
                        list(self.slots.writes.values())))
                if self.slots.active() else "not established"),
             "functions / addressing     %s"
             % ("instruction numbers are already unique; no frames needed"
                if self.frames.get("unique_addresses") else
                (("%d recovered" % len(self.frames["functions"]))
                 if self.frames_ok
                 else "not established (numbers may be shared between functions)")),
             "basic blocks / loops       %d / %d%s"
             % (len(self.cfg.blocks), len(self.cfg.loops),
                "" if self.frames_ok else
                "  (unreliable: instruction numbers may collide)"),
             "calls matched to code      %d of %d recorded"
             % (len(self.calls), len(self.calls) + len(self.unmatched)),
             "traced-run exposure        %s"
             % ((lambda e, c: "%d of %d checks exposed" % (e, c) if c else
                 "not measured; this capture has no probe section")(
                     *exposure.assess(
                         getattr(self.capture, "probe", {}))[:2])),
             "metamethod dispatches      %s"
             % (("%d site(s)" % len(self.meta)) if self.meta else "none seen"),
             "call sites                 %s"
             % ((lambda d, n: "%d, of which %d reached more than one target"
                 % (n, d))(sum(1 for s in self.sites.values() if s.dynamic()),
                           len(self.sites)) if self.sites else "none"),
             "repeated, answer unused    %s"
             % (("%d group(s), %d call(s) in all"
                 % (len(self.probes), sum(p.count for p in self.probes)))
                if self.probes else "none"),
             "counters recovered         %s"
             % (("%d, of which %d gave a proved loop bound"
                 % (len(self.counters),
                    sum(1 for c in self.counters.values()
                        if c.header() is not None)))
                if self.counters else "none"),
             "behaviour accounted for    %d of %d action(s) (%.0f%%)"
             % (getattr(self, "accounted", 0),
                getattr(self, "accounted", 0) + self.unaccounted,
                100 * getattr(self, "accounted_share", 0.0)),
             "behaviour in order          longest unbroken agreement %d "
             "action(s); %d not accounted for"
             % (self.in_step, self.unaccounted),
             "variables after grouping   %s"
             % (("%d over %d slot(s); %d slot(s) held more than one"
                 % (len(self.webs.webs),
                    len(set(w.slot for w in self.webs.webs.values())),
                    len(self.webs.split)))
                if self.webs.active() else "not established"),
             "unexplored branch targets  %d (%d of them fed by a value that "
             "never varied)" % (len(self.cfg.unexplored), self.opaque),
             "program instructions known %s"
             % ((lambda t, c: "%d in the array; this run reached %d (%.0f%%)"
                 % (t, c, 100.0 * c / max(t, 1)) if t else
                 "the capture did not carry the instruction array, so every "
                 "figure here is a share of the run, not of the program")(
                     *staticcode.coverage(self.capture.code,
                                          self.program))),
             ] + ([
             "the whole program          %d instruction(s) in %d function(s), "
             "%d%% of them an operation this run also performed - the "
             "functions it never entered included"
             % (sum(len(self.program_decoded.decoded[p])
                    for p in self.program_decoded.distinct()),
                len(self.program_decoded.distinct()),
                100 * sum(1 for p in self.program_decoded.distinct()
                          for v in self.program_decoded.decoded[p].values()
                          if v[0] is not None)
                // max(1, sum(len(self.program_decoded.decoded[p])
                              for p in self.program_decoded.distinct()))),
             ] if getattr(self, "program_decoded", None) else []) + [
             "instructions explained     %d of %d (%.0f%%)"
             % (explained, total, 100 * cov),
             "verdicts                   real %d, unproven %d, decoy %d"
             % (counts.get(evidence.OBSERVED, 0),
                counts.get(evidence.UNKNOWN, 0),
                counts.get(evidence.DECOY, 0)),
             "runnable rendering         %s"
             % ((lambda n: "%d statement(s)" % n if n else
                 "EMPTY - nothing rendered as a statement, so there is "
                 "nothing to run or compare")(
                     len(verify.statement_lines(self.runnable)))),
             "value checks               %s"
             % ("none - nothing in this capture could be recomputed, so this "
                "says nothing" if self.consistent is None
                else "all agreed with the VM" if self.consistent
                else "DISAGREEMENTS FOUND - see the verification report"),
             "",
             "What this is: the program that ran, rebuilt from the VM's own",
             "execution. What it is not: the original file. Text the compiler",
             "discarded - names, comments, formatting - is gone for good, and",
             "code that never ran is marked, not invented."]
        return "\n".join(L)

    def _counter_names(self):
        """The name the output gives each counter, so the report and the code
        call the same variable the same thing."""
        out = {}
        for wid, c in self.counters.items():
            row = c.rows[0] if c.rows else None
            key = (self.slots.writes.get(row) if row is not None else None)
            if key is not None:
                out[wid] = self.emitter.R.var(key, row)
        return out

    def write(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        files = {
            "SUMMARY.txt": self.summary() + "\n\n" + version.describe(),
            "WHAT_IT_DOES.txt": plain.build(
                self.capture, self.lift, self.emitter.R, self.calls,
                self.unmatched, self.models, self.verdicts, self.slots,
                self.env_names, self.webs, self.facts),
            "RECONSTRUCTED.lua": self.source,
            "NAMES.txt": naming.report(getattr(self, "names", [])),
            "PROVENANCE.txt": self.emitter.provenance(),
            "FUNCTIONS.txt": frames.report(self.frames),
            "MACHINERY.txt": noise.report(self.capture.rows),
            "OPCODES.txt": opsem.report(self.models) + "\n\n" +
                           vmsrc.report(self.vm, self.from_handlers,
                                        len(self.models), self.handler_why)
                           if self.vm else opsem.report(self.models),
            "VALUES.txt": stackint.report(self.lift, self.models),
            "VARIABLES.txt": dataflow.report(self.lift, self.slots) +
                             ("\n\nSTORED SLOTS\n" + "-" * 46 + "\n  " +
                              self.env_why if self.env_why else "") +
                             "\n\nCONTAINERS\n" + "-" * 46 + "\n  " +
                             self.tables.why +
                             "\n\n" + webs.report(self.webs),
            "CONTROL_FLOW.txt": cfgx.report(self.cfg, self.frames_ok) +
                               "\n\n" + sccp.report(self.facts, self.slots),
            "VARIABLE_GROUPS.txt": webs.report(self.webs) + "\n\n" +
                                   induct.report(self.counters,
                                                 self._counter_names()),
            # The program's records, not the capture's. The interpreter's own
            # machinery runs at numbers that are not in the program's array and
            # never could be, so counting it here reports a mismatch that is
            # not one.
            "PROGRAM_SIZE.txt": staticcode.report(
                self.capture.code, self.program, self.cfg),
            "EXPOSURE.txt": exposure.report(
                getattr(self.capture, "probe", {}),
                _tri(self.capture.headers.get("hooks_hidden"))),
            "METATABLES.txt": metatab.report(self.meta),
            "CALL_SITES.txt": dispatch.report(self.sites),
            "REPEATED_CALLS.txt": probes.report(
                self.probes, len(self.calls) + len(self.unmatched)),
            "DECOY.txt": decoy.report(self.verdicts, self.cfg) + "\n\n" +
                         decoy.readable(self.verdicts, self.lift,
                                        self.emitter.R, self.calls, self.models),
            "VERIFICATION.txt": self.verification,
            "BRANCHES.txt": branches.report(self.branch_why, self.cfg),
            "FUNCTIONS_CAPTURED.txt": _protos_report(self.capture),
            "ALL_INSTRUCTIONS.txt": self.program_text,
            "WHERE_IT_GOES.txt": getattr(self, "flow_text", ""),
            "WHAT_IT_SAYS.txt": getattr(self, "vocab_text", ""),
            "THE_GATE.txt": getattr(self, "gate_text", ""),
            "READ_THIS_FIRST.txt": getattr(self, "story_text", ""),
            "LAYER_ONE_AS_LUA.lua": getattr(self, "source_text", ""),
            "PROGRAM_LISTING.txt": getattr(self, "listing_text", ""),
            "THE_TWO_PARTS.txt": getattr(self, "split_text", ""),
            "HOST_QUESTIONS.txt": antitamper.report(self.capture.calls),
            "DISAGREEMENTS.txt": disagree.report(
                self.lift, self.models, self.differences, self.capture.rows),
            "behaviour_check.lua": verify.behaviour_harness(self.runnable),
            "RECONSTRUCTED_runnable.lua": self.runnable,
            "RECONSTRUCTED_clean.lua": self.cleaned,
            "ACTIONS.lua": self.actions_text,
            "behaviour_check_actions.lua": verify.behaviour_harness(
                self.actions_text),
            "behaviour_check_clean.lua": verify.behaviour_harness(self.cleaned),
        }
        for name, body in files.items():
            with open(os.path.join(outdir, name), "w", encoding="utf-8") as f:
                f.write(body if body.endswith("\n") else body + "\n")
        return sorted(files)


def _tri(v):
    """A header's true/false, or None when the capture does not say. An absent
    answer is not a false one."""
    if v is None:
        return None
    t = str(v).strip().lower()
    if t.startswith("true"):
        return True
    if t.startswith("false"):
        return False
    return None


def merge_summary(analyses):
    """What several runs of the same program add up to.

    Counted in instructions, not in records: a run that goes round a loop more
    times covers no new code, so records would flatter it. What matters is which
    distinct instructions any run explained, and which branch targets no run
    entered."""
    explained, seen, unexplored, taken = set(), set(), {}, set()
    per_run = []
    for a in analyses:
        mine_ok, mine_all = set(), set()
        for pc, v in a.verdicts.items():
            mine_all.add(pc)
            if v.verdict == evidence.OBSERVED:
                mine_ok.add(pc)
        explained |= mine_ok
        seen |= mine_all
        per_run.append((a.capture.name, len(mine_ok), len(mine_all),
                        len(a.capture.rows)))
        for b in a.cfg.branches:
            for t in b["taken"]:
                taken.add((b["pc"], t))
            for t in b["untaken"]:
                unexplored[(b["pc"], t)] = unexplored.get((b["pc"], t), 0) + 1
    still = sorted(k for k in unexplored if k not in taken)
    new_any = len(explained) > max((p[1] for p in per_run), default=0)
    L = ["ACROSS %d RUN(S)" % len(analyses),
         "=" * 46,
         "The obfuscator takes a different path each run, so runs can only add.",
         "An instruction explained in any run counts as explained; a branch",
         "target counts as unexplored only when no run took it.", "",
         "distinct instructions explained by at least one run: %d of %d seen"
         % (len(explained), len(seen)), ""]
    for name, ok, allp, rows in per_run:
        L.append("  %-28s %4d of %4d instruction(s)   %6d record(s)"
                 % (name, ok, allp, rows))
    L.append("")
    if not new_any and len(analyses) > 1:
        L.append("No run explained an instruction the others did not, so these")
        L.append("captures cover the same path. Extra runs only add when they go")
        L.append("somewhere new; if they were taken from the same output, or the")
        L.append("script takes the same branch every time, merging them changes")
        L.append("nothing.")
        L.append("")
    if still:
        L.append("branch targets no run has entered (%d):" % len(still))
        for pc, t in still[:40]:
            L.append("  %s -> %s" % (cfgx._fmt(pc), cfgx._fmt(t)))
        L.append("")
        L.append("Driving those paths in another capture is what would resolve")
        L.append("them. They are not missing from the program; they are missing")
        L.append("from the evidence.")
    else:
        L.append("every branch target seen in these captures was entered by some")
        L.append("run.")
    return "\n".join(L)


def _no_claims_from_nothing():
    """No report may assert a finding when it was given nothing to work with.

    This is the shape of error that a verifier cannot catch and a fuzzer will
    never trip: the code does not crash, it states something confidently that
    it has no grounds for, and a false pass reads exactly like a real one. It
    was found twice - the behaviour comparison calling an empty pair a match,
    and the verification verdict calling zero checks consistent - so every
    report is now built from a capture with nothing in it and read for the
    words that assert a finding."""
    import re
    import tempfile
    capture = tracefmt.Capture(
        "BEGIN_UNOBF_RESULT\nrun_ok: true\n---OPCODES---\nEND_UNOBF_RESULT",
        "nothing")
    a = Analysis(capture)
    out = tempfile.mkdtemp()
    written = a.write(out)
    claim = re.compile(
        r"\b(every \w+ matches|all agreed|does what the program|"
        r"verdict: consistent|is verified\b|confirmed|proven correct|"
        r"no disagreement\b)", re.I)
    safe = re.compile(
        r"nothing was compared|nothing was checked|no evidence|"
        r"not a check that passed|not a verdict of consistent|says nothing",
        re.I)
    bad = []
    for name in written:
        if not name.endswith(".txt"):
            continue
        body = open(os.path.join(out, name), encoding="utf-8").read()
        for ln in body.splitlines():
            if claim.search(ln) and not safe.search(ln):
                bad.append("%s: %s" % (name, ln.strip()[:70]))
    assert not bad, "reports claim a finding from an empty capture:\n  " + \
        "\n  ".join(bad)
    # and the flag the app shows must say "nothing was checked", not "clean"
    assert a.consistent is None, ("the value-check flag reads %r on a capture "
                                  "with nothing in it" % (a.consistent,))
    print("no-claims-from-nothing ok")


def selftest():
    """Round-trip the engine against programs whose source is known.

    The reference VM compiles a known program, randomises its opcode numbering,
    hides its constants behind a resolver and buries it in machinery. The engine
    then gets only the capture. What it rebuilds is compared with the program
    that produced it."""
    import refvm
    ok = True
    print("SELF-TEST - reconstructing programs whose source is known")
    print("=" * 62)
    for name in ("rich", "loop", "calls", "branch", "funcs",
                 "nested", "reuse", "down", "dyn"):
        prog = refvm.FIXTURES[name]()
        text, em = refvm.run(prog)
        a = Analysis(tracefmt.Capture(text, name))
        truth = {v: k for k, v in em.opnum.items()}
        wrong = []
        for op, m in a.models.items():
            t = truth.get(op, "")
            if t.startswith("MACH") or t == "HALT" or m.pops is None:
                continue
            if t in refvm.CONTEXTUAL:
                continue
            want = refvm.ISA.get(t)
            if want is None:
                continue
            if isinstance(want[0], str):
                if m.pushes != 1:
                    wrong.append("%s arity" % t)
            elif (m.pops, m.pushes) != want:
                wrong.append("%s arity %d->%d, expected %d->%d"
                             % (t, m.pops, m.pushes, want[0], want[1]))
        for op, m in a.models.items():
            if m.operation and truth.get(op) != m.operation:
                wrong.append("OP named %s but it is %s"
                             % (m.operation, truth.get(op)))
        # the decoy sits in the program's own function, so compare inside it
        main_fn = a.lift.steps[0].fn if a.lift.steps else 0
        truth_decoys = {i for i, ins in enumerate(prog.code) if ins[0] == "DECOY"}
        found = {pc for (fn, pc), v in a.verdicts.items()
                 if v.verdict == evidence.DECOY and fn == main_fn
                 and pc < len(prog.code)}
        missed = truth_decoys - found
        false = found - truth_decoys
        if missed:
            wrong.append("missed decoy at pc %s" % sorted(missed))
        if false:
            wrong.append("called real code a decoy at pc %s" % sorted(false))
        # Three states, not two. False is a real disagreement and a failure.
        # None means no named operation could be recomputed from this capture,
        # which is not a failure - and not a pass either. This assertion read
        # None as a disagreement, having previously read it as agreement,
        # because the flag itself only had two values.
        if a.consistent is False:
            wrong.append("value checks disagreed with the VM")
        # The runnable rendering is handed to an executor, so it has to load.
        # An output that cannot compile wastes a round of someone's time and
        # proves nothing, so it is checked here whenever a parser is available.
        try:
            import luaparser.ast as lua_ast
        except ImportError:
            lua_ast = None
        if lua_ast is not None:
            # `what`, not `name`: this used to reuse the fixture's own loop
            # variable, so every result was printed under the name of the last
            # thing parsed here instead of the fixture that produced it, and a
            # check that asked which fixture it was looking at got the wrong
            # answer.
            for what, text in (("the runnable reconstruction", a.runnable),
                               ("the behaviour check",
                                verify.behaviour_harness(a.runnable))):
                try:
                    lua_ast.parse(text)
                except Exception as e:
                    wrong.append("%s is not valid Lua: %s"
                                 % (what, str(e)[:120]))
        # The array and the trace need not count the same way. Shift the
        # trace and the measured offset must follow it, or every figure taken
        # against the array is silently out by that much.
        import staticcode as _sc2
        for _shift in (1, -1):
            _rows = [dict(_r, pc=_r["pc"] + _shift) for _r in a.capture.rows]
            _k, _n, _ = _sc2.offset(a.capture.code, _rows)
            if _k != _shift:
                wrong.append("a trace shifted by %+d was measured as %+d"
                             % (_shift, _k))
        # Each of the four below exists to break one stage, and the answer is
        # known. A stage that crashes is caught elsewhere; these catch a stage
        # that runs and is wrong.
        if name == "nested":
            if len({lp["head"] for lp in a.cfg.loops}) < 2:
                wrong.append("two nested loops came back as %d loop head(s)"
                             % len({lp["head"] for lp in a.cfg.loops}))
            _body = [l for l in a.source.splitlines()
                     if l.strip() and not l.strip().startswith("--")]
            if _body and max(len(l) - len(l.lstrip()) for l in _body) < 8:
                wrong.append("the inner loop was not nested in the output")
        if name == "reuse" and a.webs.active():
            _on0 = [w for w in a.webs.webs.values()
                    if str(w.slot).endswith("0)")]
            if len(_on0) != 2:
                wrong.append("a slot holding two unrelated values came back as "
                             "%d variable(s)" % len(_on0))
        if name == "down":
            _cs = list(a.counters.values())
            if len(_cs) != 1 or _cs[0].step != -2 or _cs[0].start != 10:
                wrong.append("the counter 10,8,6,... was read as %s"
                             % [(c.start, c.step) for c in _cs])
        if name == "dyn":
            _t = {t for s2 in a.sites.values() for t in s2.targets}
            # the two real callees, and nothing the interpreter was holding
            if not {"print", "warn"} <= _t:
                wrong.append("the two callees came back as %s" % sorted(_t)[:4])
            _junk = [t for t in _t if t.isdigit() and len(t) > 8]
            if _junk:
                wrong.append("interpreter bookkeeping reported as a call "
                             "target: %s" % _junk[:3])
        # Run the reconstruction, for real, in Lua. Everything above reasons
        # ABOUT the output; this is the only check that makes it happen. It
        # found a loader missing outside Lua 5.1, an environment that attached
        # through a pcall and failed silently, a reconstruction that called a
        # string, and one that could not terminate - none of which a parser,
        # a fuzzer or any amount of reading would have shown.
        _ran, _out = verify.execute(verify.behaviour_harness(a.runnable))
        if _ran is False:
            wrong.append("the reconstruction does not run: %s" % _out)
        elif _ran is True:
            _p = verify.parse_block(_out)
            if _p["ok"] is not True:
                wrong.append("the reconstruction ran but did not finish: %s"
                             % (_p["error"] or "no reason given"))
        if not verify.statement_lines(a.runnable):
            wrong.append("the runnable rendering has no statements, so there "
                         "is nothing to run or compare")
        if a.lift.divergences:
            wrong.append("%d stack desynchronisation(s)" % len(a.lift.divergences))

        # The instruction array is ground truth here: the fixture VM dumps the
        # program it compiled, so every number the trace shows must be in it,
        # and anything in it that the trace does not show is code that really
        # did not run. Both directions are checked, because each one caught a
        # bug: machinery counted as program, and a halt slot left out of the
        # array.
        import staticcode as _sc
        ran = {r["pc"] for r in a.program}
        stray = sorted(ran - set(a.capture.code))
        if stray:
            wrong.append("ran at %s, which the instruction array does not have"
                         % stray[:5])
        never = sorted(set(a.capture.code) - ran)
        expect_dead = name in ("branch",)
        if expect_dead and not never:
            wrong.append("every instruction ran, but this fixture has a side "
                         "that cannot run on its input")
        if not expect_dead and never:
            wrong.append("%d instruction(s) never ran (%s), but this fixture "
                         "has no unreachable code" % (len(never), never[:5]))
        status = "PASS" if not wrong else "FAIL"
        ok = ok and not wrong
        print("\n[%s] %s" % (status, name))
        for w in wrong:
            print("       %s" % w)
        print("  ---- original ----")
        for ln in prog.source.rstrip().splitlines():
            print("  | " + ln)
        print("  ---- rebuilt from the capture alone ----")
        for ln in a.source.splitlines():
            if ln.startswith("--") or not ln.strip():
                continue
            print("  | " + ln)
    # the two passes that reason about paths rather than about the one path
    # this run took are checked on graphs small enough to verify by hand
    import dispatch as _dispatch
    import verify as _verify
    import exposure as _exposure
    import metatab as _metatab
    import induct as _induct
    import probes as _probes
    import sccp as _sccp
    import webs as _webs
    print()
    _sccp._selftest()
    _webs._selftest()
    _induct._selftest()
    _probes._selftest()
    _exposure._selftest()
    _metatab._selftest()
    _dispatch._selftest()
    import actions as _ac
    if _ac._selftest():
        ok = False
    import protodecode as _pd
    if _pd._selftest():
        ok = False
    import lua_tokens as _lt
    if _lt._selftest():
        ok = False
    import protohook as _ph
    if _ph._selftest():
        ok = False
    import antitamper as _at
    if _at._selftest():
        ok = False
    import branches as _br
    if _br._selftest():
        ok = False
    import disagree as _dis
    if _dis._selftest():
        ok = False
    _verify._selftest()
    import naming as _nm
    if _nm._selftest():
        ok = False
    # The desktop app's own wiring: a button with no handler, a handler with no
    # button, a channel the preload offers and main.js does not answer. All three
    # are invisible in review and none of them needs the app to be launched.
    import apptest as _app
    if _app.selftest():
        ok = False
    # The offline runner: what it reads out of a run, and what it refuses to
    # call a success. It needs no luau binary to check any of that.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import localvm as _lv
    if _lv._selftest():
        ok = False
    # The harness's own decision - one run or two - tested against the shipped
    # text of universal.lua rather than a description of it.
    import tracefmt as _tf
    tprobs = _tf._selftest()
    if tprobs:
        ok = False
    import harnesstest as _ht
    hprobs, hran = _ht.selftest()
    print("harness decision      : %d case(s), %d problem(s)%s"
          % (len(_ht.CASES), len(hprobs), "" if hran else "  [NOT RUN]"))
    for hp in hprobs:
        print("  - %s" % hp)
    if hprobs and hran:
        ok = False
    _no_claims_from_nothing()
    print("\n%s" % ("all self-tests passed" if ok else "SELF-TEST FAILURES"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("captures", nargs="*")
    ap.add_argument("-o", "--out", default="out")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--vm-source",
                    help="the interpreter's own source (the inner chunk the "
                         "harness writes out), so opcode meanings can be read "
                         "from its handlers")
    ap.add_argument("--one-run", action="store_true",
                    help="the files are pieces of a single run, not separate "
                         "runs; fold them together first")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.captures:
        ap.error("give at least one capture file, or --selftest")
    analyses = []
    vm_src = None
    if a.vm_source and os.path.isfile(a.vm_source):
        with open(a.vm_source, encoding="latin1") as f:
            vm_src = f.read()
    for cap in tracefmt.load(a.captures, one_run=a.one_run):
        an = Analysis(cap, vm_src)
        sub = os.path.join(a.out, os.path.splitext(cap.name)[0])
        names = an.write(sub)
        analyses.append(an)
        print(an.summary())
        print("\nwritten to %s: %s\n" % (sub, ", ".join(names)))
    if len(analyses) > 1:
        body = merge_summary(analyses)
        os.makedirs(a.out, exist_ok=True)
        with open(os.path.join(a.out, "ACROSS_RUNS.txt"), "w") as f:
            f.write(body + "\n")
        print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
