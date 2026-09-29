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
import emit            # noqa: E402
import evidence        # noqa: E402
import exposure        # noqa: E402
import exprs           # noqa: E402
import frames          # noqa: E402
import dispatch        # noqa: E402
import induct          # noqa: E402
import metatab         # noqa: E402
import noise           # noqa: E402
import opsem           # noqa: E402
import plain           # noqa: E402
import probes         # noqa: E402
import sccp           # noqa: E402
import stackint        # noqa: E402
import staticcode      # noqa: E402
import tracefmt        # noqa: E402
import types_ as typecheck  # noqa: E402
import vmsrc           # noqa: E402
import webs            # noqa: E402
import verify          # noqa: E402
import version         # noqa: E402


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
        # The interpreter states what its opcodes do; a short run cannot.
        self.vm, self.from_handlers, self.handler_why = (None, 0, {})
        if vm_source:
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
            bad, examined, why = typecheck.check(
                self.models, self.lift, metatab.rescued(self.meta))
            self.type_withdrawn, self.type_examined = bad, examined
            self.handler_why.update(why)
            self.from_handlers -= bad
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
        self.verdicts = decoy.classify(
            self.lift, self.cfg, self.calls, self.slots, self.alias,
            self.env_ops)
        # A branch whose condition is one constant on every path that reaches
        # it can only ever go one way. That is recorded against the branch and
        # against the target that was never entered. It does not delete
        # anything: a programmer's own always-true test reads the same way as
        # an obfuscator's, and this pass cannot tell which it is looking at.
        self.opaque = decoy.apply_predicates(self.verdicts, self.predicates,
                                             self.cfg)
        self.emitter = emit.Emitter(
            self.lift, self.cfg, self.models, self.slots, self.alias,
            self.calls, {pc: v.why for pc, v in self.verdicts.items()
                         if v.verdict == evidence.DECOY},
            self.env_rows, self.env_names, False, self.unmatched, self.webs,
            self.counters)
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
        self.verification, self.consistent = verify.report(
            self.lift, self.models, self.verdicts, capture.calls, self.calls,
            (getattr(self, "type_withdrawn", 0),
             getattr(self, "type_examined", 0)))
        _f, self.in_step, self.unaccounted = verify.fidelity(
            capture.calls, self.calls)

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
             ] + ([
             "THE SCRIPT STOPPED EARLY",
             "  %s" % self.capture.run_error,
             "  Everything below describes the %d instruction(s) that ran "
             "before" % len(self.capture.rows),
             "  that, which is not the program.",
             "",
             ] if getattr(self.capture, "run_error", None) else []) + [
             "captured instructions      %d" % len(self.capture.rows),
             "interpreter machinery      %d record(s) folded away"
             % (len(self.capture.rows) - len(self.program)),
             "program instructions       %d" % len(self.program),
             "distinct opcodes           %d, arity measured for %d, operation "
             "known for %d (%d read from the interpreter's handlers)"
             % (len(self.models), arity, named, self.from_handlers),
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
             "behaviour                  longest unbroken agreement %d "
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
                getattr(self.capture, "probe", {})),
            "METATABLES.txt": metatab.report(self.meta),
            "CALL_SITES.txt": dispatch.report(self.sites),
            "REPEATED_CALLS.txt": probes.report(
                self.probes, len(self.calls) + len(self.unmatched)),
            "DECOY.txt": decoy.report(self.verdicts, self.cfg) + "\n\n" +
                         decoy.readable(self.verdicts, self.lift,
                                        self.emitter.R, self.calls, self.models),
            "VERIFICATION.txt": self.verification,
            "behaviour_check.lua": verify.behaviour_harness(self.runnable),
            "RECONSTRUCTED_runnable.lua": self.runnable,
        }
        for name, body in files.items():
            with open(os.path.join(outdir, name), "w", encoding="utf-8") as f:
                f.write(body if body.endswith("\n") else body + "\n")
        return sorted(files)


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
    _verify._selftest()
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
