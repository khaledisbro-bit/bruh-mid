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
import exprs           # noqa: E402
import frames          # noqa: E402
import noise           # noqa: E402
import opsem           # noqa: E402
import stackint        # noqa: E402
import tracefmt        # noqa: E402
import vmsrc           # noqa: E402
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
        self.cfg = cfgx.build(self.lift, self.slots)
        self.env_ops, self.env_why = exprs.identify_env(
            self.lift, self.models, self.calls, self.slots)
        self.verdicts = decoy.classify(
            self.lift, self.cfg, self.calls, self.slots, self.alias,
            self.env_ops)
        self.emitter = emit.Emitter(
            self.lift, self.cfg, self.models, self.slots, self.alias,
            self.calls, {pc: v.why for pc, v in self.verdicts.items()
                         if v.verdict == evidence.DECOY},
            self.env_rows, self.env_names)
        self.emitter.run()
        self.source = self.emitter.text()
        self.verification, self.consistent = verify.report(
            self.lift, self.models, self.verdicts)

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
             "unexplored branch targets  %d" % len(self.cfg.unexplored),
             "instructions explained     %d of %d (%.0f%%)"
             % (explained, total, 100 * cov),
             "verdicts                   real %d, unproven %d, decoy %d"
             % (counts.get(evidence.OBSERVED, 0),
                counts.get(evidence.UNKNOWN, 0),
                counts.get(evidence.DECOY, 0)),
             "value checks               %s"
             % ("all agreed with the VM" if self.consistent
                else "DISAGREEMENTS FOUND - see the verification report"),
             "",
             "What this is: the program that ran, rebuilt from the VM's own",
             "execution. What it is not: the original file. Text the compiler",
             "discarded - names, comments, formatting - is gone for good, and",
             "code that never ran is marked, not invented."]
        return "\n".join(L)

    def write(self, outdir):
        os.makedirs(outdir, exist_ok=True)
        files = {
            "SUMMARY.txt": self.summary() + "\n\n" + version.describe(),
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
                             self.tables.why,
            "CONTROL_FLOW.txt": cfgx.report(self.cfg, self.frames_ok),
            "DECOY.txt": decoy.report(self.verdicts, self.cfg),
            "VERIFICATION.txt": self.verification,
            "behaviour_check.lua": verify.behaviour_harness(self.source),
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
    for name in ("rich", "loop", "calls", "branch", "funcs"):
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
        if not a.consistent:
            wrong.append("value checks disagreed with the VM")
        if a.lift.divergences:
            wrong.append("%d stack desynchronisation(s)" % len(a.lift.divergences))
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
