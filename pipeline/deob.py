#!/usr/bin/env python3
"""
deob.py - one-command driver. Put the obfuscated file in, it does the rest.

    python3 deob.py obf.lua

Stages, run in order, each automatic except the one executor step:
  1. DETECT  - identify the obfuscator family and per-build knobs.
  2. STATIC  - unwrap Layer 1, dump inner source/data, VM structure, classify.
  3. HARNESS - generate a ready-to-paste executor harness with the obfuscated
               source EMBEDDED (no readfile, no folder hassle).
  4. AUDIT   - once you paste the executor result back, verify and write the
               final source.

Typical flow:
    python3 deob.py obf.lua                 # stages 1-3, prints what to run
    # run out/harness.lua in your executor, save its output as result.txt
    python3 deob.py obf.lua --trace result.txt   # stage 4: verify + finalize

Flags:
    --detect         only identify (stage 1), no files written
    -o DIR           output directory (default: out)
    --trace FILE     the executor result block; runs the audit and finalizes
"""
import argparse, json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import unobf  # noqa: E402
import ai      # noqa: E402


def safe_long_bracket(content):
    """Pick a Lua long-bracket level [==[ ... ]==] that cannot collide with the
    content (level = one more '=' than the longest ]=*] run inside)."""
    longest = 0
    for m in re.finditer(r"\](=*)\]", content):
        longest = max(longest, len(m.group(1)))
    for m in re.finditer(r"\](=*)$", content):
        longest = max(longest, len(m.group(1)))
    eq = "=" * (longest + 1)
    return "[" + eq + "[", "]" + eq + "]"


def detect(src, log):
    # robust: any failure downgrades to universal mode instead of crashing
    try:
        inner_src, inner_data = unobf.unwrap_layer1(src, log)
    except Exception as e:
        log["layer1_error"] = str(e)
        inner_src, inner_data = None, None
    if inner_src is None:
        return None, None, "unknown-family"
    try:
        unobf.analyze_inner(inner_src.decode("latin1"), log)
    except Exception as e:
        log["analyze_error"] = str(e)
        return None, None, "unknown-family"
    return inner_src, inner_data, "base85+Zstd Luau VM"


def make_harness(src, outdir, template="unobf.lua", safe=False):
    """Embed the obfuscated source into the given harness template (no readfile).
    The FULL source is embedded verbatim - never truncated. safe=True disables
    the opcode-dispatch trace so the run finishes without tripping the VM's
    self-integrity check (constants + behavior only)."""
    tmpl = open(os.path.join(HERE, template), encoding="utf-8").read()
    op, cl = safe_long_bracket(src)
    embedded = "local SOURCE\nSOURCE = " + op + "\n" + src + "\n" + cl
    tmpl, n = re.subn(r"local SOURCE\ndo\n.*?\nend", lambda _m: embedded,
                      tmpl, count=1, flags=re.S)
    if n != 1:
        raise RuntimeError("could not embed SOURCE into harness template")
    if safe:
        tmpl = tmpl.replace("local TRACE_OPCODES = true",
                            "local TRACE_OPCODES = false", 1)
    # prove the whole obfuscated file went in (guards against silent truncation)
    if src not in tmpl:
        raise RuntimeError("embedded harness does not contain the full source")
    path = os.path.join(outdir, "harness.lua")
    open(path, "w", encoding="utf-8").write(tmpl)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--out", default="out")
    ap.add_argument("--detect", action="store_true")
    ap.add_argument("--trace", nargs="+",
                    help="one or more executor result files; extra runs are merged")
    ap.add_argument("--candidate", help="optional candidate source for the audit")
    ap.add_argument("--safe", action="store_true",
                    help="also emit a resolver-only harness that never trips the "
                         "VM integrity check (constants + behavior, no opcode trace)")
    a = ap.parse_args()

    src = open(a.input, encoding="latin1").read()
    log = {"sample": os.path.basename(a.input), "size": len(src)}
    inner_src, inner_data, family = detect(src, log)

    universal = inner_src is None  # unknown family -> obfuscator-agnostic trace
    print(f"[1/4] DETECT  : {family if not universal else 'unknown-family (universal mode)'}")
    if inner_src is not None:
        vm = log["inner_vm"]
        print(f"              resolver={vm['resolver']}  functions={vm['local_function_count']}")
    if a.detect:
        return

    os.makedirs(a.out, exist_ok=True)
    if not universal:
        open(os.path.join(a.out, "inner_source.lua"), "wb").write(inner_src)
        open(os.path.join(a.out, "inner_data.bin"), "wb").write(inner_data)
        unobf.classify_constructs(src, log["inner_vm"], log)
        # static VM lift: import table + readable strings, straight from bytes
        try:
            import lift
            lifted = lift.lift(inner_data)
            log["lift"] = {"segments": lifted.get("segments"),
                           "imports": [".".join(p) for p in (lifted.get("imports") or [])],
                           "strings": lifted.get("strings", [])[:120]}
            with open(os.path.join(a.out, "vm_imports.txt"), "w") as f:
                f.write("static VM imports (recovered from bytes, no execution):\n")
                for imp in log["lift"]["imports"]:
                    f.write("  " + imp + "\n")
                if log["lift"]["strings"]:
                    f.write("\nreadable strings:\n")
                    for s in log["lift"]["strings"]:
                        f.write("  " + s + "\n")
            print(f"[2b/4] LIFT   : {len(log['lift']['imports'])} static imports -> {a.out}/vm_imports.txt")
        except Exception as e:
            log["lift_error"] = str(e)
        json.dump(log, open(os.path.join(a.out, "analysis_log.json"), "w"), indent=2)
        vmtext = unobf.vm_structure_text(log)
        if log.get("lift", {}).get("imports"):
            vmtext += "\n\nstatic VM imports (from bytes, no execution):\n" + \
                      "\n".join("  " + i for i in log["lift"]["imports"])
        open(os.path.join(a.out, "vm_structure.txt"), "w").write(vmtext)
        print(f"[2/4] STATIC  : inner_source={len(inner_src)}  inner_data={len(inner_data)}  -> {a.out}/")
    else:
        json.dump(log, open(os.path.join(a.out, "analysis_log.json"), "w"), indent=2)
        print(f"[2/4] STATIC  : unknown family -> universal dynamic trace (behavior, not static source)")

    tmpl = "universal.lua"  # universal harness handles both known and unknown families here
    if a.safe:  # write the safe variant first, then move it aside
        os.replace(make_harness(src, a.out, template=tmpl, safe=True),
                   os.path.join(a.out, "harness_safe.lua"))
        print(f"              SAFE harness -> {a.out}/harness_safe.lua  (no opcode trace, runs clean)")
    harness = make_harness(src, a.out, template=tmpl)
    print(f"[3/4] HARNESS : {harness}  (full source embedded; run it in your executor)")

    if not a.trace:
        print("\nnext:")
        print(f"  1) run {harness} in your executor")
        print(f"  2) save the printed BEGIN_UNOBF_RESULT..END block to result.txt")
        print(f"  3) python3 {os.path.basename(__file__)} {a.input} --trace result.txt")
        return

    trace_files = a.trace if isinstance(a.trace, list) else [a.trace]
    all_traces = [open(t, encoding="latin1").read() for t in trace_files]
    trace = all_traces[0]  # primary trace drives the behavior/flow report
    cand = a.candidate and open(a.candidate, encoding="latin1").read() or ""
    verdict, findings, tr, cf = ai.audit(log, trace, cand)
    print(f"[4/4] AUDIT   : verdict={verdict}")
    for t, m in findings:
        print(f"              [{t}] {m}")
    # write a readable behavior report from the trace, with REAL vs DECOY split
    summ = os.path.join(a.out, "BEHAVIOR.txt")
    lines = ["run_ok: %s" % tr["run_ok"], ""]
    if tr["prints"]:
        lines.append("== printed output ==")
        lines += tr["prints"]; lines.append("")
    if tr["ops"]:
        lines.append("== arithmetic ==")
        lines += tr["ops"]; lines.append("")
    if tr["module"]:
        lines.append("== module ==")
        lines += tr["module"]; lines.append("")
    if tr["behavior"]:
        cls = ai.classify_behavior(tr["behavior"])
        conf, why = ai.confidence(cls, tr)
        nev = len(tr["behavior"]) + len(tr.get("consts", [])) + len(tr["prints"])
        lines.append("== provenance ==")
        lines.append("  every line below is derived from %d captured runtime records." % nev)
        lines.append("  nothing is invented, guessed, or filled in from a known sample.")
        lines.append("")
        intent = ai.build_intent(cls, tr)
        lines.append("== reconstructed intent ==")
        if intent:
            for it in intent:
                lines.append("  - " + it)
        else:
            lines.append("  (no external intent isolated)")
        lines.append("  confidence: %s (%s)" % (conf, why))
        lines.append("")
        mc = ai.meaningful_constants(tr.get("behavior", []))
        if mc:
            lines.append("== recovered constants (from real API arguments) ==")
            for it in mc:
                lines.append("  " + it)
            lines.append("")
        resolved = tr.get("resolved", [])
        if resolved:
            fr = ai.filter_resolved(resolved)
            lines.append("== deep constants (dumped from inner VM resolver) ==")
            lines.append("  %d tokens resolved; VM/crypto noise removed by structure:" % len(resolved))
            lines.append("  dropped %d hash/random strings + %d LCG/hash/index numbers." %
                         (fr["dropped_strings"], fr["dropped_numbers"]))
            lines.append("")
            lines.append("  -- recovered program API surface, grouped by area --")
            for it in ai.reconstruct_outline(fr["strings"], fr["numbers"]):
                lines.append("  " + it)
            if fr["small"]:
                lines.append("  [small ints, real but VM-index-ambiguous] " +
                             ", ".join(fr["small"]))
            lines.append("")
            lines.append("  (%d clean program strings + %d clean numbers kept of %d resolved)" %
                         (len(fr["strings"]), len(fr["numbers"]), len(resolved)))
            lines.append("")
        cov, notes = ai.coverage_check(tr, log)
        lines.append("== coverage audit (did we read all of the obf?) ==")
        lines.append("  verdict: %s" % cov)
        for nt in notes:
            lines.append("  " + nt)
        lines.append("")
        lines.append("== REAL program behavior ==")
        if cls["REAL"]:
            for l, _w in cls["REAL"]:
                lines.append("  " + l)
        elif tr["prints"]:
            lines.append("  the program's real result is its printed output (see top):")
            for p in tr["prints"][:20]:
                lines.append("    " + p)
        else:
            lines.append("  (none isolated)")
        lines.append("")
        lines.append("== DECOY (anti-tamper, ignore) ==")
        for l, w in cls["DECOY"]:
            lines.append("  " + l + "   # " + w)
        lines.append("")
        if cls["LOADER"]:
            lines.append("== loader (unwrap layer) ==")
            for l, _w in cls["LOADER"]:
                lines.append("  " + l)
            lines.append("")
        if cls["UNKNOWN"]:
            lines.append("== uncertain ==")
            for l, _w in cls["UNKNOWN"]:
                lines.append("  " + l)
            lines.append("")
        # a written summary so we save the actual folder file below
        json.dump({k: [x[0] for x in v] for k, v in cls.items()},
                  open(os.path.join(a.out, "classification.json"), "w"), indent=2)
    if len(lines) <= 2:
        lines.append("(no behavior captured - the run may have been empty or the")
        lines.append(" result block did not reach the analyzer)")
        lines.append("")
        lines.append("--- raw trace received ---")
        lines.append(trace[:4000])
    open(summ, "w").write("\n".join(lines))
    print(f"              behavior -> {summ}")
    # source-shaped reconstruction from the same evidence (readable .lua)
    try:
        import reconstruct
        lift_imports = (log.get("lift") or {}).get("imports")
        rlua = reconstruct.reconstruct(tr, lift_imports=lift_imports)
        rpath = os.path.join(a.out, "RECONSTRUCTED.lua")
        open(rpath, "w").write(rlua)
        print(f"              reconstruction -> {rpath}")
    except Exception as e:
        print(f"              (reconstruction skipped: {e})")
    # devirtualization: lift the opcode trace (dispatch hook) into a disassembly,
    # and derive+verify opcode semantics from the inner VM source when we have it.
    has_opcodes = "---OPCODES---" in trace or re.search(r"(?m)^-?\d+;-?\d+;[^;]*;-?\d+", trace)
    if has_opcodes:
        try:
            import devirt
            vmsrc = None
            isp = os.path.join(a.out, "inner_source.lua")
            if os.path.exists(isp):
                vmsrc = open(isp, encoding="latin1").read()
            disasm = devirt.summarize(trace, vm_source=vmsrc)
            dpath = os.path.join(a.out, "DISASSEMBLY.txt")
            open(dpath, "w").write(disasm)
            print(f"              disassembly -> {dpath}")
            # value-flow reconstruction (needs the 5-field value trace)
            try:
                import flow
                if ";" in trace and re.search(r"\n-?\d+;-?\d+;[^;]*;-?\d+;", trace):
                    fpath = os.path.join(a.out, "FLOW.txt")
                    open(fpath, "w").write(flow.reconstruct(trace))
                    print(f"              value-flow -> {fpath}")
            except Exception as e:
                print(f"              (value-flow skipped: {e})")
            if vmsrc:
                import opmap
                sp_rows = devirt.parse_ops_sp(trace)   # tolerant 3..6 field parse
                steps = [(pc, op, od) for pc, op, od, _sp, _v in sp_rows]
                steps_sp = [(pc, op, od, sp) for pc, op, od, sp, _v in sp_rows]
                om = opmap.build_map(vmsrc, steps, steps_sp)
                mpath = os.path.join(a.out, "OPCODE_MAP.txt")
                open(mpath, "w").write(opmap.report(om))
                nconf = sum(1 for v in om.values() if v["verdict"] == "CONFIRMED")
                print(f"              opcode map -> {mpath}  ({nconf}/{len(om)} confirmed)")
        except Exception as e:
            print(f"              (disassembly skipped: {e})")
    if verdict == "CONSISTENT" and cand:
        final = os.path.join(a.out, "FINAL_SOURCE.lua")
        open(final, "w").write(cand)
        print(f"              CERTIFIED -> {final}")

    # ONE combined report: merge every trace given now with any earlier traces
    # kept in the out dir, so multiple runs (which expose different code paths)
    # add up into a single picture of the whole script.
    try:
        import final as finalmod
        merged = list(all_traces)
        # also fold in any resolver-constant dumps saved beside the traces
        rc = os.path.join(a.out, "resolved_constants.txt")
        if os.path.exists(rc):
            merged.append(open(rc, encoding="latin1").read())
        frecon = os.path.join(a.out, "FINAL_RECONSTRUCTION.txt")
        open(frecon, "w").write(finalmod.consolidate(merged))
        print(f"              FINAL report -> {frecon}  (merged {len(merged)} source(s))")
    except Exception as e:
        print(f"              (final report skipped: {e})")
    # evidence-tagged logic reconstruction (OBSERVED/INFERRED/UNRESOLVED/DECOY)
    try:
        import logic
        lpath = os.path.join(a.out, "LOGIC.txt")
        open(lpath, "w").write(logic.reconstruct(all_traces))
        print(f"              LOGIC report -> {lpath}")
    except Exception as e:
        print(f"              (logic report skipped: {e})")
    # control-flow reconstruction (basic blocks, loops) from the opcode stream
    try:
        import cfg
        cpath = os.path.join(a.out, "CONTROL_FLOW.txt")
        open(cpath, "w").write(cfg.report(trace))
        print(f"              CONTROL-FLOW -> {cpath}")
    except Exception as e:
        print(f"              (control-flow skipped: {e})")

    # a plain index so you can see everything produced in one place
    print("\n== all results in %s ==" % a.out)
    for name in ("FINAL_RECONSTRUCTION.txt", "BEHAVIOR.txt", "RECONSTRUCTED.lua",
                 "FLOW.txt", "DISASSEMBLY.txt", "OPCODE_MAP.txt", "vm_structure.txt",
                 "vm_imports.txt", "inner_source.lua", "inner_data.bin"):
        p = os.path.join(a.out, name)
        if os.path.exists(p):
            print("   %-26s %8d bytes" % (name, os.path.getsize(p)))


if __name__ == "__main__":
    main()
