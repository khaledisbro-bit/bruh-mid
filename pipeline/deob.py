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
    inner_src, inner_data = unobf.unwrap_layer1(src, log)
    if inner_src is None:
        return None, None, "unknown-family"
    knobs = unobf.analyze_inner(inner_src.decode("latin1"), log)
    family = "base85+Zstd Luau VM"
    return inner_src, inner_data, family


def make_harness(src, outdir, template="unobf.lua"):
    """Embed the obfuscated source into the given harness template (no readfile)."""
    tmpl = open(os.path.join(HERE, template), encoding="utf-8").read()
    op, cl = safe_long_bracket(src)
    embedded = "local SOURCE\nSOURCE = " + op + "\n" + src + "\n" + cl
    tmpl = re.sub(r"local SOURCE\ndo\n.*?\nend", lambda _m: embedded,
                  tmpl, count=1, flags=re.S)
    path = os.path.join(outdir, "harness.lua")
    open(path, "w", encoding="utf-8").write(tmpl)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--out", default="out")
    ap.add_argument("--detect", action="store_true")
    ap.add_argument("--trace")
    ap.add_argument("--candidate", help="optional candidate source for the audit")
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
        json.dump(log, open(os.path.join(a.out, "analysis_log.json"), "w"), indent=2)
        open(os.path.join(a.out, "vm_structure.txt"), "w").write(unobf.vm_structure_text(log))
        print(f"[2/4] STATIC  : inner_source={len(inner_src)}  inner_data={len(inner_data)}  -> {a.out}/")
    else:
        json.dump(log, open(os.path.join(a.out, "analysis_log.json"), "w"), indent=2)
        print(f"[2/4] STATIC  : unknown family -> universal dynamic trace (behavior, not static source)")

    harness = make_harness(src, a.out, template="universal.lua" if universal else "unobf.lua")
    print(f"[3/4] HARNESS : {harness}  (paste into your executor, save its output)")

    if not a.trace:
        print("\nnext:")
        print(f"  1) run {harness} in your executor")
        print(f"  2) save the printed BEGIN_UNOBF_RESULT..END block to result.txt")
        print(f"  3) python3 {os.path.basename(__file__)} {a.input} --trace result.txt")
        return

    trace = open(a.trace, encoding="latin1").read()
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
        lines.append("== REAL program behavior ==")
        if cls["REAL"]:
            for l, _w in cls["REAL"]:
                lines.append("  " + l)
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
    if verdict == "CONSISTENT" and cand:
        final = os.path.join(a.out, "FINAL_SOURCE.lua")
        open(final, "w").write(cand)
        print(f"              CERTIFIED -> {final}")


if __name__ == "__main__":
    main()
