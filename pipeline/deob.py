#!/usr/bin/env python3
"""
deob.py - one command, from an obfuscated file to a reconstruction.

    python3 deob.py obf.lua                        # stages 1-3
    python3 deob.py obf.lua --trace capture.txt    # stage 4: analyse

Stages
  1 DETECT   identify the outer layer and unwrap it.
  2 STATIC   dump the inner interpreter and whatever the bytes give up without
             running anything.
  3 HARNESS  write a runnable harness with the WHOLE obfuscated file embedded,
             which captures the interpreter's own execution.
  4 ANALYSE  lift that capture into a value graph, recover the program from it,
             and verify the result against the VM's record.

Stage 4 is the deobfuscator proper and lives in core/. It measures everything it
needs from the capture in front of it - opcode numbering, stack effects, variable
slots, machinery boundaries - because this obfuscator changes all of them per
build and per run. Nothing is carried between samples, and nothing is written
that the recovered graph does not contain.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "core"))

import unobf                      # noqa: E402
from core import driver, tracefmt  # noqa: E402


def safe_long_bracket(content):
    """A Lua long-bracket level that cannot collide with the content."""
    longest = 0
    for m in re.finditer(r"\](=*)\]", content):
        longest = max(longest, len(m.group(1)))
    for m in re.finditer(r"\](=*)$", content):
        longest = max(longest, len(m.group(1)))
    eq = "=" * (longest + 1)
    return "[" + eq + "[", "]" + eq + "]"


def detect(src, log):
    try:
        inner_src, inner_data = unobf.unwrap_layer1(src, log)
    except Exception as e:
        log["layer1_error"] = str(e)
        return None, None, "unknown-family"
    if inner_src is None:
        return None, None, "unknown-family"
    try:
        unobf.analyze_inner(inner_src.decode("latin1"), log)
    except Exception as e:
        log["analyze_error"] = str(e)
        return None, None, "unknown-family"
    return inner_src, inner_data, "base85+Zstd Luau VM"


def make_harness(src, outdir, template="universal.lua", safe=False):
    """Embed the obfuscated source into the harness. The WHOLE file goes in,
    verbatim; a truncated sample would analyse a different program."""
    tmpl = open(os.path.join(HERE, template), encoding="utf-8").read()
    op, cl = safe_long_bracket(src)
    embedded = "local SOURCE\nSOURCE = " + op + "\n" + src + "\n" + cl
    tmpl, n = re.subn(r"local SOURCE\ndo\n.*?\nend", lambda _m: embedded,
                      tmpl, count=1, flags=re.S)
    if n != 1:
        raise RuntimeError("could not embed the source into the harness")
    if safe:
        tmpl = tmpl.replace("local TRACE_OPCODES = true",
                            "local TRACE_OPCODES = false", 1)
    if src not in tmpl:
        raise RuntimeError("the harness does not contain the whole source")
    path = os.path.join(outdir, "harness.lua")
    open(path, "w", encoding="utf-8").write(tmpl)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--out", default="out")
    ap.add_argument("--detect", action="store_true")
    ap.add_argument("--trace", nargs="+",
                    help="one or more captures; extra runs can only add")
    ap.add_argument("--one-run", action="store_true",
                    help="the trace files are pieces of a SINGLE run (the "
                         "console block plus the instruction dump beside it), "
                         "so fold them together instead of treating each as a "
                         "separate run")
    ap.add_argument("--safe", action="store_true",
                    help="also write a harness that does not trace opcodes, for "
                         "builds whose integrity check reacts to the trace")
    a = ap.parse_args()

    src = open(a.input, encoding="latin1").read()
    log = {"sample": os.path.basename(a.input), "size": len(src)}
    inner_src, inner_data, family = detect(src, log)
    universal = inner_src is None
    print("[1/4] DETECT  : %s" % (family if not universal
                                  else "unknown family, universal mode"))
    if inner_src is not None:
        vm = log["inner_vm"]
        print("              resolver=%s  functions=%d"
              % (vm["resolver"], vm["local_function_count"]))
    if a.detect:
        return 0

    os.makedirs(a.out, exist_ok=True)
    if not universal:
        open(os.path.join(a.out, "inner_source.lua"), "wb").write(inner_src)
        open(os.path.join(a.out, "inner_data.bin"), "wb").write(inner_data)
        unobf.classify_constructs(src, log["inner_vm"], log)
        try:
            import lift
            lifted = lift.lift(inner_data)
            log["lift"] = {"segments": lifted.get("segments"),
                           "imports": [".".join(p) for p in (lifted.get("imports") or [])],
                           "strings": lifted.get("strings", [])[:120]}
            with open(os.path.join(a.out, "vm_imports.txt"), "w") as f:
                f.write("recovered from the bytes alone, without running "
                        "anything:\n")
                for imp in log["lift"]["imports"]:
                    f.write("  " + imp + "\n")
                if log["lift"]["strings"]:
                    f.write("\nreadable strings:\n")
                    for s in log["lift"]["strings"]:
                        f.write("  " + s + "\n")
            print("[2b/4] LIFT   : %d static import(s) -> %s/vm_imports.txt"
                  % (len(log["lift"]["imports"]), a.out))
        except Exception as e:
            log["lift_error"] = str(e)
        open(os.path.join(a.out, "vm_structure.txt"), "w").write(
            unobf.vm_structure_text(log))
        print("[2/4] STATIC  : inner_source=%d  inner_data=%d -> %s/"
              % (len(inner_src), len(inner_data), a.out))
    else:
        print("[2/4] STATIC  : unknown family; the capture will carry the "
              "analysis")
    json.dump(log, open(os.path.join(a.out, "analysis_log.json"), "w"), indent=2)

    if a.safe:
        os.replace(make_harness(src, a.out, safe=True),
                   os.path.join(a.out, "harness_safe.lua"))
        print("              safe harness -> %s/harness_safe.lua" % a.out)
    harness = make_harness(src, a.out)
    print("[3/4] HARNESS : %s  (whole source embedded)" % harness)

    if not a.trace:
        print("\nnext:")
        print("  1) run %s in your executor" % harness)
        print("  2) save its BEGIN_UNOBF_RESULT..END block to capture.txt")
        print("  3) python3 %s %s --trace capture.txt"
              % (os.path.basename(__file__), a.input))
        return 0

    captures = tracefmt.load(a.trace, one_run=a.one_run)
    analyses = []
    for cap in captures:
        if not cap.has_instructions():
            print("[4/4] ANALYSE : %s has no instruction records - the dispatch "
                  "hook did not match this build, so there is nothing to lift."
                  % cap.name)
            continue
        an = driver.Analysis(cap)
        an.write(a.out)
        analyses.append(an)
        print("[4/4] ANALYSE : %s" % cap.name)
        print(an.summary())
    if len(analyses) > 1:
        body = driver.merge_summary(analyses)
        open(os.path.join(a.out, "ACROSS_RUNS.txt"), "w").write(body + "\n")
        print("\n" + body)
    if not analyses:
        return 1

    print("\n== results in %s ==" % a.out)
    for name in sorted(os.listdir(a.out)):
        p = os.path.join(a.out, name)
        if os.path.isfile(p):
            print("   %-24s %9d bytes" % (name, os.path.getsize(p)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
