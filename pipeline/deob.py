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
import sys as _sys

# A path can hold characters the console's code page cannot encode - a Windows
# Documents folder is named in the user's own language, and printing it under
# cp1252 raises UnicodeEncodeError and takes the whole run down with it. That
# happened while merely listing the folders being watched, before any work.
#
# Nothing here needs a particular encoding to be correct, so output is written
# as UTF-8 and anything the terminal still cannot show is replaced rather than
# raised. A character that prints as a question mark costs nothing; a traceback
# instead of a run costs the run.
for _stream in (_sys.stdout, _sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "core"))

import unobf                      # noqa: E402
from core import driver, tracefmt, version  # noqa: E402


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


def _first_attempt_error(cap):
    """The error from the attempt whose instructions we are about to describe.

    When the untraced retry finishes, the capture's headline error is gone - but
    the rows still came from the attempt that raised, and that error is what the
    reader needs."""
    for a in (getattr(cap, "attempts", None) or []):
        if a["instructions"] > 0 and not a["ok"] and a["error"]:
            return a["error"]
    return "the run that produced these instructions raised"


def make_harness(src, outdir, template="universal.lua", safe=False, chunk=1,
                 name="harness.lua", visible_hooks=False, standalone=False):
    """Embed the obfuscated source into the harness. The WHOLE file goes in,
    verbatim; a truncated sample would analyse a different program.

    standalone=True leaves the source OUT and keeps the harness reading obf.lua
    from the executor's own folder instead. That is worth having for one reason:
    four times in a row a capture arrived from the harness already on disk
    because getting a new one meant loading the script and re-running the
    analysis, and the new harness is written at the moment the old capture is
    being read. A standalone harness updates by replacing one file."""
    tmpl = open(os.path.join(HERE, template), encoding="utf-8").read()
    if not standalone:
        op, cl = safe_long_bracket(src)
        embedded = "local SOURCE\nSOURCE = " + op + "\n" + src + "\n" + cl
        tmpl, n = re.subn(r"local SOURCE\ndo\n.*?\nend", lambda _m: embedded,
                          tmpl, count=1, flags=re.S)
        if n != 1:
            raise RuntimeError("could not embed the source into the harness")
    # Stamp the build in, so a capture says which harness wrote it instead of
    # leaving that to be inferred from which features its output happens to have.
    tmpl, ns = re.subn(r"local HARNESS_ENGINE = 0",
                       "local HARNESS_ENGINE = %d" % version.VERSION, tmpl,
                       count=1)
    if ns != 1:
        raise RuntimeError("the harness template has no engine stamp to set")
    if safe:
        tmpl = tmpl.replace("local TRACE_OPCODES = true",
                            "local TRACE_OPCODES = false", 1)
    if chunk != 1:
        tmpl = tmpl.replace("local TRACE_CHUNK = 1",
                            "local TRACE_CHUNK = %d" % chunk, 1)
    if visible_hooks:
        tmpl = tmpl.replace("local HIDE_HOOKS = true",
                            "local HIDE_HOOKS = false", 1)
    if not standalone and src not in tmpl:
        raise RuntimeError("the harness does not contain the whole source")
    path = os.path.join(outdir, name)
    open(path, "w", encoding="utf-8").write(tmpl)
    return path


def _replay(localvm, luau, out_dir, script="behaviour_check.lua",
            where="replay"):
    """Run the generated behaviour harness under the stand-in and return what it
    printed, or None.

    It runs in its own folder: the builder writes one combined chunk under a
    fixed name, and the capture's own chunk is in the output folder already.
    Overwriting that would destroy the one file that reproduces the capture.
    """
    import os as _os
    script = _os.path.join(out_dir, script)
    if not _os.path.isfile(script):
        return None
    where = _os.path.join(out_dir, where)
    _os.makedirs(where, exist_ok=True)
    try:
        rec = localvm.run(luau, script, cwd=where)
    except Exception:
        return None
    out = (rec.get("stdout") or "")
    with open(_os.path.join(where, "replay_stdout.txt"), "w",
              encoding="utf-8") as f:
        f.write("command: %s\n" % rec.get("command"))
        f.write(out)
        if rec.get("stderr"):
            f.write("\n---- stderr ----\n" + rec["stderr"])
    return out if "BEGIN_BEHAVIOUR" in out else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--out", default="out")
    ap.add_argument("--detect", action="store_true")
    ap.add_argument("--trace", nargs="+",
                    help="one capture per run; extra runs can only add. A run "
                         "written out in two files is given as one argument "
                         "with the pieces joined by + (block.txt+dump.txt)")
    ap.add_argument("--one-run", action="store_true",
                    help="the trace files are pieces of a SINGLE run (the "
                         "console block plus the instruction dump beside it), "
                         "so fold them together instead of treating each as a "
                         "separate run")
    ap.add_argument("--collect", nargs="?", type=int, const=1, metavar="RUNS",
                    help="watch the executor's workspace and pick each run's "
                         "files up automatically, then analyse them. Give the "
                         "number of runs to collect (default 1)")
    ap.add_argument("--visible-hooks", action="store_true",
                    help="emit a harness whose trace hooks are ordinary "
                         "globals instead of being served through the "
                         "environment's metatable. Try this when a run records "
                         "no instructions although the hook was placed: a VM "
                         "that copies its environment loses hooks that are not "
                         "real fields")
    ap.add_argument("--find-workspace", action="store_true",
                    help="find the folder your executor writes to. Run "
                         "writefile(\"VMSMART_WHERE.txt\", \"here\") in the "
                         "executor first, then this prints the folder to pass "
                         "to --workspace")
    ap.add_argument("--workspace",
                    help="the executor's output folder, if --collect cannot "
                         "find it")
    ap.add_argument("--behaviour", metavar="FILE",
                    help="what behaviour_check.lua printed. Compares the "
                         "reconstruction's calls with the program's and writes "
                         "the result")
    ap.add_argument("--chunks", type=int, default=2, metavar="N",
                    help="write a harness for each of the first N nested "
                         "interpreters (default 2). One run traces one of them; "
                         "run each and merge the captures")
    ap.add_argument("--vm-source",
                    help="the interpreter's own source, if it is not where "
                         "the harness left it")
    ap.add_argument("--offline", nargs="?", const=True, metavar="LUAU",
                    help="take the capture here, with no executor and no "
                         "Roblox: run the harness under a luau binary against "
                         "the stand-in environment. Optionally name the binary.")
    ap.add_argument("--luau", metavar="PATH",
                    help="where a Luau binary is, for running the "
                         "reconstruction and comparing its calls with the "
                         "program's. Use it when the capture is already in "
                         "hand (--trace) and only that check is wanted")
    ap.add_argument("--safe", action="store_true",
                    help="also write a harness that does not trace opcodes, for "
                         "builds whose integrity check reacts to the trace")
    a = ap.parse_args()

    print("deob.py (%s)" % version.banner())

    if a.find_workspace:
        import collect as collector
        print("looking for %s ..." % collector.MARKER)
        hits = collector.find_marker()
        if not hits:
            print("")
            print("not found. Run this one line in your executor first:")
            print('    writefile("%s", "here")' % collector.MARKER)
            print("")
            print("Then run this again. If it still finds nothing, your")
            print("executor writes somewhere this does not search - open the")
            print("file from inside the executor to see where it landed, and")
            print("pass that folder with --workspace.")
            return 1
        print("")
        print("your executor writes to:")
        for h in hits:
            print("   %s" % h)
        print("")
        print("use it like this:")
        print('   python3 %s %s --collect 2 --workspace "%s"'
              % (os.path.basename(__file__), a.input, hits[0]))
        return 0
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

    # Always. A build that checks its own source reacts to the dispatch patch
    # and to nothing else the harness does, and the difference between the two
    # harnesses is the cleanest evidence of that there is: same run, same
    # everything, one of them patches the interpreter's loop and one does not.
    # It cost nothing to write and it was behind a flag nobody knew to pass.
    os.replace(make_harness(src, a.out, safe=True,
                            visible_hooks=a.visible_hooks),
               os.path.join(a.out, "harness_safe.lua"))
    # A copy that carries no script and reads obf.lua from the executor's folder.
    # Updating this package then means replacing ONE file instead of re-running
    # the analysis to get a fresh harness - which is what went wrong four times:
    # the capture came from the harness already on disk.
    make_harness(src, a.out, visible_hooks=a.visible_hooks, standalone=True,
                 name="harness_standalone.lua")
    harness = make_harness(src, a.out,
                           visible_hooks=a.visible_hooks)
    print("[3/4] HARNESS : %s  (whole source embedded)" % harness)
    print("              Run THIS one. The harness makes two edits to the "
          "chunk to observe it,")
    print("              and on any round that raises it takes ONE back out "
          "and runs the same")
    print("              payload again - dispatch logger, then resolver "
          "rewrite - until the")
    print("              script finishes or the chunk is untouched. Every "
          "round goes into the")
    print("              capture, so the report says which edit it was, or "
          "that it was none.")
    print("              also: %s  (never patches the dispatch loop; only "
          "needed to" % os.path.join(a.out, "harness_safe.lua"))
    print("              reproduce a clean run on its own)")
    print("              also: %s"
          % os.path.join(a.out, "harness_standalone.lua"))
    print("              The same harness with NO script inside it. Put your "
          "script in your")
    print("              executor's folder as obf.lua and run this instead. "
          "Updating then")
    print("              means replacing this one file - no re-analysis to get "
          "a fresh harness.")
    # One run traces one interpreter, because patching two trips the VM's
    # integrity check. The program's tail runs inside the later ones, so a
    # harness for each is written and their captures merge as separate runs.
    extra = []
    for n in range(2, a.chunks + 1):
        extra.append(make_harness(src, a.out, chunk=n,
                                  visible_hooks=a.visible_hooks,
                                  name="harness_chunk%d.lua" % n))
    for p2 in extra:
        print("              also: %s  (traces the next interpreter down)" % p2)

    if a.collect:
        import collect as collector
        try:
            spaces = collector.find_workspaces(a.workspace)
        except SystemExit as e:
            print(str(e))
            return 1
        if not spaces:
            print("\n[4/4] COLLECT : could not find where your executor writes "
                  "its output.")
            print("              It looks for a folder already holding one of "
                  "the files the")
            print("              harness writes, so before the first run there "
                  "is nothing to find.")
            print("")
            print("              To find that folder, run this one line in your "
                  "executor:")
            print("                  writefile(\"%s\", \"here\")"
                  % collector.MARKER)
            print("              then:")
            print("                  python3 %s %s --find-workspace"
                  % (os.path.basename(__file__), a.input))
            print("              and pass what it prints with --workspace.")
            return 1
        print("")
        runs = collector.watch(spaces, a.collect,
                               os.path.join(a.out, "captures"))
        if not runs:
            print("\nnothing was collected.")
            return 1
        a.trace = runs
        print("")

    if getattr(a, "offline", None):
        import localvm
        want = None if a.offline is True else a.offline
        luau, report = localvm.find(want)
        print("[3b/4] OFFLINE: looking for a Luau interpreter")
        for ln in report.splitlines():
            print("              " + ln)
        if not luau:
            print("              " + localvm.where_to_put_one())
            return 1
        # The one host service a Luau binary cannot perform. It is computed
        # from the script's own blobs by a real Zstd decoder, before the run,
        # and handed to the stand-in as data. See core/sidecar.py.
        from core import sidecar as sidecarmod
        ents, snote = sidecarmod.decompressions(src)
        print("              " + sidecarmod.describe(ents, snote))
        side = sidecarmod.emit_lua(ents, snote) if ents else None
        rec = localvm.run(luau, harness, sidecar_text=side)
        print("              " + localvm.describe(rec))
        # A build whose packing this tool does not recognise hands its bytes
        # over at run time instead. The run writes down what it was asked for
        # and could not be given; those bytes are decompressed here and the
        # payload is run again with the answer. Bounded, because each round
        # must bring back something new or there is nothing to gain.
        for _round in range(4):
            more, mnote = sidecarmod.from_request(rec.get("stdout") or "")
            fresh = [e for e in more
                     if e["key"] not in {x["key"] for x in ents}]
            if not fresh:
                if mnote and not ents:
                    print("              " + mnote)
                break
            ents = ents + fresh
            print("              the run asked for %d frame(s) this tool had "
                  "not found in the file; decompressed from the bytes the "
                  "program itself produced, running again"
                  % len(fresh))
            side = sidecarmod.emit_lua(ents, snote)
            rec = localvm.run(luau, harness, sidecar_text=side)
            print("              " + localvm.describe(rec))
        # The whole run is kept, not only the block inside it. When a capture
        # comes back empty the reason is almost always in the lines before the
        # block, and those were being thrown away - the file below is the one
        # thing worth sending when an offline run says nothing.
        whole = os.path.join(a.out, "offline_stdout.txt")
        with open(whole, "w", encoding="utf-8") as f:
            f.write("command: %s\n" % rec["command"])
            f.write("exit: %s%s\n\n" % (rec["returncode"],
                                        "  (timed out)" if rec["timed_out"]
                                        else ""))
            f.write("---- stdout ----\n" + (rec["stdout"] or "") + "\n")
            f.write("---- stderr ----\n" + (rec["stderr"] or "") + "\n")
        print("              whole run -> %s" % whole)
        for ln in (rec["stderr"] or "").strip().splitlines()[:3]:
            print("              luau said: " + ln)
        if rec["returncode"] not in (0, None):
            print("              luau exited %s" % rec["returncode"])
        if rec["capture"]:
            path = os.path.join(a.out, "offline_capture.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write(rec["capture"] + "\n")
            print("              capture -> %s" % path)
            a.trace = [path]
        else:
            return 1

    if not a.trace:
        print("\nnext:")
        print("  1) run %s in your executor" % harness)
        print("  2) save its BEGIN_UNOBF_RESULT..END block to capture.txt")
        print("  3) python3 %s %s --trace capture.txt"
              % (os.path.basename(__file__), a.input))
        print("")
        print("or skip the copying: python3 %s %s --collect 1"
              % (os.path.basename(__file__), a.input))
        print("  then run harness.lua ONCE, and nothing else.")
        print("")
        print("  harness_chunk2.lua is for builds that nest a second")
        print("  interpreter inside the first. Run it only if harness.lua's")
        print("  own output says an interpreter was left untraced - on a build")
        print("  with one interpreter it records nothing, and running it after")
        print("  harness.lua overwrites the capture that did work.")
        return 0

    missing = [t for t in tracefmt.expand(a.trace) if not os.path.isfile(t)]
    if missing:
        print("\n[4/4] ANALYSE : nothing to read.")
        for t in missing:
            print("              %s is not here" % t)
        here = [f for f in sorted(os.listdir("."))
                if f.lower().endswith((".txt", ".log"))][:12]
        print("\nA capture file is what your executor printed or wrote out. To")
        print("make one: run %s in the executor, then either copy its" % harness)
        print("BEGIN_UNOBF_RESULT..END_UNOBF_RESULT block into a text file, or")
        print("take unobf_result.txt and opcode_trace.txt from the executor's")
        print("workspace folder. Each separate run goes in its own file.")
        if here:
            print("\nText files in this folder you could mean:")
            for f in here:
                print("   " + f)
        return 1
    # The interpreter's own source names what its opcodes do. The harness
    # writes it out when it patches a chunk, so it is used when it is there.
    vm_src = None
    vm_path = a.vm_source
    # The interpreter's source as the RUN saw it. The static stage can only
    # recover it for a packing this tool recognises; the harness simply keeps
    # the string the program handed to loadstring, so a build that packs itself
    # some other way still gets its opcodes read from its own handlers. That is
    # the difference between four in ten instructions explained and nine.
    if not vm_path:
        for cap_path in (a.trace or []):
            for piece in str(cap_path).split("+"):
                if not os.path.isfile(piece):
                    continue
                with open(piece, encoding="latin1") as f:
                    text = f.read()
                mark = "\n---INNERSRC---\n"
                i = text.find(mark)
                if i < 0:
                    continue
                body = text[i + len(mark):]
                j = body.find("\n---")
                if j >= 0:
                    body = body[:j]
                body = body.strip("\n")
                if len(body) > 2000:
                    out_p = os.path.join(a.out, "inner_source.lua")
                    if not os.path.isfile(out_p):
                        with open(out_p, "w", encoding="latin1") as f:
                            f.write(body)
                        print("              the run kept the interpreter's own "
                              "source (%d bytes); opcode meanings will be read "
                              "from its handlers" % len(body))
                    vm_path = out_p
                    break
            if vm_path:
                break
    if not vm_path:
        # The interpreter's own source names what its opcodes do. The static
        # stage writes it as inner_source.lua in this very output directory, and
        # that name was not in this list - so every offline report said
        # "operation known for 0" while the file sat beside it.
        for cand in [os.path.join(a.out, "captures", "run1_vm.txt"),
                     os.path.join(a.out, "inner_source.lua"),
                     os.path.join(a.out, "inner_chunk_1.txt"),
                     "inner_chunk_1.txt"]:
            if os.path.isfile(cand):
                vm_path = cand
                break
    if vm_path and os.path.isfile(vm_path):
        with open(vm_path, encoding="latin1") as f:
            vm_src = f.read()
        print("              interpreter source: %s (%d bytes) - opcode "
              "meanings will be read from its handlers"
              % (vm_path, len(vm_src)))

    behaviour = None
    if a.behaviour:
        if not os.path.isfile(a.behaviour):
            print("\n%s is not here." % a.behaviour)
            return 1
        with open(a.behaviour, encoding="latin1") as f:
            behaviour = f.read()

    captures = tracefmt.load(a.trace, one_run=a.one_run)
    analyses = []
    for cap in captures:
        if not cap.has_instructions():
            print("[4/4] ANALYSE : %s has no instruction records." % cap.name)
            print("              %s" % cap.why_no_instructions())
            # A capture with no rows can still carry the harness's verdict on
            # WHY there are none, and that is the whole answer for a build that
            # objects to being traced. Dropping it here threw away the finding.
            note = tracefmt.stopped_under_the_trace(cap)
            if note:
                print("              %s" % note)
            for extra in (tracefmt.the_program_ended_itself(cap),
                          tracefmt.what_the_interpreter_had(cap),
                          tracefmt.the_standin_answered(cap)):
                if extra:
                    print("              " + extra.replace("\n", "\n              "))
            continue
        stopped = (getattr(cap, "run_error", None)
                   or getattr(cap, "rows_from_failed_run", False))
        if stopped and len(cap.rows) < 100:
            print("[4/4] ANALYSE : %s - the script stopped early." % cap.name)
            print("              %s" % (cap.run_error or _first_attempt_error(cap)))
            print("              Only %d instruction(s) ran before it did, so "
                  "what follows" % len(cap.rows))
            print("              describes those, not the program. This is not "
                  "a reconstruction")
            print("              of the script; it is a reconstruction of its "
                  "first few steps.")
            for extra in (tracefmt.the_program_ended_itself(cap),
                          tracefmt.what_the_interpreter_had(cap),
                          tracefmt.the_standin_answered(cap)):
                if extra:
                    print("              " + extra.replace("\n", "\n              "))
        an = driver.Analysis(cap, vm_src)
        an.write(a.out)
        analyses.append(an)
        print("[4/4] ANALYSE : %s" % cap.name)
        print(an.summary())
        # THE ACCEPTANCE TEST, run here rather than asked for. Coverage says
        # how much of the run was explained; it does not say the reconstruction
        # would DO the same things. The only check that says that is executing
        # it and comparing the calls it makes, in order, with the ones the
        # program made. The script to do it is written beside the report, and
        # where a Luau binary is to hand there is no reason to leave it to the
        # reader: it is run, and its result goes in the report.
        if not behaviour:
            import localvm as _lv
            _hint = getattr(a, "luau", None) or (
                None if getattr(a, "offline", None) is True
                else getattr(a, "offline", None))
            _luau, _why = _lv.find(_hint)
            if _luau:
                behaviour = _replay(_lv, _luau, a.out)
                if behaviour:
                    print("              the reconstruction was run here and "
                          "its calls compared with the program's")
                else:
                    print("              the reconstruction could not be run "
                          "here; behaviour_check.lua is beside the report")
        # THE REMOVAL, TESTED. The report also writes the same program with
        # everything unproven taken out. Whether that was safe is not something
        # to assert: both are run, and if the smaller one makes the same calls
        # in the same order, the lines taken out had no effect anything could
        # see. If it does not, the removal was wrong and this says so.
        clean_note = None
        if behaviour:
            import localvm as _lv2
            _hint2 = getattr(a, "luau", None) or (
                None if getattr(a, "offline", None) is True
                else getattr(a, "offline", None))
            _luau2, _ = _lv2.find(_hint2)
            if _luau2:
                clean_out = _replay(_lv2, _luau2, a.out,
                                    script="behaviour_check_clean.lua",
                                    where="replay_clean")
                if clean_out:
                    from core import verify as _v2
                    full = _v2.parse_block(behaviour)
                    lean = _v2.parse_block(clean_out)
                    same = (full.get("calls") == lean.get("calls"))
                    clean_note = (
                        "the smaller program makes the same %d call(s) in the "
                        "same order, so the lines taken out of it had no "
                        "effect anything could see"
                        % len(lean.get("calls") or ())
                        if same else
                        "THE REMOVAL CHANGED THE PROGRAM: the smaller program "
                        "makes %d call(s) where the whole one makes %d. The "
                        "lines taken out were not all unobservable, and the "
                        "whole rendering is the one to read"
                        % (len(lean.get("calls") or ()),
                           len(full.get("calls") or ())))
                    print("              " + clean_note)
                    # The verdict goes INSIDE the file. Someone opening the
                    # smaller rendering on its own must not have to find this
                    # report to learn whether taking those lines out was safe.
                    cpath = os.path.join(a.out, "RECONSTRUCTED_clean.lua")
                    if os.path.isfile(cpath):
                        with open(cpath, encoding="utf-8") as f:
                            cbody = f.read()
                        banner = ("-- CHECKED: this file was run and makes the "
                                  "same calls, in the same order, as the whole\n"
                                  "-- rendering. The lines taken out had no "
                                  "effect anything could see.\n"
                                  if same else
                                  "-- DO NOT READ THIS AS THE PROGRAM. It was "
                                  "run and it does NOT do what the whole\n"
                                  "-- rendering does: some of the lines taken "
                                  "out of it mattered after all.\n"
                                  "-- RECONSTRUCTED.lua is the one to read.\n")
                        with open(cpath, "w", encoding="utf-8") as f:
                            f.write(banner + cbody)
                # And the host-actions file, checked the same way: it is run,
                # and what it does is compared with what the program did. A
                # file that says "this is what the program did" has to be able
                # to show it.
                act_out = _replay(_lv2, _luau2, a.out,
                                  script="behaviour_check_actions.lua",
                                  where="replay_actions")
                if act_out:
                    from core import verify as _v3
                    act = _v3.parse_block(act_out)
                    want = _v3.parse_block(behaviour)
                    n_act = len(act.get("calls") or ())
                    actions_note = (
                        "ACTIONS.lua performs %d call(s); the program made %d, "
                        "and the whole rendering makes %d"
                        % (n_act, len(cap.calls or ()),
                           len(want.get("calls") or ())))
                    if act.get("error"):
                        actions_note += " - it stopped on: %s" % act["error"]
                    print("              " + actions_note)
                    clean_note = (clean_note or "") + "\n  " + actions_note
        if behaviour:
            from core import verify as vmod
            text, matched, missing, extra = vmod.compare_behaviour(
                cap.calls, behaviour)
            if clean_note:
                text += ("\n\nTHE SMALLER PROGRAM\n"
                         + "-" * 46 + "\n  " + clean_note + "\n")
            path = os.path.join(a.out, "BEHAVIOUR_COMPARISON.txt")
            open(path, "w").write(text + "\n")
            # The verification report is written before this check can run - it
            # needs the harness that report's own folder carries - so it says
            # the behaviour check was not run. It has been now, and the result
            # belongs in the same file: it is the only check that compares what
            # the reconstruction DOES with what the program did, and a reader
            # who stops at the verification report must not be told it is
            # missing when it is not.
            vpath = os.path.join(a.out, "VERIFICATION.txt")
            if os.path.isfile(vpath):
                with open(vpath, encoding="utf-8") as f:
                    vtext = f.read()
                with open(vpath, "w", encoding="utf-8") as f:
                    f.write(vtext.rstrip("\n")
                            + "\n\nbehaviour check - RUN. The reconstruction "
                              "was executed against\nthe same stand-in "
                              "environment and the calls it made were "
                              "compared\nwith the program's, in order. This is "
                              "the one check that tests\nwhat the "
                              "reconstruction DOES rather than how much of the "
                              "run was\nexplained, and the two numbers are not "
                              "the same thing.\n\n"
                            + "\n".join("  " + ln for ln in
                                        text.splitlines()[3:]) + "\n")
            print("")
            print(text)
            print("")
            print("              behaviour comparison -> %s" % path)
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
