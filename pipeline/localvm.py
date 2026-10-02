#!/usr/bin/env python3
"""
localvm.py - take a capture with no executor and no Roblox.

Every capture this package has read came out of a real Roblox client driven by an
executor. That is the best place to watch a program: real services, real
instances, real network. It is also the one place a person may not have.

The harness does not actually need Roblox. It is a Luau chunk that builds its own
environment for the payload and hooks the interpreter; what it takes from the
host is a short list of roots (see robloxenv.lua). So a capture can be taken
offline: concatenate the stand-in and the harness, run the result under a `luau`
binary, and read the BEGIN_UNOBF_RESULT block it prints.

WHAT THIS IS NOT
----------------
It is not the same evidence. Under an executor the program had a game; here it
has a stand-in whose services resolve and whose fields are all absent. A program
that only works with real services fails here, and that failure is reported as a
failure rather than smoothed into a partial success. The capture carries
`environment: standin` so nothing downstream can read this run as a run in a
game.

The interpreter is never assumed either. `find` reports every path it looked at
and why each was rejected, and `probe` makes a candidate prove it runs Luau
before anything is handed to it. Picking the first thing named `luau` on PATH
would be a claim about the machine rather than a reading of it.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
STANDIN = os.path.join(HERE, "robloxenv.lua")

BEGIN = "BEGIN_UNOBF_RESULT"
END = "END_UNOBF_RESULT"
DEFAULT_TIMEOUT = 120

# The sentinel the probe demands back. It uses Luau-only syntax, so a Lua 5.x
# binary that happens to be named `luau` fails the proof instead of passing it.
_PROBE = 'local t: number = 7 print(`vmsmart-luau-{t}`)'
_PROBE_WANT = "vmsmart-luau-7"


def _candidates(explicit=None):
    """Every path worth trying, in order, with where each came from."""
    out = []
    if explicit:
        out.append((explicit, "given on the command line"))
    env = os.environ.get("VMSMART_LUAU")
    if env:
        out.append((env, "from $VMSMART_LUAU"))
    for name in ("luau", "luau.exe"):
        found = shutil.which(name)
        if found:
            out.append((found, "found on PATH as %s" % name))
    here = os.path.dirname(HERE)
    for rel in ("luau", "luau.exe", "bin/luau", "bin/luau.exe",
                "tools/luau", "tools/luau.exe"):
        out.append((os.path.join(here, rel), "beside the package"))
        out.append((os.path.join(os.getcwd(), rel), "in the working directory"))
    seen, uniq = set(), []
    for p, why in out:
        q = os.path.abspath(p)
        if q not in seen:
            seen.add(q)
            uniq.append((p, why))
    return uniq


def probe(path, timeout=30):
    """Make a candidate prove it runs Luau. Returns (ok, why)."""
    if not os.path.isfile(path):
        return False, "no file there"
    if not os.access(path, os.X_OK):
        return False, "not executable"
    d = tempfile.mkdtemp(prefix="vmsmart-probe-")
    s = os.path.join(d, "probe.luau")
    try:
        with open(s, "w", encoding="utf-8") as f:
            f.write(_PROBE)
        r = subprocess.run([path, s], capture_output=True, timeout=timeout)
        out = (r.stdout or b"").decode("utf-8", "replace")
        if _PROBE_WANT in out:
            return True, "ran a Luau-only script and printed what was asked"
        err = (r.stderr or b"").decode("utf-8", "replace").strip()
        return False, ("ran but did not print the sentinel%s"
                       % (": " + err.splitlines()[0] if err else ""))
    except subprocess.TimeoutExpired:
        return False, "did not finish the probe in %ds" % timeout
    except OSError as exc:
        return False, "could not be run (%s)" % exc.__class__.__name__
    finally:
        shutil.rmtree(d, ignore_errors=True)


def find(explicit=None):
    """(path, report). path is None when nothing proved itself."""
    lines, chosen = [], None
    for p, why in _candidates(explicit):
        ok, note = probe(p)
        lines.append("  %-6s %s  (%s) - %s" % ("USE" if ok else "no", p, why, note))
        if ok and chosen is None:
            chosen = p
    head = ("A Luau interpreter was found." if chosen else
            "No Luau interpreter proved itself. Every path tried:")
    return chosen, head + "\n" + "\n".join(lines)


def where_to_put_one():
    return ("Download a `luau` binary from the Luau project's releases and put "
            "it beside this package, on PATH, or name it in $VMSMART_LUAU. It "
            "is one file and needs no install.")


def build(harness, out_dir):
    """The stand-in and the harness as one chunk, written where it will run.

    They are concatenated rather than chained with dofile/require, because which
    of those a given Luau build exposes is itself a host question and this is one
    less of them."""
    with open(STANDIN, encoding="utf-8") as f:
        pre = f.read()
    with open(harness, encoding="utf-8", errors="replace") as f:
        body = f.read()
    # the stand-in ends in a `return`, which would end the chunk
    pre = pre.replace("\nreturn VMSMART_STANDIN\n", "\n")
    path = os.path.join(out_dir, "offline_harness.luau")
    with open(path, "w", encoding="utf-8") as f:
        f.write(pre + "\n-- ---- harness ----\n" + body)
    return path


def run(luau, harness, timeout=DEFAULT_TIMEOUT, cwd=None):
    """Run one harness offline and bring back everything it said."""
    cwd = cwd or os.path.dirname(os.path.abspath(harness)) or "."
    script = build(harness, cwd)
    rec = {"harness": harness, "script": script, "timeout": timeout,
           "command": "%s %s" % (luau, script), "timed_out": False,
           "stdout": "", "stderr": "", "capture": None, "returncode": None}
    try:
        r = subprocess.run([luau, script], capture_output=True,
                           timeout=timeout, cwd=cwd)
        rec["returncode"] = r.returncode
        rec["stdout"] = (r.stdout or b"").decode("utf-8", "replace")
        rec["stderr"] = (r.stderr or b"").decode("utf-8", "replace")
    except subprocess.TimeoutExpired as exc:
        rec["timed_out"] = True
        rec["stdout"] = _as_text(exc.stdout)
        rec["stderr"] = _as_text(exc.stderr)
    rec["capture"] = extract(rec["stdout"])
    rec["instructions"] = _count_ops(rec["capture"])
    return rec


def _as_text(v):
    if v is None:
        return ""
    return v.decode("utf-8", "replace") if isinstance(v, bytes) else str(v)


def extract(text):
    """The capture block, or None.

    The LAST BEGIN and the first END after it. A payload that prints something
    containing the marker would otherwise have its text read as the harness's;
    the harness prints its block once, at the very end, so the last one is its
    own."""
    if not text:
        return None
    i = text.rfind(BEGIN)
    if i < 0:
        return None
    j = text.find(END, i)
    if j < 0:
        return None
    return text[i:j + len(END)]


def _count_ops(capture):
    """Instruction rows in a capture, without importing the reader."""
    if not capture:
        return 0
    n, started = 0, False
    for ln in capture.splitlines():
        s = ln.strip()
        if s.startswith("---OPCODES---"):
            started = True
            continue
        if started:
            if s.startswith("---"):
                break
            if s and s[0].isdigit() and ";" in s:
                n += 1
    return n


def describe(rec):
    """One plain sentence about what happened, and what to do about it."""
    name = os.path.basename(rec.get("harness", "the harness"))
    if rec.get("timed_out"):
        return ("%s did not finish within %ds. Offline runs have no executor to "
                "cut a loop short, so a program that waits forever waits "
                "forever; raise the timeout or run the untraced harness."
                % (name, rec.get("timeout")))
    if not rec.get("capture"):
        err = (rec.get("stderr") or "").strip().splitlines()
        return ("%s printed no capture block%s. Nothing can be read from this "
                "run." % (name, (" - " + err[0]) if err else ""))
    return ("%s produced a capture with %d instruction row(s), taken against the "
            "stand-in environment rather than a game."
            % (name, rec.get("instructions", 0)))


def _selftest():
    bad = []

    def eq(what, got, want):
        if got != want:
            bad.append("%s: %r, expected %r" % (what, got, want))

    # the capture block is the LAST one, so a payload that prints the marker
    # cannot have its own text read as the harness's
    t = ("%s\nfake: printed by the payload\n%s\n"
         "noise\n%s\nrun_ok: true\n---OPCODES---\n1;2;3;0;x\n%s\n"
         % (BEGIN, END, BEGIN, END))
    c = extract(t)
    eq("the last block wins", "run_ok: true" in c, True)
    eq("and not the payload's", "printed by the payload" in c, False)
    eq("rows counted", _count_ops(c), 1)
    eq("no block, no claim", extract("nothing here"), None)
    eq("an unterminated block is not a block",
       extract(BEGIN + "\nrun_ok: true\n"), None)

    # rows stop at the next section, so a later list is not counted as code
    c2 = ("%s\n---OPCODES---\n1;2;;0;x\n2;3;;0;y\n---SLICES---\n9:9:ok:9\n%s"
          % (BEGIN, END))
    eq("rows stop at the next section", _count_ops(c2), 2)

    # describe never reports a timeout or an empty run as a success
    d = describe({"harness": "h.lua", "timed_out": True, "timeout": 5})
    if "did not finish" not in d:
        bad.append("a timeout must be reported as one: %r" % d)
    d = describe({"harness": "h.lua", "capture": None, "stderr": "boom"})
    if "no capture" not in d or "boom" not in d:
        bad.append("an empty run must say so and carry the error: %r" % d)
    d = describe({"harness": "h.lua", "capture": "x", "instructions": 4})
    if "stand-in" not in d:
        bad.append("a successful offline run must still say it was a stand-in: "
                   "%r" % d)

    # a candidate that is not there, or not Luau, is rejected with a reason
    ok, why = probe(os.path.join(HERE, "definitely-not-here"))
    eq("a missing binary is rejected", ok, False)
    if "no file" not in why:
        bad.append("rejection should say why: %r" % why)
    ok, why = probe(sys.executable)      # a real binary that is not Luau
    eq("a non-Luau binary is rejected", ok, False)

    # find reports every path it tried even when it finds nothing
    path, report = find("/nonexistent/luau")
    if path is None and "/nonexistent/luau" not in report:
        bad.append("the report must name the paths tried: %r" % report[:120])

    # the built chunk must carry both halves and no stray return between them
    d = tempfile.mkdtemp(prefix="vmsmart-build-")
    try:
        h = os.path.join(d, "h.lua")
        with open(h, "w") as f:
            f.write("print('harness body')\n")
        built = build(h, d)
        with open(built, encoding="utf-8") as f:
            text = f.read()
        if "VMSMART_STANDIN" not in text or "harness body" not in text:
            bad.append("the built chunk is missing a half")
        if "\nreturn VMSMART_STANDIN\n" in text:
            bad.append("the stand-in's return would end the chunk before the "
                       "harness ran")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    print("localvm selftest %s" % ("ok" if not bad else "FAILURES"))
    for b in bad:
        print("  - %s" % b)
    return bad


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(1 if _selftest() else 0)
    p, report = find(sys.argv[1] if len(sys.argv) > 1 else None)
    print(report)
    if not p:
        print("\n" + where_to_put_one())
        raise SystemExit(1)
