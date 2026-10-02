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
import glob
import os
import re
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
    # a release asset is often left under the name it was downloaded as, so
    # anything named luau-something is worth trying too. The ones that are a
    # different tool are rejected by name later, with that as the reason.
    for root, where in ((here, "beside the package"),
                        (os.getcwd(), "in the working directory"),
                        (os.path.join(here, "bin"), "in bin/"),
                        (os.path.join(here, "tools"), "in tools/")):
        for hit in sorted(glob.glob(os.path.join(root, "luau*"))):
            if os.path.isfile(hit):
                out.append((hit, where + ", by name"))
    seen, uniq = set(), []
    for p, why in out:
        q = os.path.abspath(p)
        if q not in seen:
            seen.add(q)
            uniq.append((p, why))
    return uniq


# The Luau project ships more than one binary. Only `luau` runs a script; the
# others parse, analyse or compile and exit. Their names say so, so a candidate
# whose name is one of them is rejected for what it is rather than after a run
# whose output would be misread.
_NOT_A_RUNNER = ("ast", "analyze", "analyse", "compile", "reduce", "bytecode")


def _wrong_tool(path):
    """The reason this binary is not the one that runs scripts, or None."""
    stem = os.path.splitext(os.path.basename(path))[0].lower()
    for part in re.split(r"[-_.]", stem):
        if part in _NOT_A_RUNNER:
            return ("this is luau-%s, a different tool in the same release - it "
                    "prints a %s and exits, it does not run a script" %
                    (part, "parse tree" if part == "ast" else "report"))
    return None


def _not_a_program(path):
    """The reason the file cannot start as a program, or None.

    Windows answers a file that is named .exe but is not a Windows program with
    "The system cannot execute the specified program", which says nothing about
    why. The first two bytes do: a real one begins MZ. A download that was saved
    as an HTML error page, or a zip that was never unpacked, does not."""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError as exc:
        return "could not be read (%s)" % (exc.strerror or exc.__class__.__name__)
    if not head:
        return "the file is empty - the download did not finish"
    if path.lower().endswith(".exe") and head[:2] != b"MZ":
        if head[:2] == b"PK":
            return ("this is still a zip, not the program inside it - unpack "
                    "luau-windows.zip and use the luau.exe from it")
        return ("this is not a Windows program: it does not start with MZ. The "
                "download was saved as something else (an error page, or a "
                "partial file)")
    if head[:2] == b"MZ" and not path.lower().endswith(".exe"):
        return None
    return None


def probe(path, timeout=30):
    """Make a candidate prove it runs Luau. Returns (ok, why)."""
    if not os.path.isfile(path):
        return False, "no file there"
    wrong = _wrong_tool(path)
    if wrong:
        return False, wrong
    broken = _not_a_program(path)
    if broken:
        return False, broken
    # os.access(X_OK) is a real answer on POSIX and close to meaningless on
    # Windows, where almost any existing file passes it, so it only decides here.
    if os.name != "nt" and not os.access(path, os.X_OK):
        return False, "not executable (chmod +x it)"
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
        return False, "could not be started - %s" % _why_it_would_not_start(exc)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _why_it_would_not_start(exc):
    """The OS message, plus the cause behind the ones that hide it.

    Windows reports a binary built for another architecture, and one whose
    runtime DLLs are absent, with the same sentence. Saying which two things to
    check beats repeating the sentence back."""
    msg = (getattr(exc, "strerror", None) or str(exc) or
           exc.__class__.__name__).strip()
    win = getattr(exc, "winerror", None)
    if win in (193, 216):
        return ("%s (WinError %d). The file is not a program this Windows runs: "
                "wrong architecture for this machine, or the download is not "
                "the binary. Download the x64 Windows asset and unpack it."
                % (msg, win))
    if win == 2:
        return "%s (WinError 2). Nothing is at that path." % msg
    if win == 5:
        return ("%s (WinError 5). Windows refused it: the file is blocked after "
                "download (Properties, then Unblock), or a policy stops it."
                % msg)
    if win:
        return "%s (WinError %d)" % (msg, win)
    return msg


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
    lines = [
        "Download a `luau` binary from the Luau project's releases and put it "
        "beside this package, on PATH, or name it in $VMSMART_LUAU. It is one "
        "file and needs no install.",
        "Take the runner, not its neighbours: the release also ships luau-ast, "
        "luau-analyze and luau-compile, and none of those runs a script.",
    ]
    if os.name == "nt":
        lines.append(
            "On Windows: unpack the zip (do not run the exe from inside it), "
            "take the x64 build, and if Windows refuses to start it open "
            "Properties and tick Unblock. `luau.exe --version` is the quickest "
            "way to see whether the file starts at all.")
    return "\n".join(lines)


def build(harness, out_dir, sidecar_text=None):
    """The stand-in and the harness as one chunk, written where it will run.

    They are concatenated rather than chained with dofile/require, because which
    of those a given Luau build exposes is itself a host question and this is one
    less of them. The sidecar, when there is one, goes FIRST: it is data the
    stand-in reads, so it has to exist before the stand-in does.
    """
    with open(STANDIN, encoding="utf-8") as f:
        pre = f.read()
    with open(harness, encoding="utf-8", errors="replace") as f:
        body = f.read()
    # the stand-in ends in a `return`, which would end the chunk
    pre = pre.replace("\nreturn VMSMART_STANDIN\n", "\n")
    path = os.path.join(out_dir, "offline_harness.luau")
    with open(path, "w", encoding="utf-8") as f:
        if sidecar_text:
            f.write("-- ---- host decompression, computed before the run ----\n")
            f.write(sidecar_text)
        f.write(pre + "\n-- ---- harness ----\n" + body)
    return path


def run(luau, harness, timeout=DEFAULT_TIMEOUT, cwd=None, sidecar_text=None):
    """Run one harness offline and bring back everything it said."""
    cwd = cwd or os.path.dirname(os.path.abspath(harness)) or "."
    script = build(harness, cwd, sidecar_text)
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

    # a different tool from the same release is rejected for what it is, and
    # the runner itself is never caught by that rule
    for name in ("luau-ast.exe", "luau-analyze", "luau_compile.exe",
                 "/x/y/luau-ast"):
        if _wrong_tool(name) is None:
            bad.append("%s is not the runner and must be rejected" % name)
    if _wrong_tool("luau-ast.exe") and "parse tree" not in _wrong_tool("luau-ast.exe"):
        bad.append("the luau-ast rejection should say what it prints instead")
    for name in ("luau", "luau.exe", "/opt/luau", "luau-win64.exe",
                 "C:/tools/luau.exe"):
        if _wrong_tool(name) is not None:
            bad.append("%s is the runner and must not be rejected by name: %s"
                       % (name, _wrong_tool(name)))

    # a file that cannot start as a program is diagnosed from its first bytes,
    # before anything is handed to the OS
    d = tempfile.mkdtemp(prefix="vmsmart-head-")
    try:
        def wrote(name, data):
            q = os.path.join(d, name)
            with open(q, "wb") as f:
                f.write(data)
            return q

        z = wrote("luaux.exe", b"PK\x03\x04rest")
        why = _not_a_program(z)
        if not why or "zip" not in why:
            bad.append("a zip named .exe must be named as one: %r" % why)
        if "zip" not in (probe(z)[1] or ""):
            bad.append("probe must stop at the zip rather than try to run it")
        e = wrote("empty.exe", b"")
        if "empty" not in (_not_a_program(e) or ""):
            bad.append("an unfinished download must be reported as empty")
        h = wrote("page.exe", b"<!DOCTYPE html><html>")
        why = _not_a_program(h)
        if not why or "MZ" not in why:
            bad.append("a non-program named .exe must be reported: %r" % why)
        real = wrote("luau.exe", b"MZ\x90\x00")
        if _not_a_program(real) is not None:
            bad.append("a file that starts MZ must pass the header check")
        # a POSIX binary has no .exe and is not judged by that rule
        posix = wrote("luau", b"\x7fELF")
        if _not_a_program(posix) is not None:
            bad.append("a POSIX binary must pass the header check")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # the two Windows errors that hide their cause get the cause spelled out
    def oserr(code):
        exc = OSError(8, "The system cannot execute the specified program")
        exc.winerror = code
        return _why_it_would_not_start(exc)

    for code, want in ((216, "architecture"), (193, "architecture"),
                       (5, "Unblock"), (2, "Nothing is at that path")):
        got = oserr(code)
        if want not in got:
            bad.append("WinError %d should point at %s: %r" % (code, want, got))
    plain = _why_it_would_not_start(OSError("something else"))
    if "WinError" in plain:
        bad.append("an error with no winerror must not claim one: %r" % plain)

    # the advice names the trap the release layout sets
    if "luau-ast" not in where_to_put_one():
        bad.append("the advice should say the other binaries are not the runner")

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
