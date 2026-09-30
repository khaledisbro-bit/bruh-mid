#!/usr/bin/env python3
"""
tracefmt.py - read a harness capture without knowing anything about the program.

A capture is a flat text stream. Sections announce themselves with ---NAME---
markers; a raw instruction dump has no markers at all. Every line is classified
by its SHAPE, never by what it says:

  instruction row   int ; int ; csv ; int ; text      (3..6 fields)
  constant row      TAG : text                        (single upper-case tag)
  call record       recv : method ( args )            or  NAME : arg
  scalar header     key : value                       at the top of the capture

No list of API names, service names or program strings appears anywhere in this
module, so the same parser reads any sample.
"""
import re

_ROW = re.compile(r"^(-?\d+);(-?\d+);([^;]*)"
                  r"(?:;(-?\d+))?(?:;([^;]*?))?(?:;(.*))?$")
_CONST = re.compile(r"^([A-Z]):(.*)$")
_CODEROW = re.compile(r"^(\d+):(.*)$")
_METHOD = re.compile(r"^([\w.]+):(\w+)\((.*)\)$")
_NAMED = re.compile(r"^([\w.]+):\s*(.+)$")
_SECTION = re.compile(r"^-{2,}([A-Z_]+)-{2,}$")
_BODY = re.compile(r"BEGIN_UNOBF_RESULT\n?(.*?)\n?END_UNOBF_RESULT", re.S)


class Capture:
    """One harness run. Sections are whatever the capture declared."""

    def __init__(self, text, name="capture"):
        self.name = name
        self.raw = text
        m = _BODY.search(text)
        self.body = m.group(1) if m else text
        self.sections = _split(self.body)
        self.headers = _headers(_header_lines(self.sections))
        self.rows = _rows(self.body)
        self.constants = _constants(self.sections)
        # One capture can hold two runs of the same payload, and their call
        # logs are written one after the other into the same section. Comparing
        # a reconstruction against both concatenated would count every call
        # twice, so the two are kept apart: `calls` are the ones from the run
        # the instructions came from, which is the run a reconstruction
        # describes, and `calls_after_retry` are what the second run added.
        before, after = _split_on_retry(self.sections.get("BEHAVIOR", []))
        self.calls, self.notes = _calls(before)
        self.calls_after_retry, notes2 = _calls(after)
        self.notes = self.notes + notes2
        self.code = _code(self.sections, self.body)
        self.prints = [l.split("PRINT:", 1)[1].strip()
                       for l in self.sections.get("PRINTS", []) if "PRINT:" in l]
        self.probe = _probe(self.sections)
        self.attempts = _attempts(self.body)
        self.harness_id = self.headers.get("harness_id")
        self.trace_verdict = self.headers.get("trace_verdict")
        self.run_error = _run_error(self.headers, self.body)
        self.rows_from_failed_run = _rows_from_failed_run(self.attempts,
                                                         len(self.rows))

    def has_instructions(self):
        return len(self.rows) > 0

    def why_no_instructions(self):
        """Why this capture carries no instructions.

        "The hook did not match" was being printed for every empty capture,
        which is one of three different things and the only one nobody can act
        on. The harness writes what it did into the behaviour log, so read it
        rather than assume.
        """
        notes = "\n".join(self.sections.get("BEHAVIOR", []))
        placed = "patched dispatch" in notes
        skipped = "left untraced" in notes
        if placed:
            return ("the trace hook WAS placed in this build's interpreter, "
                    "and then never fired. That is not a build this cannot "
                    "read - it is the hook being unreachable from where the "
                    "interpreter runs, which is a fault here and worth "
                    "reporting with this capture.")
        if skipped:
            return ("this run was asked to trace a different interpreter than "
                    "the one that ran the program. Run harness.lua on its own; "
                    "harness_chunk2.lua traces the next interpreter down and "
                    "produces nothing when there is only one.")
        return ("the trace hook never matched this build's dispatch loop, so "
                "no instruction was ever logged.")

    def summary(self):
        return ("%s: %d instruction rows, %d in the code array, %d constants, "
                "%d calls, %d prints, sections=%s"
                % (self.name, len(self.rows), len(self.code),
                   len(self.constants), len(self.calls), len(self.prints),
                   ",".join(k or "head" for k in self.sections)))


def _split(body):
    out, cur = {}, ""
    out[cur] = []
    for ln in body.splitlines():
        m = _SECTION.match(ln.strip())
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
            continue
        out[cur].append(ln)
    return out


def _header_lines(sections):
    """Where a capture's scalar headers actually are.

    They were read from the top of the capture only, and on a real capture they
    are not there: the harness interrogates its environment first, which opens
    ---PROBE---, and nothing closes it before the run writes run_ok, loaded and
    mode. So every real capture parsed with NO headers at all, and "run_ok was
    never stated" is indistinguishable from "run_ok: false" - which is how a
    clean run came to be reported as a run that stopped early.

    The harness now opens ---RUN--- for them. PROBE is still read, because
    captures made before that marker existed are still on disk and still worth
    reading; its own rows are tag<TAB>value and carry no colon, so they cannot
    be mistaken for headers.
    """
    out = []
    for key in ("", "RUN", "PROBE"):
        out.extend(sections.get(key, []))
    return out


def _headers(lines):
    h = {}
    for ln in lines:
        ln = ln.strip()
        if not ln or _ROW.match(ln):
            continue
        m = re.match(r"^([a-z_]+)\s*[:=]\s*(.*)$", ln)
        if m:
            h[m.group(1)] = m.group(2).strip()
    return h


def _rows(body):
    """Instruction rows, wherever they appear (marked section or raw dump).
    Each row: dict(i, pc, opcode, operands, sp, value)."""
    out = []
    for ln in body.splitlines():
        s = ln.strip()
        if not s or s.startswith("-"):
            if not _ROW.match(s):
                continue
        m = _ROW.match(s)
        if not m:
            continue
        ops = []
        for x in m.group(3).split(","):
            if x == "":
                continue
            try:
                ops.append(int(x))
            except ValueError:
                ops.append(x)
        sp = int(m.group(4)) if m.group(4) is not None else None
        val = m.group(5) if m.group(5) not in (None, "") else None
        out.append({"i": len(out), "pc": int(m.group(1)),
                    "opcode": int(m.group(2)), "operands": ops,
                    "sp": sp, "value": val})
    return out


_ATTEMPT = re.compile(
    r"^attempt(\d+):\s*mode=(\S+)\s+loaded=(\S+)\s+run_ok=(\S+)\s+"
    r"return_type=(\S+)\s+instructions=(\d+)\s+constants=(\d+)")
_ATTEMPT_ERR = re.compile(r"^attempt(\d+)_error:\s*(.*)$")


def _attempts(body):
    """The harness's own account of how many times it ran the payload.

    One capture can now hold two runs of the same payload: traced, and - when
    the traced run raised while the dispatch patch was in - untraced. Reading
    the headline alone would describe one of them and lose the other, and which
    one it lost would depend on which finished.
    """
    out, byi = [], {}
    for ln in body.splitlines():
        t = ln.strip()
        m = _ATTEMPT.match(t)
        if m:
            rec = {"n": int(m.group(1)), "mode": m.group(2),
                   "loaded": m.group(3) == "true", "ok": m.group(4) == "true",
                   "return_type": m.group(5), "instructions": int(m.group(6)),
                   "constants": int(m.group(7)), "error": None}
            out.append(rec)
            byi[rec["n"]] = rec
            continue
        m = _ATTEMPT_ERR.match(t)
        if m and int(m.group(1)) in byi:
            byi[int(m.group(1))]["error"] = m.group(2).strip()
    return out


def _rows_from_failed_run(attempts, nrows):
    """Whether the instructions in this capture came from a run that raised.

    This is the trap the retry opens. The headline outcome is the BEST attempt,
    so a capture whose untraced retry finished reads run_ok: true - while every
    instruction row in it came from the traced attempt, which died. Believing
    the headline would mean treating a handful of rows as a whole program.
    """
    if not attempts or nrows == 0:
        return False
    producers = [a for a in attempts if a["instructions"] > 0]
    if not producers:
        return False
    return all(not a["ok"] for a in producers)


def _run_error(headers, body):
    """What the harness said about the payload's own run.

    A run that raised after a handful of instructions still produces a capture
    that parses, and everything downstream then describes those few
    instructions as if they were the program. The error is in the capture; it
    just was not being read."""
    ok = str(headers.get("run_ok", "")).strip().lower().startswith("true")
    err = None
    for ln in body.splitlines():
        t = ln.strip()
        if t.startswith("error:"):
            err = t[len("error:"):].strip()
            break
    if ok and not err:
        return None
    return err or "the run did not finish"


def stopped_under_the_trace(capture):
    """Whether the dispatch patch is what ended this run - and how we know.

    There used to be one answer here, and it was a suspicion: the hook went in,
    the run raised a few instructions later, and a build that checks its own
    source would look exactly like that. Settling it needed the same payload run
    again without the patch, which meant a second file and a person choosing
    between them. That choice went wrong twice, and a capture from the wrong
    file is indistinguishable from the right one at a glance, so the wrong
    conclusion got drawn with nothing to contradict it.

    The harness now runs both itself and writes down the comparison. When it
    did, this reports a FINDING and says which way it went. When it did not,
    the old suspicion still stands, worded as one.
    """
    v = getattr(capture, "trace_verdict", None) or ""
    a = getattr(capture, "attempts", None) or []
    if v.startswith("patch_caught"):
        first = a[0] if a else {}
        return ("FINDING - this build objects to being traced. The harness ran "
                "the same payload twice in one session: WITH the dispatch loop "
                "patched it raised (%s), and WITHOUT the patch it finished. "
                "Editing the interpreter's source is what it reacted to, so "
                "this is a self-checking build.\n"
                "  What that costs: the %d instruction row(s) here come from "
                "the traced attempt, the one that died. They are real, and they "
                "are not the whole program. The untraced attempt recovered "
                "constants and behaviour but logs no instructions, because "
                "logging them is the thing this build catches."
                % (first.get("error") or "no error recorded",
                   len(capture.rows)))
    if v.startswith("not_the_trace"):
        return ("FINDING - the trace is not what ended this run. The harness "
                "ran the same payload with the dispatch patch and without it, "
                "in one session, and it raised both times. The failure is the "
                "program's own: a missing service, a guard the environment "
                "does not satisfy, or a path this executor cannot take.")
    if capture.run_error is None:
        return None
    notes = "\n".join(capture.sections.get("BEHAVIOR", []))
    if "patched dispatch" not in notes:
        return None
    if len(capture.rows) > 200:
        return None
    return ("The trace hook went into this build's interpreter and the script "
            "raised %d instruction(s) later - too few for a program that just "
            "loaded an interpreter. A build that checks its own source would "
            "behave exactly like this, because patching the dispatch loop "
            "changes that source.\n"
            "  This is a suspicion, not a finding, because the capture holds "
            "only the traced run. The harness settles it by running the payload "
            "again unpatched in the same session and writing a trace_verdict "
            "line; this capture has none, so it came from a harness older than "
            "that or from a run where the patch never went in." % len(capture.rows))


def _probe(sections):
    """What the harness could still tell about itself.

    The harness interrogates its own environment before running the payload
    and writes down the answers, so the shields are measured rather than
    assumed. Rows are `tag<TAB>value`."""
    out = {}
    for ln in sections.get("PROBE", []):
        if "\t" not in ln:
            continue
        tag, _, val = ln.partition("\t")
        out[tag.strip()] = val.strip()
    return out


def _code(sections, body):
    """The interpreter's whole instruction array, when the capture carries it.

    A trace shows the instructions that RAN. The array holds every instruction
    the program has, and without it coverage can only be measured against what
    was executed, which flatters itself: a run that touches a tenth of the
    program looks complete. Rows are `pc:operands`, and a row the run never
    reached is exactly what makes this worth reading."""
    out = {}
    lines = sections.get("CODE")
    if lines is None:
        # a bare dump, written by the harness beside the printed block
        if ";" in body[:400] or "---" in body[:200]:
            return out
        lines = body.splitlines()
    for ln in lines:
        m = _CODEROW.match(ln.strip())
        if not m:
            continue
        ops = []
        for x in m.group(2).split(","):
            x = x.strip()
            if x == "":
                ops.append(None)
                continue
            try:
                ops.append(int(x))
            except ValueError:
                ops.append(x)
        out[int(m.group(1))] = ops
    return out


def _constants(sections):
    """Resolver dump entries as (tag, text) in resolution order. The tag is
    whatever single letter the harness used; we do not assume which letters
    exist."""
    out = []
    for key in ("RESOLVED", "CONSTANTS", ""):
        for ln in sections.get(key, []):
            m = _CONST.match(ln.strip())
            if m:
                out.append((m.group(1), m.group(2)))
    return out


# The harness writes this line into the behaviour log when it re-runs the
# payload with the dispatch patch left out. It is the boundary between two runs'
# worth of records in one section.
_RETRY_MARK = "[retry: same payload"


def _split_on_retry(lines):
    """Behaviour lines before the retry, and after it."""
    for i, ln in enumerate(lines):
        if _RETRY_MARK in ln:
            return lines[:i], lines[i + 1:]
    return lines, []


def _calls(lines):
    """Structured call records from the proxied-environment log, by syntax only.
    Returns (calls, notes). A call is dict(recv, method, args, raw)."""
    calls, notes = [], []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        m = _METHOD.match(s)
        if m:
            calls.append({"recv": m.group(1), "method": m.group(2),
                          "args": _args(m.group(3)), "raw": s})
            continue
        m = _NAMED.match(s)
        if m and " " not in m.group(1):
            calls.append({"recv": None, "method": m.group(1),
                          "args": _args(m.group(2)), "raw": s})
            continue
        notes.append(s)
    return calls, notes


def _args(text):
    """Split an argument preview at top-level commas (it may hold {a=1, b=2})."""
    out, depth, cur, q = [], 0, "", None
    for ch in text:
        if q:
            cur += ch
            if ch == q:
                q = None
            continue
        if ch in "\"'":
            q = ch; cur += ch; continue
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip()); cur = ""; continue
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def combine(caps):
    """Fold several files of ONE run into a single capture.

    An executor writes a run out in pieces: the console block carries the calls
    and the constants but only the first few thousand instructions, while the
    instruction dump beside it carries all of them. They describe the same
    execution, so analysing them separately would throw away half the evidence
    in each.

    Where two pieces hold the same instructions, the longer one wins - one is
    the truncated copy of the other. Where they hold different instructions,
    they are joined in order. Calls, constants and printed output are unioned,
    keeping the order each piece recorded."""
    if not caps:
        return None
    base = caps[0]
    for other in caps[1:]:
        base.rows = _longer(base.rows, other.rows)
        if other.code and not base.code:
            base.code = other.code
        elif other.code:
            base.code.update(other.code)
        base.calls = _union(base.calls, other.calls, lambda c: c["raw"])
        # The retry's records stay on their own side of the fold too. Merging
        # them into `calls` here would undo the split and count them twice.
        base.calls_after_retry = _union(base.calls_after_retry,
                                       other.calls_after_retry,
                                       lambda c: c["raw"])
        base.constants = _union(base.constants, other.constants, lambda c: c)
        base.prints = _union(base.prints, other.prints, lambda p: p)
        base.headers.update(other.headers)
        # The pieces are one run written out in parts, so the text is one text.
        # Keeping only the first piece's body left every fact derived from it -
        # the attempts, the error, which run the rows came from - describing one
        # piece and claiming to describe the run.
        base.body = base.body + "\n" + other.body
        base.attempts = _attempts(base.body)
        base.harness_id = base.headers.get("harness_id")
        base.trace_verdict = base.headers.get("trace_verdict")
        base.run_error = _run_error(base.headers, base.body)
        base.rows_from_failed_run = _rows_from_failed_run(base.attempts,
                                                          len(base.rows))
        for k, v in other.sections.items():
            base.sections.setdefault(k, []).extend(v)
        base.name = base.name + "+" + other.name
    for i, r in enumerate(base.rows):
        r["i"] = i
    return base


def _key(rows):
    return [(r["pc"], r["opcode"], tuple(r["operands"])) for r in rows]


def _longer(a, b):
    if not a:
        return b
    if not b:
        return a
    ka, kb = _key(a), _key(b)
    if kb[:len(ka)] == ka:
        return b
    if ka[:len(kb)] == kb:
        return a
    return a + b


def _union(a, b, key):
    seen = {key(x) for x in a}
    out = list(a)
    for x in b:
        if key(x) not in seen:
            seen.add(key(x))
            out.append(x)
    return out


def load(paths, one_run=False):
    """Read captures.

    Each argument is one run. A run written out in pieces - the printed block
    and the instruction dump beside it - is given as those pieces joined by +,
    so several runs each in two files stay separate runs:

        --trace run1a.txt+run1b.txt run2a.txt+run2b.txt

    one_run treats every argument as a piece of a single run instead."""
    import os
    caps = []
    for p in paths:
        parts = [q for q in p.split("+") if q]
        group = []
        for q in parts:
            with open(q, encoding="latin1") as f:
                group.append(Capture(f.read(), os.path.basename(q)))
        caps.append(combine(group) if len(group) > 1 else group[0])
    if one_run and len(caps) > 1:
        return [combine(caps)]
    return caps


def expand(paths):
    """The actual files behind the arguments, for checking they exist."""
    out = []
    for p in paths:
        out += [q for q in p.split("+") if q]
    return out


def _selftest():
    """Captures whose SHAPE has caught this parser out before.

    Every case here is a layout a real harness produced, not a layout invented
    to be easy. The first one is the important one: the run's headers arriving
    inside ---PROBE--- because nothing closed that section. The reference
    fixtures put headers at the very top, so they never exercised it, and a
    clean run was being reported as a run that stopped early.
    """
    bad = []

    def check(what, got, want):
        if got != want:
            bad.append("%s: %r, expected %r" % (what, got, want))

    # 1) headers after an unclosed PROBE section - the real pre-RUN layout
    c = Capture("BEGIN_UNOBF_RESULT\n---PROBE---\nclock_is_monotonic\ttrue\n"
                "loaded: true\nrun_ok: true  return_type: nil\nmode: universal\n"
                "---OPCODES---\n1;2;3;0;x\nEND_UNOBF_RESULT")
    check("clean run under an unclosed PROBE", c.run_error, None)
    check("probe survives the header scan", c.probe.get("clock_is_monotonic"),
          "true")

    # 2) the same, failing
    c = Capture("BEGIN_UNOBF_RESULT\n---PROBE---\nloaded: true\n"
                "run_ok: false  return_type: nil\nerror: boom\n"
                "---OPCODES---\n1;2;3;0;x\nEND_UNOBF_RESULT")
    check("failed run under an unclosed PROBE", c.run_error, "boom")

    # 3) headers in their own RUN section, single attempt
    c = Capture("BEGIN_UNOBF_RESULT\n---PROBE---\nx\ty\n---RUN---\n"
                "harness_id: untraced\nattempts: 1\n"
                "attempt1: mode=untraced loaded=true run_ok=true "
                "return_type=nil instructions=0 constants=3\n"
                "loaded: true\nrun_ok: true  return_type: nil\n"
                "---OPCODES---\nEND_UNOBF_RESULT")
    check("harness_id read", c.harness_id, "untraced")
    check("one attempt parsed", len(c.attempts), 1)
    check("no rows, so nothing came from a failed run",
          c.rows_from_failed_run, False)
    check("clean single run", c.run_error, None)

    # 4) two attempts: the traced one died, the untraced one finished. The
    #    headline says run_ok true and every row still came from the dead one.
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nharness_id: traced+retry\n"
                "attempts: 2\n"
                "attempt1: mode=traced loaded=true run_ok=false return_type=nil "
                "instructions=9 constants=1\n"
                "attempt1_error: it raised\n"
                "attempt2: mode=untraced loaded=true run_ok=true "
                "return_type=table instructions=0 constants=402\n"
                "run_ok: true  return_type: table\n"
                "trace_verdict: patch_caught -- x\n"
                "---OPCODES---\n1;2;3;0;x\nEND_UNOBF_RESULT")
    check("retry headline is not an error", c.run_error, None)
    check("rows came from the attempt that died", c.rows_from_failed_run, True)
    check("attempt error kept", c.attempts[0]["error"], "it raised")
    note = stopped_under_the_trace(c)
    if not note or not note.startswith("FINDING"):
        bad.append("a settled trace verdict should read as a finding, got %r"
                   % (note or "")[:40])

    # 5) both attempts died: the trace is exonerated, the run still failed
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nattempts: 2\n"
                "attempt1: mode=traced loaded=true run_ok=false return_type=nil "
                "instructions=9 constants=1\n"
                "attempt1_error: a\n"
                "attempt2: mode=untraced loaded=true run_ok=false "
                "return_type=nil instructions=0 constants=1\n"
                "attempt2_error: b\n"
                "run_ok: false  return_type: nil\nerror: a\n"
                "trace_verdict: not_the_trace -- x\n"
                "---OPCODES---\n1;2;3;0;x\nEND_UNOBF_RESULT")
    check("both-failed run still reports the error", c.run_error, "a")
    note = stopped_under_the_trace(c) or ""
    if "not what ended this run" not in note:
        bad.append("an exonerated trace should say so, got %r" % note[:60])

    # 6) no attempt block at all (an older harness): the old suspicion stands
    c = Capture("BEGIN_UNOBF_RESULT\n---PROBE---\nrun_ok: false\nerror: e\n"
                "---BEHAVIOR---\n  [patched dispatch a/b/c sp=d]\n"
                "---OPCODES---\n1;2;3;0;x\nEND_UNOBF_RESULT")
    note = stopped_under_the_trace(c) or ""
    if "suspicion, not a finding" not in note:
        bad.append("an unsettled capture should stay a suspicion, got %r"
                   % note[:60])
    check("no attempts, so no claim about which run made the rows",
          c.rows_from_failed_run, False)

    print("tracefmt selftest %s" % ("ok" if not bad else "FAILURES"))
    for b in bad:
        print("  - %s" % b)
    return bad


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        raise SystemExit(1 if _selftest() else 0)
    for c in load(sys.argv[1:]):
        print(c.summary())
