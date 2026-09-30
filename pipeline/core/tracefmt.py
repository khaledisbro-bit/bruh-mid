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
        self.harness_engine = _int(self.headers.get("harness_engine"))
        self.code_arrays = _int(self.headers.get("code_arrays"))
        self.protos_seen = _int(self.headers.get("protos_seen"))
        self.slices = _slices(self.sections.get("SLICES", []))
        self.recheck = _recheck(self.body)
        self.env_missing = [l.strip() for l in
                            self.sections.get("ENVMISSING", []) if l.strip()]
        self.row_notes = _row_notes(self.body)
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


_ATTEMPT = re.compile(r"^attempt(\d+):\s*(.*)$")
_ATTEMPT_ERR = re.compile(r"^attempt(\d+)_error:\s*(.*)$")
_KV = re.compile(r"(\w+)=(\S*)")


def _attempts(body):
    """The harness's own account of how many times it ran the payload.

    One capture can hold several runs of the same payload: the harness takes one
    of its own edits back out on each round that raised, until the payload
    finishes or there is nothing left to remove. Reading the headline alone would
    describe one round and lose the rest, and which one it lost would depend on
    which finished.

    Fields are read as key=value pairs, in any order, because the set of fields
    grew once already and a capture written by an older harness still has to
    parse.
    """
    out, byi = [], {}
    for ln in body.splitlines():
        t = ln.strip()
        m = _ATTEMPT_ERR.match(t)
        if m:
            if int(m.group(1)) in byi:
                byi[int(m.group(1))]["error"] = m.group(2).strip()
            continue
        m = _ATTEMPT.match(t)
        if not m or "=" not in m.group(2):
            continue
        kv = dict(_KV.findall(m.group(2)))
        rec = {"n": int(m.group(1)),
               "mode": kv.get("mode", "?"),
               "level": _int(kv.get("level")),
               "loaded": kv.get("loaded") == "true",
               "ok": kv.get("run_ok") == "true",
               "return_type": kv.get("return_type", "nil"),
               "instructions": _int(kv.get("instructions")) or 0,
               "constants": _int(kv.get("constants")) or 0,
               "resolver": kv.get("resolver") == "true",
               "dispatch": kv.get("dispatch") == "true",
               "error": None}
        out.append(rec)
        byi[rec["n"]] = rec
    return out


_RECHECK = re.compile(r"^code_recheck:\s*(.*)$")


def _recheck(body):
    """What each instruction array held at the end compared with when it was
    first seen.

    A row that appeared or changed means the array rewrites itself as it runs, so
    a dump taken at one moment describes that moment. Reading it as the program's
    instructions is then a claim the capture cannot support."""
    out = []
    for ln in body.splitlines():
        m = _RECHECK.match(ln.strip())
        if not m:
            continue
        kv = dict(_KV.findall(m.group(1)))
        if "arr" not in kv:
            out.append({"arr": None, "raw": m.group(1).strip()})
            continue
        out.append({"arr": _int(kv.get("arr")),
                    "rows_first": _int(kv.get("rows_first")) or 0,
                    "rows_last": _int(kv.get("rows_last")) or 0,
                    "same": _int(kv.get("same")) or 0,
                    "changed": _int(kv.get("changed")) or 0,
                    "appeared": _int(kv.get("appeared")) or 0,
                    "vanished": _int(kv.get("vanished")) or 0,
                    "raw": m.group(1).strip()})
    return out


def _row_notes(body):
    """The sixth field of an instruction row: what the row itself was when the
    interpreter read something that was not an instruction, and which array it
    came from. An instruction whose row is nil used to be recorded as an
    instruction with no operands, which is what a real no-operand instruction
    looks like - so the one moment worth seeing was written down as ordinary."""
    out = {}
    for ln in body.splitlines():
        m = _ROW.match(ln.strip())
        if not m or not m.group(6):
            continue
        kv = {}
        for part in m.group(6).split("|"):
            k, _, v = part.partition("=")
            if k:
                kv[k.strip()] = v.strip()
        if kv:
            out[int(m.group(1))] = kv
    return out


def _slices(lines):
    """Every slice the payload asked the deserialiser's accessor for.

    Rows are name:index:ok|MISSING:count. The accessor returns nil for an index
    the data does not carry, and its caller indexes that nil straight away - so a
    MISSING row is the request a run of this family dies on, named at last."""
    out = []
    for ln in lines:
        parts = ln.strip().split(":")
        if len(parts) < 3:
            continue
        out.append({"accessor": parts[0], "index": _int(parts[1]),
                    "present": parts[2] == "ok",
                    "count": _int(parts[3]) if len(parts) > 3 else None})
    return out


def _int(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


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
        # The verdict line names which edit it was; repeating the harness's own
        # words beats guessing it was the dispatch patch, which it need not be.
        detail = v.split("--", 1)[1].strip() if "--" in v else v
        raised = [x for x in a if not x["ok"]]
        return ("FINDING - this build objects to being edited. %s\n"
                "  So it is a self-checking build.\n"
                "  What that costs: the %d instruction row(s) here come from a "
                "round that died - only the traced round logs instructions, and "
                "the round that finished is a later one. They are real, and "
                "they are not the whole program. %s"
                % (detail, len(capture.rows),
                   ("The round that finished recovered constants and behaviour "
                    "but no instructions, because logging them is the thing "
                    "this build catches." if raised else "")))
    if v.startswith(("not_the_patches", "not_the_trace")):
        rounds = ", ".join("%s (%s)" % (x["mode"],
                                       x["error"] or "no error recorded")
                           for x in a) or "one round"
        deepest = a[-1] if a else {}
        # What the LAST round still carried has to come from the capture, not
        # from the absence of a field. A capture written before the rounds
        # recorded their patch level says nothing about it, and reading silence
        # as "nothing was edited" is a claim made from missing data.
        # The conclusion has to be as strong as the rounds, and no stronger.
        # An unedited round that raised rules the harness out. A capture that
        # never reached one rules out only the edits it did remove, and saying
        # otherwise would be the same mistake this whole mechanism exists to
        # stop: a verdict reached past the evidence.
        lvl = deepest.get("level")
        clean = (lvl == 0) or (lvl is not None
                               and not deepest.get("resolver")
                               and not deepest.get("dispatch"))
        if clean:
            return ("FINDING - the harness's own edits are not what ended this "
                    "run. It ran the same payload and took one edit back out on "
                    "each round that raised: %s. The last round did not edit "
                    "the chunk at all and it raised too.\n"
                    "  What is left: the program itself, or something this "
                    "environment does not give it. The probe section says what "
                    "a traced run could notice here, and the behaviour log says "
                    "what the program asked for before it stopped - that is "
                    "where to look next, not at the trace." % rounds)
        removed = "the dispatch logger" if any(x.get("dispatch") for x in a) \
            else "the edit it could remove"
        return ("PARTLY SETTLED - the harness ran the same payload again with "
                "%s taken out, and it raised both times: %s. So that edit is "
                "not what ended the run.\n"
                "  Not settled: this capture never reached a round with the "
                "chunk untouched - the constant resolver was still rewritten, "
                "or the capture does not record what the round carried. The "
                "current harness keeps removing edits until nothing is left, so "
                "a fresh capture answers this; this one does not."
                % (removed, rounds))
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


def what_the_arrays_did(capture):
    """Whether the instructions in this capture describe the program.

    Two things stop them doing that, and both are facts the capture now carries
    rather than suspicions. One: a build of this class runs a prototype per
    function, each with its own instruction array, so ONE array is one function.
    Two: some of those arrays decrypt their rows as they run, so a row read at
    the start is not the row the interpreter later executes.

    Returns a list of lines, empty when the capture says neither happened."""
    L = []
    n = getattr(capture, "code_arrays", None)
    if n is not None and n > 1:
        L.append("This run handed over %d separate instruction arrays. A build "
                 "of this class keeps one per function, so the array in the CODE "
                 "section is ONE function's instructions, not the program's. "
                 "Coverage below is measured against that one." % n)
    pn = getattr(capture, "protos_seen", None)
    if pn:
        L.append("The prototype makers were hooked, and %d prototype(s) were "
                 "handed over as they were BUILT. That reaches functions this "
                 "run never called, whose instructions no trace can show - "
                 "coverage below counts them as never entered rather than as "
                 "absent." % pn)
    moved = [r for r in (getattr(capture, "recheck", None) or [])
             if r.get("arr") is not None
             and (r["changed"] or r["appeared"])]
    for r in moved:
        L.append("Array %d rewrote itself while it ran: %d row(s) changed and "
                 "%d appeared between the first read and the end (%d rows then, "
                 "%d now). Its rows are decrypted as earlier instructions "
                 "execute, so a dump is a snapshot and an instruction the run "
                 "never reached has no readable row at all."
                 % (r["arr"], r["changed"], r["appeared"],
                    r["rows_first"], r["rows_last"]))
    sl = getattr(capture, "slices", None) or []
    if sl:
        missing = [r for r in sl if not r["present"]]
        counts = [r["count"] for r in sl if r["count"] is not None]
        L.append("The deserialiser's accessor was watched: %d request(s), %d of "
                 "them for an index the data does not carry%s."
                 % (len(sl), len(missing),
                    (", out of %d entries" % counts[0]) if counts else ""))
        if missing:
            first = missing[0]
            L.append("The first request that came back empty was %s(%s)%s. The "
                     "accessor returns nil there and its caller indexes that nil "
                     "immediately, which is the \"attempt to index nil with "
                     "number\" this run reports. So the run does not die of a "
                     "guard or a check: it asks for a slice that is not in the "
                     "payload it was given."
                     % (first["accessor"], first["index"],
                        (" of %d" % first["count"]) if first["count"] else ""))
            L.append("Where to look next: what produced the payload. An index "
                     "past the end means the data arrived shorter than the "
                     "program expects - a decode or decompress step that gave "
                     "back less than it should, not anything the interpreter "
                     "does with it.")
    notes = getattr(capture, "row_notes", None) or {}
    nonrows = {pc: kv["row"] for pc, kv in notes.items() if "row" in kv}
    if nonrows:
        sample = sorted(nonrows.items())[:6]
        L.append("At %d traced instruction(s) the interpreter read something "
                 "that was not an instruction row: %s. That is the interpreter "
                 "about to index a value it cannot index, which is what this "
                 "run's error says happened."
                 % (len(nonrows),
                    ", ".join("pc %d = %s" % (pc, v) for pc, v in sample)
                    + (", ..." if len(nonrows) > 6 else "")))
        # Why the row is absent, from what the capture recorded rather than from
        # a guess. A dumped array holding a full row at the same number is not a
        # contradiction once the key is looked at.
        bykey = [(pc, kv) for pc, kv in sorted(notes.items())
                 if "row" in kv and "as_number" in kv]
        if bykey:
            pc, kv = bykey[0]
            if kv.get("as_number") == "present":
                L.append("At pc %d the row is absent under the key the "
                         "interpreter used, and PRESENT under the same number as "
                         "an integer (the counter's type here is %s%s). The "
                         "array is not missing the instruction - it is being "
                         "asked for it with the wrong kind of key."
                         % (pc, kv.get("pctype", "unknown"),
                            ", and not integral" if "pc_not_integral" in kv
                            else ""))
            else:
                L.append("At pc %d the row is absent under the key the "
                         "interpreter used AND under that number as an integer%s"
                         ", so the instruction is genuinely not in the array. "
                         "The counter's type is %s. An index past the end means "
                         "the array is shorter than the program expects."
                         % (pc,
                            (" (the array holds %s)" % kv["arrlen"])
                            if "arrlen" in kv else "",
                            kv.get("pctype", "unknown")))
    arrs = sorted({kv["arr"] for kv in notes.values() if "arr" in kv})
    if len(arrs) > 1:
        L.append("The traced instructions came from %d different arrays (%s), "
                 "so their numbers are not one sequence and a jump between them "
                 "is not a jump inside one function."
                 % (len(arrs), ", ".join(arrs)))
    return L


def env_did_not_have(capture):
    """Names the payload read that this environment did not carry.

    Not errors: a script testing for a feature reads nil on purpose. But a run
    that dies indexing nil has to be explained by something, and the report kept
    ending at "the program, or something this environment does not give it" with
    nothing to say about which."""
    m = getattr(capture, "env_missing", None) or []
    if not m:
        return []
    return ["The payload read %d name(s) this environment does not carry. Any "
            "of them coming back nil is normal on its own - a script testing "
            "for a feature reads nil on purpose - but a run that died indexing "
            "nil has to be explained, and this is the list:" % len(m),
            "  " + ", ".join(m[:60]) + (", ..." if len(m) > 60 else "")]


def which_harness(capture, current):
    """Whether this capture was written by the harness in this package.

    It normally is not, and that is not anyone's mistake: the new harness is
    written at the same moment the report is read, so the capture in hand came
    from the copy already on disk. Three captures in a row were read as evidence
    about the current code when they came from an older harness, and what the
    report concluded from them was limited by a harness that had already been
    replaced.

    So the capture says which build wrote it, and this says what that means. It
    never guesses from which features the output happens to have."""
    got = getattr(capture, "harness_engine", None)
    if got == current:
        return None
    if got is None:
        return ("This capture was written by a harness older than the one in "
                "this package (it does not stamp its build, which harnesses "
                "from engine 42 on do). Everything below is read from it as it "
                "stands - but where it says a question is not settled, the "
                "current harness.lua may already settle it. Re-run the "
                "harness.lua beside this report before concluding anything "
                "about what the harness could not reach.")
    if got < current:
        return ("This capture was written by engine %d; this package is engine "
                "%d. It is read as it stands, and nothing below is invented to "
                "fill the gap - but a question this capture leaves open may "
                "already be answered by the harness.lua beside this report."
                % (got, current))
    return ("This capture was written by engine %d, which is NEWER than this "
            "package (engine %d). It may hold sections this reader does not "
            "know about; those are ignored rather than guessed at."
            % (got, current))


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
        base.harness_engine = _int(base.headers.get("harness_engine"))
        base.code_arrays = _int(base.headers.get("code_arrays"))
        base.protos_seen = _int(base.headers.get("protos_seen"))
        base.slices = _slices(base.sections.get("SLICES", []))
        base.recheck = _recheck(base.body)
        base.env_missing = _union(base.env_missing, other.env_missing,
                                  lambda x: x)
        base.row_notes = _row_notes(base.body)
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
    # Two rounds that both raised rule out the edit that was removed and NOTHING
    # more: this capture never reached a round with the chunk untouched, so the
    # verdict must stop short of exonerating the harness.
    if not note.startswith("PARTLY SETTLED"):
        bad.append("two rounds without an untouched one should be partly "
                   "settled, got %r" % note[:60])
    if "not what ended the run" not in note:
        bad.append("it should still rule out the edit it removed, got %r"
                   % note[:80])

    # 6) three rounds, all raised: the harness removed every edit it could
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\n"
                "harness_id: traced->resolver-only->unpatched\nattempts: 3\n"
                "attempt1: mode=traced level=2 loaded=true run_ok=false "
                "return_type=nil instructions=9 constants=1 resolver=true "
                "dispatch=true\nattempt1_error: a\n"
                "attempt2: mode=resolver-only level=1 loaded=true run_ok=false "
                "return_type=nil instructions=0 constants=1 resolver=true "
                "dispatch=false\nattempt2_error: a\n"
                "attempt3: mode=unpatched level=0 loaded=true run_ok=false "
                "return_type=nil instructions=0 constants=1 resolver=false "
                "dispatch=false\nattempt3_error: a\n"
                "run_ok: false  return_type: nil\nerror: a\n"
                "trace_verdict: not_the_patches -- x\n"
                "---OPCODES---\n1;2;3;0;x\nEND_UNOBF_RESULT")
    check("three rounds parsed", len(c.attempts), 3)
    check("level read", c.attempts[2]["level"], 0)
    check("the deepest round edited nothing", c.attempts[2]["resolver"], False)
    check("run still failed", c.run_error, "a")
    note = stopped_under_the_trace(c) or ""
    if "not what ended this run" not in note:
        bad.append("an exonerated set of edits should say so, got %r"
                   % note[:60])
    if "did not edit the chunk at all" not in note:
        bad.append("the report should say the last round was unedited, got %r"
                   % note[:120])

    # 7) the resolver rewrite was the culprit, not the dispatch logger
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nattempts: 3\n"
                "attempt1: mode=traced level=2 loaded=true run_ok=false "
                "return_type=nil instructions=9 constants=1 resolver=true "
                "dispatch=true\nattempt1_error: a\n"
                "attempt2: mode=resolver-only level=1 loaded=true run_ok=false "
                "return_type=nil instructions=0 constants=1 resolver=true "
                "dispatch=false\nattempt2_error: a\n"
                "attempt3: mode=unpatched level=0 loaded=true run_ok=true "
                "return_type=table instructions=0 constants=9 resolver=false "
                "dispatch=false\n"
                "run_ok: true  return_type: table\n"
                "trace_verdict: patch_caught -- the resolver rewrite is what "
                "it reacted to.\n"
                "---OPCODES---\n1;2;3;0;x\nEND_UNOBF_RESULT")
    check("a finished later round is not an error", c.run_error, None)
    check("rows still came from a round that died",
          c.rows_from_failed_run, True)
    note = stopped_under_the_trace(c) or ""
    if "resolver rewrite" not in note:
        bad.append("the report should name the edit the harness named, got %r"
                   % note[:120])

    # 8) no attempt block at all (an older harness): the old suspicion stands
    c = Capture("BEGIN_UNOBF_RESULT\n---PROBE---\nrun_ok: false\nerror: e\n"
                "---BEHAVIOR---\n  [patched dispatch a/b/c sp=d]\n"
                "---OPCODES---\n1;2;3;0;x\nEND_UNOBF_RESULT")
    note = stopped_under_the_trace(c) or ""
    if "suspicion, not a finding" not in note:
        bad.append("an unsettled capture should stay a suspicion, got %r"
                   % note[:60])
    check("no attempts, so no claim about which run made the rows",
          c.rows_from_failed_run, False)

    # 9) several arrays, one of them rewriting itself, a row that was not a row,
    #    and names the environment did not carry. Each of these used to be
    #    thrown away before it reached the report.
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: false\nerror: e\n"
                "code_arrays=3\n"
                "code_recheck: arr=1 rows_first=2108 rows_last=2108 same=2102 "
                "changed=6 appeared=0 vanished=0\n"
                "code_recheck: arr=2 rows_first=40 rows_last=51 same=40 "
                "changed=0 appeared=11 vanished=0\n"
                "env_missing=2\n---ENVMISSING---\nbuffer\nsomename\n"
                "---OPCODES---\n2;354;;0;nil;arr=1\n"
                "2010;0;;0;nil;row=nil|arr=2\nEND_UNOBF_RESULT")
    check("array count read", c.code_arrays, 3)
    check("both rechecks read", len(c.recheck), 2)
    check("a changed array is seen", c.recheck[0]["changed"], 6)
    check("an appeared row is seen", c.recheck[1]["appeared"], 11)
    check("env names read", c.env_missing, ["buffer", "somename"])
    check("a non-row is recorded as what it was",
          c.row_notes.get(2010, {}).get("row"), "nil")
    check("an ordinary row carries only its array",
          c.row_notes.get(2, {}).get("arr"), "1")
    said = " ".join(what_the_arrays_did(c))
    for want in ("3 separate instruction arrays", "rewrote itself",
                 "was not an instruction row", "2 different arrays"):
        if want not in said:
            bad.append("the array report should say %r, got %r"
                       % (want, said[:120]))
    env = " ".join(env_did_not_have(c))
    if "buffer" not in env:
        bad.append("the environment report should name what was missing")

    # 10) a capture that says none of that must claim none of it
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: true\n"
                "---OPCODES---\n1;2;3;0;x\nEND_UNOBF_RESULT")
    check("no array count claimed", c.code_arrays, None)
    check("no recheck claimed", c.recheck, [])
    check("no environment claim", env_did_not_have(c), [])
    check("no array claim", what_the_arrays_did(c), [])

    # 11) the slice log and the key probe - the two facts that turn "it died
    #     indexing nil" into a named request
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: false\nerror: e\n"
                "slice_requests: 2\ncode_arrays=1\n"
                "---SLICES---\noS:1:ok:3\noS:4:MISSING:3\n"
                "---OPCODES---\n2010;0;;0;nil;row=nil|pctype=number|"
                "as_number=absent|arrlen=2108|arr=1\nEND_UNOBF_RESULT")
    check("both slice requests read", len(c.slices), 2)
    check("the missing one is marked", c.slices[1]["present"], False)
    check("its index is kept", c.slices[1]["index"], 4)
    said = " ".join(what_the_arrays_did(c))
    for want in ("oS(4) of 3", "not in the payload it was given",
                 "genuinely not in the array", "shorter than the program"):
        if want not in said:
            bad.append("the slice report should say %r, got %r"
                       % (want, said[:160]))

    # the other way round: absent under the interpreter's key, present as an
    # integer. That is a key-type fault, not a missing instruction, and saying
    # the wrong one of those sends the reader after the wrong thing entirely.
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: false\nerror: e\n"
                "---OPCODES---\n2010;0;;0;nil;row=nil|pctype=string|"
                "as_number=present|arrlen=2108|arr=1\nEND_UNOBF_RESULT")
    said = " ".join(what_the_arrays_did(c))
    if "wrong kind of key" not in said or "string" not in said:
        bad.append("a key-type fault should be named as one, got %r"
                   % said[:160])
    if "genuinely not in the array" in said:
        bad.append("a present-as-integer row must not be called absent")

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
