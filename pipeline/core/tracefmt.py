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
        # Rows past the point where the stand-in's invented values entered the
        # program's own arithmetic are not evidence about the program, and the
        # report says so. Saying so and then reconstructing from them anyway
        # would make the report decoration, so they are cut here, once, and what
        # was cut is reported.
        self.fiction_at_row = _int(self.headers.get("derived_arithmetic_at_row"))
        self.fiction_at_behavior = _int(
            self.headers.get("derived_arithmetic_at_behavior"))
        self.rows_dropped_as_fiction = 0
        if self.fiction_at_row and self.fiction_at_row > 0:
            keep = self.fiction_at_row - 1
            if keep < len(self.rows):
                self.rows_dropped_as_fiction = len(self.rows) - keep
                self.rows_after_fiction = self.rows[keep:]
                self.rows = self.rows[:keep]
        self.constants = _constants(self.sections)
        # One capture can hold two runs of the same payload, and their call
        # logs are written one after the other into the same section. Comparing
        # a reconstruction against both concatenated would count every call
        # twice, so the two are kept apart: `calls` are the ones from the run
        # the instructions came from, which is the run a reconstruction
        # describes, and `calls_after_retry` are what the second run added.
        # The behaviour log is cut at the boundary too, for the same reason the
        # rows are: a service call or an instance created by a program that is
        # already computing with values this package invented is not something
        # the program would necessarily have done in a game. Counting those into
        # "services it asked for" put the stand-in's consequences in the report
        # as the program's behaviour.
        beh = self.sections.get("BEHAVIOR", [])
        fb = _int(self.headers.get("derived_arithmetic_at_behavior"))
        self.behaviour_set_aside = 0
        self.behaviour_after_fiction = []
        if fb is not None and 0 <= fb < len(beh):
            self.behaviour_set_aside = len(beh) - fb
            self.behaviour_after_fiction = beh[fb:]
            beh = beh[:fb]
        before, after = _split_on_retry(beh)
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
        self.environment = self.headers.get("environment")
        self.code_arrays = _int(self.headers.get("code_arrays"))
        self.protos_seen = _int(self.headers.get("protos_seen"))
        self.slices = _slices(self.sections.get("SLICES", []))
        self.jumps = _jumps(self.sections.get("JUMPS", []))
        self.checks = _checks(self.sections.get("CHECKS", []))
        self.conds = _conds(self.sections.get("CONDS", []))
        self.block_rows = _blockrows(self.sections.get("BLOCKS", []))
        self.pctables = _pctables(self.sections.get("PCTABLES", []))
        self.standin_lines = [l.strip() for l in
                              self.sections.get("STANDIN", []) if l.strip()]
        self.derived_arithmetic = 0
        self.standin_limit_hit = False
        for l in self.standin_lines:
            m = re.match(r"derived_arithmetic: (\d+)", l)
            if m:
                self.derived_arithmetic = int(m.group(1))
            if "stopped answering at its own limit" in l:
                self.standin_limit_hit = True
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
        which is one of four different things and the only one nobody can act
        on. The harness says what it did in its own headers, so read those
        first: `dispatch_patched` is the harness's answer to this exact
        question. The behaviour log is the second source, and it is capped at
        120 lines, so a long run can push the patch note out of the capture -
        reading only the log turned a patched run into "never matched".
        """
        notes = "\n".join(self.sections.get("BEHAVIOR", []))
        patched = self.headers.get("dispatch_patched")
        placed = patched == "true" or "patched dispatch" in notes
        skipped = "left untraced" in notes
        err = self.run_error or ""
        if not self.headers and not notes:
            return ("this capture has no headers and no behaviour log, so the "
                    "harness stopped before it reported anything about the "
                    "chunk. Send the whole output of the run, not only the "
                    "block: the reason is above the block, not in it.")
        if self.headers.get("loaded") == "false":
            return ("the chunk never loaded in this run%s, so the interpreter "
                    "never started and there was nothing to log. This is a "
                    "load failure, not a build the trace cannot read."
                    % (" (" + err.splitlines()[0] + ")" if err else ""))
        if placed:
            return ("the trace hook WAS placed in this build's interpreter, "
                    "and then never fired%s. That is not a build this cannot "
                    "read - it is the hook being unreachable from where the "
                    "interpreter runs, or the run ending before the first "
                    "instruction, which is a fault here and worth reporting "
                    "with this capture."
                    % (", and the run raised: " + err.splitlines()[0]
                       if err else ""))
        if skipped:
            return ("this run was asked to trace a different interpreter than "
                    "the one that ran the program. Run harness.lua on its own; "
                    "harness_chunk2.lua traces the next interpreter down and "
                    "produces nothing when there is only one.")
        if patched == "false":
            return ("the harness reports dispatch_patched: false, so the trace "
                    "hook never matched this build's dispatch loop and no "
                    "instruction was ever logged.")
        return ("this capture does not say whether the hook was placed: there "
                "is no dispatch_patched header and no patch note in the "
                "behaviour log, so nothing here answers why there are no "
                "instructions. The run output above the block does.")

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
        note = m.group(6) if m.lastindex and m.lastindex >= 6 else ""
        # The pending count, recorded and NOT folded into the pointer.
        #
        # The deferred writes of this family leave values for slots the producing
        # handler has already counted: the pointer at the loop top is right, and
        # only the array contents are a step behind. Adding the count to the
        # pointer made the measured arities disagree MORE, which is how that was
        # established - so the count is kept for the lifter, which needs to know
        # the top slot's value is pending, and the pointer is left alone.
        pend = None
        if note:
            pm = re.search(r"pend=(-?\d+)", note)
            if pm:
                pend = int(pm.group(1))
        row = {"i": len(out), "pc": int(m.group(1)),
               "opcode": int(m.group(2)), "operands": ops,
               "sp": sp, "value": val, "pending": pend}
        out.append(row)
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


def _checks(lines):
    """The integrity checks that fired, in the order they fired.

    `site<N>:count=<c>:pc=<p>` - the site number is the check's position in the
    interpreter's own text, so the FIRST line is the first check this build
    failed, which is the only one whose cause is still visible.
    """
    out = []
    for ln in lines:
        m = re.match(r"site(\d+):count=(-?\d+):pc=(\S+)\s*$", ln.strip())
        if m:
            out.append({"site": int(m.group(1)), "count": int(m.group(2)),
                        "pc": m.group(3)})
    return out


def _conds(lines):
    """`<pc>:site<N>:<condition text> -> name=value name=value`."""
    out = []
    for ln in lines:
        m = re.match(r"(\S+):site(\d+):(.*?) -> (.*)$", ln.strip())
        if m:
            out.append({"pc": m.group(1), "site": int(m.group(2)),
                        "text": m.group(3).strip(), "values": m.group(4).strip()})
    return out


def _blockrows(lines):
    """`<pc>:site<N>:<type>:<len>:row_at_pc=<yes|no>`."""
    out = []
    for ln in lines:
        m = re.match(r"(\S+):site(\d+):(\w+):(-?\d+):row_at_pc=(yes|no)\s*$",
                     ln.strip())
        if m:
            out.append({"pc": m.group(1), "site": int(m.group(2)),
                        "kind": m.group(3), "len": int(m.group(4)),
                        "has_row": m.group(5) == "yes"})
    return out


def _pctables(lines):
    """`<name>: <n> key(s), <k> not numbers, first <m> in order: a,b,c`."""
    out = []
    for ln in lines:
        # `in order:` with nothing after it is the empty-table case, and the
        # strip has already taken the trailing space off, so the space after the
        # colon cannot be required.
        m = re.match(r"(\w+): (\d+) key\(s\), (\d+) not numbers, "
                     r"first (\d+) in order:\s*(.*)$", ln.strip())
        if m:
            keys = [int(x) for x in m.group(5).split(",") if x.strip().lstrip("-").isdigit()]
            out.append({"name": m.group(1), "total": int(m.group(2)),
                        "not_numbers": int(m.group(3)), "keys": keys})
        else:
            m2 = re.match(r"(\w+): could not be read - (.*)$", ln.strip())
            if m2:
                out.append({"name": m2.group(1), "total": -1,
                            "not_numbers": 0, "keys": [],
                            "error": m2.group(2)})
    return out


def _jumps(lines):
    """Every branch target this run resolved, and how.

    Rows are decoder:from_pc:operand:table|COMPUTED:target. A COMPUTED row means
    the decoder's lookup table had no entry for that operand, so the target was
    derived from a base instead - and a derived target can land outside every
    block the interpreter knows about."""
    out = []
    for ln in lines:
        p = ln.strip().split(":")
        if len(p) != 5 or p[3] not in ("table", "COMPUTED"):
            continue
        out.append({"decoder": p[0], "from": _int(p[1]), "operand": _int(p[2]),
                    "looked_up": p[3] == "table", "target": _int(p[4])})
    return out


def _slices(lines):
    """Every slice the payload asked the deserialiser's accessor for.

    Rows are name:index:ok|MISSING:count. The accessor returns nil for an index
    the data does not carry, and its caller indexes that nil straight away - so a
    MISSING row is the request a run of this family dies on, named at last."""
    out = []
    for ln in lines:
        parts = ln.strip().split(":")
        # Strict about the shape. A loose reading of "anything with two colons"
        # swallowed run headers that had landed in this section by accident and
        # reported `attempt1_error` as a slice request, which is nonsense stated
        # with a straight face.
        if len(parts) != 4:
            continue
        idx, cnt = _int(parts[1]), _int(parts[3])
        if idx is None or cnt is None or parts[2] not in ("ok", "MISSING"):
            continue
        if not re.match(r"^[\w.]+$", parts[0]):
            continue
        out.append({"accessor": parts[0], "index": idx,
                    "present": parts[2] == "ok", "count": cnt})
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


def the_standin_answered(capture):
    """What a stand-in run made up, and where the trace stops being evidence.

    A stand-in exists so a program can be watched without the host it was written
    for. It earns that by answering the host's questions, and every answer is a
    fact about this package rather than about Roblox. Two of those answers matter
    more than the others:

    - a datatype or a field answered where the host would have answered
      differently sends the program down a branch it might not have taken;
    - ARITHMETIC on an answered value produces another answered value, and from
      the first of those the program is computing with numbers nothing gave it.

    So the second is reported as a boundary. Rows after it are a reading of this
    package, not of the program, and a reconstruction built from them would be a
    reconstruction of the stand-in.
    """
    lines = getattr(capture, "standin_lines", None) or []
    if not lines:
        return None
    types = [l.split(": ", 1)[1] for l in lines
             if l.startswith("datatype answered: ")]
    fields = [l for l in lines if l.startswith("field answered: ")]
    out = ["WHAT THE STAND-IN ANSWERED FOR"]
    if types:
        out.append("  %d host datatype(s) this environment does not have were "
                   "answered for: %s%s"
                   % (len(types), ", ".join(types[:12]),
                      " and more" if len(types) > 12 else ""))
    if fields:
        out.append("  %d field path(s) on host objects were answered. The build "
                   "reads them to decide whether it is running somewhere real."
                   % len(fields))
    fb = getattr(capture, "fiction_at_behavior", None)
    aside = getattr(capture, "behaviour_set_aside", 0) or 0
    if fb is not None and aside:
        # the behaviour log is a list of entries, not of rows, so the count of
        # entries at the boundary is what divides it
        out.append("  Of what the program was recorded doing, the first %d "
                   "entries came before the boundary and are counted below. The "
                   "other %d are set aside: they were made by a program already "
                   "computing with invented values, so a service call or an "
                   "instance created there may be one it would never have made "
                   "in a game." % (fb, aside))
    dropped = getattr(capture, "rows_dropped_as_fiction", 0) or 0
    if dropped:
        out.append("  %d instruction row(s) after that point have been left out "
                   "of everything below: the analysis reads only the rows from "
                   "before the stand-in's answers reached the program's "
                   "arithmetic." % dropped)
    n = getattr(capture, "derived_arithmetic", 0) or 0
    if n:
        out.append("  BOUNDARY - %d arithmetic operation(s) were performed on "
                   "values this stand-in invented. From the first one the "
                   "program is computing with numbers no host gave it, so the "
                   "instructions after that point describe this package and not "
                   "the program. Anything read from them - constants, calls, a "
                   "reconstruction - is evidence about the stand-in." % n)
        out.append("  What that leaves standing: everything BEFORE the first "
                   "such operation, and the fact that the program got that far.")
    if getattr(capture, "standin_limit_hit", False):
        out.append("  The stand-in stopped answering at its own limit, so this "
                   "run ended on this package rather than on the program.")
    if getattr(capture, "enum_values_derived", False):
        out.append("  Enum values here are derived, not the host's.")
    return "\n".join(out)


def the_program_ended_itself(capture):
    """Whether the interpreter stopped the run on purpose, and on what.

    This family carries one three-statement block in more than a thousand
    places: bump a counter, stir a value, and once the counter passes a
    threshold read an entry of a table that is not there. That read is the
    error every capture of this build has carried, and reporting it as "the
    interpreter read something that was not an instruction" put the blame on
    the trace. The harness now numbers those sites and records which one fired
    first, so the sentence can name the cause instead of the symptom.
    """
    checks = getattr(capture, "checks", None) or []
    if not checks:
        return None
    first = checks[0]
    lines = ["FINDING - this build ended the run itself. Its interpreter carries "
             "a check that, once it has failed often enough, reads an entry of a "
             "table that does not exist - which is the error this capture "
             "reports."]
    lines.append("  The first check to fail was site %d, at counter %s, with the "
                 "failure count at %d. %d check(s) fired in all."
                 % (first["site"], first["pc"], first["count"], len(checks)))
    sites = []
    for c in checks:
        if c["site"] not in sites:
            sites.append(c["site"])
    if len(sites) > 1:
        lines.append("  Sites involved, in order: %s."
                     % ", ".join(str(x) for x in sites[:8]))
    # the decision that came before it, if the harness recorded one
    conds = getattr(capture, "conds", None) or []
    if conds:
        c = conds[0]
        lines.append("  Before that, at counter %s, the interpreter refused to "
                     "produce the instruction table it reads from. The condition "
                     "it tested was `%s`, and the values it read were: %s."
                     % (c["pc"], c["text"], c["values"]))
    rows = getattr(capture, "block_rows", None) or []
    nil_rows = [r for r in rows if r["kind"] != "table"]
    if nil_rows:
        lines.append("  So the instruction table was %s at counter %s, and every "
                     "counter after that read no instruction. The branch that "
                     "got there is not what failed; the refusal is."
                     % (nil_rows[0]["kind"], nil_rows[0]["pc"]))
    lines.append("  What this means for the capture: the rows above are the "
                 "instructions that ran BEFORE the refusal. They are real. "
                 "Nothing after it is the program.")
    return "\n".join(lines)


def what_the_interpreter_had(capture):
    """The tables the loop looks up by its counter, and what was in them.

    An empty one is the finding. These builds keep the program in one table and
    its verification data in others, and a run that ends early with a full
    program table and an empty verification table says where to look next -
    which no instruction trace can.
    """
    tabs = getattr(capture, "pctables", None) or []
    if not tabs:
        return None
    lines = ["WHAT THE INTERPRETER HAD TO WORK WITH",
             "  Read once, at the loop's first turn, so these are the tables as "
             "the run started. One that fills as the program goes - a cache - is "
             "empty here for that reason and not for any other."]
    biggest = None
    for t in sorted(tabs, key=lambda x: -x["total"]):
        if t.get("error"):
            lines.append("  %s: could not be read - %s" % (t["name"], t["error"]))
            continue
        if t["total"] == 0:
            lines.append("  %s: EMPTY. The loop looks this up by its counter and "
                         "there is nothing in it." % t["name"])
            continue
        span = ""
        if t["keys"]:
            span = " first key %d" % t["keys"][0]
        lines.append("  %s: %d entries%s" % (t["name"], t["total"], span))
        if biggest is None or t["total"] > biggest[1]:
            biggest = (t["name"], t["total"])
    if biggest:
        lines.append("  The largest is %s with %d entries, which is the size of "
                     "the program this interpreter was given."
                     % (biggest[0], biggest[1]))
    empties = [t["name"] for t in tabs if t["total"] == 0]
    if empties:
        lines.append("  %s came back empty while the program table did not. A "
                     "loop that needs an entry there gets nil for every counter, "
                     "and this build treats that as a reason to stop."
                     % ", ".join(empties))
    return "\n".join(lines)


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


def trace_was_filtered(capture):
    """Whether this capture holds the instructions that ran, or a subset.

    This family dispatches with a chain of equality tests on the opcode and a
    bit-tree in the final else. A logger anchored in that else sees only the
    instructions whose opcode fell through every handler - which looks exactly
    like a short run, because what comes back is a handful of rows with gaps.

    Captures written before engine 51 were anchored there. Their instruction
    counts, their jumps and their gaps are all properties of which handler each
    instruction missed, not of what the program did. A capture that says
    src=looptop was taken where every instruction passes."""
    notes = getattr(capture, "row_notes", None) or {}
    if not notes:
        return []
    tops = sum(1 for kv in notes.values() if kv.get("src") == "looptop")
    if tops:
        return []
    srcs = {kv.get("src") for kv in notes.values() if kv.get("src")}
    if not srcs:
        return []
    return ["This capture's instructions were logged from inside the dispatch "
            "chain, not at the loop top. In this family the chain tests the "
            "opcode against one handler after another, so a logger there records "
            "ONLY the instructions that missed every test. The rows below are "
            "real, and the count, the jumps and the gaps between them are "
            "properties of which handler each instruction missed - not of what "
            "the program did. A capture from engine 51 or later is taken where "
            "every instruction passes, and says src=looptop."]


def opcode_grouping_doubt(capture):
    """Whether instructions grouped under one decoded opcode really are one.

    The interpreter's decode turns a per-instruction encoded field into a small
    opcode number, and that field differs per program counter BY DESIGN - so two
    rows sharing a decoded opcode are expected to differ there, and a difference
    proves nothing.

    What does count is the operands. One opcode takes one shape of operand row.
    When rows grouped under a single decoded opcode carry different NUMBERS of
    operands, either the opcode is context-dependent or the decode did not
    separate them - and everything measured per opcode afterwards is measured
    across instructions that are not the same instruction.

    This is an observation with its evidence, not a verdict. Saying which of the
    two it is needs the interpreter's handlers, not this."""
    byop = {}
    for r in capture.rows:
        byop.setdefault(r["opcode"], []).append(r)
    out = []
    for op, rows in sorted(byop.items()):
        widths = {}
        for r in rows:
            widths.setdefault(len(r["operands"]), []).append(r["pc"])
        if len(widths) < 2:
            continue
        shape = "; ".join(
            "%d operand(s) at pc %s" % (w, ",".join(str(p) for p in sorted(set(pcs))[:6]))
            for w, pcs in sorted(widths.items()))
        out.append((op, len(rows), shape))
    if not out:
        return []
    L = ["Opcode grouping is not established for %d of the decoded opcode(s). "
         "One opcode takes one shape of operand row, and these do not:" % len(out)]
    for op, n, shape in out:
        L.append("  opcode %s covers %d instruction(s) with mixed shapes - %s"
                 % (op, n, shape))
    L.append("Either those opcodes are context-dependent, or the decode did not "
             "separate them. Anything measured per opcode below is measured "
             "across instructions that may not be the same instruction. Which of "
             "the two it is needs the interpreter's own handlers to say, and "
             "this capture does not settle it.")
    return L


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
    jp = getattr(capture, "jumps", None) or []
    if jp:
        bad = [j for j in jp if not j["looked_up"]]
        L.append("The jump decoder was watched: %d branch target(s) resolved, %d "
                 "of them NOT found in its lookup table."
                 % (len(jp), len(bad)))
        if bad:
            f = bad[0]
            L.append("The first miss was at pc %s: operand %s is not in the "
                     "table, so the target was computed from a base instead and "
                     "came out as %s. A computed target is not a branch the "
                     "program wrote - it is what this decoder does when it does "
                     "not recognise the operand, and it can land outside every "
                     "block the interpreter knows about."
                     % (f["from"], f["operand"], f["target"]))
            L.append("Where to look next: why the table has no entry for that "
                     "operand. Either the table was not fully built when the "
                     "jump ran, or the operand was decoded with the wrong key - "
                     "both are upstream of the interpreter, not in it.")
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
    # A row the harness read from the array, where its own loop variable said
    # something else. That is worth saying out loud: it is the difference between
    # this tool misreading the run and the run misbehaving.
    disagreed = [pc for pc, kv in sorted(notes.items())
                 if "hook_var_disagrees" in kv]
    if disagreed:
        L.append("At %d instruction(s) the dispatch loop's own variable did not "
                 "hold the row the array holds at that number, so the row was "
                 "read from the array instead (pc %s%s). The reading is sound; "
                 "what it says is that this tool's hook cannot rely on that "
                 "variable in this build, and it no longer does."
                 % (len(disagreed), ", ".join(str(p) for p in disagreed[:8]),
                    ", ..." if len(disagreed) > 8 else ""))
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
        # Why the row is absent, from what the capture recorded rather than
        # from a guess.
        bykey = [(pc, kv) for pc, kv in sorted(notes.items())
                 if "row" in kv and "as_number" in kv]
        if bykey:
            pc, kv = bykey[0]
            if kv.get("as_number") == "present":
                # This is the shape of a capture from a harness that read the
                # wrong variable: the row is in the array and the logger saw nil.
                # It is a fault in the harness, and calling it a fault in the
                # build sent this work down the wrong road for several rounds.
                L.append("At pc %d the row is PRESENT in the array under that "
                         "number, and the harness that wrote this capture logged "
                         "nil for it. That is this tool's own hook reading a "
                         "variable that is not the array - not the build doing "
                         "anything. The operands at these instructions are "
                         "recoverable and this capture does not carry them; a "
                         "capture from engine 48 or later reads the row from the "
                         "array and does." % pc)
            else:
                L.append("At pc %d the row is absent from the array under that "
                         "number%s, so the instruction is genuinely not there. "
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


def taken_against_a_standin(capture):
    """Whether this capture came from a game or from a stand-in.

    This used to say the stand-in answers every field with nothing, so nothing is
    invented. That stopped being true: a build that fingerprints the host walks
    its datatypes, and a stand-in that answers nothing never gets past that, so
    the stand-in now answers structurally and writes down every answer. The
    sentence here has to match what the file does, or the report is reassuring
    about something that is no longer the case. What the stand-in answered, and
    where its answers entered the program's own arithmetic, is in
    the_standin_answered.
    """
    env = getattr(capture, "environment", None)
    if not env or not str(env).startswith("standin"):
        return []
    out = ["This capture was taken OFFLINE, against a stand-in environment "
           "(%s) rather than a Roblox client. It is not the same evidence as a "
           "capture from a game: services resolve so calls are recorded, and "
           "where the program asks the host something this package cannot "
           "answer truthfully, it answers structurally and writes the answer "
           "down." % env]
    n = getattr(capture, "derived_arithmetic", 0) or 0
    if n:
        out.append("Those answers reached the program's own arithmetic %d "
                   "time(s) in this run, so read the boundary below before "
                   "anything else here." % n)
    return out


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
        base.jumps = _jumps(base.sections.get("JUMPS", []))
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

    # The four sections the watches write, and the two reports that read them.
    # Each case is the shape the real harness produced on a real build.
    cap = Capture(
        "BEGIN_UNOBF_RESULT\n---RUN---\ndispatch_patched: true\nloaded: true\n"
        "run_ok: false  return_type: nil\nerror: attempt to index nil with number\n"
        "---PCTABLES---\n"
        "BQ: 3077 key(s), 0 not numbers, first 60 in order: 1,2,3\n"
        "YN: 0 key(s), 0 not numbers, first 0 in order: \n"
        "BH: 1043 key(s), 0 not numbers, first 60 in order: 1,19,23\n"
        "---CHECKS---\nsite3:count=0:pc=2668\nsite259:count=1:pc=2669\n"
        "---CONDS---\n2667:site2: not Yw and (Bm~=0 or BR[3]~=0)  -> Yw=nil Bm=531573\n"
        "---BLOCKS---\n1:site4:table:8:row_at_pc=yes\n2667:site2:nil:-1:row_at_pc=no\n"
        "---OPCODES---\n1;344;;0;nil\nEND_UNOBF_RESULT")
    check("checks parsed", len(cap.checks), 2)
    check("the first check is the first one", cap.checks[0]["site"], 3)
    check("its counter is kept", cap.checks[0]["pc"], "2668")
    check("conditions parsed", len(cap.conds), 1)
    check("the condition text survives", cap.conds[0]["text"],
          "not Yw and (Bm~=0 or BR[3]~=0)")
    check("block rows parsed", len(cap.block_rows), 2)
    check("a nil array is read as one", cap.block_rows[1]["kind"], "nil")
    check("pc tables parsed", len(cap.pctables), 3)
    t = the_program_ended_itself(cap)
    if not t or "ended the run itself" not in t:
        bad.append("a capture with integrity checks must name the cause: %r" % t)
    if t and "site 3" not in t:
        bad.append("the first site has to be named: %r" % t)
    if t and "not Yw and" not in t:
        bad.append("the condition before the refusal belongs in the finding: %r" % t)
    w = what_the_interpreter_had(cap)
    if not w or "YN: EMPTY" not in w:
        bad.append("an empty table is the finding and must be stated: %r" % w)
    if w and "3077" not in w:
        bad.append("the program size should come from the largest table: %r" % w)
    # a capture with none of those sections says nothing rather than guessing
    plain = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nloaded: true\n"
                    "---OPCODES---\n1;344;;0;nil\nEND_UNOBF_RESULT")
    if the_program_ended_itself(plain) is not None:
        bad.append("with no checks recorded there is no finding to report")
    if what_the_interpreter_had(plain) is not None:
        bad.append("with no tables recorded there is nothing to describe")
    # a table the watch could not read is reported as that, not as empty
    cap2 = Capture("BEGIN_UNOBF_RESULT\n---PCTABLES---\n"
                   "BQ: could not be read - refused\n---OPCODES---\nEND_UNOBF_RESULT")
    w2 = what_the_interpreter_had(cap2)
    if not w2 or "could not be read" not in w2:
        bad.append("an unreadable table must not be reported as empty: %r" % w2)

    # the behaviour log is cut at the boundary as well
    bcut = Capture(
        "BEGIN_UNOBF_RESULT\n---RUN---\nenvironment: standin/robloxenv\n"
        "derived_arithmetic_at_row: 3\nderived_arithmetic_at_behavior: 2\n"
        "---BEHAVIOR---\nGetService: Players  -> real service\n"
        "Instance.new: Folder\nGetService: HttpService  -> real service\n"
        "Instance.new: Part\n"
        "---STANDIN---\nderived_arithmetic: 5 operation(s), first at add(1,2)\n"
        "---OPCODES---\n1;10;;0;nil\n2;11;;0;nil\n"
        "3;12;;0;nil\nEND_UNOBF_RESULT")
    check("calls before the boundary are kept", len(bcut.calls), 2)
    check("the rest are set aside", bcut.behaviour_set_aside, 2)
    tb = the_standin_answered(bcut)
    if not tb or "set aside" not in tb:
        bad.append("the behaviour cut has to be stated: %r" % tb)
    joined = " ".join(str(c) for c in bcut.calls)
    if "HttpService" in joined:
        bad.append("a call from after the boundary must not be counted as the "
                   "program's behaviour")

    # the row cut: rows at and after the boundary are not read by the analysis
    cut = Capture(
        "BEGIN_UNOBF_RESULT\n---RUN---\nenvironment: standin/robloxenv\n"
        "derived_arithmetic_at_row: 3\nloaded: true\n"
        "---STANDIN---\nderived_arithmetic: 5 operation(s), first at add(1,2)\n"
        "---OPCODES---\n1;10;;0;nil\n2;11;;0;nil\n3;12;;0;nil\n4;13;;0;nil\n"
        "END_UNOBF_RESULT")
    check("rows before the boundary are kept", len(cut.rows), 2)
    check("the rest are counted as cut", cut.rows_dropped_as_fiction, 2)
    tc = the_standin_answered(cut)
    if not tc or "left out of everything below" not in tc:
        bad.append("the cut has to be stated where the boundary is: %r" % tc)
    # with no boundary header nothing is cut
    nocut = Capture("BEGIN_UNOBF_RESULT\n---OPCODES---\n1;10;;0;nil\n"
                    "2;11;;0;nil\nEND_UNOBF_RESULT")
    check("no boundary, no cut", len(nocut.rows), 2)
    check("and nothing reported as cut", nocut.rows_dropped_as_fiction, 0)

    # a stand-in capture reports what it made up, and names the boundary
    cap3 = Capture(
        "BEGIN_UNOBF_RESULT\n---RUN---\nenvironment: standin/robloxenv\n"
        "loaded: true\nrun_ok: false  return_type: nil\n---STANDIN---\n"
        "datatype answered: UDim2\ndatatype answered: Color3\n"
        "field answered: Color3.R x10\n"
        "derived_arithmetic: 75965 operation(s) on values this stand-in "
        "invented, first at add(1,2)\n"
        "---OPCODES---\n1;344;;0;nil\nEND_UNOBF_RESULT")
    check("the stand-in's answers are parsed", len(cap3.standin_lines), 4)
    check("the derived-arithmetic count is read", cap3.derived_arithmetic, 75965)
    t3 = the_standin_answered(cap3)
    if not t3 or "BOUNDARY" not in t3:
        bad.append("derived arithmetic must be reported as a boundary: %r" % t3)
    if t3 and "UDim2" not in t3:
        bad.append("the datatypes answered for belong in the report: %r" % t3)
    if t3 and "describe this package and not the program" not in t3:
        bad.append("the report must say what the rows after the boundary are")
    # with no derived arithmetic there is no boundary to claim
    cap4 = Capture("BEGIN_UNOBF_RESULT\n---STANDIN---\n"
                   "datatype answered: UDim2\n---OPCODES---\nEND_UNOBF_RESULT")
    t4 = the_standin_answered(cap4)
    if t4 and "BOUNDARY" in t4:
        bad.append("a run that never computed on an invented value has no "
                   "boundary: %r" % t4)
    # a capture from a real host says nothing at all here
    if the_standin_answered(Capture("BEGIN_UNOBF_RESULT\n---OPCODES---\n"
                                    "END_UNOBF_RESULT")) is not None:
        bad.append("a capture with no stand-in section must report nothing")

    def why(body):
        return Capture("BEGIN_UNOBF_RESULT\n" + body + "\nEND_UNOBF_RESULT"
                       ).why_no_instructions()

    # 0) an empty capture is one of four things, and the headers say which.
    # Reading only the behaviour log was wrong: it is capped at 120 lines, so a
    # long run drops the patch note and a patched run read as "never matched".
    w = why("---RUN---\ndispatch_patched: true\nloaded: true\n"
            "run_ok: true  return_type: nil\n---BEHAVIOR---\n"
            + "\n".join("  call x%d" % i for i in range(200)))
    if "WAS placed" not in w:
        bad.append("a patched run with no instructions must say the hook was "
                   "placed, even when the log pushed the note out: %r" % w)
    w = why("---RUN---\ndispatch_patched: false\nloaded: true\n"
            "run_ok: true  return_type: nil")
    if "never matched" not in w:
        bad.append("dispatch_patched: false is the one case that did not "
                   "match: %r" % w)
    w = why("---RUN---\ndispatch_patched: true\nloaded: false\n"
            "run_ok: false  return_type: nil\nerror: could not load\n")
    if "never loaded" not in w or "could not load" not in w:
        bad.append("a chunk that never loaded must be reported as that, with "
                   "its error: %r" % w)
    w = why("---OPCODES---")
    if "no headers and no behaviour log" not in w:
        bad.append("a capture that reports nothing must say so rather than "
                   "blame the hook: %r" % w)
    w = why("---RUN---\nloaded: true\nrun_ok: true  return_type: nil")
    if "does not say whether" not in w:
        bad.append("a capture with no dispatch_patched header must not claim "
                   "the hook missed: %r" % w)
    w = why("---RUN---\nloaded: true\nrun_ok: true  return_type: nil\n"
            "---BEHAVIOR---\n  [chunk 2 left untraced; this run traces #1]")
    if "different interpreter" not in w:
        bad.append("tracing the wrong chunk stays its own answer: %r" % w)

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
    # a header that lands in this section by accident is not a slice request
    c2 = Capture("BEGIN_UNOBF_RESULT\n---SLICES---\noS:4:MISSING:3\n"
                 "attempt1_error: :1: attempt to index nil with number\n"
                 "trace_verdict: not_the_patches -- x\n"
                 "counts: prints=0 loads=4 behavior=24\n"
                 "---OPCODES---\nEND_UNOBF_RESULT")
    check("only the real slice row is read", len(c2.slices), 1)
    check("and it is the right one", c2.slices[0]["accessor"], "oS")
    check("the missing one is marked", c.slices[1]["present"], False)
    check("its index is kept", c.slices[1]["index"], 4)
    said = " ".join(what_the_arrays_did(c))
    for want in ("oS(4) of 3", "not in the payload it was given",
                 "genuinely not there", "shorter than the program"):
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
    if "own hook reading a variable" not in said:
        bad.append("a row present in the array that the harness logged as nil "
                   "is this tool's fault and must be named as one, got %r"
                   % said[:200])
    if "genuinely not there" in said:
        bad.append("a row present in the array must not be called absent")

    # 12) a capture from the fixed harness: the row came from the array and the
    #     loop variable disagreed. The operands are real and the note is a
    #     statement about this tool, not about the build.
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: false\nerror: e\n"
                "---OPCODES---\n2010;0;7,8;0;nil;src=array|"
                "hook_var_disagrees=nil|arr=1\nEND_UNOBF_RESULT")
    check("the operands are read", c.rows[0]["operands"], [7, 8])
    said = " ".join(what_the_arrays_did(c))
    if "did not hold the row" not in said or "no longer does" not in said:
        bad.append("a hook disagreement should be reported as this tool's "
                   "limitation, got %r" % said[:200])
    if "not an instruction row" in said:
        bad.append("a row that WAS read must not be reported as absent")

    # 13) one decoded opcode covering rows of different operand shapes. The
    #     encoded field differing is expected and must NOT be reported; the
    #     operand shapes differing must be.
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: true\n---OPCODES---\n"
                "10;0;1,2,3;0;nil;rawop=111\n"
                "11;0;5;0;nil;rawop=222\n"
                "12;7;9;0;nil;rawop=333\n"
                "13;7;8;0;nil;rawop=444\nEND_UNOBF_RESULT")
    said = " ".join(opcode_grouping_doubt(c))
    if "opcode 0 covers 2" not in said:
        bad.append("mixed operand shapes under one opcode should be reported, "
                   "got %r" % said[:160])
    if "opcode 7" in said:
        bad.append("an opcode whose rows all have one operand shape must not be "
                   "flagged just because the encoded field differs: %r"
                   % said[:160])
    if "not a verdict" in said.lower() and "settle" not in said:
        bad.append("the observation should say what would settle it")

    # all one shape -> nothing claimed at all
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: true\n---OPCODES---\n"
                "10;0;1;0;nil;rawop=111\n11;0;2;0;nil;rawop=222\n"
                "END_UNOBF_RESULT")
    check("consistent shapes claim nothing", opcode_grouping_doubt(c), [])

    # 14) a capture logged inside the dispatch chain is a SUBSET and must say so
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: false\nerror: e\n"
                "---OPCODES---\n2;354;;0;nil;src=array|arr=1\n"
                "2010;0;1,2;0;nil;src=array|arr=1\nEND_UNOBF_RESULT")
    said = " ".join(trace_was_filtered(c))
    if "ONLY the instructions that missed every test" not in said:
        bad.append("a capture logged inside the dispatch chain must be named a "
                   "subset, got %r" % said[:140])
    # one taken at the loop top claims nothing
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: false\nerror: e\n"
                "---OPCODES---\n2;354;;0;nil;src=looptop|arr=1\n"
                "END_UNOBF_RESULT")
    check("a loop-top capture is not called filtered", trace_was_filtered(c), [])
    # and a capture with no src note at all claims nothing either
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: true\n"
                "---OPCODES---\n2;354;;0;nil\nEND_UNOBF_RESULT")
    check("no note, no claim", trace_was_filtered(c), [])

    # 15) a branch target that was computed rather than looked up
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: false\nerror: e\n"
                "---JUMPS---\nel:3:5551:table:120\nel:6:889496670:COMPUTED:2009\n"
                "---OPCODES---\n1;354;;0;nil;src=looptop\nEND_UNOBF_RESULT")
    check("both jumps read", len(c.jumps), 2)
    check("the miss is marked", c.jumps[1]["looked_up"], False)
    check("its target is kept", c.jumps[1]["target"], 2009)
    said = " ".join(what_the_arrays_did(c))
    for want in ("1 of them NOT found", "pc 6", "came out as 2009",
                 "outside every block"):
        if want not in said:
            bad.append("the jump report should say %r, got %r"
                       % (want, said[:200]))
    # all looked up -> no alarm
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: true\n"
                "---JUMPS---\nel:3:5551:table:120\n---OPCODES---\n"
                "1;354;;0;nil;src=looptop\nEND_UNOBF_RESULT")
    said = " ".join(what_the_arrays_did(c))
    if "NOT found in its lookup table" in said and "0 of them" not in said:
        bad.append("a clean jump log must not raise an alarm: %r" % said[:120])

    # 16) an offline capture must be named as one, and a host capture must not
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nenvironment: standin/robloxenv\n"
                "run_ok: true\n---OPCODES---\n1;2;;0;x\nEND_UNOBF_RESULT")
    said = " ".join(taken_against_a_standin(c))
    if "taken OFFLINE" not in said or "not the same" in said.lower()[:0]:
        bad.append("an offline capture must say so, got %r" % said[:120])
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nenvironment: host\n"
                "run_ok: true\n---OPCODES---\n1;2;;0;x\nEND_UNOBF_RESULT")
    check("a host capture claims nothing", taken_against_a_standin(c), [])
    c = Capture("BEGIN_UNOBF_RESULT\n---RUN---\nrun_ok: true\n"
                "---OPCODES---\n1;2;;0;x\nEND_UNOBF_RESULT")
    check("a capture that does not say is not guessed at",
          taken_against_a_standin(c), [])

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
