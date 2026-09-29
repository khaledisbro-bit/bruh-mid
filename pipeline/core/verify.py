#!/usr/bin/env python3
"""
verify.py - check the reconstruction against what the VM actually did.

A reconstruction that reads well is worth nothing if it behaves differently, so
the output is tested rather than admired. Two checks run here, and a third is
prepared for the executor.

REPLAY CHECK. Every operation the analysis named was named from some of its
instances. This re-derives EVERY instance from its recorded inputs and compares
the result with the value the VM reported. A single disagreement means the
operation was misidentified, and it is reported as a failure rather than
smoothed over.

GRAPH CHECK. Every value the analysis claims to understand is recomputed from
its inputs and compared with the value observed on the stack. This catches a
wrong arity that happened to keep the stack balanced: the shape would survive,
the arithmetic would not.

BEHAVIOUR CHECK. The reconstruction is written out as a runnable script wrapped
in the same instrumented environment the original was captured in. Running both
and comparing the recorded call sequences is the real test - same calls, same
arguments, same order - and it is the one check that has to happen in the
executor, so the script is generated here ready to run.
"""
from evidence import OBSERVED, UNKNOWN

import opsem


class Result:
    def __init__(self):
        self.checks = 0
        self.agreed = 0
        self.failures = []
        self.skipped = 0

    @property
    def rate(self):
        return self.agreed / self.checks if self.checks else 0.0


def replay(L, models):
    """Recompute every instance of every named operation."""
    r = Result()
    for st in L.steps:
        if len(st.pushed) != 1:
            continue
        m = models.get(st.op)
        if m is None or not m.operation:
            continue
        f = opsem.CANDIDATES.get(m.operation)
        if f is None or len(st.popped) != 2:
            continue
        a, b = st.popped[0].runtime, st.popped[1].runtime
        want = st.pushed[0].runtime
        if a is None or b is None or want is None:
            r.skipped += 1
            continue
        got = f(a, b)
        if got is None:
            r.skipped += 1
            continue
        r.checks += 1
        if opsem._same(got, want):
            r.agreed += 1
        else:
            r.failures.append(
                "fn%d:%d: OP_%d was read as %s, but %s %s %s gave %s while the VM "
                "reported %s" % (st.fn, st.pc, st.op, m.operation, a, m.operation,
                                 b, got, want))
    return r


def graph(L, models):
    """Recompute every value that has a named producer and known inputs."""
    r = Result()
    for v in L.values:
        m = models.get(v.op)
        if m is None or not m.operation or len(v.inputs) != 2:
            continue
        f = opsem.CANDIDATES.get(m.operation)
        if f is None:
            continue
        a = L.values[v.inputs[0]].runtime
        b = L.values[v.inputs[1]].runtime
        if a is None or b is None or v.runtime is None:
            r.skipped += 1
            continue
        got = f(a, b)
        if got is None:
            r.skipped += 1
            continue
        r.checks += 1
        if opsem._same(got, v.runtime):
            r.agreed += 1
        else:
            r.failures.append(
                "v%d (pc %d): rebuilding it as %s %s %s gives %s, but the VM "
                "reported %s" % (v.id, v.pc, a, m.operation, b, got, v.runtime))
    return r


def coverage(L, verdicts):
    """How much of what ran the reconstruction actually explains."""
    total = len(L.steps)
    if not total:
        return 0.0, 0, 0
    explained = sum(1 for st in L.steps
                    if verdicts.get(st.key()) and
                    verdicts[st.key()].verdict == OBSERVED)
    return explained / total, explained, total


# A RAW string. Without the r, Python turns every \n in the Lua below into a
# real newline, and a Lua short string cannot span lines - so the generated
# harness did not compile at all, and running it printed nothing. Nothing in
# this text wants Python's escapes; the \n in it are Lua's.
BEHAVIOUR_HARNESS = r'''-- Behaviour comparison harness (generated).
--
-- Runs the reconstruction inside a watched environment and prints every call it
-- makes. Feed the printed block back with --behaviour and the two sequences are
-- compared: the same calls, with the same arguments, in the same order, is what
-- makes a reconstruction correct.
--
-- Calls are written as a dotted path with its arguments - GetService("Players"),
-- Instance.new("Part") - which is also how the original capture's records are
-- read before comparing, so the two can be lined up whatever shape each log
-- used.
local RECONSTRUCTED = %s

local seen = {}
local function preview(v)
    local t = typeof and typeof(v) or type(v)
    if t == "string" then return string.format("%%q", #v > 60 and v:sub(1, 60) .. ".." or v) end
    if t == "number" or t == "boolean" then return tostring(v) end
    if t == "nil" then return "nil" end
    if t == "table" then return "table" end
    return t
end
local function argstr(...)
    local n = select("#", ...)
    local p = {}
    for i = 1, n do p[i] = preview((select(i, ...))) end
    return table.concat(p, ", ")
end

-- A watched name has to work in every shape the program might use it in: called
-- directly, indexed then called, or used as a receiver with a colon. A proxy
-- that only answers one of those ends the run at the first of the others.
local watch
watch = function(ns)
    local function record(...)
        seen[#seen + 1] = ns .. "(" .. argstr(...) .. ")"
        return watch(ns)
    end
    return setmetatable({}, {
        __index = function(_, k) return watch(ns .. "." .. tostring(k)) end,
        __call = function(_, first, ...)
            -- a colon call passes the receiver itself as the first argument;
            -- dropping it keeps both shapes reading the same way
            if first ~= nil and type(first) == "table" then
                return record(...)
            end
            return record(first, ...)
        end,
        __concat = function(a, b) return tostring(a) .. tostring(b) end,
        __tostring = function() return ns end,
    })
end

local env = setmetatable({}, { __index = function(_, k)
    if k == "print" then
        return function(...) seen[#seen + 1] = "print(" .. argstr(...) .. ")" end
    end
    return watch(tostring(k))
end })

local fn, err = loadstring(RECONSTRUCTED)
if not fn then
    print("BEGIN_BEHAVIOUR\ncompile_error: " .. tostring(err) .. "\nEND_BEHAVIOUR")
    return
end
pcall(setfenv, fn, env)
local ok, e = pcall(fn)
local out = { "BEGIN_BEHAVIOUR", "run_ok: " .. tostring(ok) }
if not ok then out[#out + 1] = "error: " .. tostring(e) end
out[#out + 1] = "---BEHAVIOUR---"
for i = 1, #seen do out[#out + 1] = seen[i] end
out[#out + 1] = "END_BEHAVIOUR"
print(table.concat(out, "\n"))
'''


def normalise(rec):
    """One shape for a call, whatever shape its log used.

    The capture writes `GetService: Players` for a service lookup, `Instance.new:
    Part` for a construction and `Svc:Method(args)` for a proxied call. The
    behaviour harness writes a dotted path with its arguments. Both are reduced
    to the same thing here, or the two sequences could never be lined up."""
    if isinstance(rec, str):
        return rec.strip()
    name = rec.get("method") or ""
    recv = rec.get("recv")
    path = ("%s.%s" % (recv, name)) if recv else name
    args = []
    for a in rec.get("args") or ():
        a = a.strip()
        if a.startswith('"') or _PLAIN.match(a):
            args.append(a)
        else:
            args.append('"%s"' % a)
    return "%s(%s)" % (path, ", ".join(args))


_PLAIN = __import__("re").compile(
    r"^(-?\d+(\.\d+)?|true|false|nil|table|function|\{.*\})$")


def parse_block(text):
    """The call sequence out of a printed BEGIN_BEHAVIOUR block."""
    if "BEGIN_BEHAVIOUR" in text:
        text = text.split("BEGIN_BEHAVIOUR", 1)[1]
    text = text.split("END_BEHAVIOUR", 1)[0]
    ok, err, calls = None, None, []
    body = text.split("---BEHAVIOUR---", 1)
    head = body[0]
    for ln in head.splitlines():
        ln = ln.strip()
        if ln.startswith("run_ok:"):
            ok = ln.split(":", 1)[1].strip() == "true"
        elif ln.startswith(("error:", "compile_error:")):
            err = ln.split(":", 1)[1].strip()
    if len(body) > 1:
        for ln in body[1].splitlines():
            ln = ln.strip()
            if ln:
                calls.append(ln)
    return {"ok": ok, "error": err, "calls": calls}


def _bracket(text):
    longest = 0
    i = 0
    while True:
        j = text.find("]", i)
        if j < 0:
            break
        k = j + 1
        while k < len(text) and text[k] == "=":
            k += 1
        if k < len(text) and text[k] == "]":
            longest = max(longest, k - j - 1)
        i = j + 1
    eq = "=" * (longest + 1)
    return "[" + eq + "[\n" + text + "\n]" + eq + "]"


def statement_lines(source):
    """The statements in a rendering, ignoring comments and the OP prelude.

    The prelude is fixed text that defines the stand-in for an unproven
    instruction. A rendering carrying nothing but the prelude is empty, and it
    still looks like a Lua file of a respectable size."""
    lines = [l for l in (source or "").splitlines()
             if l.strip() and not l.strip().startswith("--")]
    body = []
    seen_prelude = False
    for i, l in enumerate(lines):
        if not seen_prelude and l.strip() == "end":
            seen_prelude = True
            body = lines[i + 1:]
            break
    if not seen_prelude:
        body = lines
    return [l for l in body if l.strip()]


def behaviour_harness(source):
    """A runnable script that replays the reconstruction under the same watched
    environment, so its call sequence can be compared with the original's.

    When the rendering has no statements there is nothing to replay. Wrapping
    that in the usual harness produces a script that runs, prints an empty
    sequence and compares clean against nothing - which reads like a passing
    check. It says what happened instead."""
    if not statement_lines(source):
        return ('-- Behaviour comparison harness (generated).\n'
                '--\n'
                '-- There is nothing to compare. The runnable rendering of this\n'
                '-- capture came out with no statements in it: every instruction\n'
                '-- either had no meaning this run established, or produced a\n'
                '-- value nothing used.\n'
                '--\n'
                '-- Running this would print an empty call sequence, which would\n'
                '-- then compare clean against the program and read like a check\n'
                '-- that passed. It is not one.\n'
                'print("BEGIN_BEHAVIOUR\\n'
                'run_ok: false\\n'
                'error: the reconstruction has no statements to run\\n'
                'END_BEHAVIOUR")\n')
    return BEHAVIOUR_HARNESS % _bracket(source)


def fidelity(records, calls):
    """How much of what the program did the reconstruction accounts for.

    "11 of 20 matched" says how many records found an instruction; it does not
    say whether the reconstruction would DO the same things in the same order.
    This lines the two sequences up and reports the longest unbroken stretch of
    the program's actions that the reconstruction makes, and which actions it
    does not make at all. Nine right in a row then nothing is a different result
    from nine scattered, and the difference decides how far the output can be
    trusted.

    Identical actions are counted one for one, not as a set: a program that
    creates four folders is not accounted for by a reconstruction that creates
    one."""
    from collections import Counter
    have = Counter(c.record.get("raw") for c in calls)
    accounted = []
    for rec in records:
        raw = rec.get("raw")
        if have.get(raw, 0) > 0:
            have[raw] -= 1
            accounted.append(True)
        else:
            accounted.append(False)
    best = run = 0
    best_at = at = 0
    for i, ok in enumerate(accounted):
        if ok:
            if run == 0:
                at = i
            run += 1
            if run > best:
                best, best_at = run, at
        else:
            run = 0
    missing = [r for r, ok in zip(records, accounted) if not ok]
    L = ["BEHAVIOUR - the program's actions against the reconstruction's",
         "-" * 60,
         "The environment recorded %d call(s) the program made. The"
         % len(records),
         "reconstruction accounts for %d of them, counted one for one."
         % (len(records) - len(missing)), ""]
    if best:
        L.append("  Its longest unbroken agreement is %d action(s), starting at"
                 % best)
        L.append("  the program's action %d:" % (best_at + 1))
        for r in records[best_at:best_at + min(best, 12)]:
            L.append("    " + (r.get("raw") or ""))
        if best > 12:
            L.append("    ... %d more in that stretch" % (best - 12))
    else:
        L.append("  It makes none of the actions the program made.")
    if missing:
        L.append("")
        L.append("  not accounted for (%d):" % len(missing))
        for r in missing[:20]:
            L.append("    " + (r.get("raw") or ""))
        if len(missing) > 20:
            L.append("    ... %d more" % (len(missing) - 20))
        L.append("")
        L.append("  An action the program took that the reconstruction does not")
        L.append("  make is missing evidence, not a disagreement: the")
        L.append("  instruction behind it is outside what this capture traced,")
        L.append("  or nothing in the capture carried a value to anchor it on.")
        L.append("  Tracing the chunk it happened in is what closes it.")
    return "\n".join(L), best, len(missing)


def compare_behaviour(records, block_text):
    """Compare what the program did with what the reconstruction did.

    `records` are the original capture's call records; `block_text` is what the
    behaviour harness printed. Both are reduced to one shape first, then lined up
    in order."""
    got = parse_block(block_text)
    want = [normalise(r) for r in records]
    have = [normalise(c) for c in got["calls"]]
    L = ["BEHAVIOUR COMPARISON",
         "=" * 46,
         "The program's calls against the reconstruction's, in order.", ""]
    if got["ok"] is False or got["error"]:
        L.append("  The reconstruction did not finish: %s"
                 % (got["error"] or "it stopped without saying why"))
        L.append("  Whatever it managed before stopping is compared below, but a")
        L.append("  run that ends early cannot account for what came after.")
        L.append("")
    from collections import Counter
    pool = Counter(have)
    matched, missing = [], []
    for w in want:
        if pool.get(w, 0) > 0:
            pool[w] -= 1
            matched.append(w)
        else:
            missing.append(w)
    extra = sorted(pool.elements())
    # longest run of the program's calls the reconstruction made, in order
    i = j = best = run = 0
    while i < len(want) and j < len(have):
        if want[i] == have[j]:
            run += 1
            best = max(best, run)
            i += 1
            j += 1
        else:
            run = 0
            j += 1
            if j >= len(have):
                i += 1
                j = 0
    L += ["  the program made %d call(s); the reconstruction made %d"
          % (len(want), len(have)),
          "  same call, matched one for one: %d" % len(matched),
          "  longest run in the same order: %d" % best, ""]
    if missing:
        L.append("  the program made these and the reconstruction did not (%d):"
                 % len(missing))
        for m in missing[:20]:
            L.append("    " + m)
        if len(missing) > 20:
            L.append("    ... %d more" % (len(missing) - 20))
        L.append("")
    if extra:
        L.append("  the reconstruction made these and the program did not (%d):"
                 % len(extra))
        for e in extra[:20]:
            L.append("    " + e)
        if len(extra) > 20:
            L.append("    ... %d more" % (len(extra) - 20))
        L.append("")
        L.append("  A call the program never made is the serious kind of error:")
        L.append("  it means a reading put an action into the program that was")
        L.append("  not there.")
        L.append("")
    if not missing and not extra:
        L.append("  Every call matches, one for one and in order. On the")
        L.append("  behaviour this capture recorded, the reconstruction does what")
        L.append("  the program did.")
    else:
        L.append("  verdict: the reconstruction accounts for %d of the %d call(s)"
                 % (len(matched), len(want)))
        L.append("  the program made%s."
                 % (", and makes %d it did not" % len(extra) if extra else ""))
    return "\n".join(L), len(matched), len(missing), len(extra)


def report(L, models, verdicts, records=(), calls=(), types=None):
    rp, gr = replay(L, models), graph(L, models)
    cov, explained, total = coverage(L, verdicts)
    def rate(r):
        """A proportion is only worth printing when there is something to take
        it of. One check passing is one check passing, not a hundred percent."""
        if r.checks == 0:
            return "nothing could be recomputed, so this check says nothing"
        if r.checks < 5:
            return ("%d of %d - too few to mean anything on its own"
                    % (r.agreed, r.checks))
        return "%d of %d (%.0f%%)" % (r.agreed, r.checks, 100 * r.rate)

    lines = ["VERIFICATION",
             "=" * 46,
             "Each check is reported on its own. A proportion taken of one or",
             "two cases is not evidence about the rest, and coverage is not",
             "correctness - they are different numbers and are kept apart.", "",
             "replay check - every instance of every named operation recomputed",
             "  attempted %d, agreed %d, disagreed %d, not evaluable %d"
             % (rp.checks, rp.agreed, len(rp.failures), rp.skipped),
             "  %s" % rate(rp),
             "  Not evaluable means the operation cannot be recomputed from what",
             "  the capture reports - an index, a call or a constant load has no",
             "  arithmetic to redo - or an input's value was not reported. Those",
             "  are tested by type instead, below."]
    for f in rp.failures[:10]:
        lines.append("  FAILED " + f)
    lines += ["",
              "graph check - every value with a named producer recomputed",
              "  attempted %d, agreed %d, disagreed %d, not evaluable %d"
              % (gr.checks, gr.agreed, len(gr.failures), gr.skipped),
              "  %s" % rate(gr)]
    for f in gr.failures[:10]:
        lines.append("  FAILED " + f)
    lines += ["",
              "coverage - how much of what ran is explained",
              "  %d of %d executed instructions are accounted for by something"
              % (explained, total),
              "  the program observably did (%.0f%%)" % (100 * cov),
              "",
              "behaviour check - not run here",
              "  Comparing behaviour means executing both the original and the",
              "  reconstruction. The script that does it is written alongside",
              "  this report as behaviour_check.lua; run it in the executor and",
              "  compare its call sequence with the original capture's.",
              "  Until that comparison is made, this reconstruction is verified",
              "  against the recorded execution, not against a second run."]
    ok = (not rp.failures) and (not gr.failures)
    if types:
        withdrawn, examined = types
        lines += ["",
                  "type check - every instance of every named operation tested",
                  "  against the types its values had",
                  "  examined %d instance(s); withdrew %d reading(s) the values"
                  % (examined, withdrawn),
                  "  make impossible (indexing nothing, calling a number, and",
                  "  the like). A value the capture did not report never",
                  "  withdraws a reading; only an impossibility does."]
    if records:
        fid, prefix, missing = fidelity(records, calls)
        lines += ["", fid]
    lines += ["", "verdict: %s" % (
        "consistent with every value the VM reported"
        if ok else "INCONSISTENT - see the failures above")]
    return "\n".join(lines), ok
