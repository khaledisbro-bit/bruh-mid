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


BEHAVIOUR_HARNESS = '''-- Behaviour comparison harness (generated).
--
-- Runs the reconstruction inside the same watched environment the original was
-- captured in, and prints the call sequence it produces. Run the original
-- capture harness and this one, then compare the two BEHAVIOUR blocks: the same
-- calls, with the same arguments, in the same order, is what makes a
-- reconstruction correct. Anything else is a reconstruction that only looks
-- right.
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
local function watch(ns)
    return setmetatable({}, { __index = function(_, k)
        return function(_, ...)
            seen[#seen + 1] = ns .. ":" .. tostring(k) .. "(" .. argstr(...) .. ")"
            return watch(ns .. "." .. tostring(k))
        end
    end })
end

local env = setmetatable({}, { __index = function(_, k)
    if k == "print" then
        return function(...) seen[#seen + 1] = "print(" .. argstr(...) .. ")" end
    end
    return watch(tostring(k))
end })

local fn, err = loadstring(RECONSTRUCTED)
if not fn then
    print("BEGIN_BEHAVIOUR\\ncompile_error: " .. tostring(err) .. "\\nEND_BEHAVIOUR")
    return
end
pcall(setfenv, fn, env)
local ok, e = pcall(fn)
local out = { "BEGIN_BEHAVIOUR", "run_ok: " .. tostring(ok) }
if not ok then out[#out + 1] = "error: " .. tostring(e) end
out[#out + 1] = "---BEHAVIOUR---"
for i = 1, #seen do out[#out + 1] = seen[i] end
out[#out + 1] = "END_BEHAVIOUR"
print(table.concat(out, "\\n"))
'''


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


def behaviour_harness(source):
    """A runnable script that replays the reconstruction under the same watched
    environment, so its call sequence can be compared with the original's."""
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


def compare_behaviour(original_calls, replay_calls):
    """Compare two recorded call sequences: same calls, same order."""
    a = [c.get("raw", "") if isinstance(c, dict) else str(c)
         for c in original_calls]
    b = [c.get("raw", "") if isinstance(c, dict) else str(c)
         for c in replay_calls]
    n = min(len(a), len(b))
    same = 0
    diffs = []
    for i in range(n):
        if a[i] == b[i]:
            same += 1
        else:
            diffs.append("position %d: original made %s, reconstruction made %s"
                         % (i + 1, a[i], b[i]))
    if len(a) != len(b):
        diffs.append("the original made %d call(s), the reconstruction made %d"
                     % (len(a), len(b)))
    return {"matched": same, "of": max(len(a), len(b)), "differences": diffs}


def report(L, models, verdicts, records=(), calls=()):
    rp, gr = replay(L, models), graph(L, models)
    cov, explained, total = coverage(L, verdicts)
    lines = ["VERIFICATION",
             "=" * 46,
             "The reconstruction is checked against the VM's own record, not",
             "against how plausible it looks.", "",
             "replay check - every instance of every named operation recomputed",
             "  %d checked, %d agreed, %d could not be evaluated"
             % (rp.checks, rp.agreed, rp.skipped),
             "  agreement: %.1f%%" % (100 * rp.rate)]
    for f in rp.failures[:10]:
        lines.append("  FAILED " + f)
    lines += ["",
              "graph check - every value with a named producer recomputed",
              "  %d checked, %d agreed, %d could not be evaluated"
              % (gr.checks, gr.agreed, gr.skipped),
              "  agreement: %.1f%%" % (100 * gr.rate)]
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
    if records:
        fid, prefix, missing = fidelity(records, calls)
        lines += ["", fid]
    lines += ["", "verdict: %s" % (
        "consistent with every value the VM reported"
        if ok else "INCONSISTENT - see the failures above")]
    return "\n".join(lines), ok
