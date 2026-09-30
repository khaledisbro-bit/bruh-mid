#!/usr/bin/env python3
"""
harnesstest.py - run the harness's own decision logic and check what it decides.

The harness runs the payload, and when the traced run raises while the dispatch
patch is in place it runs the SAME payload again with the patch left out. That
decision is the difference between "this build objects to being traced" and
"this program errors on its own", and it used to be a person choosing between
two files. A wrong choice there produced a capture that looked exactly like the
right one, so the wrong conclusion got drawn from it with nothing to contradict
it.

So the decision is tested, and tested as SHIPPED: the run block is read out of
universal.lua and executed verbatim under stubs. Nothing here paraphrases it.
A paraphrase would pass while the file was broken, which is the failure mode
this module exists to remove.

No sample, no program string and no obfuscator name appears here. The stubs
decide only whether a run raises, which is the one input the decision reads.
"""
import io
import os

HERE = os.path.dirname(os.path.abspath(__file__))
UNIVERSAL = os.path.join(os.path.dirname(HERE), "universal.lua")

_START = "-- ------------------------------------------------------------------- the run"
_END = 'say("mode: universal")'

# Everything the run block reads from the harness around it. The payload stub is
# the only part with a choice to make, and it makes it from SCEN alone.
_PRELUDE = """
local SCEN = SCEN
local R = {}
local function say(...) local p={} for i=1,select("#",...) do p[i]=tostring((select(i,...))) end R[#R+1]=table.concat(p,"\\t") end
local ops, resolved, prints, loads, behavior = {}, {}, {}, {}, {}
local SOURCE = "payload"
local env = {}
local function typeof(v) return type(v) end
local function setfenv() end
local TRACE_OPCODES = SCEN.trace
local TRACE_CHUNK = 1
local dispatchDone = false
local patchable = 0
local function realLoad(src)
  if SCEN.noload then return nil end
  return function()
    -- what the loadstring hook would have done while the payload was running
    if TRACE_OPCODES and SCEN.patchable then
      patchable = patchable + 1
      if SCEN.patched then
        dispatchDone = true
        for i = 1, 3 do ops[#ops+1] = "row" end
      end
    end
    resolved[#resolved+1] = "S:x"
    local ok
    if TRACE_OPCODES then ok = SCEN.traced_ok else ok = SCEN.untraced_ok end
    if not ok then
      error(TRACE_OPCODES and "traced failure" or "untraced failure", 0)
    end
    return nil
  end
end
"""

# name -> (scenario, expected header prefixes)
CASES = {
    "traced run finishes": (
        dict(trace=True, patchable=True, patched=True,
             traced_ok=True, untraced_ok=True),
        # nothing raised, so there is nothing to re-run and no verdict to give
        {"harness_id": "traced", "attempts": "1", "run_ok": "true",
         "trace_verdict": None}),
    "dies traced, lives untraced": (
        dict(trace=True, patchable=True, patched=True,
             traced_ok=False, untraced_ok=True),
        {"harness_id": "traced+retry", "attempts": "2", "run_ok": "true",
         "trace_verdict": "patch_caught"}),
    "dies both ways": (
        dict(trace=True, patchable=True, patched=True,
             traced_ok=False, untraced_ok=False),
        {"harness_id": "traced+retry", "attempts": "2", "run_ok": "false",
         "trace_verdict": "not_the_trace"}),
    "untraced harness, dies": (
        dict(trace=False, patchable=True, patched=False,
             traced_ok=False, untraced_ok=False),
        # no patch was placed, so there is nothing to take out and no second run
        {"harness_id": "untraced", "attempts": "1", "run_ok": "false",
         "trace_verdict": None}),
    "trace asked, hook never matched": (
        dict(trace=True, patchable=True, patched=False,
             traced_ok=False, untraced_ok=False),
        {"harness_id": "trace_requested_but_unpatched", "attempts": "1",
         "trace_verdict": None}),
    "payload will not compile": (
        dict(trace=True, patchable=True, patched=True,
             traced_ok=True, untraced_ok=True, noload=True),
        {"harness_id": "untested", "attempts": "1", "loaded": "false",
         "trace_verdict": None}),
}


def run_block(path=UNIVERSAL):
    """The run block, verbatim, out of the harness file."""
    s = io.open(path, encoding="utf-8").read()
    i = s.index(_START)
    j = s.index(_END) + len(_END)
    return s[i:j]


def _headers(text):
    out = {}
    for ln in text.splitlines():
        if ":" in ln:
            k, _, v = ln.partition(":")
            out.setdefault(k.strip(), v.strip())
    return out


# Names the harness assigns to at its own top level. Every one of them must be
# a declared local: a bare assignment in Lua makes a GLOBAL, and a global the
# payload can read is a name that exists in no real environment. The harness
# already hides its hook names behind the environment's metatable for exactly
# that reason, and these would walk straight past that work.
_MUST_BE_LOCAL = ("ORIGINAL_LINES", "PATCH_AT", "PATCH_ADDED", "TRACE_OPCODES",
                  "TRACE_CHUNK", "dispatchDone", "patchable", "HIDE_HOOKS")


def _declared_locals(path=UNIVERSAL):
    """Which of those names the file actually declares as locals."""
    src = io.open(path, encoding="utf-8").read()
    problems = []
    for name in _MUST_BE_LOCAL:
        found = False
        for ln in src.splitlines():
            t = ln.strip()
            if not t.startswith("local "):
                continue
            decl = t[len("local "):].split("=")[0]
            if name in [x.strip() for x in decl.split(",")]:
                found = True
                break
        if not found:
            problems.append("%s is assigned by the harness but never declared "
                            "local, so it becomes a global the payload can read"
                            % name)
    return problems


def selftest(path=UNIVERSAL):
    """Returns (problems, ran). ran is False when no Lua runtime is here."""
    leaks = _declared_locals(path)
    try:
        import lupa
    except ImportError:
        return (leaks + ["no Lua runtime available, so the harness's own "
                         "decision was not exercised (pip install lupa)"],
                False)
    script = _PRELUDE + run_block(path) + '\nreturn table.concat(R, "\\n")\n'
    problems = list(leaks)
    for name, (scen, want) in CASES.items():
        L = lupa.LuaRuntime(unpack_returned_tuples=True)
        L.globals().SCEN = L.table_from(dict(scen))
        try:
            out = L.execute(script)
        except Exception as exc:                      # noqa: BLE001
            problems.append("%s: the run block would not run: %s" % (name, exc))
            continue
        got = _headers(out)
        for key, exp in want.items():
            have = got.get(key)
            if exp is None:
                if have is not None:
                    problems.append("%s: %s should not be reported at all, "
                                    "capture says %r" % (name, key, have))
                continue
            if have is None:
                problems.append("%s: no %s line in the capture" % (name, key))
            elif not have.startswith(exp):
                problems.append("%s: %s reads %r, expected it to start %r"
                                % (name, key, have, exp))
        # A failed attempt has no return value, so it must not claim one.
        for ln in out.splitlines():
            if (ln.startswith("attempt") and "run_ok=false" in ln
                    and "return_type=nil" not in ln):
                problems.append("%s: a failed attempt reports a return type: %s"
                                % (name, ln.strip()))
    return (problems, True)


if __name__ == "__main__":
    probs, ran = selftest()
    print("harness decision self-test: %d case(s), %d problem(s)%s"
          % (len(CASES), len(probs), "" if ran else "  [NOT RUN]"))
    for p in probs:
        print("  - %s" % p)
    raise SystemExit(1 if probs else 0)
