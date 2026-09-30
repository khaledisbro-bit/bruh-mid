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
local function say(...) local p={} for i=1,select("#", ...) do p[i]=tostring((select(i,...))) end R[#R+1]=table.concat(p,"\\t") end
local ops, resolved, prints, loads, behavior = {}, {}, {}, {}, {}
local constSeen = 0
local SOURCE = "payload"
local env = {}
local function typeof(v) return type(v) end
local function setfenv() end
local TRACE_OPCODES = SCEN.trace
local TRACE_CHUNK = 1
local PATCH_LEVEL = TRACE_OPCODES and 2 or 1
local LEVEL_NAME = { [2] = "traced", [1] = "resolver-only", [0] = "unpatched" }
local dispatchDone, resolverDone, patchable = false, false, 0
local ORIGINAL_LINES, PATCH_AT, PATCH_ADDED = nil, nil, 0
local function realLoad(src)
  if SCEN.noload then return nil end
  return function()
    -- what the loadstring hook would have done while the payload was running
    if PATCH_LEVEL >= 1 and SCEN.resolver_matches then resolverDone = true end
    if PATCH_LEVEL >= 2 and SCEN.dispatch_matches then
      patchable = 1
      dispatchDone = true
      for i = 1, 3 do ops[#ops+1] = "row" end
    end
    constSeen = constSeen + 1
    -- The payload finishes only once the edit it objects to is gone. `lives_at`
    -- is the highest patch level it tolerates; nil means it never finishes.
    if SCEN.lives_at ~= nil and PATCH_LEVEL <= SCEN.lives_at then return nil end
    error("raised at level " .. PATCH_LEVEL, 0)
  end
end
"""

# name -> (scenario, expected header prefixes)
CASES = {
    # nothing raised, so there is nothing to take back out and no verdict to give
    "finishes at full patch level": (
        dict(trace=True, resolver_matches=True, dispatch_matches=True,
             lives_at=2),
        {"harness_id": "traced", "attempts": "1", "run_ok": "true",
         "trace_verdict": None}),
    # objects to the dispatch logger only: one step down is enough
    "dispatch logger caught": (
        dict(trace=True, resolver_matches=True, dispatch_matches=True,
             lives_at=1),
        {"harness_id": "traced->resolver-only", "attempts": "2",
         "run_ok": "true", "trace_verdict": "patch_caught"}),
    # tolerates neither edit: the harness has to go all the way to untouched.
    # This is the case that was being reported as "without the patch" while the
    # resolver rewrite was still in the chunk.
    "resolver rewrite caught": (
        dict(trace=True, resolver_matches=True, dispatch_matches=True,
             lives_at=0),
        {"harness_id": "traced->resolver-only->unpatched", "attempts": "3",
         "run_ok": "true", "trace_verdict": "patch_caught"}),
    # raises however little is done to it: not the instrumentation
    "raises at every level": (
        dict(trace=True, resolver_matches=True, dispatch_matches=True,
             lives_at=None),
        {"harness_id": "traced->resolver-only->unpatched", "attempts": "3",
         "run_ok": "false", "trace_verdict": "not_the_patches"}),
    # the dispatch hook never matched this build, so level 2 changed nothing and
    # stepping down from it would repeat the same run and read as evidence
    "dispatch hook never matched": (
        dict(trace=True, resolver_matches=True, dispatch_matches=False,
             lives_at=None),
        {"harness_id": "resolver-only->unpatched", "attempts": "2",
         "trace_verdict": "not_the_patches"}),
    # neither hook matched: one run, nothing to remove, no verdict claimed
    "no hook matched at all": (
        dict(trace=True, resolver_matches=False, dispatch_matches=False,
             lives_at=None),
        {"harness_id": "trace_requested_but_unpatched", "attempts": "1",
         "run_ok": "false", "trace_verdict": None}),
    # the untraced harness starts a level down and still has the resolver to give
    "untraced harness, raises": (
        dict(trace=False, resolver_matches=True, dispatch_matches=True,
             lives_at=None),
        {"harness_id": "resolver-only->unpatched", "attempts": "2",
         "run_ok": "false", "trace_verdict": "not_the_patches"}),
    "payload will not compile": (
        dict(trace=True, resolver_matches=True, dispatch_matches=True,
             lives_at=2, noload=True),
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
                  "TRACE_CHUNK", "dispatchDone", "resolverDone", "patchable",
                  "HIDE_HOOKS", "PATCH_LEVEL", "LEVEL_NAME", "constSeen",
                  "codeArrays", "codeArrayN", "codeMap", "codeRefs",
                  "codeOrdered", "codeRows", "missing", "missingSeen",
                  "missingN", "HARNESS_ENGINE")


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
