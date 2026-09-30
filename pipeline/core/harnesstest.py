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
local PATCH_LEVEL = TRACE_OPCODES and 3 or 1
local LEVEL_NAME = { [3] = "protos+traced", [2] = "traced",
                     [1] = "resolver-only", [0] = "unpatched" }
local dispatchDone, resolverDone, protosDone, patchable = false, false, false, 0
local protoN = 0
local slices, sliceN = {}, 0
local ORIGINAL_LINES, PATCH_AT, PATCH_ADDED = nil, nil, 0
local function realLoad(src)
  if SCEN.noload then return nil end
  return function()
    -- what the loadstring hook would have done while the payload was running
    if PATCH_LEVEL >= 3 and SCEN.proto_matches then protosDone = true end
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
    # nothing raised: nothing to take back out, no verdict to give
    "finishes at full patch level": (
        dict(trace=True, proto_matches=True, resolver_matches=True,
             dispatch_matches=True, lives_at=3),
        {"harness_id": "protos+traced", "attempts": "1", "run_ok": "true",
         "trace_verdict": None}),
    # objects to the outermost edit only
    "proto hook caught": (
        dict(trace=True, proto_matches=True, resolver_matches=True,
             dispatch_matches=True, lives_at=2),
        {"harness_id": "protos+traced->traced", "attempts": "2",
         "run_ok": "true", "trace_verdict": "patch_caught"}),
    "dispatch logger caught": (
        dict(trace=True, proto_matches=True, resolver_matches=True,
             dispatch_matches=True, lives_at=1),
        {"harness_id": "protos+traced->traced->resolver-only", "attempts": "3",
         "run_ok": "true", "trace_verdict": "patch_caught"}),
    # tolerates no edit at all: the harness has to reach untouched
    "resolver rewrite caught": (
        dict(trace=True, proto_matches=True, resolver_matches=True,
             dispatch_matches=True, lives_at=0),
        {"harness_id": "protos+traced->traced->resolver-only->unpatched",
         "attempts": "4", "run_ok": "true", "trace_verdict": "patch_caught"}),
    "raises at every level": (
        dict(trace=True, proto_matches=True, resolver_matches=True,
             dispatch_matches=True, lives_at=None),
        {"harness_id": "protos+traced->traced->resolver-only->unpatched",
         "attempts": "4", "run_ok": "false", "trace_verdict": "not_the_patches"}),
    # an edit that never went in is not stepped over: doing so would repeat the
    # round and read as evidence
    "no proto maker matched": (
        dict(trace=True, proto_matches=False, resolver_matches=True,
             dispatch_matches=True, lives_at=None),
        {"harness_id": "traced->resolver-only->unpatched", "attempts": "3",
         "trace_verdict": "not_the_patches"}),
    "dispatch hook never matched": (
        dict(trace=True, proto_matches=False, resolver_matches=True,
             dispatch_matches=False, lives_at=None),
        {"harness_id": "resolver-only->unpatched", "attempts": "2",
         "trace_verdict": "not_the_patches"}),
    "no hook matched at all": (
        dict(trace=True, proto_matches=False, resolver_matches=False,
             dispatch_matches=False, lives_at=None),
        {"harness_id": "trace_requested_but_unpatched", "attempts": "1",
         "run_ok": "false", "trace_verdict": None}),
    # the untraced harness starts below the tracing edits
    "untraced harness, raises": (
        dict(trace=False, proto_matches=True, resolver_matches=True,
             dispatch_matches=True, lives_at=None),
        {"harness_id": "resolver-only->unpatched", "attempts": "2",
         "run_ok": "false", "trace_verdict": "not_the_patches"}),
    "payload will not compile": (
        dict(trace=True, proto_matches=True, resolver_matches=True,
             dispatch_matches=True, lives_at=3, noload=True),
        {"harness_id": "untested", "attempts": "1", "loaded": "false",
         "trace_verdict": None}),
}


def run_block(path=UNIVERSAL):
    """The run block, verbatim, out of the harness file."""
    s = io.open(path, encoding="utf-8").read()
    i = s.index(_START)
    j = s.index(_END) + len(_END)
    return s[i:j]


_PROTO_CASES = {
    # A maker shaped like the real thing: the prototype is the parameter indexed
    # through ITSELF, and the interpreter closure is built inside it.
    "named maker": (
        "local function build(env, P, ups) local CODE = P[P[3]] "
        "return function(...) local pc=1 while true do local NO=CODE[pc] "
        "if NO==nil then return end pc=pc+1 end end end return build", True),
    "anonymous maker": (
        "local build = function(e, Q, u) local C = Q[Q[2]] "
        "return function(...) return C end end return build", True),
    # Nothing indexed through itself, so there is no prototype to name and the
    # hook must refuse rather than pick something.
    "nothing self-indexed": (
        "local function f(a,b) return a+b end return f", False),
}


def proto_hook(path=UNIVERSAL):
    """The prototype-maker hook, driven on sources whose shape is known.

    The discriminator is the only part that matters and it is name-free: the
    prototype is the parameter indexed through itself. These cases check that it
    fires on a maker whether the function is named or anonymous, that the patched
    source still COMPILES, that the hook is handed the real prototype table, and
    that a source with nothing self-indexed is refused instead of guessed at.

    The first version matched only `function(` and so found no maker at all in a
    source that names its functions, which is why the named case is here.
    """
    try:
        import lupa
    except ImportError:
        return []
    src = io.open(path, encoding="utf-8").read()
    try:
        a = src.index("local function patchProtos(s)")
        b = src.index("local function patchResolver(s)")
    except ValueError:
        return ["universal.lua has no patchProtos to test"]
    L = lupa.LuaRuntime(unpack_returned_tuples=True)
    mk = L.execute(src[a:b] + "\nreturn patchProtos\n")
    chk = L.eval("function(s) local f,e=(load or loadstring)(s);"
                 " return f and 'OK' or tostring(e) end")
    bad = []
    for name, (text, should) in _PROTO_CASES.items():
        got = mk(text)
        if should and got is None:
            bad.append("%s: no maker found, so no prototype would be dumped"
                       % name)
            continue
        if not should:
            if got is not None:
                bad.append("%s: a maker was claimed where nothing is indexed "
                           "through itself" % name)
            continue
        out = got[0]
        if "__PROTO(" not in out:
            bad.append("%s: nothing was injected" % name)
        verdict = chk(out)
        if verdict != "OK":
            bad.append("%s: the patched source does not compile: %s"
                       % (name, verdict))
    # the hook must receive the prototype itself, not something near it
    got = mk(_PROTO_CASES["named maker"][0])
    if got is not None:
        seen = []
        L2 = lupa.LuaRuntime(unpack_returned_tuples=True)
        L2.globals().__PROTO = lambda p: seen.append(p)
        try:
            build = L2.execute(got[0])
            build(None, L2.table_from({3: L2.table_from([7, 8, 9])}), None)
        except Exception as exc:                      # noqa: BLE001
            bad.append("the patched maker would not run: %s" % exc)
        if not seen:
            bad.append("the hook never fired while the maker ran")
        elif seen[0] is None or seen[0][3] is None or seen[0][3][1] != 7:
            bad.append("the hook was handed something that is not the prototype")
    return bad


# The accessor this family hands slices out through. The shape is what matters:
# a one-parameter local function that indexes a captured table by that parameter
# and returns nil when the entry is absent. The caller then indexes the nil, and
# the engine says "attempt to index nil with number".
_SLICE_CASES = {
    "the real shape": (
        "local function oS(ow)local oM=oz[ow];if not oM then return nil end;"
        "return {oD,oM[2],oM[1]}end", True),
    # a one-parameter function that does NOT guard is not this accessor
    "no nil guard": (
        "local function f(i)local m=t[i];return m end", False),
    # the guard must be on the value taken from the table, not on something else
    "guard on another value": (
        "local function f(i)local m=t[i];if not other then return nil end;"
        "return m end", False),
}


def slice_hook(path=UNIVERSAL):
    """The slice-accessor watch, checked on the shape it exists for.

    Also checked as a PURE INSERTION: the patched text must differ from the
    original by the injected call and by nothing else. An injection that rewrote
    any of the surrounding text would be changing the program it is there to
    observe, and on a one-line megabyte source no one would see it happen.
    """
    try:
        import lupa
    except ImportError:
        return []
    src = io.open(path, encoding="utf-8").read()
    try:
        a = src.index("local slices, sliceN = {}, 0")
        b = src.index("local function patchProtos(s)")
    except ValueError:
        return ["universal.lua has no patchSlices to test"]
    L = lupa.LuaRuntime(unpack_returned_tuples=True)
    mk = L.execute(src[a:b].replace("HID.__SLICE", "local _unused")
                   + "\nreturn patchSlices\n")
    chk = L.eval("function(s) local f,e=(load or loadstring)(s);"
                 " return f and 'OK' or tostring(e) end")
    bad = []
    for name, (text, should) in _SLICE_CASES.items():
        got = mk(text)
        if should and got is None:
            bad.append("%s: the accessor was not matched, so no slice request "
                       "would be recorded" % name)
            continue
        if not should:
            if got is not None:
                bad.append("%s: matched something that is not this accessor"
                           % name)
            continue
        out = got[0]
        if "__SLICE(" not in out:
            bad.append("%s: nothing was injected" % name)
            continue
        verdict = chk(out)
        if verdict != "OK":
            bad.append("%s: the patched source does not compile: %s"
                       % (name, verdict))
        # pure insertion: deleting the injected call must give the original back
        import re as _re
        undone = _re.sub(r"if __SLICE then __SLICE\([^)]*\)end;", "", out)
        if undone != text:
            bad.append("%s: the injection changed text around it. original %r, "
                       "recovered %r" % (name, text[:60], undone[:60]))
    return bad


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
                  "missingN", "HARNESS_ENGINE", "protosDone", "protoSeen",
                  "protoN", "slices", "sliceN")


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
    leaks = _declared_locals(path) + proto_hook(path) + slice_hook(path)
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
    print("harness decision self-test: %d case(s) + %d proto + %d slice, "
          "%d problem(s)%s"
          % (len(CASES), len(_PROTO_CASES), len(_SLICE_CASES), len(probs),
             "" if ran else "  [NOT RUN]"))
    for p in probs:
        print("  - %s" % p)
    raise SystemExit(1 if probs else 0)
