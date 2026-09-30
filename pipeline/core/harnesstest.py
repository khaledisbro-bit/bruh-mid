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
local slicesDone = false
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


# The shape the production bug needed: the row statement comes AFTER the opcode
# expression, so the name is not in scope where the logger goes. Taking the first
# `local X=Y[PC];` in the file finds this one anyway and injects a name Lua then
# resolves to a nil global - which is precisely what the real sample did.
_ROW_AFTER = ("local function I(C,P) while true do "
              "local U=((P-1)*7919+3)%2147483647;"
              "local L=(Q+U)%2147483647;"
              "local R=C[P];"
              "if ((L-U)%0x7FFFFFFF)==3 then end end end;")

# Two loops SHARING the counter's name, which obfuscated output does constantly.
# The pc name then cannot tell them apart and only position can.
_SHARED_PC = (
    "local function A(Ca,P) while true do local Ra=Ca[P];"
    "local Ua=((P-1)*11+1)%2147483647;local La=(Qa+Ua)%2147483647;"
    "if ((La-Ua)%0x7FFFFFFF)==1 then end end end;"
    "local function B(Cb,P) while true do local Rb=Cb[P];"
    "local Ub=((P-1)*13+2)%2147483647;local Lb=(Qb+Ub)%2147483647;"
    "if ((Lb-Ub)%0x7FFFFFFF)==2 then end end end;")

_TWO_VMS = {
    "I1": ("local function I1(C1,P1) while true do local R1=C1[P1];"
           "local U1=((P1-1)*1146147578+7)%2147483647;"
           "local L1=(Q1+U1)%2147483647;"
           "if ((L1-U1)%0x7FFFFFFF)==3 then end end end;"),
    "I2": ("local function I2(C2,P2) while true do local R2=C2[P2];"
           "local U2=((P2-1)*999983+11)%2147483647;"
           "local L2=(Q2+U2)%2147483647;"
           "if ((L2-U2)%0x7FFFFFFF)==5 then end end end;"),
}


def dispatch_anchor(path=UNIVERSAL):
    """Every name in the injected call must come from ONE interpreter.

    Each name used to be taken with its own match against the whole source, which
    returns the first occurrence in the file. A build with more than one
    interpreter on one line - which is every build of this family - then gave a
    row variable from one loop and an injection point in another. The logger read
    a name that was not in scope, saw nil, and the capture said the interpreter
    had read a missing instruction. Six rounds of this work believed that.

    So the opcode expression is the anchor and everything else is found by
    walking back from it. These cases put two interpreters on one line in both
    orders and demand that the injection never mixes them.
    """
    try:
        import lupa
    except ImportError:
        return []
    src = io.open(path, encoding="utf-8").read()
    try:
        a = src.index("-- The last match of a pattern that starts at or before")
        b = src.index("local function patchResolver(s)")
    except ValueError:
        return ["universal.lua has no anchored patchDispatch to test"]
    L = lupa.LuaRuntime(unpack_returned_tuples=True)
    mk = L.execute("local HID = {}\nlocal PATCH_AT, PATCH_ADDED, ORIGINAL_LINES\n"
                   + src[a:b] + "\nreturn patchDispatch\n")
    chk = L.eval("function(s) local f,e=(load or loadstring)(s);"
                 " return f and 'OK' or tostring(e) end")
    bad = []
    for first, second in (("I1", "I2"), ("I2", "I1")):
        text = _TWO_VMS[first] + _TWO_VMS[second]
        got = mk(text)
        if got is None:
            bad.append("%s first: no dispatch loop was found at all"
                       % first)
            continue
        out = got[0]
        i = out.find("__OP(")
        if i < 0:
            bad.append("%s first: nothing was injected" % first)
            continue
        seg = out[i:i + 64]
        n = first[-1]
        other = "2" if n == "1" else "1"
        if ("P%s," % n) not in seg or ("R%s," % n) not in seg:
            bad.append("%s first: the injection does not use that loop's own "
                       "names: %s" % (first, seg))
        if ("P%s," % other) in seg or ("R%s," % other) in seg:
            bad.append("%s first: the injection mixed in the OTHER loop's "
                       "names: %s" % (first, seg))
        verdict = chk(out)
        if verdict != "OK":
            bad.append("%s first: the patched source does not compile: %s"
                       % (first, verdict))

    # The row declared AFTER the injection point. Injecting there names a
    # variable that is not in scope yet, so this must be refused outright rather
    # than patched with a name that will read nil.
    got = mk(_ROW_AFTER)
    if got is not None:
        out = got[0]
        i = out.find("__OP(")
        if i >= 0 and ",R," in out[i:i + 48]:
            bad.append("a row declared after the injection point was used "
                       "anyway, so the logger would read a nil global: %s"
                       % out[i:i + 48])

    # Two loops sharing the counter's name: only position separates them.
    got = mk(_SHARED_PC)
    if got is None:
        bad.append("two loops sharing a counter name: nothing was found")
    else:
        out = got[0]
        i = out.find("__OP(")
        seg = out[i:i + 56]
        if "Ra," not in seg:
            bad.append("with a shared counter name the first loop's row should "
                       "be used: %s" % seg)
        if "Rb," in seg or "Cb)" in seg:
            bad.append("with a shared counter name the SECOND loop's names were "
                       "mixed in: %s" % seg)
        if chk(out) != "OK":
            bad.append("shared-counter patch does not compile: %s" % chk(out))
    return bad


def op_rows(path=UNIVERSAL):
    """Where the instruction logger reads the row from.

    It used to read the variable the dispatch loop assigns it to, matched from one
    place in a one-line megabyte source while the call is injected at another. On
    the real sample that variable was nil for six of nine instructions, and the
    capture reported the interpreter reading something that was not an
    instruction row - which was believed, and was wrong: the same capture recorded
    a full row in the array at those very numbers.

    So the row comes from the array and the counter, which is what the
    interpreter itself indexes, and a disagreement with the loop variable is
    recorded as a fault in this hook rather than as a fact about the program.
    These cases pin all four outcomes.
    """
    try:
        import lupa
    except ImportError:
        return []
    src = io.open(path, encoding="utf-8").read()
    try:
        a = src.index("HID.__OP = function(pc, oc, NO, sp, top, arr)")
        b = src.index("-- SAFE MODE:")
    except ValueError:
        return ["universal.lua has no __OP to test"]
    pre = ("\nlocal ops, opn = {}, 0\nlocal HID = {}\n"
           "local function vprev(v)\n"
           "  local t = type(v)\n"
           "  if t == 'string' then return '\"'..v..'\"'\n"
           "  elseif t == 'nil' then return 'nil'\n"
           "  elseif t == 'table' then return '{}'\n"
           "  else return tostring(v) end\n"
           "end\n"
           "local ids, idn = {}, 0\n"
           "local function arrayId(a) local k=tostring(a)\n"
           "  if ids[k]==nil then idn=idn+1; ids[k]=idn end; return ids[k] end\n")
    L = lupa.LuaRuntime(unpack_returned_tuples=True)
    op, ops = L.execute(pre + src[a:b] + "\nreturn HID.__OP, ops\n")
    arr = L.table_from({2010: L.table_from([111, 7, 8]),
                        4: L.table_from([222, 418462, 1])})
    bad = []

    # the case that was being misread: loop variable nil, array row present
    op(2010, 0, None, 0, None, arr)
    r = ops[1]
    if "7,8" not in r:
        bad.append("the operands in the array were not recovered: %s" % r)
    if "src=array" not in r:
        bad.append("the row's source was not recorded: %s" % r)
    if "hook_var_disagrees" not in r:
        bad.append("a hook that read the wrong variable must say so: %s" % r)
    if "row=nil" in r:
        bad.append("a row that IS in the array must not be reported absent: %s"
                   % r)

    # agreeing case: no complaint
    op(4, 297, arr[4], 0, None, arr)
    r = ops[2]
    if "418462,1" not in r or "hook_var_disagrees" in r:
        bad.append("an agreeing row should be quiet: %s" % r)

    # genuinely absent: still reported absent
    op(9999, 5, None, 0, None, arr)
    if "row=nil" not in ops[3]:
        bad.append("a row that is really absent must be reported: %s" % ops[3])

    # no array handed over: fall back to the variable and say which
    op(3, 92, L.table_from([1, 5, 6]), 0, None, None)
    r = ops[4]
    if "5,6" not in r or "src=loopvar" not in r:
        bad.append("with no array, the loop variable is the only source and the "
                   "row should say so: %s" % r)
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
                  "protoN", "slices", "sliceN", "slicesDone")


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
    leaks = (_declared_locals(path) + proto_hook(path)
             + slice_hook(path) + op_rows(path) + dispatch_anchor(path))
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
