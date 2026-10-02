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
-- the ladder's rung that keeps the trace and drops the resolver. The stub below
-- has to respect it, or the round it produces looks identical to the one before.
local RESOLVER_OFF = false
local protoN = 0
local slices, sliceN = {}, 0
local blocks, blockN = {}, 0
local conds, condN = {}, 0
local viols, violN = {}, 0
local keyTabs, keyTabN = {}, 0
local fields, fieldN = {}, 0
local jumps, jumpN = {}, 0
local slicesDone = false
local ORIGINAL_LINES, PATCH_AT, PATCH_ADDED = nil, nil, 0
local function realLoad(src)
  if SCEN.noload then return nil end
  return function()
    -- what the loadstring hook would have done while the payload was running
    if PATCH_LEVEL >= 3 and SCEN.proto_matches then protosDone = true end
    if PATCH_LEVEL >= 1 and SCEN.resolver_matches and not RESOLVER_OFF then
      resolverDone = true
    end
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
    # The resolver-off round is tried before the logger is given up, so a
    # payload that only tolerates level 1 passes through it on the way.
    "dispatch logger caught": (
        dict(trace=True, proto_matches=True, resolver_matches=True,
             dispatch_matches=True, lives_at=1),
        {"harness_id": "protos+traced->traced->traced-no-resolver->"
                       "resolver-only",
         "attempts": "4", "run_ok": "true", "trace_verdict": "patch_caught"}),
    # tolerates no edit at all: the harness has to reach untouched
    "resolver rewrite caught": (
        dict(trace=True, proto_matches=True, resolver_matches=True,
             dispatch_matches=True, lives_at=0),
        {"harness_id": "protos+traced->traced->traced-no-resolver->"
                       "resolver-only->unpatched",
         "attempts": "5", "run_ok": "true", "trace_verdict": "patch_caught"}),
    # Five rounds, not four: between "traced" and "resolver-only" there is a
    # round that keeps the trace and drops the resolver. Without it, a build
    # that objects to the resolver rewrite and one that objects to the dispatch
    # logger produce the same ladder, and only the second leaves instructions
    # behind.
    "raises at every level": (
        dict(trace=True, proto_matches=True, resolver_matches=True,
             dispatch_matches=True, lives_at=None),
        {"harness_id": "protos+traced->traced->traced-no-resolver->"
                       "resolver-only->unpatched",
         "attempts": "5", "run_ok": "false", "trace_verdict": "not_the_patches"}),
    # an edit that never went in is not stepped over: doing so would repeat the
    # round and read as evidence
    "no proto maker matched": (
        dict(trace=True, proto_matches=False, resolver_matches=True,
             dispatch_matches=True, lives_at=None),
        {"harness_id": "traced->traced-no-resolver->resolver-only->unpatched",
         "attempts": "4", "trace_verdict": "not_the_patches"}),
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
    # a bare HID table, so any other hook that shares this slice of the file
    # can define itself without the extraction needing to know about it
    mk = L.execute("local HID={}\n" + src[a:b] + "\nreturn patchSlices\n")
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
        # the injected call now contains parentheses of its own, so the undo
        # has to run to the call's own `)end;` rather than the first `)`
        undone = _re.sub(r"if __SLICE then __SLICE\(.*?\)end;", "", out)
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


def no_source_message(path=UNIVERSAL):
    """What the harness says when it has no script to run.

    The standalone copy carries no script and reads obf.lua from the executor's
    own folder, so this is the message a person sees most often when something is
    set up wrong. It used to be `assert(SOURCE, "no source")`, which names
    nothing anyone can act on."""
    try:
        import lupa
    except ImportError:
        return []
    src = io.open(path, encoding="utf-8").read()
    if "readfile(\"obf.lua\")" not in src:
        return ["universal.lua no longer reads obf.lua"]
    L = lupa.LuaRuntime(unpack_returned_tuples=True)
    g = L.globals()
    g.readfile = L.eval("function() error('not found') end")
    g.print = L.eval("function(s) MSG = tostring(s) end")
    try:
        _ok, err = L.eval("function(s) return pcall(load(s)) end")(src)
    except Exception as exc:                          # noqa: BLE001
        return ["the harness would not even load: %s" % exc]
    msg = str(g.MSG or err or "")
    bad = []
    if msg.strip() == "no source":
        bad.append("the no-script message is still the bare assert, which tells "
                   "a person nothing they can act on")
    for want in ("obf.lua", "harness.lua"):
        if want not in msg:
            bad.append("the no-script message should name %s, got %r"
                       % (want, msg[:120]))
    return bad


# The loop top of this family: the row is fetched, a field is taken from it,
# the OPCODE is taken from index 0 with an `or 0` fallback, and only then does the
# dispatch chain start. Every instruction passes through here.
_LOOP_TOP = ("local function I(ed,Jq) while true do local Jg=ed[Jq];"
             "Jg=pM and pM[Jq];local Jd=Jg and Jg[1]or -1;"
             "local JY=Jg and Jg[0]or 0;Jq=Jq+1;"
             "if JY==156 then elseif JY==339 then else "
             "local JP=((Jq-1)*809834779+JL)%2147483647;"
             "local JZ=(JY+JP)%2147483647;"
             "if ((JZ-JP)%0x7FFFFFFF)==1 then end end end end;")


# The same loop, formatted the way a build that does NOT minify emits it, and
# the same loop with an unguarded opcode read. Neither is a different kind of
# interpreter; both were invisible to a matcher that had one minifier's spacing
# written into it.
_LOOP_TOP_SPACED = (
    "local function I(ed, Jq)\n"
    "  while true do\n"
    "    local Jg = ed[Jq]\n"
    "    local Jd = Jg and Jg[1] or -1\n"
    "    local JY = Jg and Jg[0] or 0\n"
    "    Jq = Jq + 1\n"
    "    if JY == 156 then elseif JY == 339 then end\n"
    "  end\n"
    "end\n")

_LOOP_TOP_BARE = ("local function I(ed,Jq) while true do local Jg=ed[Jq];"
                  "local JY=Jg[0];Jq=Jq+1;"
                  "if JY==156 then elseif JY==339 then end end end;")

# a bare read early, a guarded loop later. The guarded one is the dispatch loop,
# and a matcher that takes whichever comes first picks the wrong one.
_BARE_THEN_GUARDED = ("local function pre(t,k) local r=t[k];local v=r[2] "
                      "return v end;" + _LOOP_TOP)

_NO_LOOP = "local a=1 local b=a+2 print(b) return b"


_JUMP_DECODER = ("local function el(x,k,s,o)if k~=0 then x=Nn(x,k)end;"
                 "local e=eO[x] or {eK[3]+x,-1,-1,-1};local z=e[1];return z end;")
_NOT_A_DECODER = ("local function f(a,b,c,d)local e=tbl[a] end;")


def probes_are_passive(path=UNIVERSAL):
    """A probe must not read through the program's own tables.

    These VMs put a metatable on the tables they look values up in, whose
    __index decrypts the entry and advances a running key. An extra read is an
    extra step of that key, and every later read then comes out wrong. The first
    jump watch read the lookup table twice more per branch; the traced round went
    from 12 instructions to NONE. The watch destroyed the run it existed to
    observe, and the capture reported that as the program failing.

    So the test is a count, not an opinion: run the original and the patched
    source against a table that counts every __index and __len it is asked for,
    and demand the same number.
    """
    try:
        import lupa
    except ImportError:
        return []
    src = io.open(path, encoding="utf-8").read()
    L = lupa.LuaRuntime(unpack_returned_tuples=True)
    try:
        jb = src.index("local jumps, jumpN = {}, 0")
        sb = src.index("local slices, sliceN = {}, 0")
        pp = src.index("local function patchProtos(s)")
    except ValueError:
        return ["universal.lua has no jump or slice watch to test"]
    mkJ = L.execute("local HID={}\n" + src[jb:pp] + "\nreturn patchJumps\n")
    mkS = L.execute("local HID={}\n" + src[sb:jb] + "\nreturn patchSlices\n")
    run = L.eval("""function(src)
  local reads = 0
  local real = {}
  local eO = setmetatable({}, {__index=function(t,k) reads=reads+1; return real[k] end,
                              __len=function() reads=reads+100; return 0 end})
  local env = {eO=eO, oz=eO, Nn=function(a) return a end, eK={0,0,0},
               __JMP=function() end, __SLICE=function() end,
               rawget=rawget, rawlen=rawlen}
  local f = (load or loadstring)(src, "c", "t", setmetatable(env,{__index=_G}))
  if not f then return -1 end
  local ok = pcall(f)
  if not ok then return -2 end
  return reads
end""")
    cases = {
        "jump decoder": (mkJ,
            "local function el(x,k,s,o)if k~=0 then x=Nn(x,k)end;"
            "local e=eO[x] or {eK[3]+x,-1,-1,-1};return e[1] end;return el(7,0,1,1)"),
        "slice accessor": (mkS,
            "local function oS(ow)local oM=oz[ow];if not oM then return nil end;"
            "return {1,oM} end;return oS(3)"),
    }
    bad = []
    for name, (mk, text) in cases.items():
        got = mk(text)
        if got is None:
            bad.append("%s: not matched, so this check proves nothing" % name)
            continue
        base, patched = run(text), run(got[0])
        if patched < 0:
            bad.append("%s: the patched source does not run (%d)" % (name, patched))
        elif patched != base:
            bad.append("%s: the probe added %d read(s) through the program's own "
                       "table - it would advance a decrypting key and corrupt "
                       "the run it is watching" % (name, patched - base))
    return bad


def jump_hook(path=UNIVERSAL):
    """The jump decoder's lookup, and whether it hit or fell back.

    This family resolves a branch target through a table with an `or {...}`
    fallback: a miss means the target is COMPUTED from a base rather than read,
    and a computed target can land outside every block the interpreter knows.
    On the real sample the run dies six instructions after its first jump, so
    which of the two happened is the question the capture has to answer."""
    try:
        import lupa
    except ImportError:
        return []
    src = io.open(path, encoding="utf-8").read()
    try:
        a = src.index("local jumps, jumpN = {}, 0")
        b = src.index("local function patchProtos(s)")
    except ValueError:
        return ["universal.lua has no patchJumps to test"]
    L = lupa.LuaRuntime(unpack_returned_tuples=True)
    mk = L.execute("local HID={}\n" + src[a:b] + "\nreturn patchJumps\n")
    chk = L.eval("function(s) local f,e=(load or loadstring)(s);"
                 " return f and 'OK' or tostring(e) end")
    bad = []
    got = mk(_JUMP_DECODER)
    if got is None:
        bad.append("the jump decoder was not matched, so a computed target "
                   "would go unrecorded")
    else:
        out = got[0]
        if "__JMP(" not in out:
            bad.append("nothing was injected into the decoder")
        # The log goes AFTER the lookup on purpose. Reporting from `e` - the
        # value the VM just computed - and testing the table with rawget is what
        # keeps the probe from reading through a decrypting metatable. An earlier
        # version read the table again to answer "was it there", and that extra
        # read is what killed the run.
        if out.find("__JMP(") < out.find("local e=eO[x]"):
            bad.append("the log must come AFTER the lookup, so it can report "
                       "the value the VM computed instead of reading again")
        seg = out[out.find("__JMP("):out.find("__JMP(") + 90]
        if "rawget(" not in seg:
            bad.append("the probe must test the table with rawget: %s" % seg)
        if "eO[x]" in seg:
            bad.append("the probe reads through the program's own table, which "
                       "advances a decrypting key: %s" % seg)
        if chk(out) != "OK":
            bad.append("the patched decoder does not compile: %s" % chk(out))
        import re as _re
        undone = _re.sub(r"if __JMP then __JMP\(.*?\)end;", "", out)
        if undone.replace(";;", ";") != _JUMP_DECODER.replace(";;", ";"):
            bad.append("the injection changed text around it")
    # a four-parameter function with no `or {` fallback is not this decoder
    if mk(_NOT_A_DECODER) is not None:
        bad.append("matched a function that has no lookup fallback")
    return bad


def loop_top(path=UNIVERSAL):
    """The logger must go at the loop top, and take the opcode the VM takes.

    It used to be anchored on arithmetic in the dispatch chain's FINAL else, so it
    only ever saw instructions whose opcode fell through every handler. Nine rows
    came back from the real sample and were read as "the program ran nine
    instructions and died". They were nine instructions out of however many ran,
    selected by which handler they missed, and every count and every jump this
    package reported for that build came from that filtered subset.

    Checked here: the anchor is the loop top, the opcode comes from the row's own
    index (0 for this family, read from the source and not assumed), the injection
    is a pure insertion, and the row variable is trusted THERE - because the
    interpreter has just read its opcode out of it - even though the array named
    at the loop top is not the one the row came from.
    """
    try:
        import lupa
    except ImportError:
        return []
    src = io.open(path, encoding="utf-8").read()
    try:
        # from lastBefore, because the fallback path uses it and a mutant that
        # disables the loop top must still be able to run
        a = src.index("-- The last match of a pattern that starts at or before")
        b = src.index("local function patchResolver(s)")
    except ValueError:
        return ["universal.lua has no loop-top patcher to test"]
    L = lupa.LuaRuntime(unpack_returned_tuples=True)
    pd = L.execute("local HID={}\nlocal PATCH_AT,PATCH_ADDED,ORIGINAL_LINES\n"
                   + src[a:b] + "\nreturn patchDispatch\n")
    chk = L.eval("function(s) local f,e=(load or loadstring)(s);"
                 " return f and 'OK' or tostring(e) end")
    bad = []
    got = pd(_LOOP_TOP)
    if got is None:
        return ["the loop top was not found at all, so the logger would fall "
                "back to the dispatch chain and see only the instructions that "
                "miss every handler"]
    out, why = got[0], got[1]
    if "loop top" not in why:
        bad.append("the loop-top strategy should say so: %r" % why)
    if "[0]" not in why:
        bad.append("the opcode index should be read from the source and "
                   "reported: %r" % why)
    i = out.find("__OP(")
    if i < 0:
        bad.append("nothing was injected")
        return bad
    seg = out[i:i + 80]
    if ",JY," not in seg:
        bad.append("the injection must log the interpreter's OWN opcode "
                   "variable: %s" % seg)
    if ",true)" not in seg:
        bad.append("a loop-top injection must mark the row variable as "
                   "trustworthy: %s" % seg)
    # it must land BEFORE the dispatch chain, not inside its final else
    if out.find("__OP(") > out.find("if JY==156"):
        bad.append("the injection landed after the dispatch chain started, so "
                   "it would miss every instruction a handler takes")
    if chk(out) != "OK":
        bad.append("the patched source does not compile: %s" % chk(out))
    # Luau has no empty statement, so `;;` anywhere in the result is a syntax
    # error there even though the Lua this test runs under accepts it. The
    # harness then loads the UNPATCHED chunk instead and the round reports a
    # trace that logged nothing.
    if ";;" in out:
        bad.append("the patched source contains `;;`, which Luau rejects")
    # pure insertion
    import re as _re
    # every watch the harness adds at the loop top is an INSERTION, so removing
    # the inserted text has to give the original chunk back character for
    # character. Each new watch is listed here on purpose: a watch that rewrote
    # the chunk instead of adding to it would pass unnoticed otherwise.
    undone = _re.sub(r";if __OP then __OP\([^)]*\)end;if __CODE then "
                     r"__CODE\([^)]*\)end", "", out)
    undone = _re.sub(r";if __KEYS then __KEYS\([^)]*\)end"
                     r"(?:;if __KEYS then __KEYS\([^)]*\)end)*", "", undone)
    if undone != _LOOP_TOP:
        bad.append("the injection changed text around it")

    # The spacing is the minifier's, not the build's. These three cases are the
    # same loop written differently, and each was a loop the matcher reported as
    # absent.
    for name, text, want in (("spaced out over lines", _LOOP_TOP_SPACED,
                              "guarded"),
                             ("an unguarded opcode read", _LOOP_TOP_BARE,
                              "bare"),
                             ("a bare read before the real loop",
                              _BARE_THEN_GUARDED, "guarded")):
        got = pd(text)
        if got is None:
            bad.append("%s: the loop top was not found" % name)
            continue
        out2, why2 = got[0], got[1]
        if want not in why2:
            bad.append("%s: the capture should name the shape %s: %r"
                       % (name, want, why2))
        if "__OP(" not in out2:
            bad.append("%s: nothing was injected" % name)
            continue
        if ",JY," not in out2[out2.find("__OP("):out2.find("__OP(") + 80]:
            bad.append("%s: the wrong opcode variable was logged" % name)
        if chk(out2) != "OK":
            bad.append("%s: the patched source does not compile: %s"
                       % (name, chk(out2)))
        if out2.find("__OP(") > out2.find("if JY==156" if "\n" not in text
                                          else "if JY == 156"):
            bad.append("%s: the injection landed after the dispatch chain"
                       % name)
    return bad


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
        a = src.index("HID.__OP = function(pc, oc, NO, sp, top, arr")
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
                  "protoN", "slices", "sliceN", "slicesDone",
                  "jumps", "jumpN")


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


def debug_shield(path=UNIVERSAL):
    """The shield must answer about the SCRIPT, not about itself.

    The harness replaces debug.info so a patched chunk still reports the lines it
    shipped with. A numeric first argument is a stack level counted from the
    caller, and the shield is a frame the script does not know it has - so the
    level has to be raised by one. It was not, and the call went through a pcall
    as well, which is a second frame: level 1 landed on pcall, a C function, and
    every script that asked which line it was on got -1. A build that checks its
    own line numbers reads that as tampering.

    This runs under a real Luau binary, because the answer depends on how that
    interpreter counts frames and no paraphrase of it is worth anything. With no
    Luau available the check is skipped rather than guessed.
    """
    import os
    import subprocess
    import sys
    import tempfile
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        import localvm
    except ImportError:
        return []
    luau, _ = localvm.find()
    if not luau:
        return []
    src = io.open(path, encoding="utf-8").read()
    try:
        a = src.index("local ORIGINAL_LINES, PATCH_AT, PATCH_ADDED")
        b = src.index("setmetatable(DBG, { __index = realdebug })")
    except ValueError:
        return ["universal.lua has no debug shield to test"]
    block = src[a:b] + "setmetatable(DBG, { __index = realdebug })\n"
    script = ("local realenv = getfenv and getfenv() or _G\n"
              + block +
              "local shielded, direct = DBG.info(1, \"l\"), debug.info(1, \"l\")\n"
              "print(\"shielded=\" .. tostring(shielded) .. \" direct=\" "
              ".. tostring(direct))\n")
    d = tempfile.mkdtemp(prefix="vmsmart-shield-")
    try:
        f = os.path.join(d, "shield.luau")
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(script)
        r = subprocess.run([luau, f], capture_output=True, timeout=30)
        out = (r.stdout or b"").decode("utf-8", "replace").strip()
        err = (r.stderr or b"").decode("utf-8", "replace").strip()
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
    if "shielded=" not in out:
        return ["the shield could not be exercised under Luau: %s"
                % (err.splitlines()[0] if err else out or "no output")]
    parts = dict(p.split("=", 1) for p in out.split() if "=" in p)
    shielded, direct = parts.get("shielded"), parts.get("direct")
    bad = []
    if shielded == "-1":
        bad.append("the shield reports line -1, which is what a C frame reports "
                   "- the script is being told about the harness, not itself")
    elif shielded != direct:
        bad.append("the shield reports line %s where the real debug.info on the "
                   "same line reports %s" % (shielded, direct))
    return bad


def selftest(path=UNIVERSAL):
    """Returns (problems, ran). ran is False when no Lua runtime is here."""
    leaks = (_declared_locals(path) + proto_hook(path)
             + slice_hook(path) + op_rows(path) + dispatch_anchor(path)
             + no_source_message(path) + loop_top(path) + jump_hook(path)
    + debug_shield(path)
             + probes_are_passive(path))
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
