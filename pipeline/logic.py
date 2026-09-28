#!/usr/bin/env python3
"""
logic.py - evidence-tagged logic reconstruction from the trace(s).

Goes past the API/constant inventory toward program logic, and labels every
line with the evidence behind it so nothing is presented as more certain than
it is:

  OBSERVED    - the VM actually performed this at runtime (a proxied API call
                with its real arguments, an Instance.new, a GetService).
  INFERRED    - a constructor/value the VM decoded and its value flowed on the
                stack, but we did not observe the full call arguments.
  UNRESOLVED  - an API/handler the VM resolved but whose body did NOT run on the
                observed path (e.g. PlayerAdded on a run that took another
                branch). NOT deleted - the obfuscator takes different paths per
                run, so absence on one trace is not proof of absence.
  DECOY       - anti-tamper throwaway (random-named Instance.new, gauntlet
                primitives).

It also builds a call graph (which service/object each method was called on)
and, when several runs are merged, an item OBSERVED on any run is promoted to
OBSERVED. This is the honest state: observed logic is reconstructed; unobserved
branches are located and marked, not fabricated.
"""
import re

import ai
import flow as flowmod

# high-level logic each API family implies (so the report names the behaviour,
# not just the symbol). Only emitted when the API was actually recovered.
_LOGIC_HINTS = [
    (("GetAsync", "GetDataStore", "PlayerStats"), "persistent data LOAD"),
    (("SetAsync", "UpdateAsync", "IncrementAsync"), "persistent data SAVE"),
    (("PlayerAdded",), "player-join lifecycle handler"),
    (("PlayerRemoving",), "player-leave lifecycle handler (usually saves)"),
    (("Coins", "XP", "Level"), "player stat state (coins / xp / level)"),
    (("TweenService", "TweenInfo", "Create"), "animation via tween"),
    (("RaycastParams", "Raycast", "Origin", "Direction"), "raycasting"),
    (("ColorSequence", "Color3", "Keypoints"), "colour gradient build"),
    (("spawn", "task", "defer", "delay", "wait"), "async / periodic scheduling"),
    (("pcall",), "error handling"),
]

_EVENTS = ("PlayerAdded", "PlayerRemoving", "CharacterAdded", "Changed",
           "Touched", "Heartbeat", "RenderStepped", "Stepped")


def _observed_calls(behavior):
    """Real calls the VM made, from the instrumented environment. Returns list of
    (statement, kind) where kind is 'service'|'instance'|'method'|'decoy'."""
    cls = ai.classify_behavior(behavior)
    decoy = {l for l, _ in cls["DECOY"]}
    out = []
    for l in behavior:
        if l in decoy:
            m = re.match(r"Instance\.new:\s*(.+)$", l)
            if m:
                out.append(('Instance.new("%s")' % m.group(1).strip(), "decoy"))
            continue
        m = re.match(r"GetService:\s*(\w+)", l)
        if m and m.group(1) != "EncodingService":
            out.append(('game:GetService("%s")' % m.group(1), "service"))
            continue
        m = re.match(r"Instance\.new:\s*(.+)$", l)
        if m:
            out.append(('Instance.new("%s")' % m.group(1).strip(), "instance"))
            continue
        m = re.match(r"(\w[\w.]*)\:(\w+)\((.*)\)$", l)   # ns:method(args)
        if m:
            out.append(("%s:%s(%s)" % (m.group(1), m.group(2), m.group(3)), "method"))
    return out


def reconstruct(traces):
    """traces: list of raw trace texts (each may hold ---BEHAVIOR---/---RESOLVED---
    /---OPCODES--- sections). Returns an evidence-tagged logic report."""
    observed, decoys = [], []
    resolved_tokens, flow_strings = [], []
    for text in traces:
        tr = ai.parse_trace(text)
        for stmt, kind in _observed_calls(tr.get("behavior", [])):
            (decoys if kind == "decoy" else observed).append(stmt)
        resolved_tokens += tr.get("resolved", [])
        # value-flow real strings (from a 5-field trace)
        for _pc, _op, _od, _sp, v in flowmod.parse(text):
            s = flowmod._real_string(v) if v else None
            if s:
                flow_strings.append(s)

    obs = list(dict.fromkeys(observed))
    dec = list(dict.fromkeys(decoys))
    fr = ai.filter_resolved(resolved_tokens) if resolved_tokens else \
        {"strings": [], "numbers": []}
    api = set(fr["strings"]) | set(flow_strings)
    observed_names = set(re.findall(r"[A-Za-z_]\w+", " ".join(obs)))

    # UNRESOLVED = recovered API that we never saw called on the observed path
    unresolved_events = sorted(n for n in _EVENTS if n in api and n not in observed_names)
    # INFERRED constructors: value decoded + flowed but no observed call args
    inferred = [n for n in ("RaycastParams", "ColorSequence", "Color3",
                            "ColorSequenceKeypoint", "TweenInfo", "CFrame",
                            "Vector3", "NumberRange", "BrickColor", "PhysicalProperties")
                if n in api and n not in observed_names]

    L = []
    L.append("LOGIC RECONSTRUCTION (evidence-tagged)")
    L.append("=" * 46)
    L.append("Each line carries its evidence. OBSERVED = the VM did it at runtime;")
    L.append("INFERRED = value decoded/flowed but full call not seen; UNRESOLVED =")
    L.append("resolved but its body did not run on this path (kept, not deleted -")
    L.append("the obfuscator branches differently per run); DECOY = anti-tamper.")
    L.append("")

    # high-level behaviours present
    hints = []
    for keys, desc in _LOGIC_HINTS:
        if any(k in api or any(k in o for o in obs) for k in keys):
            hints.append(desc)
    if hints:
        L.append("== program behaviours detected ==")
        for h in dict.fromkeys(hints):
            L.append("  - " + h)
        L.append("")

    L.append("== OBSERVED calls (real, with runtime arguments) ==")
    for s in obs:
        L.append("  [OBSERVED]   " + s)
    if not obs:
        L.append("  (none on this path)")
    L.append("")

    if inferred:
        L.append("== INFERRED constructors (value decoded + flowed) ==")
        for n in inferred:
            L.append("  [INFERRED]   %s.new(...)  -- args not fully observed" % n)
        L.append("")

    if unresolved_events:
        L.append("== UNRESOLVED (resolved, body not run on this path) ==")
        for n in unresolved_events:
            src = "Players" if n in ("PlayerAdded", "PlayerRemoving") else "<obj>"
            L.append("  [UNRESOLVED] %s.%s:Connect(function(...) ... end)  "
                     "-- drive this event or merge another run to recover the body"
                     % (src, n))
        L.append("")

    if dec:
        L.append("== DECOY (anti-tamper, ignored) ==")
        L.append("  " + ", ".join(dec[:12]))
        L.append("")

    # call graph: object -> methods observed on it
    graph = {}
    for s in obs:
        m = re.match(r"([\w.]+):(\w+)\(", s)
        if m:
            graph.setdefault(m.group(1), set()).add(m.group(2))
        m2 = re.match(r'game:GetService\("(\w+)"\)', s)
        if m2:
            graph.setdefault("game", set()).add('GetService("%s")' % m2.group(1))
    if graph:
        L.append("== call graph (object -> methods observed) ==")
        for obj in sorted(graph):
            L.append("  %s -> %s" % (obj, ", ".join(sorted(graph[obj]))))
        L.append("")

    L.append("== honesty ==")
    L.append("  OBSERVED lines are real runtime calls. INFERRED/UNRESOLVED are")
    L.append("  located and labelled, never invented. Full function/control-flow")
    L.append("  bodies (if/for/while, state updates) need control-flow recovery")
    L.append("  across merged runs; unobserved branches are marked, not deleted.")
    return "\n".join(L)


if __name__ == "__main__":
    import sys
    texts = [open(p, encoding="latin1").read() for p in sys.argv[1:]]
    print(reconstruct(texts))
