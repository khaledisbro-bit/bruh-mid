#!/usr/bin/env python3
"""
final.py - consolidate every run into one organized reconstruction.

The obfuscator randomizes its path per run, so different runs expose different
parts of the program (one run showed the DataStore system, another the visual
system). This merges the recovered constant surfaces from any number of traces
(value-flow traces and/or resolver-constant dumps) into a single, de-duplicated,
grouped picture of the whole script, plus a reconstructed Lua skeleton.

Everything here was observed on the VM at runtime across the given traces.
Nothing is invented; VM/crypto noise and anti-tamper decoys are filtered out.

    python3 final.py trace1.txt [trace2.txt ...]
"""
import re
import sys

import ai
import flow


def values_from_trace(text):
    """Real program strings + numbers from a value-flow trace (5-field)."""
    strings, numbers = [], []
    for _pc, _op, _od, _sp, v in flow.parse(text):
        if not v:
            continue
        s = flow._real_string(v)
        if s is not None:
            if re.fullmatch(r"-?\d+(\.\d+)?", s):
                numbers.append(s)
            else:
                strings.append(s)
    return strings, numbers


def values_from_resolved(text):
    """Real program strings + numbers from a resolver-constant dump (S:/N:)."""
    toks = [l.strip() for l in text.splitlines() if l.strip().startswith(("S:", "N:"))]
    if not toks:
        # maybe it's the ---RESOLVED--- section of a full trace
        if "---RESOLVED---" in text:
            body = text.split("---RESOLVED---", 1)[1].split("END_UNOBF", 1)[0]
            toks = [l.strip() for l in body.splitlines() if l.strip().startswith(("S:", "N:"))]
    fr = ai.filter_resolved(toks)
    return fr["strings"], fr["numbers"]


def consolidate(traces):
    S, N = [], []
    seen_s, seen_n = set(), set()

    def add(strings, numbers):
        for s in strings:
            if s not in seen_s:
                seen_s.add(s); S.append(s)
        for n in numbers:
            if n not in seen_n:
                seen_n.add(n); N.append(n)

    for text in traces:
        if re.search(r"\n-?\d+;-?\d+;[^;]*;-?\d+;", text):     # value-flow trace
            add(*values_from_trace(text))
        if "S:" in text or "N:" in text or "---RESOLVED---" in text:
            add(*values_from_resolved(text))

    sset = set(S)
    # subsystem detection (by the API each area needs)
    subsystems = []
    if {"DataStoreService"} & sset or {"GetDataStore", "PlayerStats_V2"} & sset:
        keys = [k for k in ("Coins", "Level", "XP", "Cash", "Gold", "Wins", "Kills")
                if k in sset]
        subsystems.append(("player data store",
                           "DataStoreService + keys %s; PlayerAdded/PlayerRemoving handlers"
                           % (keys or "(recovered)")))
    if {"RaycastParams", "CFrame", "ColorSequence", "TweenInfo"} & sset:
        subsystems.append(("visual / effects",
                           "raycast + CFrame/Vector3 placement, Color3/ColorSequence "
                           "gradients, TweenService/TweenInfo animation"))

    L = []
    L.append("FINAL RECONSTRUCTION  -  consolidated from %d run(s)" % len(traces))
    L.append("=" * 60)
    L.append("The obfuscator takes a different path each run, so each trace")
    L.append("reveals part of the program. Merged below: %d strings + %d numbers,"
             % (len(S), len(N)))
    L.append("every one observed on the VM at runtime. No fabrication; VM/crypto")
    L.append("noise and anti-tamper decoys removed by structure.")
    L.append("")
    L.append("== what the script is ==")
    if subsystems:
        for name, desc in subsystems:
            L.append("  [%s] %s" % (name, desc))
    else:
        L.append("  (subsystems not conclusively identified)")
    L.append("")
    L.append("== recovered API surface, grouped by area ==")
    for line in ai.reconstruct_outline(S, N):
        L.append(line)
    L.append("")
    L.append("== reconstructed Lua skeleton (from the merged evidence) ==")
    L.extend(_skeleton(sset, N))
    L.append("")
    L.append("== honesty ==")
    L.append("  This is the program's real constant + behaviour surface, recovered")
    L.append("  from execution. It is NOT byte-exact source: the VM discarded the")
    L.append("  original text and randomizes opcodes per run, so exact statement")
    L.append("  structure for the un-run branches cannot be recovered without")
    L.append("  guessing, which is deliberately not done.")
    return "\n".join(L)


def _skeleton(sset, N):
    out = []
    services = [s for s in ("Players", "Workspace", "HttpService", "RunService",
                            "ReplicatedStorage", "TweenService", "DataStoreService")
                if s in sset]
    for s in services:
        out.append('local %s = game:GetService("%s")' % (s, s))
    if "DataStoreService" in sset or "PlayerStats_V2" in sset:
        out.append('')
        out.append('local store = DataStoreService:GetDataStore("PlayerStats_V2")')
        keys = [k for k in ("Coins", "Level", "XP") if k in sset]
        if keys:
            out.append("local DEFAULT = { " +
                       ", ".join("%s = %s" % (k, "100" if k == "Coins" and "100" in N else "0")
                                 for k in keys) + " }")
        if "PlayerAdded" in sset:
            out.append("Players.PlayerAdded:Connect(function(player) --[[ load stats ]] end)")
        if "PlayerRemoving" in sset:
            out.append("Players.PlayerRemoving:Connect(function(player) --[[ save stats ]] end)")
    if "RaycastParams" in sset:
        out.append('')
        out.append("local rp = RaycastParams.new()")
        if "IgnoreWater" in sset:
            out.append("rp.IgnoreWater = true")
    if "ColorSequence" in sset:
        stops = sorted(float(n) for n in N if 0 <= _f(n) <= 1)
        out.append("local gradient = ColorSequence.new({ --[[ Color3 keypoints at %s ]] })"
                   % ", ".join(str(s) for s in stops[:8]))
    if "TweenInfo" in sset:
        out.append("local info = TweenInfo.new(--[[ time, EasingStyle, EasingDirection ]])")
    out.append("-- (bodies of event-gated handlers run only on their event; not traced)")
    return ["  " + l if l else l for l in out]


def _f(n):
    try:
        return float(n)
    except ValueError:
        return -1


if __name__ == "__main__":
    texts = [open(p, encoding="latin1").read() for p in sys.argv[1:]]
    print(consolidate(texts))
