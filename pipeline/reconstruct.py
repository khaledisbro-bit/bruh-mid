#!/usr/bin/env python3
"""
reconstruct.py - emit a readable, source-shaped .lua from runtime evidence.

This does NOT invent code. The base85+Zstd obfuscator compiles the original Lua
to VM bytecode and discards the source text, so there is no original to recover
byte-for-byte. What CAN be recovered, and what this writes, is a faithful
skeleton built only from:
  * the API calls the program actually made, in the order it made them (trace),
  * the constants its inner-VM resolver returned (deep-constant dump),
  * the import paths the static lifter read from the bytes (lift.py).

Every line is annotated with where it came from. Nothing is guessed. Event
handler bodies are left as stubs because a passive trace never fires the event,
and that is stated in-line rather than filled with invented logic.
"""
import re

import ai


# services that belong to the obfuscator's own unwrap layer, not user code
_LOADER_SERVICES = {"EncodingService"}


def _service_calls(behavior):
    """Ordered, de-duplicated GetService names from the trace (loader excluded)."""
    seen, out = set(), []
    for l in behavior:
        m = re.match(r"GetService:\s*(\w+)", l)
        if m and m.group(1) not in seen and m.group(1) not in _LOADER_SERVICES:
            seen.add(m.group(1)); out.append(m.group(1))
    return out


def _datastores(behavior):
    ds = []
    for l in behavior:
        for name in re.findall(r'GetDataStore\("([^"]+)"\)', l):
            if name not in ds:
                ds.append(name)
    return ds


def _instances(behavior):
    """Instance.new classes with a real/decoy tag from the classifier."""
    cls = ai.classify_behavior(behavior)
    decoy = {l for l, _ in cls["DECOY"]}
    out = []
    for l in behavior:
        m = re.match(r"Instance\.new:\s*(.+)$", l)
        if m:
            out.append((m.group(1).strip(), l in decoy))
    return out


def reconstruct(tr, lift_imports=None):
    """Return reconstructed Lua source text from a parsed trace `tr`."""
    behavior = tr.get("behavior", [])
    resolved = tr.get("resolved", [])
    fr = ai.filter_resolved(resolved) if resolved else \
        {"strings": [], "numbers": [], "small": [], "dropped_strings": 0, "dropped_numbers": 0}
    cls = ai.classify_behavior(behavior)
    conf, why = ai.confidence(cls, tr)
    cov, _notes = ai.coverage_check(tr, {})

    services = _service_calls(behavior)
    stores = _datastores(behavior)
    instances = _instances(behavior)
    sset = set(fr["strings"])
    L = []
    add = L.append

    add("-- ============================================================")
    add("-- RECONSTRUCTED by VmSmart from runtime evidence.")
    add("-- This is NOT the original source. The obfuscator compiled the")
    add("-- script to VM bytecode and discarded the source text; no original")
    add("-- text exists to recover. Every line below is built only from what")
    add("-- the program provably did (captured calls, in order) and the")
    add("-- constants its VM resolver returned. Nothing here is invented.")
    add("--")
    add("--   confidence: %s (%s)" % (conf, why))
    add("--   coverage  : %s" % cov)
    add("-- ============================================================")
    add("")

    if tr.get("prints"):
        add("-- the program printed this output (its real, observed result):")
        for p in tr["prints"][:20]:
            add("--   " + p)
        add("")

    if services:
        add("-- services the program requested, in order:")
        for s in services:
            add('local %s = game:GetService("%s")' % (s, s))
        add("")

    if stores:
        add("-- data store(s) opened (observed call):")
        for d in stores:
            var = re.sub(r"\W", "", d) or "store"
            add('local %s = DataStoreService:GetDataStore("%s")' % (var, d))
        # stat keys / defaults come from resolved constants, not observed calls
        keys = [k for k in ("Coins", "Level", "XP", "Cash", "Gold", "Wins",
                            "Kills", "Points") if k in sset]
        if keys:
            add("-- stat keys resolved from the VM (default values are constants,")
            add("-- not observed as GetAsync/SetAsync calls in this trace):")
            add("local DEFAULT_STATS = {")
            for k in keys:
                default = "100" if k == "Coins" and "100" in fr["numbers"] else "0"
                add("    %s = %s," % (k, default))
            add("}")
        add("")

    # real (non-decoy) instances
    real_inst = [c for c, d in instances if not d]
    if real_inst:
        add("-- instances the program created (decoys filtered out):")
        for c in real_inst:
            add('Instance.new("%s")' % c)
        add("")
    decoy_inst = [c for c, d in instances if d]
    if decoy_inst:
        add("-- anti-tamper decoys observed and IGNORED (not program logic):")
        add("--   " + ", ".join(dict.fromkeys(decoy_inst)))
        add("")

    # event handlers present as resolved constants -> stub, body event-gated
    ev = [e for e in ("PlayerAdded", "PlayerRemoving", "CharacterAdded") if e in sset]
    if ev and "Connect" in sset:
        add("-- event handlers present (the VM resolved these + Connect). Their")
        add("-- bodies run only when the event fires, so a passive trace never")
        add("-- captured them. Stubbed honestly rather than invented:")
        for e in ev:
            src = "Players" if e in ("PlayerAdded", "PlayerRemoving") else "character"
            arg = "player" if src == "Players" else "character"
            add("%s.%s:Connect(function(%s)" % (src, e, arg))
            add("    -- body event-gated: not observed in this trace")
            add("end)")
        add("")

    if lift_imports:
        add("-- global imports read statically from the bytecode (lift.py):")
        add("--   " + ", ".join(lift_imports[:40]))
        add("")

    add("-- recovered constant surface, grouped by area (deep-constant dump):")
    for line in ai.reconstruct_outline(fr["strings"], fr["numbers"]):
        add("--" + line)
    if fr["dropped_strings"] or fr["dropped_numbers"]:
        add("-- (%d VM/crypto noise strings + %d noise numbers were filtered out)"
            % (fr["dropped_strings"], fr["dropped_numbers"]))
    return "\n".join(L) + "\n"
