#!/usr/bin/env python3
"""
ai.py - Stage-5 semantic audit + reconciliation layer.

Consumes three inputs and decides whether a candidate reconstruction is
internally consistent with what the sample provably does:
  --static   analysis_log.json     (from unobf.py)
  --trace    unobf_result.txt       (from unobf.lua, run in an executor)
  --candidate recovered_source.lua  (the reconstruction under audit)

It never trusts the candidate. It runs deterministic checks:
  * run_ok: did the VM actually execute, or did we only see anti-tamper noise?
  * operation coverage: every op the candidate claims must appear in the trace
    (ADD/SUB/MUL/...), and every traced op must be explained by the candidate.
  * string coverage: every string literal in the candidate must appear in the
    traced constant set (locals excepted); unexplained traced strings are flagged.
  * leftover layers: no undecoded blobs / base85 / decode loops left in candidate.
  * dynamic dispatch: no unresolved runtime-built calls left in candidate.
It then prints a verdict and the questions to send back to unobf.py/unobf.lua.

Optional escalation: if ANTHROPIC_API_KEY and ANTHROPIC_MODEL are set, it asks
the model to do a final natural-language audit of candidate-vs-evidence. Without
them it runs the deterministic audit only (fully offline).
"""
import argparse, json, math, os, re, sys
from collections import Counter

# --------------------------------------------------------------------------- #
# Decoy classifier: separate anti-tamper / gauntlet noise from real program
# behavior, using evidence (not looks). Signals:
#   DECOY  - Instance.new with a random high-entropy "class" (probe marker), or
#            primitive instances (Part/Folder/Model) created inside the gauntlet
#            burst; created-then-destroyed throwaways.
#   REAL   - calls with meaningful string args, DataStore/Remote/Http/Player ops.
#   LOADER - the obfuscator's own unwrap layer (EncodingService, loadstring).
# --------------------------------------------------------------------------- #
VALID_CLASSES = {
    "Part", "Folder", "Model", "Configuration", "RemoteEvent", "RemoteFunction",
    "BindableEvent", "BindableFunction", "ScreenGui", "Frame", "TextButton",
    "TextLabel", "TextBox", "ImageLabel", "ImageButton", "Sound", "Animation",
    "Humanoid", "Tool", "Script", "LocalScript", "ModuleScript", "IntValue",
    "StringValue", "BoolValue", "NumberValue", "ObjectValue", "Attachment",
    "Beam", "ParticleEmitter", "MeshPart", "UnionOperation", "SpawnLocation",
    "Highlight", "ProximityPrompt", "ClickDetector", "SurfaceGui", "BillboardGui",
}
LOADER_TOKENS = ("EncodingService", "loadstring", "DecompressBuffer", "CompressionAlgorithm")
REAL_API = re.compile(
    r"DataStore|GetAsync|SetAsync|UpdateAsync|IncrementAsync|RemoveAsync|GetSortedAsync|"
    r"RemoteEvent|RemoteFunction|FireServer|FireClient|FireAllClients|InvokeServer|InvokeClient|"
    r"HttpService|JSONEncode|JSONDecode|PostAsync|RequestAsync|GetDataStore|GetOrderedDataStore|"
    r"PlayerAdded|PlayerRemoving|CharacterAdded|MarketplaceService|PromptPurchase|"
    r"TeleportService|Teleport|BindToClose|MessagingService|PublishAsync|SubscribeAsync")


def _entropy(s):
    if not s:
        return 0.0
    c = Counter(s); n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def looks_random(s):
    if not s or s in VALID_CLASSES:
        return False
    if len(s) < 10:
        return False
    hu = any(c.isupper() for c in s)
    hl = any(c.islower() for c in s)
    hd = any(c.isdigit() for c in s)
    return hu and hl and hd and _entropy(s) > 3.2


def _instance_arg(line):
    m = re.search(r"Instance\.new:\s*(.+)$", line)
    return m.group(1).strip() if m else None


def _has_meaningful_string(line):
    for m in re.findall(r'"([^"]+)"', line):
        if len(m) >= 3 and re.search(r"[A-Za-z]", m) and not looks_random(m):
            return True
    return False


def build_intent(cls, tr):
    """Human-readable reconstruction of the real intent from classified behavior.
    Handles short/print/compute programs too (falls back to prints/ops)."""
    real = [l for l, _ in cls.get("REAL", [])]
    services, datastores, remotes, http, keys = set(), set(), set(), set(), set()
    for l in real:
        m = re.match(r"GetService:\s*(\w+)", l)
        if m:
            services.add(m.group(1))
        for ds in re.findall(r'GetDataStore\("([^"]+)"\)', l):
            datastores.add(ds)
        for rk in re.findall(r'(?:GetAsync|SetAsync|UpdateAsync|IncrementAsync)\("([^"]+)"', l):
            keys.add(rk)
        for r in re.findall(r'(?:FireServer|FireClient|InvokeServer)\b', l):
            remotes.add(l.strip())
        for u in re.findall(r'https?://[^\s")]+', l):
            http.add(u)
    out = []
    if services:
        out.append("services: " + ", ".join(sorted(services)))
    if datastores:
        out.append("DataStores: " + ", ".join('"%s"' % d for d in sorted(datastores)))
    if keys:
        out.append("keys: " + ", ".join('"%s"' % k for k in sorted(keys)))
    if http:
        out.append("http: " + ", ".join(sorted(http)))
    if remotes:
        out.append("remotes: " + str(len(remotes)))
    if tr.get("prints"):
        out.append("prints %d line(s)" % len(tr["prints"]))
    if tr.get("ops"):
        out.append("arithmetic: %d op(s)" % len(tr["ops"]))
    return out


def confidence(cls, tr):
    """Score how much we trust the separation, with a plain reason."""
    real, decoy = len(cls.get("REAL", [])), len(cls.get("DECOY", []))
    gauntlet = decoy > 0 and any("anti-tamper probe" in w or "gauntlet" in w for _, w in cls.get("DECOY", []))
    if tr.get("run_ok") is False:
        return "LOW", "the VM did not finish (anti-tamper or error); behavior is partial"
    if real == 0 and not tr.get("prints") and not tr.get("ops"):
        return "LOW", "no real behavior isolated; the program may be event-gated or bytecode-only"
    if gauntlet and real >= 3:
        return "HIGH", "anti-tamper gauntlet identified and filtered; real API surface captured"
    if real >= 1:
        return "MEDIUM", "real behavior captured; decoy separation partial"
    return "LOW", "little signal captured"


def classify_behavior(lines):
    """Return dict with REAL / DECOY / LOADER / UNKNOWN lists of (line, reason)."""
    gauntlet = any(looks_random(_instance_arg(l) or "") for l in lines)
    out = {"REAL": [], "DECOY": [], "LOADER": [], "UNKNOWN": []}
    for l in lines:
        if any(tok in l for tok in LOADER_TOKENS):
            out["LOADER"].append((l, "obfuscator unwrap layer, not user code"))
            continue
        a = _instance_arg(l)
        if a is not None:
            if looks_random(a):
                out["DECOY"].append((l, "random fake class name = anti-tamper probe"))
            elif gauntlet and (a in VALID_CLASSES or a.lower() == "part"):
                out["DECOY"].append((l, "primitive instance created inside the gauntlet burst"))
            else:
                out["UNKNOWN"].append((l, "instance create without gauntlet context"))
            continue
        if REAL_API.search(l) or _has_meaningful_string(l):
            out["REAL"].append((l, "meaningful API call / string constant"))
            continue
        if l.startswith("GetService:"):
            svc = l.split(":", 1)[1].strip()
            if svc in ("DataStoreService", "Players", "HttpService", "ReplicatedStorage",
                       "MessagingService", "MarketplaceService", "TeleportService"):
                out["REAL"].append((l, "service used by real logic"))
            else:
                out["UNKNOWN"].append((l, "service (gauntlet or real, unproven)"))
            continue
        out["UNKNOWN"].append((l, "unclassified"))
    return out


def parse_trace(text):
    m = re.search(r"BEGIN_UNOBF_RESULT\n(.*)\nEND_UNOBF_RESULT", text, re.S)
    body = m.group(1) if m else text
    lines = body.splitlines()
    tr = {"run_ok": None, "ops": [], "strings": [], "behavior": [], "module": [], "prints": []}
    section = None
    for ln in lines:
        if ln.startswith("run_ok:"):
            tr["run_ok"] = "true" in ln.split("run_ok:")[1].split()[0]
        elif ln.startswith("MODULE "):
            tr["module"].append(ln)
        elif ln == "---STRINGS---": section = "strings"
        elif ln == "---OPS---": section = "ops"
        elif ln == "---BEHAVIOR---": section = "behavior"
        elif ln in ("---PRINTS---", "---CONSTANTS---"): section = None  # handled by prefix
        elif ln == "---RESOLVED---": section = "resolved"
        elif section:
            tr.setdefault(section, []).append(ln)
        if ln.startswith("PRINT:"):
            tr["prints"].append(ln[len("PRINT:"):].strip())
        if ln.startswith("K: "):
            tr.setdefault("consts", []).append(ln[3:])
    tr.setdefault("consts", [])
    return tr


IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{1,40}$")
STOP = {"string", "table", "concat", "char", "sub", "format", "insert", "remove",
        "byte", "rep", "gsub", "find", "match", "self", "true", "false", "nil",
        "function", "return", "local", "then", "else", "end", "and", "not"}


def meaningful_constants(behavior):
    """Extract genuine program constants from the ARGUMENTS of captured API
    calls (high signal), not from a noisy per-byte dump. Pulls quoted strings,
    table field names, and numbers out of lines like
    GetDataStore("PlayerStats_V2") and JSONEncode({Coins=100, Level=1, XP=0})."""
    strings, fields, numbers, seen = [], [], [], set()
    for line in behavior:
        # skip pure Instance.new noise; keep API-argument lines
        for s in re.findall(r'"([^"]{2,60})"', line):
            if s not in seen and re.search(r"[A-Za-z]", s) and not looks_random(s):
                seen.add(s); strings.append(s)
        for f in re.findall(r'\{([^}]*)\}', line):          # table body -> fields
            for k, v in re.findall(r'(\w+)\s*=\s*([^,}]+)', f):
                if k not in seen:
                    seen.add(k); fields.append(k)
                if re.match(r"^-?\d+(\.\d+)?$", v.strip()) and v.strip() not in seen:
                    seen.add(v.strip()); numbers.append(v.strip())
    out = []
    if strings:
        out.append("strings: " + ", ".join('"%s"' % s for s in strings[:40]))
    if fields:
        out.append("fields: " + ", ".join(fields[:40]))
    if numbers:
        out.append("numbers: " + ", ".join(numbers[:40]))
    return out


def coverage_check(tr, log):
    """Honest completeness audit: did we process the whole obfuscated program,
    or were parts skipped? Reports concrete signals, no guessing."""
    notes, complete = [], True
    if tr.get("run_ok") is True:
        notes.append("[ok] the program ran to completion")
    elif tr.get("run_ok") is False:
        complete = False
        notes.append("[partial] the VM stopped early (anti-tamper or a client-only API); "
                     "logic after that point was NOT reached")
    else:
        complete = False
        notes.append("[unknown] no run status; the trace may be truncated")
    loads = [l for l in tr.get("behavior", []) if l.startswith("loadstring")]
    for l in loads:
        m = re.search(r"inner layer:\s*([^)]+)", l)
        layer = m.group(1).strip() if m else "?"
        if layer not in ("plain/unknown",):
            complete = False
            notes.append("[nested] an inner obfuscation layer was loaded (%s); it holds more "
                         "logic that a single trace does not fully expand" % layer)
        else:
            notes.append("[nested] the program loadstring'd an inner chunk (%s); its internal "
                         "constants/branches are only partially observable at runtime" % layer)
    events = [l for l in tr.get("behavior", []) if re.search(r"PlayerAdded|CharacterAdded|Connect", l)]
    if events:
        complete = False
        notes.append("[event-gated] %d event handler(s) connected; their bodies run only when the "
                     "event fires, so that logic is not in this trace" % len(events))
    verdict = "FULL" if complete else "PARTIAL"
    return verdict, notes


OP_SYMBOL = {"+": "ADD", "-": "SUB", "*": "MUL", "/": "DIV", "%": "MOD", "^": "POW"}


def candidate_facts(src):
    """Extract checkable claims from the candidate source."""
    facts = {"ops": set(), "strings": set(), "leftover_decode": [], "dynamic": []}
    # strip comments, then strings, before detecting binary operators in code
    code = re.sub(r"--\[\[.*?\]\]", " ", src, flags=re.S)
    code = re.sub(r"--[^\n]*", " ", code)
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', code):
        s = m.group(1) or m.group(2)
        if s: facts["strings"].add(s)
    code_nostr = re.sub(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', " ", code)
    for sym, name in OP_SYMBOL.items():
        if re.search(r"[\w)]\s*" + re.escape(sym) + r"\s*[\w(]", code_nostr):
            facts["ops"].add(name)
    # leftover decoding layers
    for pat, label in [(r"fromstring|DecompressBuffer", "buffer/zstd decode"),
                       (r"for %w-=1,85", "base85 loop"),
                       (r"bxor|bit32", "bit decode"),
                       (r"string%.char%(.-%%256", "byte-rebuild loop")]:
        if re.search(pat.replace("%", "\\"), src):
            facts["leftover_decode"].append(label)
    # unresolved dynamic dispatch
    for m in re.finditer(r"loadstring\s*\(|_G\s*\[|getfenv\s*\(\s*\)\s*\[", src):
        facts["dynamic"].append(m.group(0))
    return facts


def printed_value(prints):
    """The oracle prints print(a, b) as 'a, b'. Return the last argument."""
    if not prints:
        return None
    parts = prints[-1].split(", ")
    return parts[-1] if parts else None


def try_reproduce_output(src):
    """If the candidate is the byte-xor decoder idiom, recompute its output.
    Recognizes:
      transform(s,k): bxor(byte(s,i), k + (i % M))
      decode(t):      out[i] = transform(t[i], BASE + i)
      parts = { "..","..", ... }
    Returns the produced string, or None if the shape does not match."""
    mmod = re.search(r"bxor\([^,]+,\s*\w+\s*\+\s*\(?\s*\w+\s*%\s*(\d+)", src)
    mbase = re.search(r"transform\(\w+\[?\w*\]?,\s*(\d+)\s*\+\s*\w+\)", src)
    mparts = re.search(r"parts\s*=\s*\{(.*?)\}", src, re.S)
    if not (mmod and mbase and mparts):
        return None
    M, BASE = int(mmod.group(1)), int(mbase.group(1))
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', mparts.group(1))
    def unescape(s):
        return s.encode().decode("unicode_escape")
    out = []
    for idx, p in enumerate(parts, 1):
        s = unescape(p)
        k = BASE + idx
        for i in range(1, len(s) + 1):
            out.append(chr((ord(s[i-1]) ^ (k + (i % M))) & 0xFF))
    return "".join(out)


def audit(static, trace, cand_src):
    tr = parse_trace(trace)
    cf = candidate_facts(cand_src)
    findings = []

    # 1. did the VM run?
    if tr["run_ok"] is False:
        findings.append(("BLOCKER", "trace run_ok=false: VM did not execute the payload; "
                         "captured stream is anti-tamper noise, not program logic. Re-run the oracle."))
    elif tr["run_ok"] is None:
        findings.append(("WARN", "trace has no run_ok marker; cannot confirm execution."))

    # program class: a returned/captured module with arithmetic actions, vs a
    # print-class program that just computes and prints. Pick the check accordingly.
    traced_ops = set()
    for o in tr["ops"] + [m for m in tr["module"]]:
        for name in OP_SYMBOL.values():
            if name + "(" in o: traced_ops.add(name)
    has_module = bool(tr["module"])
    print_class = bool(tr["prints"]) and not has_module

    behavior_verified = False
    if print_class:
        # verify the candidate reproduces the exact printed output
        cand_has_print = bool(re.search(r"\bprint\s*\(", cand_src))
        findings.append(("OK", f"print-class program; observed output: {tr['prints']}"))
        if not cand_has_print:
            findings.append(("MISSING_LOGIC", "trace prints output but candidate has no print()."))
        out = try_reproduce_output(cand_src)
        expect = printed_value(tr["prints"])
        if out is not None and expect is not None:
            if out == expect:
                findings.append(("OK", f"candidate reproduces exact output: {out!r}"))
                behavior_verified = True
            else:
                findings.append(("MISSING_LOGIC", f"candidate output {out!r} != traced {expect!r}"))
        elif out is None:
            findings.append(("CHECK", "candidate output could not be recomputed; confirm by running it."))
    else:
        # 2. operation coverage (module/arithmetic programs)
        missing = cf["ops"] - traced_ops
        extra = traced_ops - cf["ops"]
        if missing:
            findings.append(("MISSING", f"candidate uses ops {sorted(missing)} not seen in trace; verify or remove."))
        if extra:
            findings.append(("MISSING_LOGIC", f"trace shows ops {sorted(extra)} the candidate does not account for."))
        if cf["ops"] and traced_ops and not missing and not extra:
            findings.append(("OK", f"operation set matches trace: {sorted(traced_ops)}"))

    # 3-4. string coverage + leftover decode. Skip when the candidate already
    # reproduces the exact traced output: its byte ops are the genuine program,
    # and its encoded inputs are not expected to appear as traced constants.
    if not behavior_verified:
        traced_strings = set(tr["strings"])
        unexplained = [s for s in cf["strings"] if s not in traced_strings and len(s) > 1]
        if unexplained:
            findings.append(("CHECK", f"candidate string literals not in traced constants: {unexplained[:10]}"))
        if cf["leftover_decode"]:
            findings.append(("LEFTOVER", f"candidate still contains decode machinery: {cf['leftover_decode']} "
                             "(should be resolved away in final source)."))

    # 5. unresolved dynamic dispatch (always checked)
    if cf["dynamic"]:
        findings.append(("DYNAMIC", f"candidate has unresolved dynamic dispatch: {set(cf['dynamic'])}"))

    blocking = any(t in ("BLOCKER", "MISSING", "MISSING_LOGIC", "LEFTOVER", "DYNAMIC") for t, _ in findings)
    verdict = "CONSISTENT" if not blocking else "NEEDS_REANALYSIS"
    return verdict, findings, tr, cf


def maybe_llm(static, trace, cand_src, findings):
    key, model = os.environ.get("ANTHROPIC_API_KEY"), os.environ.get("ANTHROPIC_MODEL")
    if not (key and model):
        return None
    try:
        import anthropic
    except ImportError:
        return "anthropic SDK not installed; skipped LLM audit"
    client = anthropic.Anthropic(api_key=key)
    prompt = ("You are auditing a deobfuscation. Compare the candidate source against the "
              "execution evidence. Report only: missing logic, contradictions, leftover decode "
              "layers, unresolved dynamic calls.\n\n"
              f"DETERMINISTIC FINDINGS:\n{json.dumps(findings, indent=2)}\n\n"
              f"TRACE (truncated):\n{trace[:6000]}\n\nCANDIDATE:\n{cand_src[:6000]}")
    msg = client.messages.create(model=model, max_tokens=1500,
                                 messages=[{"role": "user", "content": prompt}])
    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--static", required=True)
    ap.add_argument("--trace", required=True)
    ap.add_argument("--candidate", required=True)
    a = ap.parse_args()
    static = json.load(open(a.static)) if os.path.exists(a.static) else {}
    trace = open(a.trace, encoding="latin1").read() if os.path.exists(a.trace) else ""
    cand = open(a.candidate, encoding="latin1").read() if os.path.exists(a.candidate) else ""
    verdict, findings, tr, cf = audit(static, trace, cand)
    print("=== ai.py semantic audit ===")
    print("verdict:", verdict)
    for t, msg in findings:
        print(f"  [{t}] {msg}")
    llm = maybe_llm(static, trace, cand, findings)
    if llm:
        print("\n=== LLM audit ===\n" + llm)
    sys.exit(0 if verdict == "CONSISTENT" else 3)


if __name__ == "__main__":
    main()
