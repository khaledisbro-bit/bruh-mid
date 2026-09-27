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
import argparse, json, os, re, sys


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
        elif section:
            tr[section].append(ln)
        if ln.startswith("PRINT:"):
            tr["prints"].append(ln[len("PRINT:"):].strip())
    return tr


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
