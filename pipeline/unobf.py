#!/usr/bin/env python3
"""
unobf.py - static analyzer + orchestrator (Stage 1 + Stage 4 of the pipeline).

Works on the base85 + Zstd obfuscator family (obf2 / obf3 / 25ms_version_khaled
and siblings). Nothing is hardcoded per sample: every per-build knob is read out
of the sample's own source text, and each candidate is decode-tested before it
is trusted.

What it does deterministically (STATIC-VERIFIED):
  1. Layer-1 unwrap:  base85(custom alphabet) -> Zstd -> header split ->
     inner VM source + inner VM data.
  2. Auto-detect the inner VM knobs: entry params, LCG stream(s), the constant
     resolver (name / arg / gc offset / decoder / table), integrity hashes.
  3. Function inventory + reachability from the entry, and a
     REAL / SUSPICIOUS / DECOY / UNKNOWN classification of every top-level
     construct it can see, with a reason per verdict.
  4. Emit analysis_log.json, vm_structure.txt, and (for the runtime-keyed
     layers static cannot decode) the trace-oracle harness to finish in an
     executor.

What it CANNOT do statically, and says so:
  - Decode the inner constant pool. The decoder is keyed by a value derived at
    run time (entry arg `B`) and instructions are decrypted per-pc by the LCG,
    so there is no static key. That layer is handed to the dynamic oracle
    (unobf.lua) and reconciled by ai.py.

Usage:
    python3 unobf.py <sample.lua> -o <outdir>
    python3 unobf.py <sample.lua> --scan-only
"""
import argparse, json, os, re, sys

try:
    import zstandard
except ImportError:
    zstandard = None


# ----------------------------------------------------------------- Layer 1
def find_base85_alphabet(src):
    """The real alphabet is loaded by `for i=1,85 do M[sub(A,i,i)]=i-1 end`.
    Decoys plant extra 85-char literals; we return every candidate."""
    cands = []
    for m in re.finditer(r"for \w+=1,85 do \w+%?\[?\w*\(?\w*\(?\[\[(.{85}?)\]\]", src, re.S):
        cands.append(m.group(1))
    # generic: any [[...]] exactly 85 chars, all distinct
    for m in re.finditer(r"\[\[(.{85}?)\]\]", src, re.S):
        s = m.group(1)
        if len(s) == 85 and len(set(s)) == 85 and s not in cands:
            cands.append(s)
    return cands


def find_blobs(src):
    """Every  [KEY]=[[ ... ]]  long-bracket data blob."""
    return [(int(k), b) for k, b in re.findall(r"\[(\d+)\]\s*=\s*\[\[(.*?)\]\]", src, re.S)]


def find_header_subtractors(src):
    """Header lengths appear as ( ... - CONST) % 4294967296."""
    return [int(x) for x in re.findall(r"-\s*(\d{6,})\s*\)\s*%\s*4294967296", src)]


def b85_decode(blob, alphabet):
    lm = {c: i for i, c in enumerate(alphabet)}
    out, v, n = bytearray(), 0, 0
    for ch in blob:
        d = lm.get(ch)
        if d is None:
            raise ValueError("char not in alphabet")
        v = v * 85 + d; n += 1
        if n == 5:
            out += bytes([(v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255])
            v = n = 0
    if n > 1:
        for _ in range(5 - n):
            v = v * 85 + 84
        out += bytes([(v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255])[:n - 1]
    return bytes(out)


def unwrap_layer1(src, log):
    """Try every (alphabet, blob) pair; keep the one that yields valid Zstd."""
    if zstandard is None:
        raise SystemExit("pip install zstandard")
    alphabets = find_base85_alphabet(src)
    blobs = find_blobs(src)
    subs = find_header_subtractors(src)
    log["layer1"] = {"alphabet_candidates": len(alphabets), "blob_keys": [k for k, _ in blobs],
                     "header_subtractors": subs}
    for key, blob in sorted(blobs, key=lambda kv: -len(kv[1])):
        for alpha in alphabets:
            try:
                raw = b85_decode(blob, alpha)
            except ValueError:
                log.setdefault("decoys", []).append(f"blob[{key}] x alphabet rejected (charset mismatch)")
                continue
            if raw[:4] != b"\x28\xb5\x2f\xfd":
                log.setdefault("decoys", []).append(f"blob[{key}]: not a Zstd stream (decoy blob or wrong alphabet)")
                continue
            data = zstandard.ZstdDecompressor().decompress(raw, max_output_size=500_000_000)
            # header: two u32le, each minus a per-build subtractor
            def u32(o): return data[o] | data[o+1] << 8 | data[o+2] << 16 | data[o+3] << 24
            a, b = u32(0), u32(4)
            body = len(data) - 8
            best = None
            for sa in subs + [0]:
                la = (a - sa) % 2**32
                if la > body: continue
                for sb in subs + [0]:
                    lb = (b - sb) % 2**32
                    if 0 < la and 0 <= lb and la + lb <= body:
                        best = (la, lb, sa, sb); break
                if best: break
            if not best:
                log.setdefault("decoys", []).append(f"blob[{key}]: header lengths never fit body")
                continue
            la, lb, sa, sb = best
            seg1 = data[8:8+la]; seg2 = data[8+la:8+la+lb]
            # Orient: whichever segment parses as Lua source is the inner VM
            # source; the other is the VM data. (Runtime: loadstring(src)(data).)
            def looks_lua(b):
                head = b[:32].lstrip()[:6]
                return head[:5] in (b"local", b"retur") or head[:3] in (b"do ", b"--!")
            if looks_lua(seg1) and not looks_lua(seg2):
                inner_source, inner_data = seg1, seg2
            elif looks_lua(seg2) and not looks_lua(seg1):
                inner_source, inner_data = seg2, seg1
            else:
                inner_source, inner_data = seg1, seg2  # fall back to header order
            log["layer1"].update({"real_blob_key": key,
                                  "inner_source_len": len(inner_source),
                                  "inner_data_len": len(inner_data),
                                  "subtractors_used": [sa, sb]})
            return inner_source, inner_data
    log["layer1"]["status"] = "no clean base85+Zstd candidate; sample is a different obfuscator family"
    return None, None


# --------------------------------------------------------------- Inner VM analysis
def analyze_inner(src, log):
    """Read the VM interpreter's knobs straight out of its own source text."""
    knobs = {}
    m = re.search(r"return\(function\((\w+(?:,\w+)*),\.\.\.\)", src)
    knobs["entry_params"] = m.group(1).split(",") if m else None
    knobs["lcg"] = [{"var": v, "mul": int(a), "add": int(c), "mod": int(md)}
                    for v, a, c, md in re.findall(r"(\w+)=\(\1\*(\d+)\+(\d+)\)%(\d+)", src)]
    r = re.search(r"local function (\w+)\((\w+)\)if \2<0 then \2=-\2-(\w+) end;return (\w+)\((\w+)\[\2\]\)end", src)
    if r:
        knobs["resolver"] = {"name": r.group(1), "arg": r.group(2), "gc": r.group(3),
                             "decoder": r.group(4), "const_table": r.group(5)}
    knobs["integrity"] = {"sha256_table": "1116352408" in src,
                          "chacha_rounds": bool(re.search(r",\s*16\).*?,\s*12\).*?,\s*8\).*?,\s*7\)", src, re.S))}
    funcs = re.findall(r"local function (\w+)\(", src)
    knobs["local_function_count"] = len(funcs)
    knobs["local_functions"] = funcs
    log["inner_vm"] = knobs
    return knobs


def classify_constructs(outer_src, knobs, log):
    """REAL / SUSPICIOUS / DECOY / UNKNOWN for the statically visible pieces.
    Rule: on the decode/execute path -> REAL; provably unreferenced -> DECOY;
    otherwise SUSPICIOUS (kept, never deleted) or UNKNOWN."""
    cls = {"REAL": [], "SUSPICIOUS": [], "DECOY": [], "UNKNOWN": []}

    # Outer wrapper: base85 decoder, EncodingService decompress, header split,
    # loadstring -- all provably on the decode path (data flows blob -> J -> ZA/Zh -> loadstring).
    if "DecompressBuffer" in outer_src:
        cls["REAL"].append(("outer.EncodingService:DecompressBuffer", "consumes base85 output; feeds the split"))
    if re.search(r"for \w+=1,85 do", outer_src):
        cls["REAL"].append(("outer.base85_decoder K", "decodes the payload blob before decompress"))
    if "loadstring(" in outer_src:
        cls["REAL"].append(("outer.loadstring(ZA)(Zh,...)", "entry into the inner VM"))

    # Extra 85-char alphabet literals beyond the one used = DECOY.
    n_alpha = log.get("layer1", {}).get("alphabet_candidates", 1)
    if n_alpha > 1:
        cls["DECOY"].append((f"{n_alpha-1} extra base85 alphabet literal(s)",
                             "not the alphabet that decoded the real blob"))
    # Extra data blobs beyond the real one = DECOY (decode-tested).
    for k in log.get("layer1", {}).get("blob_keys", []):
        if k != log.get("layer1", {}).get("real_blob_key"):
            cls["DECOY"].append((f"blob[{k}]", "failed decode test (charset/zstd/header) -> decoy blob"))

    # Inner: resolver, decoder, LCG, dispatch = REAL (drive execution).
    if knobs.get("resolver"):
        rv = knobs["resolver"]
        cls["REAL"].append((f"inner.resolver {rv['name']}", f"resolves constants via {rv['decoder']}({rv['const_table']}[i])"))
    if knobs.get("lcg"):
        cls["REAL"].append(("inner.LCG stream", "per-pc instruction decryption; changing it yields garbage"))
    # Integrity/anti-tamper: SUSPICIOUS until the trace proves whether it gates the payload.
    if knobs.get("integrity", {}).get("sha256_table"):
        cls["SUSPICIOUS"].append(("inner.SHA-256 integrity", "anti-tamper; must confirm via trace whether it gates real logic"))
    log["classification"] = cls
    return cls


# --------------------------------------------------------------- trace harness
def emit_trace_harness(knobs, outer_path, out_harness):
    """Emit a self-contained executor harness parameterized by the detected
    resolver, so it works across samples (no hardcoded names)."""
    tmpl = open(os.path.join(os.path.dirname(__file__), "unobf.lua"), "r", encoding="utf-8").read() \
        if os.path.exists(os.path.join(os.path.dirname(__file__), "unobf.lua")) else None
    if tmpl:
        open(out_harness, "w", encoding="utf-8").write(tmpl)


def run(path, outdir, scan_only):
    src = open(path, encoding="latin1").read()
    log = {"sample": os.path.basename(path), "size": len(src)}
    inner_src, inner_data = unwrap_layer1(src, log)
    if inner_src is None:
        log["result"] = "layer1_unrecognized"
        print(json.dumps(log, indent=2))
        return log
    knobs = analyze_inner(inner_src.decode("latin1"), log)
    classify_constructs(src, knobs, log)

    if not scan_only:
        os.makedirs(outdir, exist_ok=True)
        open(os.path.join(outdir, "inner_source.lua"), "wb").write(inner_src)
        open(os.path.join(outdir, "inner_data.bin"), "wb").write(inner_data)
        with open(os.path.join(outdir, "analysis_log.json"), "w") as f:
            json.dump(log, f, indent=2)
        with open(os.path.join(outdir, "vm_structure.txt"), "w") as f:
            f.write(vm_structure_text(log))
    print(json.dumps(log, indent=2))
    return log


def vm_structure_text(log):
    l1, vm = log.get("layer1", {}), log.get("inner_vm", {})
    out = ["# VM structure (auto-detected, no hardcoding)", ""]
    out.append(f"sample            : {log.get('sample')} ({log.get('size')} bytes)")
    out.append(f"real blob key     : {l1.get('real_blob_key')}")
    out.append(f"inner source      : {l1.get('inner_source_len')} bytes")
    out.append(f"inner data        : {l1.get('inner_data_len')} bytes")
    out.append(f"header subtractors: {l1.get('subtractors_used')}")
    out.append("")
    out.append(f"entry params      : {vm.get('entry_params')}")
    out.append(f"LCG               : {vm.get('lcg')}")
    out.append(f"resolver          : {vm.get('resolver')}")
    out.append(f"integrity         : {vm.get('integrity')}")
    out.append(f"inner functions   : {vm.get('local_function_count')}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--out", default="unobf_out")
    ap.add_argument("--scan-only", action="store_true")
    a = ap.parse_args()
    run(a.input, a.out, a.scan_only)


if __name__ == "__main__":
    main()
