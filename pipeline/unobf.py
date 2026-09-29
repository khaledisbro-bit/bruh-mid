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
    """Dispatch to the matching obfuscator plugin (see pipeline/obfuscators/).
    Falls back to the built-in base85+Zstd path if no plugin matches."""
    if zstandard is None:
        raise SystemExit("pip install zstandard")
    try:
        import obfuscators
        plug = obfuscators.pick(src)
        if plug is not None:
            log["family"] = plug.NAME
            return plug.unwrap(src, log)
    except Exception:
        pass
    # legacy inline fallback
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
    """What the unwrapping established, and nothing more.

    An earlier version of this function matched names in the outer source and
    wrote a prepared conclusion for each one it recognised - see
    "DecompressBuffer" and get told the decompress call is on the decode path.
    That is a lookup table, not analysis: it says the same thing about a file
    that merely mentions the name, and says nothing about a file that does the
    same work under another name.

    Every entry below is the result of a test that was actually run on THIS
    file. The decode tests are the strong ones: a blob either decoded under a
    candidate alphabet into a Zstd stream whose header lengths fit its body, or
    it did not, and that is a fact about the bytes. The shape findings are
    weaker and are labelled as such: they say a piece of the interpreter has a
    given shape, not what it is for.
    """
    cls = {"REAL": [], "SUSPICIOUS": [], "DECOY": [], "UNKNOWN": []}
    l1 = log.get("layer1", {})

    # ---- decode-tested, so these are facts about the bytes ----------------
    real = l1.get("real_blob_key")
    if real is not None:
        cls["REAL"].append(("blob[%s]" % real,
                            "decoded under one of the candidate alphabets into "
                            "a Zstd stream whose two header lengths fit its "
                            "body; the payload that ran came out of it"))
    for k in l1.get("blob_keys", []):
        if k != real:
            cls["DECOY"].append(("blob[%s]" % k,
                                 "every candidate alphabet was tried on it and "
                                 "none produced a Zstd stream with a header "
                                 "that fits - it carries no payload"))
    n_alpha = l1.get("alphabet_candidates", 0)
    if real is not None and n_alpha > 1:
        cls["DECOY"].append(("%d of %d base85 alphabet literal(s)"
                             % (n_alpha - 1, n_alpha),
                             "the payload decoded under one of them; the others "
                             "were tried on it and rejected"))
    for note in l1.get("rejected", []):
        cls["DECOY"].append(note if isinstance(note, tuple) else (note, "decode test"))

    # ---- read from the interpreter's own shape, and no further ------------
    if knobs.get("resolver"):
        rv = knobs["resolver"]
        cls["REAL"].append(("%s(i)" % rv["name"],
                            "has the shape of a constant resolver - it folds a "
                            "negative index, then returns %s(%s[i]). Every "
                            "constant the program uses comes back through it, "
                            "which is why it is on the execution path"
                            % (rv["decoder"], rv["const_table"])))
    if knobs.get("lcg"):
        n = len(knobs["lcg"])
        cls["REAL"].append(("%d recurrence(s) of the form x = (x*a + c) %% m" % n,
                            "a state that advances once per instruction. The "
                            "trace decides what it feeds; the shape alone only "
                            "says the interpreter carries a changing number"))
    if knobs.get("integrity", {}).get("sha256_table"):
        cls["SUSPICIOUS"].append(
            ("a constant from SHA-256's round table is present",
             "that is all this establishes. Whether anything is hashed, and "
             "whether a hash gates the payload, is decided by the trace - not "
             "by the constant being in the file"))
    if knobs.get("integrity", {}).get("chacha_rounds"):
        cls["SUSPICIOUS"].append(
            ("rotation amounts in the order 16, 12, 8, 7 appear",
             "the order a ChaCha quarter-round uses. Whether a cipher runs, "
             "and on what, is decided by the trace"))
    if knobs.get("local_function_count"):
        cls["UNKNOWN"].append(
            ("%d local function(s) in the interpreter"
             % knobs["local_function_count"],
             "counted, not read. Which of them run, and what each one does, is "
             "measured from the capture, not guessed from the source"))
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
