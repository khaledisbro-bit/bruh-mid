"""Plugin: base85 + Zstd Luau VM family (obf2 / obf3 / 25ms_version_khaled).

    return({[KEY]=[[<base85 blob>]], H=function(L,...) ... end}):H(...)
    base85(custom alphabet) -> EncodingService Zstd -> header split -> loadstring
"""
import re

NAME = "base85+Zstd Luau VM"


def detect(src):
    return ("DecompressBuffer" in src or "CompressionAlgorithm" in src) and "1,85" in src


def _alphabets(src):
    cands = []
    for m in re.finditer(r"1,85 do.{0,60}?\[\[(.{85}?)\]\]", src, re.S):
        cands.append(m.group(1))
    for m in re.finditer(r"\[\[(.{85}?)\]\]", src, re.S):
        s = m.group(1)
        if len(s) == 85 and len(set(s)) == 85 and s not in cands:
            cands.append(s)
    return cands


def _blobs(src):
    return [(int(k), b) for k, b in re.findall(r"\[(\d+)\]\s*=\s*\[\[(.*?)\]\]", src, re.S)]


def _subs(src):
    return [int(x) for x in re.findall(r"-\s*(\d{6,})\s*\)\s*%\s*4294967296", src)]


def _b85(blob, alphabet):
    lm = {c: i for i, c in enumerate(alphabet)}
    out, v, n = bytearray(), 0, 0
    for ch in blob:
        d = lm.get(ch)
        if d is None:
            raise ValueError("charset")
        v = v * 85 + d; n += 1
        if n == 5:
            out += bytes([(v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255]); v = n = 0
    if n > 1:
        for _ in range(5 - n):
            v = v * 85 + 84
        out += bytes([(v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255])[:n - 1]
    return bytes(out)


def unwrap(src, log):
    import zstandard
    alphabets, blobs, subs = _alphabets(src), _blobs(src), _subs(src)
    log["layer1"] = {"family": NAME, "alphabet_candidates": len(alphabets),
                     "blob_keys": [k for k, _ in blobs], "header_subtractors": subs}
    for key, blob in sorted(blobs, key=lambda kv: -len(kv[1])):
        for alpha in alphabets:
            try:
                raw = _b85(blob, alpha)
            except ValueError:
                log.setdefault("decoys", []).append(f"blob[{key}] x alphabet rejected (charset)")
                continue
            if raw[:4] != b"\x28\xb5\x2f\xfd":
                log.setdefault("decoys", []).append(f"blob[{key}] not Zstd (decoy or wrong alphabet)")
                continue
            data = zstandard.ZstdDecompressor().decompress(raw, max_output_size=500_000_000)

            def u32(o):
                return data[o] | data[o + 1] << 8 | data[o + 2] << 16 | data[o + 3] << 24
            a, b = u32(0), u32(4)
            body = len(data) - 8
            best = None
            for sa in subs + [0]:
                la = (a - sa) % 2**32
                if la > body:
                    continue
                for sb in subs + [0]:
                    lb = (b - sb) % 2**32
                    if 0 < la and 0 <= lb and la + lb <= body:
                        best = (la, lb, sa, sb); break
                if best:
                    break
            if not best:
                log.setdefault("decoys", []).append(f"blob[{key}] header lengths never fit")
                continue
            la, lb, sa, sb = best
            seg1, seg2 = data[8:8 + la], data[8 + la:8 + la + lb]

            def is_lua(x):
                h = x[:32].lstrip()[:6]
                return h[:5] in (b"local", b"retur") or h[:3] in (b"do ", b"--!")
            if is_lua(seg1) and not is_lua(seg2):
                isrc, idata = seg1, seg2
            elif is_lua(seg2) and not is_lua(seg1):
                isrc, idata = seg2, seg1
            else:
                isrc, idata = seg1, seg2
            log["layer1"].update({"real_blob_key": key, "inner_source_len": len(isrc),
                                  "inner_data_len": len(idata), "subtractors_used": [sa, sb]})
            return isrc, idata
    log["layer1"]["status"] = "no clean candidate"
    return None, None
