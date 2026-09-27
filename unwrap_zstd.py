#!/usr/bin/env python3
"""unwrap_zstd - static unwrapper for the base85 + Zstd wrapper.

Target: 5a10205e-obfuscated.lua. Its outer wrapper is:

    return({H=function(L,...)
        local J = buffer.tostring(
            game:GetService("EncodingService")
                :DecompressBuffer(buffer.fromstring(K(L[240063])), Zstd))
        -- header: two little-endian u32, each with a fixed subtractor
        local ZD = (u32le(J,1) - 2152627013) % 2^32   -- inner source length
        local Zc = (u32le(J,5) - 2369095519) % 2^32   -- inner data   length
        local ZA = J[9 .. 9+ZD-1]                     -- inner Lua VM source
        local Zh = J[9+ZD .. +Zc-1]                   -- inner VM bytecode/data
        return loadstring(ZA)(Zh, ...)
    end, [240063]=[[<base85 blob>]]}):H(...)

    K = base85 decode with a custom 85-char alphabet (5 chars -> 4 bytes, big-endian).

This tool recovers the outer layer deterministically:
  base85 payload -> Zstd decompress -> split header -> inner source + data.

The inner ZA is itself a custom bytecode VM (Luraph/Prometheus style) whose
string constants are decrypted with a runtime key, so recovering the original
source from there needs a live trace (see studio_probe.lua) or a full VM lift.

Usage:
    python3 unwrap_zstd.py 5a10205e-obfuscated.lua out2
"""
import sys, os, re, zstandard


def build_b85_alphabet(src):
    m = re.search(r"for BI=1,85 do BM\[Zd\(\[\[(.*?)\]\],BI,BI\)\]=BI-1 end", src, re.S)
    if not m:
        raise SystemExit("base85 alphabet not found")
    alpha = m.group(1)
    if len(alpha) != 85:
        raise SystemExit(f"alphabet length {len(alpha)} != 85")
    return alpha


def extract_payload(src):
    m = re.search(r"\[240063\]=\[\[(.*?)\]\]", src, re.S)
    if not m:
        raise SystemExit("payload [240063] not found")
    return m.group(1)


def b85decode(F, alphabet):
    BM = {c: i for i, c in enumerate(alphabet)}
    out = bytearray(); BV = 0; BN = 0
    for ch in F:
        BD = BM.get(ch)
        if BD is None:
            return None
        BV = BV * 85 + BD; BN += 1
        if BN == 5:
            out += bytes([(BV // 16777216) % 256, (BV // 65536) % 256,
                          (BV // 256) % 256, BV % 256])
            BV = 0; BN = 0
    if BN > 1:
        i = 5 - BN
        while i > 0:
            BV = BV * 85 + 84; i -= 1
        b = bytes([(BV // 16777216) % 256, (BV // 65536) % 256,
                   (BV // 256) % 256, BV % 256])
        out += b[:BN - 1]
    elif BN == 1:
        return None
    return bytes(out)


def u32le(b, off):
    return b[off] + b[off + 1] * 256 + b[off + 2] * 65536 + b[off + 3] * 16777216


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(1)
    infile, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    src = open(infile, 'r', encoding='latin1').read()

    alpha = build_b85_alphabet(src)
    payload = extract_payload(src)
    decoded = b85decode(payload, alpha)
    if decoded is None:
        raise SystemExit("base85 decode failed")

    J = zstandard.ZstdDecompressor().decompress(decoded)

    ZD = (u32le(J, 0) - 2152627013) % 4294967296
    Zc = (u32le(J, 4) - 2369095519) % 4294967296
    ZA = J[8:8 + ZD]
    Zh = J[8 + ZD:8 + ZD + Zc]

    open(os.path.join(outdir, 'inner_source.lua'), 'wb').write(ZA)
    open(os.path.join(outdir, 'inner_data.bin'), 'wb').write(Zh)

    print("outer wrapper unwrapped")
    print(f"  base85 payload : {len(payload)} chars -> {len(decoded)} bytes")
    print(f"  zstd decompress: {len(J)} bytes")
    print(f"  inner source   : {len(ZA)} bytes -> inner_source.lua")
    print(f"  inner data     : {len(Zh)} bytes -> inner_data.bin")
    print(f"  output dir     : {outdir}")


if __name__ == '__main__':
    main()
