#!/usr/bin/env python3
"""unmoonveil - static unpacker for MoonVeil Obfuscator v1.4.5 output.

MoonVeil wraps a Lua/Luau script in layers:

    (function() ... return Qd(Gf'<base64>', {handlers}) end)()(...)

    Gf  = standard base64 decode  (strips non-alphabet chars first)
    ze  = LZSS decompressor        (2048-byte window, 11-bit distance + 5-bit length)
    Ia  = ChaCha20-variant cipher  (quarter-round rotations 16/12/8/7)
    Qd  = the VM deserializer + interpreter (reads the decrypted chunk)

    yf(cipher, key) = repeating-key XOR used for every inline string constant.

This tool recovers every deterministic layer without a Lua runtime:
  1. pulls the base64 payload out of the file
  2. base64-decodes it            -> <out>/payload.bin
  3. LZSS-decompresses it          -> <out>/payload_dec.bin
  4. decodes every yf() constant   -> <out>/constants.txt

The final VM chunk stays ChaCha-encrypted under a key the interpreter derives
at runtime, so lifting the VM bytecode to source needs a Luau VM or a full
static lifter. See RECONSTRUCTION.md.

Usage:
    python3 unmoonveil.py word.lua out
"""
import sys, os, re, base64


def lua_unescape(s):
    """Decode a Lua single-quoted string body into a list of byte values."""
    out, i, n = [], 0, len(s)
    esc = {'n': 10, 't': 9, 'r': 13, 'a': 7, 'b': 8, 'f': 12,
           'v': 11, '\\': 92, '"': 34, "'": 39, '\n': 10}
    while i < n:
        c = s[i]
        if c == '\\':
            i += 1
            if i >= n:
                break
            d = s[i]
            if d.isdigit():
                num = ''
                for _ in range(3):
                    if i < n and s[i].isdigit():
                        num += s[i]; i += 1
                    else:
                        break
                out.append(int(num) & 0xFF)
            else:
                out.append(esc.get(d, ord(d))); i += 1
        else:
            out.append(ord(c) & 0xFF); i += 1
    return out


def yf(cipher, key):
    """Repeating-key XOR. out[i] = cipher[i] XOR key[i mod len(key)]."""
    if not key:
        return ''
    return ''.join(chr((cb ^ key[i % len(key)]) & 0xFF)
                   for i, cb in enumerate(cipher))


def parse_lua_string(src, pos):
    """pos is at the opening quote. Return (byte list, index past closing quote)."""
    assert src[pos] == "'"
    i, buf = pos + 1, ''
    while i < len(src):
        c = src[i]
        if c == '\\':
            buf += src[i:i + 2]; i += 2; continue
        if c == "'":
            return lua_unescape(buf), i + 1
        buf += c; i += 1
    raise ValueError('unterminated string literal')


def decode_yf_calls(src):
    """Find and decode every yf('..','..') constant. Return list of (pos, text)."""
    results, i, pat = [], 0, 'yf('
    while True:
        j = src.find(pat, i)
        if j < 0:
            break
        k = j + len(pat)
        while k < len(src) and src[k] in ' \t':
            k += 1
        if k < len(src) and src[k] == "'":
            try:
                a1, k2 = parse_lua_string(src, k)
                m = k2
                while m < len(src) and src[m] in ' \t':
                    m += 1
                if m < len(src) and src[m] == ',':
                    m += 1
                    while m < len(src) and src[m] in ' \t':
                        m += 1
                    if m < len(src) and src[m] == "'":
                        a2, m2 = parse_lua_string(src, m)
                        results.append((j, yf(a1, a2)))
                        i = m2; continue
            except Exception:
                pass
        i = j + len(pat)
    return results


def ze_decompress(cb):
    """MoonVeil `ze` LZSS. Control byte holds 8 flags, LSB first.
       flag 1 -> literal byte. flag 0 -> 16-bit big-endian match token:
       distance = token >> 5, length = (token & 31) + 3."""
    y = 1 << 11
    lenmask = (1 << 5) - 1
    Oe, n = 0, len(cb)
    out = []
    win = bytearray()
    while Oe < n:
        we = cb[Oe]; Oe += 1
        for _ in range(8):
            rb = None
            if we & 1:
                if Oe < n:
                    rb = bytes([cb[Oe]]); Oe += 1
            else:
                if Oe + 2 <= n:
                    ac = (cb[Oe] << 8) | cb[Oe + 1]; Oe += 2
                    dist = ac >> 5
                    length = (ac & lenmask) + 3
                    x = len(win) - dist
                    if x < 0:
                        x = 0
                    rb = bytes(win[x:x + length])
            we >>= 1
            if rb is not None:
                out.append(rb)
                win += rb
                if len(win) > y:
                    win = win[-y:]
    return b''.join(out)


def extract_base64(src):
    """Return the single large base64 payload embedded in the file."""
    m = re.search(r"'([A-Za-z0-9+/=]{200,})'", src)
    if not m:
        raise SystemExit('no base64 payload found')
    return m.group(1)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(1)
    infile, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    src = open(infile, 'r', encoding='latin1').read()

    b64 = extract_base64(src)
    payload = base64.b64decode(b64)
    open(os.path.join(outdir, 'payload.bin'), 'wb').write(payload)

    dec = ze_decompress(payload)
    open(os.path.join(outdir, 'payload_dec.bin'), 'wb').write(dec)

    consts = decode_yf_calls(src)
    seen, uniq = set(), []
    for _, t in consts:
        if t not in seen:
            seen.add(t); uniq.append(t)
    with open(os.path.join(outdir, 'constants.txt'), 'w') as f:
        f.write(f'# {len(consts)} yf() calls, {len(uniq)} unique constants\n\n')
        for pos, t in consts:
            printable = t if all(32 <= ord(c) < 127 for c in t) else repr(t)
            f.write(f'@{pos}\t{printable}\n')

    print('MoonVeil v1.4.5 unpack complete')
    print(f'  base64 payload   : {len(b64)} chars -> payload.bin ({len(payload)} bytes)')
    print(f'  LZSS decompressed: payload_dec.bin ({len(dec)} bytes)')
    print(f'  yf constants     : {len(consts)} calls, {len(uniq)} unique -> constants.txt')
    print(f'  output dir       : {outdir}')


if __name__ == '__main__':
    main()
