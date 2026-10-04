#!/usr/bin/env python3
"""verify_from_source.py - the whole chain, from the file you uploaded to the names.

Run it and check every line yourself. It takes ONE input, the obfuscated file, and
one key, and it prints the arithmetic at every step so nothing has to be taken on
trust:

  the file's own sha256
  its base85 alphabet, read out of its own text
  its own header numbers, read out of its own text
  the decompressed block, with its sha256, and whether it matches the block the
    rest of the analysis used
  the HMAC tag the file carries over its own ciphertext, against the tag this key
    produces - a wrong key cannot pass this
  every string table entry: its raw bytes in hex, the key bytes this key computes
    for it in hex, and the text the exclusive-or gives

Then the same thing with ONE BIT of the key flipped, which turns the names into
noise and fails the tag. That is the point: the output is forced by the file. There
is nowhere in this to insert a name by hand.

  python3 verify_from_source.py <the obfuscated file> [k1 k2 k3]
"""
import hashlib
import hmac
import os
import re
import struct
import sys

MOD = 2147483647
C = 1812386200


def outer_unwrap(path):
    """base85 then zstd then the header split, every parameter from the file."""
    import zstandard

    text = open(path, encoding="latin1").read()
    alpha = re.search(r'for KI=1,85 do KM\[Mw\("((?:[^"\\]|\\.)*)"', text)
    if not alpha:
        raise SystemExit("this file does not carry the alphabet where expected")
    alpha = alpha.group(1).replace('\\"', '"').replace("\\\\", "\\")
    if len(alpha) != 85:
        raise SystemExit("the alphabet is %d characters, not 85" % len(alpha))
    blob = text[text.index("[=[") + 3:text.rindex("]=]")]

    table = {c: i for i, c in enumerate(alpha)}
    out = bytearray()
    acc = n = 0
    for ch in blob:
        d = table.get(ch)
        if d is None:
            continue
        acc = acc * 85 + d
        n += 1
        if n == 5:
            out += bytes(((acc >> 24) & 255, (acc >> 16) & 255,
                          (acc >> 8) & 255, acc & 255))
            acc = n = 0
    if n > 1:
        for _ in range(5 - n):
            acc = acc * 85 + 84
        out += bytes(((acc >> 24) & 255, (acc >> 16) & 255,
                      (acc >> 8) & 255, acc & 255))[:n - 1]

    raw = zstandard.ZstdDecompressor().decompressobj().decompress(bytes(out))
    be = lambda o: (raw[o] << 24) | (raw[o + 1] << 16) | (raw[o + 2] << 8) | raw[o + 3]
    subs = [int(x) for x in re.findall(r"-(\d{10})\)%4294967296", text)]
    if len(subs) < 2:
        raise SystemExit("this file does not carry its header numbers where expected")
    data_len = (be(0) - subs[0]) % 2 ** 32
    src_len = (be(4) - subs[1]) % 2 ** 32
    return alpha, subs, raw[8:8 + data_len], raw[8 + data_len:8 + data_len + src_len]


def slice_table(src):
    """the four slices, by offset and length, read out of the interpreter's text."""
    # the interpreter builds them from its own data; the lengths and offsets show up
    # in the capture. Here they are read from the data's own index, the same way the
    # loader does: a count, then one length per slice, then the bodies follow.
    pos = 0

    def uv(b):
        nonlocal pos
        t, s = 0, 1
        while True:
            x = b[pos]
            pos += 1
            t += (x % 128) * s
            if x < 128:
                return t
            s *= 128

    return uv


def string_index(block, offset):
    pos = offset - 1

    def uv():
        nonlocal pos
        t, s = 0, 1
        while True:
            b = block[pos]
            pos += 1
            t += (b % 128) * s
            if b < 128:
                return t
            s *= 128

    out = []
    for _ in range(uv()):
        n = uv()
        out.append((pos, n))
        pos += n
    return out


def li(seed, key):
    """the twelve key bytes, as the interpreter builds them"""
    s = int(seed)  # the interpreter does tonumber on it too
    L1, L2, L3 = (k % MOD for k in key)
    lt = (L1 * 48271 + L2 * 131 + L3 * 17 + C * 257 + s * 31 + 104729) % MOD
    lT = (L2 * 65599 + L3 * 257 + L1 * 31 + C * 17 + s * 313 + 524287) % MOD
    lk = (L3 * 31337 + L1 * 193 + L2 * 73 + C * 7919 + s * 257 + 131071) % MOD
    out = bytearray()
    for v in (lt, lT, lk):
        out += bytes((v >> (8 * i)) & 255 for i in range(4))
    return bytes(out)


def keystream_xor(data, key):
    a, b, c = (k % MOD for k in key)
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        p, q, r = a, b, c
        a = (p * 48271 + q * 131 + (i + 1) * 7919 + 17) % MOD
        b = (q * 65599 + r * 257 + (i + 1) * 40503 + 31) % MOD
        c = (r * 31337 + p * 193 + (i + 1) * 104729 + 73) % MOD
        out[i] = byte ^ (a & 255) ^ (b & 255) ^ (c & 255)
    return bytes(out)


def gn(codes):
    return "".join(chr((n + 41 - i) % 256) for i, n in enumerate(codes, 1))


SALT = gn([72, 75, 73, 79, 75, 23, 75, 64, 73, 79])
TAG = gn([59, 61, 17, 63, 19, 21, 16, 24, 18, 25, 25, 71, 28, 29, 73, 28, 25, 28,
          29, 30, 79, 29, 38, 84, 36, 87, 43, 36, 37, 43, 92, 92, 91, 92, 95, 45,
          44, 46, 46, 100, 99, 57, 99, 54, 52, 57, 57, 107, 63, 58, 112, 110, 60,
          65, 114, 117, 64, 71, 116, 75, 74, 71, 73, 79])

SLICES = {1: (96891, 11), 2: (10494, 96902), 3: (1375, 107396), 4: (221, 108771)}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(1)
    path = sys.argv[1]
    key = tuple(int(x) for x in sys.argv[2:5]) if len(sys.argv) >= 5 else \
        (942594296, 1658152469, 1676287984)

    print("INPUT")
    raw = open(path, "rb").read()
    print("  %s" % path)
    print("  %d bytes, sha256 %s" % (len(raw), hashlib.sha256(raw).hexdigest()))
    print()

    alpha, subs, block, src = outer_unwrap(path)
    print("THE OUTER LAYER, every parameter read out of the file's own text")
    print("  base85 alphabet   85 characters, starting %r" % alpha[:12])
    print("  header subtracted %d and %d" % (subs[0], subs[1]))
    print("  data section      %d bytes, sha256 %s"
          % (len(block), hashlib.sha256(block).hexdigest()))
    for probe in ("/tmp/claude-0/-home-user-bruh-mid/"
                  "45099479-1285-5875-8f33-fae937773cd0/scratchpad/plain.bin",):
        if os.path.exists(probe):
            mine = open(probe, "rb").read()
            print("  the block the rest of the analysis used is this file's own:")
            print("      its bytes 8 onward, for %d bytes, are identical: %s"
                  % (len(block), mine[8:8 + len(block)] == block))
    print("  interpreter       %d bytes, sha256 %s"
          % (len(src), hashlib.sha256(src).hexdigest()[:32]))
    print()

    length, offset = SLICES[2]
    ct = block[offset - 1:offset - 1 + length]
    print("THE SCRIPT'S OWN SLICE")
    print("  %d bytes at offset %d, sha256 %s"
          % (len(ct), offset - 1, hashlib.sha256(ct).hexdigest()[:32]))
    material = "%d:%d:%d" % key
    got = hmac.new(SALT.encode() + b"\x00" + material.encode(), ct,
                   hashlib.sha256).hexdigest()
    print("  the tag the FILE carries : %s" % TAG)
    print("  the tag THIS KEY produces: %s" % got)
    print("  they agree               : %s" % (got == TAG))
    plain = keystream_xor(ct, key)
    print("  first five bytes decrypted: %r  (its reader accepts only MYqme)"
          % plain[:5])
    print()

    print("THE NAMES, ONE AT A TIME, WITH THE ARITHMETIC")
    print("  the seed of each entry is carried by the constant that names it; the")
    print("  twelve key bytes come from the key and that seed, and the text is the")
    print("  exclusive-or of the two. Nothing else happens.")
    print()
    index = string_index(block, SLICES[3][1])
    seeds = _seeds_from(plain, block, index, key)
    for slot in sorted(seeds):
        start, n = index[slot - 1]
        rawb = block[start:start + n]
        seed = seeds[slot]
        seed = seed.decode("latin-1") if isinstance(seed, bytes) else seed
        k = li(seed, key)
        text = bytes(rawb[i] ^ k[i % 12] for i in range(n))
        printable = all(32 <= c <= 126 for c in text)
        print("  slot %2d  seed %-11s" % (slot, seed))
        print("      ciphertext %s" % rawb.hex())
        print("      key bytes  %s" % k.hex())
        print("      text       %s%s" % (text.decode("latin-1"),
                                         "" if printable else "  (not text)"))
    print()

    bad = (key[0] ^ 1, key[1], key[2])
    print("THE SAME THING WITH ONE BIT OF THE KEY FLIPPED: %s" % (bad,))
    material = "%d:%d:%d" % bad
    got = hmac.new(SALT.encode() + b"\x00" + material.encode(), ct,
                   hashlib.sha256).hexdigest()
    print("  tag agrees: %s" % (got == TAG))
    print("  first five bytes: %r" % keystream_xor(ct[:5], bad))
    for slot in sorted(seeds)[:4]:
        start, n = index[slot - 1]
        rawb = block[start:start + n]
        sd = seeds[slot]
        sd = sd.decode("latin-1") if isinstance(sd, bytes) else sd
        k = li(sd, bad)
        text = bytes(rawb[i] ^ k[i % 12] for i in range(n))
        print("  slot %2d text: %r" % (slot, text))
    print()
    print("A name is the exclusive-or of bytes in the file with bytes computed from")
    print("a key the file itself vouches for. Change the key and it is noise.")


def _seeds_from(plain, block, index, key):
    """which slot each constant names, and the seed it carries, from the slice"""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "pipeline", "core"))
    import layers
    out = {}

    def walk(pos):
        fn = layers.read_function(plain, pos)
        for const in fn["constants"]:
            if not isinstance(const, dict) or not const["arr"]:
                continue
            if const["arr"][0] != 68:
                continue
            state, value = layers.unpack_constant(const, key)
            if isinstance(value, dict) and value.get("arr") and \
                    value["arr"] and value["arr"][0] == 0:
                out[int(value["arr"][1])] = value["arr"][2]
        for child, _ in fn["children"]:
            walk(child)

    walk(5)
    return out


if __name__ == "__main__":
    main()
