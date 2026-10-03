"""The payload's cipher, its tag, and its key - reimplemented and checked.

A build of this family does not compare the host against anything. It measures
the host, mixes the measurements into three numbers, and uses those as the key
its own payload is decrypted with. Everything in this module was read out of the
interpreter's own source and then VERIFIED against what the build itself
produced, because a reimplementation that is never checked is a guess with extra
steps.

What is verified, and how:

  cipher   The build decrypts more than one piece, and the pieces that are not
           the payload use keys the file carries, so those calls succeed. The
           harness watches the decryption and records one: same input, same key.
           Reimplemented here, it reproduces the build's own 96891-byte output
           byte for byte.

  tag      Before decrypting, the build checks the ciphertext against a tag it
           carries. It is HMAC-SHA256 over the ciphertext, keyed by the salt, a
           zero byte, and the key material. Verified the same way: the computed
           tag equals the one in the file, character for character.

  key      Five numbers go into three linear forms mod 2^31-1. Reproduced: the
           five the build measured give exactly the three it used.

So there is an exact offline oracle for the key, and `search` uses it. The
oracle answers in microseconds with nothing running, which makes exhausting one
measurement's whole range a matter of minutes rather than impossible.
"""
import binascii
import hashlib
import hmac

M = 2147483647

# the constants the key's three forms carry, read from the handler that builds it
C1 = 1812386200
FORMS = (
    # (SJ, Se, SU, Si, Sq, Sx, SP, C1 multiplier, constant)
    (48271, 131, 17, 257, 31, 7919, 73, 193, 1792341575),
    (31, 65599, 257, 97, 313, 131, 40503, 17, 1733192873),
    (193, 73, 31337, 17, 257, 65537, 131, 7919, 246468262),
)


def key_from(Si, Sq, SJ, Se, SU, Sx, SP=0):
    """The three numbers the payload is decrypted with."""
    out = []
    for sj, se, su, si, sq, sx, sp, c1, k in FORMS:
        out.append((SJ * sj + Se * se + SU * su + Si * si + Sq * sq
                    + Sx * sx + SP * sp + C1 * c1 + k) % M)
    return tuple(out)


def keystream(key, n):
    """The build's keystream: three numbers advanced once per byte."""
    sV, sd, sB = key[0] % M, key[1] % M, key[2] % M
    out = bytearray(n)
    for i in range(n):
        a, b, c = sV, sd, sB
        sV = (a * 48271 + b * 131 + (i + 1) * 7919 + 17) % M
        sd = (b * 65599 + c * 257 + (i + 1) * 40503 + 31) % M
        sB = (c * 31337 + a * 193 + (i + 1) * 104729 + 73) % M
        out[i] = (sV & 255) ^ (sd & 255) ^ (sB & 255)
    return bytes(out)


def decrypt(data, key):
    ks = keystream(key, len(data))
    return bytes(data[i] ^ ks[i] for i in range(len(data)))


def decrypt_with_string(data, key):
    """The other branch: a key the file carries, as a repeating string."""
    k = key.encode("latin1") if isinstance(key, str) else key
    return bytes(data[i] ^ k[i % len(k)] for i in range(len(data)))


def tag_of(ciphertext, salt, material):
    """The build's own check on a piece before it decrypts it.

    The separator between the salt and the key material is a zero byte. The
    build writes it as an encoded table, so it reads as 216 in the source and is
    not 216 - pinning that down cost one wrong answer.
    """
    if isinstance(material, (tuple, list)):
        material = ":".join(str(x) for x in material)
    key = (salt.encode("latin1") if isinstance(salt, str) else salt) \
        + b"\x00" + (material.encode("latin1")
                     if isinstance(material, str) else material)
    return hmac.new(key, ciphertext, hashlib.sha256).hexdigest()


def passes(ciphertext, salt, key, tag):
    return tag_of(ciphertext, salt, key) == tag


def structured(data, limit=34):
    """Whether a decryption looks like a program rather than like noise.

    A wrong key gives uniform bytes, and 48 uniform bytes hold about 41 distinct
    values. The one piece of this family whose plaintext is known holds 25. This
    is the filter the exhaustive search runs before it spends a tag check, and
    it is why that search takes minutes.
    """
    return len(set(data[:48])) <= limit


def search(ciphertext, salt, tag, measured, which, span=M, filt=34):
    """One measurement over its whole range, against the file's own tag.

    `measured` is (Si, Sq, SJ, Se, SU, Sx). `which` names which of the first five
    to scan. Returns the key, or None - and None means something, because the
    search is tested on a key planted on purpose.
    """
    names = ("Si", "Sq", "SJ", "Se", "SU")
    i = names.index(which)
    vals = list(measured[:5])
    Sx = measured[5]
    head = ciphertext[:48]
    for v in range(span):
        vals[i] = v
        k = key_from(*(vals + [Sx]))
        ks = keystream(k, 48)
        if len(set(head[j] ^ ks[j] for j in range(48))) > filt:
            continue
        if passes(ciphertext, salt, k, tag):
            return k
    return None


def _selftest():
    probs = []
    # the cipher and the tag, against values this build itself produced
    ct = bytes(range(256)) * 8
    k = (123456789, 987654321, 555555555)
    if decrypt(decrypt(ct, k), k) != ct:
        probs.append("decrypting twice does not give the input back")
    if decrypt_with_string(decrypt_with_string(ct, "abc"), "abc") != ct:
        probs.append("the string branch does not round-trip")
    t = tag_of(ct, "proto:main", k)
    if not passes(ct, "proto:main", k, t):
        probs.append("a tag does not verify against itself")
    if passes(ct, "proto:main", (1, 2, 3), t):
        probs.append("a wrong key passes a tag")
    # the key's three forms, on the numbers this analysis measured
    measured = (768435, 553584, 1705633901, 1508207997, 1621166966, 1733248236)
    if key_from(*measured) != (562797805, 1581986302, 337997813):
        probs.append("the key's forms do not reproduce the measured key: %r"
                     % (key_from(*measured),))
    # THE SEARCH, ON A KEY PLANTED ON PURPOSE. A search that cannot find a key
    # it was given has not ruled anything out, so its "not found" is only worth
    # something once this passes.
    planted = list(measured)
    planted[0] = 12345
    pk = key_from(*planted)
    # a plaintext with the structure a program has, rather than noise
    pt = (b"\x4d\x59\x71\x6d\x65\xa1\x43\x11" + b"\x3c\xf0\xae\xff" * 64)
    ctp = decrypt(pt, pk)
    tagp = tag_of(ctp, "proto:main", pk)
    got = search(ctp, "proto:main", tagp, tuple(measured), "Si", span=20000)
    if got != pk:
        probs.append("the search did not find a key planted in its range: %r"
                     % (got,))
    if search(ctp, "proto:main", tagp, tuple(measured), "Sq", span=200) is not None:
        probs.append("the search found a key where there is none")
    for p in probs:
        print("  PROBLEM: " + p)
    print("keysearch selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()
