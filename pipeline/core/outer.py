"""The outer layer of any file in this family, with nothing assumed.

Every file of this kind carries its own loader in plain sight, and that loader
states every parameter the layer uses: the base85 alphabet, which table key holds
the body, the two numbers subtracted from the header, the byte order those header
numbers are read in, and which of the two sections is the interpreter and which is
its data. Samples differ in all of them.

So none of it is hardcoded. Each one is read out of the loader's own text and
reported, and a file that does not state one is refused by name rather than
guessed at.

What the loader looks like, in the terms it writes itself:

    for O=1,85 do z[sub(ALPHABET,O,O)]=O-1 end        the alphabet
    ...DecompressBuffer(fromstring(p(r[KEY])))...     the body, by table key
    (byte(Z,1)+byte(Z,2)*256+...-SUB1)%4294967296     the first length
    (byte(Z,5)+byte(Z,6)*256+...-SUB2)%4294967296     the second length
    loadstring(FIRST)(SECOND,...)                      which section is which
"""
import hashlib
import re


class Refused(Exception):
    """The file does not state something this needs. Named, never guessed."""


def _literal(text):
    """The long bracket body that holds the payload, with its span.

    A file of this family often opens with a comment written in long brackets
    too, so the first bracket in the text is not always the payload. The body
    is taken by size: the payload is the longest of them by a wide margin.
    """
    best = None
    for m in re.finditer(r"\[(=*)\[", text):
        pad = m.group(1)
        close = "]" + pad + "]"
        try:
            end = text.index(close, m.end())
        except ValueError:
            continue
        span = end - m.end()
        if best is None or span > best[2] - best[1]:
            best = (len(pad), m.end(), end, m.start(), end + len(close))
    if best is None:
        raise Refused("no long bracket literal: this is not one of these files")
    pad, start, end, open_at, close_at = best
    return text[start:end], pad, open_at, close_at


def _alphabet(text):
    m = re.search(r"for\s+\w+\s*=\s*1\s*,\s*85\s+do\s+\w+\[\w+\(\s*"
                  r"(['\"])((?:\\.|(?!\1).)*)\1", text)
    if not m:
        raise Refused("the loader does not carry an 85 character alphabet")
    alpha = m.group(2)
    alpha = alpha.replace("\\\\", "\\").replace('\\"', '"').replace("\\'", "'")
    if len(alpha) != 85:
        raise Refused("the alphabet reads as %d characters, not 85" % len(alpha))
    return alpha


def _subtractors(text):
    subs = [int(x) for x in re.findall(r"-\s*(\d{9,10})\s*\)\s*%\s*4294967296", text)]
    if len(subs) < 2:
        raise Refused("the loader does not carry two header subtractors")
    return subs[0], subs[1]


def _byte_order(text):
    """Whether the header's four bytes are read low end first or high end first."""
    low = re.search(r"\w+\(\w+,\s*1\)\s*\+\s*\w+\(\w+,\s*2\)\s*\*\s*256", text)
    high = re.search(r"\w+\(\w+,\s*4\)\s*\+\s*\w+\(\w+,\s*3\)\s*\*\s*256", text)
    if low and not high:
        return "little"
    if high and not low:
        return "big"
    high2 = re.search(r"\w+\(\w+,\s*1\)\s*\*\s*16777216", text)
    if high2:
        return "big"
    raise Refused("the loader does not say which way round its header reads")


def _section_order(text):
    """Which section loadstring is given: the one of the first length, or the second."""
    m = re.search(r"loadstring\(\s*(\w+)\s*\)\s*\(\s*(\w+)", text)
    if not m:
        raise Refused("the loader does not hand a section to loadstring")
    first_name, second_name = m.group(1), m.group(2)
    # which local took the FIRST length: the one assigned before the other
    order = []
    for mm in re.finditer(r"local\s+(\w+)\s*=\s*\w+\(\w+,\s*\w+,\s*\w+\s*\+\s*(\w+)",
                          text):
        order.append(mm.group(1))
    if len(order) < 2:
        # some write both on one line
        mm = re.search(r"local\s+(\w+)\s*=\s*\w+\(\w+,\s*\w+,[^;]*?;\s*\w+\s*=\s*\w+\s*\+"
                       r"\s*\w+;\s*local\s+(\w+)\s*=", text)
        if mm:
            order = [mm.group(1), mm.group(2)]
    if len(order) < 2:
        raise Refused("the loader does not cut two sections this file can follow")
    if order[0] == first_name:
        return "source_first"
    if order[1] == first_name:
        return "data_first"
    raise Refused("the section handed to loadstring is not one of the two cut")


def decode85(body, alphabet):
    table = {c: i for i, c in enumerate(alphabet)}
    out = bytearray()
    acc = n = 0
    for ch in body:
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
    elif n == 1:
        raise Refused("the base85 body has a trailing character it cannot use")
    return bytes(out)


def unwrap(path):
    """Returns a dict: every parameter read, and the two sections."""
    import zstandard

    text = open(path, encoding="latin1").read()
    body, pad, open_at, close_at = _literal(text)
    outer = text[:open_at] + text[close_at:]

    facts = {
        "path": path,
        "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest(),
        "bytes": len(text),
        "bracket_equals": pad,
        "alphabet": _alphabet(outer),
        "body_chars": len(body),
    }
    facts["subtractors"] = _subtractors(outer)
    facts["byte_order"] = _byte_order(outer)
    facts["section_order"] = _section_order(outer)

    raw = decode85(body, facts["alphabet"])
    facts["base85_bytes"] = len(raw)
    blob = zstandard.ZstdDecompressor().decompressobj().decompress(raw)
    facts["decompressed"] = len(blob)

    if facts["byte_order"] == "little":
        rd = lambda o: (blob[o] | (blob[o + 1] << 8) | (blob[o + 2] << 16)
                        | (blob[o + 3] << 24))
    else:
        rd = lambda o: ((blob[o] << 24) | (blob[o + 1] << 16)
                        | (blob[o + 2] << 8) | blob[o + 3])
    len1 = (rd(0) - facts["subtractors"][0]) % 2 ** 32
    len2 = (rd(4) - facts["subtractors"][1]) % 2 ** 32
    facts["lengths"] = (len1, len2)
    first = blob[8:8 + len1]
    second = blob[8 + len1:8 + len1 + len2]
    if 8 + len1 + len2 > len(blob):
        raise Refused("the header's lengths run past the end of the block")

    if facts["section_order"] == "source_first":
        facts["interpreter"], facts["data"] = first, second
    else:
        facts["data"], facts["interpreter"] = first, second
    facts["block"] = blob
    return facts


def describe(facts):
    out = []
    w = out.append
    w("THE OUTER LAYER, read out of the file's own loader")
    w("")
    w("  file            %s" % facts["path"])
    w("  bytes           %d" % facts["bytes"])
    w("  sha256          %s" % facts["sha256"])
    w("  long bracket    %d equals sign(s)" % facts["bracket_equals"])
    w("  alphabet        85 characters, starting %r" % facts["alphabet"][:16])
    w("  base85 body     %d characters -> %d bytes"
      % (facts["body_chars"], facts["base85_bytes"]))
    w("  decompressed    %d bytes" % facts["decompressed"])
    w("  header read     four bytes, %s end first" % facts["byte_order"])
    w("  subtracted      %d and %d" % facts["subtractors"])
    w("  lengths         %d and %d" % facts["lengths"])
    w("  order           %s" % facts["section_order"].replace("_", " "))
    w("  interpreter     %d bytes, sha256 %s"
      % (len(facts["interpreter"]),
         hashlib.sha256(facts["interpreter"]).hexdigest()[:32]))
    w("  data            %d bytes, sha256 %s"
      % (len(facts["data"]), hashlib.sha256(facts["data"]).hexdigest()[:32]))
    return "\n".join(out)


def selftest():
    bad = []
    pool = [chr(c) for c in range(33, 127) if chr(c) not in "'\"\\"]
    alpha = "".join(pool[:85])
    data = bytes(range(60))
    enc = []
    for i in range(0, len(data), 4):
        chunk = data[i:i + 4]
        v = int.from_bytes(chunk + b"\x00" * (4 - len(chunk)), "big")
        digits = []
        for _ in range(5):
            digits.append(alpha[v % 85])
            v //= 85
        enc.append("".join(reversed(digits)))
    if decode85("".join(enc), alpha) != data:
        bad.append("the base85 decoder does not undo its own encoding")
    try:
        _alphabet("nothing here")
    except Refused:
        pass
    else:
        bad.append("a file with no alphabet was not refused")
    sample = "for O=1,85 do z[P('%s',O,O)]=O-1 end" % alpha
    if _alphabet(sample) != alpha:
        bad.append("the alphabet was not read back from a loader line")
    quoted = alpha[:84] + "'"
    sample2 = "for O=1,85 do z[P('%s',O,O)]=O-1 end" % quoted.replace("'", "\\'")
    if _alphabet(sample2) != quoted:
        bad.append("an alphabet holding an escaped quote was not read back")
    if _byte_order("x=(Y(Z,1)+Y(Z,2)*256+Y(Z,3)*65536+Y(Z,4)*16777216-1)%4294967296") \
            != "little":
        bad.append("a low end first header was not recognised")
    if _byte_order("x=(Y(Z,4)+Y(Z,3)*256+Y(Z,2)*65536+Y(Z,1)*16777216-1)%4294967296") \
            != "big":
        bad.append("a high end first header was not recognised")
    if _subtractors("(a-1234567890)%4294967296 (b-987654321)%4294967296") \
            != (1234567890, 987654321):
        bad.append("the two subtractors were not read")
    for line in bad:
        print("  WRONG: %s" % line)
    print("outer selftest: %s" % ("ok" if not bad else "%d problem(s)" % len(bad)))
    return not bad


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        selftest()
    else:
        f = unwrap(sys.argv[1])
        print(describe(f))
        if len(sys.argv) > 2:
            import os
            os.makedirs(sys.argv[2], exist_ok=True)
            open(os.path.join(sys.argv[2], "interpreter.lua"), "wb").write(
                f["interpreter"])
            open(os.path.join(sys.argv[2], "data.bin"), "wb").write(f["data"])
            open(os.path.join(sys.argv[2], "block.bin"), "wb").write(f["block"])
            print("\nwritten to %s/" % sys.argv[2])
