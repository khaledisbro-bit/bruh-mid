#!/usr/bin/env python3
"""
sidecar.py - the one host service the offline run cannot compute for itself.

The offline run gives the payload a stand-in environment (robloxenv.lua) whose
rule is that roots exist and fields are absent, so nothing is invented. One
field cannot follow that rule: this family of build hands its payload to
`EncodingService:DecompressBuffer`, and a payload that does not get its bytes
back does not run at all. The real service decompresses a Zstd frame. A Luau
binary has no Zstd, so the stand-in cannot do it while the payload is running.

What it can do is bring the answer with it. The decompression is a pure function
of the bytes the payload passes, so it is computed BEFORE the run, by a real
Zstd decoder, over whatever blobs the script carries, and handed to the stand-in
as data. That is the host's work done early, not the payload's work done for it:
nothing here reads the decompressed text, decides what it means, or writes any
part of a reconstruction. The trace still has to run the interpreter to learn
anything.

Keyed by the bytes, never by the sample. An entry is found by the length of the
blob and its first and last eight bytes, which the stand-in measures on whatever
it is handed. A blob this table does not have is a miss the capture reports, with
the key it looked for, so an unknown build says so instead of running on
something that was not its own data.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def _unobf():
    """The generic decoder that already lives in this package."""
    if PKG not in sys.path:
        sys.path.insert(0, PKG)
    import unobf
    return unobf


def key_for(data):
    """The lookup key for a block of bytes.

    Length plus the first and last eight bytes. A hash over the whole blob would
    be as good and costs the stand-in a pass over half a megabyte in interpreted
    Luau for nothing; these sixteen bytes are read with string.byte.
    """
    head = data[:8]
    tail = data[-8:] if len(data) >= 8 else data
    return "%d:%s:%s" % (len(data), head.hex(), tail.hex())


def decompressions(src):
    """Every Zstd frame the script carries, decompressed.

    Returns a list of {key, compressed_len, plain, blob_key, alphabet_index}.
    Nothing is assumed about which blob is the real one: a blob that does not
    base85-decode under a candidate alphabet, or whose bytes are not a Zstd
    frame, is skipped, and the ones that are left are all reported.
    """
    try:
        import zstandard
    except ImportError:
        return [], "zstandard is not installed, so no frame could be decompressed"
    u = _unobf()
    alphabets = u.find_base85_alphabet(src)
    blobs = u.find_blobs(src)
    out, notes = [], []
    for bkey, blob in sorted(blobs, key=lambda kv: -len(kv[1])):
        for ai, alpha in enumerate(alphabets):
            try:
                raw = u.b85_decode(blob, alpha)
            except ValueError:
                continue
            if raw[:4] != ZSTD_MAGIC:
                continue
            try:
                plain = zstandard.ZstdDecompressor().decompress(
                    raw, max_output_size=500_000_000)
            except Exception as exc:
                notes.append("blob[%s] is a Zstd frame that did not "
                             "decompress (%s)" % (bkey, exc.__class__.__name__))
                continue
            out.append({"key": key_for(raw), "compressed_len": len(raw),
                        "plain": plain, "blob_key": bkey,
                        "alphabet_index": ai})
            break
    if not out and not notes:
        notes.append("no blob in this script base85-decoded into a Zstd frame")
    return out, "; ".join(notes)


def from_request(text):
    """Decompress the bytes a run asked for and could not be answered.

    Finding the frames by reading the script only works while the packing is one
    this tool knows. A build that keeps several frames in a table, or decodes
    them with something of its own, hands the bytes over at run time and the
    search beforehand finds nothing - which ends the run on its first step.

    The run writes what it was asked for, with the bytes, and this decompresses
    them for the run that follows. Nothing has to be known about the packing:
    the program produced the bytes itself.

    `text` is the capture; returns the same entries `decompressions` returns.
    """
    try:
        import zstandard
    except ImportError:
        return [], ("zstandard is not installed, so the bytes the run asked "
                    "for could not be decompressed")
    want, grab = [], False
    for ln in (text or "").splitlines():
        if ln.startswith("---"):
            grab = ln.strip() == "---WANTBYTES---"
            continue
        if grab and ln.strip():
            want.append(ln.strip())
    out, notes = [], []
    for ln in want:
        key, _, hexed = ln.partition(" ")
        if not hexed:
            continue
        try:
            raw = bytes.fromhex(hexed.strip())
        except ValueError:
            notes.append("a request came back with bytes that are not hex")
            continue
        if raw[:4] != ZSTD_MAGIC:
            notes.append("the bytes asked for (%s) are not a Zstd frame; this "
                         "stand-in only stands in for that one host service"
                         % key)
            continue
        try:
            plain = zstandard.ZstdDecompressor().decompress(
                raw, max_output_size=500_000_000)
        except Exception as exc:
            notes.append("the frame the run asked for did not decompress (%s)"
                         % exc.__class__.__name__)
            continue
        out.append({"key": key_for(raw), "compressed_len": len(raw),
                    "plain": plain, "blob_key": "asked for at run time",
                    "alphabet_index": None})
    return out, "; ".join(notes)


_SAFE = set(range(32, 127)) - {ord('"'), ord("\\")}


def chunk_replacement(inner_src, vm_row=None, vm_pc=None):
    """The interpreter's own source, edited so it hands over the program's
    functions, as Lua the harness can read.

    Keyed by the bytes the program will produce, so the harness can tell the
    chunk it is about to load from any other. The key is its length and its
    first 24 bytes, which is enough to tell one chunk from another and cheap
    for the harness to compute on a megabyte.
    """
    if PKG not in sys.path:
        sys.path.insert(0, PKG)
    import protohook
    found, why = protohook.find(inner_src, row=vm_row, pc=vm_pc)
    if found is None:
        return None, why
    patched, edit = protohook.patch(inner_src, found)
    key = "%d:%s" % (len(inner_src), inner_src[:24])
    out = ["-- ---- the interpreter, edited to hand over the program's "
           "functions ----",
           "-- " + why.replace("\n", " "),
           "-- the edit: " + edit.strip(),
           "VMSMART_CHUNK_REPLACEMENT = {}",
           "VMSMART_CHUNK_REPLACEMENT[%s] = %s" % (lua_string(key),
                                                   lua_string(patched)),
           ""]
    return "\n".join(out), why


def lua_string(data):
    """A Luau string literal for arbitrary bytes.

    Printable ASCII goes through as itself so the file stays mostly readable and
    mostly its own size; everything else becomes a decimal escape. A decimal
    escape is followed by a digit often enough that the three-digit form is used
    throughout - `\\9x` and `\\9` followed by `5` are different strings.
    """
    if isinstance(data, str):
        data = data.encode("latin1", "replace")
    parts = ['"']
    for b in data:
        if b in _SAFE:
            parts.append(chr(b))
        else:
            parts.append("\\%03d" % b)
    parts.append('"')
    return "".join(parts)


def emit_lua(entries, note=""):
    """The sidecar as a Luau chunk the stand-in reads."""
    lines = ["-- generated by sidecar.py: host decompression, computed before "
             "the run",
             "-- Nothing here is read as source. It is the bytes the payload's "
             "own loader",
             "-- would have been handed by the real service.",
             "VMSMART_DECOMPRESS = {}"]
    if note:
        lines.append("VMSMART_DECOMPRESS_NOTE = %s" % lua_string(note))
    for e in entries:
        lines.append("VMSMART_DECOMPRESS[%s] = %s"
                     % (lua_string(e["key"]), lua_string(e["plain"])))
    return "\n".join(lines) + "\n"


def describe(entries, note):
    if not entries:
        return ("no host decompression could be prepared: %s"
                % (note or "nothing to prepare"))
    return ("%d decompressed frame(s) prepared for the stand-in: %s"
            % (len(entries),
               ", ".join("blob[%s] %d bytes -> %d bytes"
                         % (e["blob_key"], e["compressed_len"], len(e["plain"]))
                         for e in entries)))


def _selftest():
    bad = []
    try:
        import zstandard
    except ImportError:
        print("sidecar selftest skipped (no zstandard)")
        return []

    # a script of this SHAPE, built here, with its own alphabet and its own
    # payload. Nothing about the real sample is used to find it.
    import random
    rnd = random.Random(7)
    alpha = list("0123456789abcdefghijklmnopqrstuvwxyz"
                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()*+-/:;<=>?@^_")
    rnd.shuffle(alpha)
    alpha = "".join(alpha[:85]) if len(alpha) >= 85 else None
    if alpha is None or len(set(alpha)) != 85:
        # build a distinct 85-char alphabet from the printable range instead
        pool = [chr(c) for c in range(33, 127) if chr(c) not in "[]"]
        alpha = "".join(pool[:85])
    plain = (b"local x = 1\nreturn x\n" * 50) + bytes(range(256))
    frame = zstandard.ZstdCompressor().compress(plain)

    def b85_encode(data, alphabet):
        out = []
        for i in range(0, len(data), 4):
            chunk = data[i:i + 4]
            pad = 4 - len(chunk)
            v = int.from_bytes(chunk + b"\x00" * pad, "big")
            digits = []
            for _ in range(5):
                digits.append(alphabet[v % 85])
                v //= 85
            out.append("".join(reversed(digits))[:5 - pad])
        return "".join(out)

    blob = b85_encode(frame, alpha)
    src = ("local M={} for i=1,85 do M[sub([[%s]],i,i)]=i-1 end "
           "return({[240063]=[[%s]]})" % (alpha, blob))
    ents, note = decompressions(src)
    if len(ents) != 1:
        bad.append("one frame in, %d out (%s)" % (len(ents), note))
    elif ents[0]["plain"] != plain:
        bad.append("the frame came back changed")
    elif ents[0]["key"] != key_for(frame):
        bad.append("the key is not the key the stand-in will compute")

    # a script with a blob that is not a frame yields nothing, and says so
    ents2, note2 = decompressions("return({[1]=[[hello there]]})")
    if ents2:
        bad.append("a blob that is not a Zstd frame must not become an entry")
    if "Zstd" not in note2 and "zstandard" not in note2:
        bad.append("an empty result must say why: %r" % note2)

    # the literal survives every byte, and a digit after an escape stays
    # separate from it
    data = bytes([9, 53, 0, 255, 34, 92]) + b"ok"
    lit = lua_string(data)
    for frag in ("\\009", "\\000", "\\255", "\\034", "\\092"):
        if frag not in lit:
            bad.append("%s is not escaped: %s" % (frag, lit))
    if "\\0095" in lit.replace("\\0095", "\\009" + "5"):
        pass
    if "ok" not in lit:
        bad.append("printable bytes should stay printable: %s" % lit)
    # keys arrive as text, bytes arrive as bytes, and both have to come out as
    # a literal rather than as an exception
    if lua_string("12:ab:cd") != '"12:ab:cd"':
        bad.append("a text key must escape like any other bytes: %s"
                   % lua_string("12:ab:cd"))

    # describe never calls an empty table a success
    if "no host decompression" not in describe([], "nothing found"):
        bad.append("an empty sidecar must be described as empty")

    print("sidecar selftest %s" % ("ok" if not bad else "FAILURES"))
    for b in bad:
        print("  - %s" % b)
    return bad


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(1 if _selftest() else 0)
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="latin1") as f:
            text = f.read()
        ents, note = decompressions(text)
        print(describe(ents, note))
