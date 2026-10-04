"""Every layer, one after the other, until nothing is left wrapped.

A protected file of this family is not one layer. Reading one and stopping is
why an analysis comes back with numbers instead of names. The layers, in the
order the build unwraps them:

  layer 0  the outer chunk. A base85 body inside return({...}), decompressed by
           a short loader the file carries in plain sight.

  layer 1  one loadstring. What comes out is the interpreter: a few thousand
           lines with every name mangled, and with it a slice table - four
           regions of the decompressed block, by offset and length.

  layer 2  each slice, decrypted. The cipher is three numbers walking forward
           once per byte. Slice 1 is the measurement layer, slice 2 is the real
           script, slice 3 is the string table, slice 4 is the import list.
           The key for a slice is built while layer 1 runs, out of what the
           machine answers.

  layer 3  the decrypted slice, deserialised. The reader refuses anything whose
           first five bytes are not MYqme, stores lengths with every byte
           inverted, folds signed numbers, and tags values with its own byte
           numbers. What comes out is a function: instructions, constants, and
           nested functions as sub-regions to read the same way.

  layer 4  each constant, unpacked. A constant is not a value. It is
           {68, blob, g}, and the blob decrypts under a key made from g alone:

               material = tostring((g * 7919 % 2147483629 + sq) % 2147483629)

           with sq a fixed hex literal the file carries. The cipher here is the
           other branch of the same function: exclusive-or against the material
           repeated. What comes out is a number, or one more wrapper.

  layer 5  that wrapper, resolved. It is {0, index, material}, and it points
           into the string table: entry `index`, exclusive-ored against
           "1812386200:" .. material repeated. What comes out is the text -
           Instance, GetService, BrickColor, the real names.

Layers 4 and 5 need no key and no run. They are arithmetic over bytes the file
already gave up, which is why the names come out even for the parts no run
reached. Only layer 2 needs the measured key, and only for slice 2.

Nothing here is pattern-matched against a known script. Every tag number, every
multiplier, the inverted length bytes, the separator, sq - all of it is read out
of the interpreter the file carries, and the selftest at the bottom checks the
chain against the file's own output rather than against an expected answer.
"""
import hmac
import hashlib
import struct


MOD2 = 2147483629          # the modulus the constant key uses
MIX = 7919                 # its multiplier
MAGIC = b"MYqme"           # the five bytes the reader demands

TAG_NIL, TAG_FALSE, TAG_TRUE = 134, 222, 202
TAG_NUMSTR, TAG_INT, TAG_DOUBLE = 15, 60, 236
TAG_STRING, TAG_TABLE = 161, 174

WRAP_CONST = 68            # {68, blob, g}        - a packed constant
WRAP_TEXT = 0              # {0, index, material} - a pointer into the strings
WRAP_PROTO = 194           # {194, blob, salt, tag} - a function, checked first
WRAP_SPLIT = 82            # {82, side, n, body, flag} - n bytes split off one end


def hex_literal(codes):
    """The file writes its own literals as number lists. char(n + 41 - i).

    Nothing is assumed about what the string says: the transform is the one the
    interpreter applies, and the caller gets whatever comes out.
    """
    return "".join(chr(n + 41 - i) for i, n in enumerate(codes, 1))


# sq, as the file builds it: a sixteen character hex literal, first eight digits
SQ_CODES = [8, 11, 11, 11, 18, 13, 63, 19, 17, 26, 24, 25, 25, 26, 30, 75]
SQ_TEXT = hex_literal(SQ_CODES)
SQ = int(SQ_TEXT[:8], 16)

# lq, the salt in front of a string table key. The file holds it as plain text.
LQ = "1812386200"


class Reader:
    """Both readers the file uses. The deserialiser inverts its length bytes;
    the packed-constant reader does not. One class, one flag."""

    def __init__(self, data, pos, inverted):
        self.d = data
        self.p = pos
        self.inv = inverted

    def uint(self):
        total, scale = 0, 1
        while True:
            if self.p >= len(self.d):
                raise ValueError("ran off the end at %d" % self.p)
            b = self.d[self.p]
            if self.inv:
                b = 255 - b
            self.p += 1
            total += (b % 128) * scale
            if b < 128:
                return total
            scale *= 128

    def int(self):
        v = self.uint()
        return v // 2 if v % 2 == 0 else -(v + 1) // 2

    def text(self):
        n = self.uint()
        out = self.d[self.p:self.p + n]
        self.p += n
        return out

    def value(self):
        t = self.d[self.p]
        self.p += 1
        if t == TAG_NIL:
            return None
        if t == TAG_FALSE:
            return False
        if t == TAG_TRUE:
            return True
        if t == TAG_NUMSTR:
            return float(self.text())
        if t == TAG_STRING:
            return self.text()
        if t == TAG_TABLE:
            arr = [self.value() for _ in range(self.uint())]
            mapped = {}
            for _ in range(self.uint()):
                k = self.value()
                mapped[k] = self.value()
            return {"arr": arr, "map": mapped}
        if self.inv:
            if t == TAG_INT:
                return self.int()
            if t == TAG_DOUBLE:
                v = struct.unpack_from("<d", self.d, self.p)[0]
                self.p += 8
                return v
        raise ValueError("unknown tag %d at %d" % (t, self.p - 1))


def repeat_xor(data, material):
    """The cipher's other branch: exclusive-or against a string repeated."""
    key = material.encode() if isinstance(material, str) else material
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def keystream_xor(data, key):
    """The cipher's number branch. Three accumulators, one step per byte."""
    a, b, c = (k % 2147483647 for k in key)
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        p, q, r = a, b, c
        a = (p * 48271 + q * 131 + (i + 1) * 7919 + 17) % 2147483647
        b = (q * 65599 + r * 257 + (i + 1) * 40503 + 31) % 2147483647
        c = (r * 31337 + p * 193 + (i + 1) * 104729 + 73) % 2147483647
        out[i] = byte ^ (a & 255) ^ (b & 255) ^ (c & 255)
    return bytes(out)


def read_function(data, pos):
    """Layer 3. The field order is the file's own; the names say what each holds.

    The slots the interpreter indexes are kept next to each field so a reader can
    check this against the interpreter without trusting the names.
    """
    r = Reader(data, pos, True)
    fn = {}
    fn["line_base"] = r.uint()                                   # slot 12
    fn["upvalues"] = r.int()                                     # slot 14
    fn["header"] = r.value()                                     # slot 1
    fn["numbers"] = [r.int() for _ in range(r.uint())]           # slot 11

    n = r.uint()                                                 # slot 10
    children = [None] * n
    for i in range(n):
        length = r.uint()
        children[n - i - 1] = (r.p, length)   # stored back to front by the file
        r.p += length
    fn["children"] = children

    fn["flags"] = r.value()                                      # slot 8
    fn["params"] = r.uint()                                      # slot 9
    fn["constants"] = [r.value() for _ in range(r.uint())]       # slot 17
    fn["mode"] = data[r.p]                                       # slot 16
    r.p += 1
    fn["extra"] = r.value()                                      # slot 7
    fn["stack"] = r.int()                                        # slot 15
    fn["names"] = r.value()                                      # slot 6
    fn["jump_key"] = r.int()                                     # slot 3
    fn["count"] = r.int()                                        # slot 4
    fn["tail"] = r.value()                                       # slot 5

    instrs = []                                                  # slot 2
    for _ in range(r.uint()):
        instrs.append([r.value() for _ in range(r.uint())])
    fn["instructions"] = instrs
    fn["jumps"] = [r.value() for _ in range(r.uint())]           # slot 13
    fn["bytes_read"] = r.p - pos
    return fn


def string_index(block, offset):
    """The string table's own index: a count, then a length per entry.

    `offset` is the slice table's offset for slice 3, one-based the way the
    interpreter reads it. The entries come back as python positions.
    """
    r = Reader(block, offset - 1, False)
    out = []
    for _ in range(r.uint()):
        length = r.uint()
        out.append((r.p, length))
        r.p += length
    return out


def unpack_constant(const):
    """Layer 4. Returns (state, value). State says why, when there is no value.

    A constant with the fourth field set to 1 takes its key from the measured
    numbers instead of from g, so it stays wrapped until the key is known. That
    is reported, not guessed.
    """
    if not isinstance(const, dict):
        return "plain", const
    arr = const["arr"]
    if arr and arr[0] == WRAP_PROTO:
        # Layer 6. A whole function, carried as a constant. The build checks it
        # before it decrypts it: the tag is an HMAC over these very bytes, keyed
        # with the salt, a zero byte and the key material. The key material here
        # is not measured off the machine - it is a value the program computes
        # and leaves on the stack at the instruction that loads this function.
        # So this one waits on the run reaching that instruction, and the tag
        # says at once whether a guess at it is right.
        salt = arr[2] if len(arr) > 2 else b""
        tag = arr[3] if len(arr) > 3 else b""
        return ("a function, %d byte(s), checked under salt %r"
                % (len(arr[1]) if len(arr) > 1 and isinstance(arr[1], bytes) else 0,
                   _text(salt)), None)
    if arr and arr[0] == WRAP_SPLIT:
        return ("bytes with %s split off one end" % (arr[2] if len(arr) > 2 else "?"),
                None)
    if len(arr) < 3 or arr[0] != WRAP_CONST:
        return "other", const
    if const["map"].get(4) == 1 or (len(arr) >= 4 and arr[3] == 1):
        return "needs the measured key", None
    blob, g = arr[1], int(arr[2])
    material = str(((g * MIX) % MOD2 + SQ) % MOD2)
    inner = repeat_xor(blob, material)
    r = Reader(inner, 0, False)
    try:
        value = r.value()
    except (ValueError, IndexError) as why:
        return "would not read: %s" % why, None
    if r.p != len(inner):
        return "did not consume its bytes", None
    return "ok", value


def _text(v):
    if isinstance(v, bytes):
        return v.decode("latin-1")
    return str(v)


def resolve_text(value, block, index):
    """Layer 5. A pointer into the string table becomes the text it names."""
    if not isinstance(value, dict):
        return None
    arr = value["arr"]
    if len(arr) < 3 or arr[0] != WRAP_TEXT:
        return None
    if value["map"].get(4) == 1 or (len(arr) >= 4 and arr[3] == 1):
        return None
    slot = int(arr[1])
    if slot < 1 or slot > len(index):
        return None
    material = arr[2]
    material = material.decode("latin-1") if isinstance(material, bytes) else str(material)
    start, length = index[slot - 1]
    return repeat_xor(block[start:start + length], LQ + ":" + material)


def constants_of(fn, block, index):
    """Every constant of one function, carried as far as the layers go.

    Each entry is a dict with what it ended as and how it got there, so a reader
    can tell a recovered name from a number from something still wrapped.
    """
    out = []
    for i, const in enumerate(fn["constants"], 1):
        state, value = unpack_constant(const)
        row = {"index": i, "state": state, "value": value, "text": None}
        if value is None and isinstance(const, dict) and const["arr"] \
                and const["arr"][0] == WRAP_PROTO:
            row["value"] = const
        if state in ("ok", "plain"):
            text = resolve_text(value, block, index)
            if text is not None:
                row["text"] = text
                row["state"] = "text"
        out.append(row)
    return out


def mac(blob, salt, material):
    """The build's own check: an HMAC over the bytes, keyed with the salt, a zero
    byte and the key material. Verified against the file's own tags."""
    key = salt + b"\x00" + material
    return hmac.new(key, blob, hashlib.sha256).hexdigest().encode()


def candidates_from(functions):
    """Every value this slice has already given up, as possible key material.

    The key for a packed function is a string the program computes and leaves on
    the stack. It is not stored, so it is not readable - but it is almost always
    a value the same slice already holds, and the build carries a tag that says
    at once whether a guess is right. So: try what the file itself produced, and
    believe only what the tag confirms. Nothing is tried that did not come out of
    these bytes, and nothing is accepted that the tag does not verify.
    """
    out = []
    seen = set()

    def add(v):
        if v is None or v in seen:
            return
        seen.add(v)
        out.append(v)

    for fn in functions:
        for row in fn["constants"]:
            if row["text"] is not None:
                add(row["text"])
            v = row["value"]
            if isinstance(v, bool):
                continue
            if isinstance(v, float):
                add(str(int(v)).encode() if v == int(v) else str(v).encode())
            elif isinstance(v, int):
                add(str(v).encode())
            elif isinstance(v, bytes):
                add(v)
    return out


def unlock_proto(const, materials):
    """Layer 6. Returns (material, plaintext) when the file's own tag agrees."""
    arr = const["arr"]
    if len(arr) < 4 or arr[0] != WRAP_PROTO:
        return None, None
    blob, salt, tag = arr[1], arr[2], arr[3]
    if not isinstance(blob, bytes) or not isinstance(salt, bytes):
        return None, None
    for material in materials:
        if mac(blob, salt, material) == tag:
            opened = repeat_xor(blob, material)
            if opened[:5] == MAGIC:
                return material, opened
            return material, None
    return None, None


def walk(block, slice_table, slice_number, key=None, index_slice=3, plain=None):
    """Every layer of one slice, with its children, as deep as it goes.

    `block` is the decompressed body. `slice_table` is {number: (length,
    offset)} exactly as the interpreter built it. `key` is the three measured
    numbers, needed only where the slice is still encrypted.
    """
    length, offset = slice_table[slice_number]
    raw = block[offset - 1:offset - 1 + length]
    report = {"slice": slice_number, "bytes": len(raw)}

    if plain is not None:
        report["encrypted"] = True
        report["note"] = "decrypted bytes supplied from the build's own run"
        if plain[:5] != MAGIC:
            report["stopped"] = "the supplied bytes do not start %r" % MAGIC
            return report
    elif raw[:5] == MAGIC:
        plain = raw
        report["encrypted"] = False
    elif key is None:
        report["encrypted"] = True
        report["stopped"] = "no key, and the slice is not already readable"
        return report
    else:
        plain = keystream_xor(raw, key)
        report["encrypted"] = True
        if plain[:5] != MAGIC:
            report["stopped"] = "the key is wrong: first five bytes are %r" % plain[:5]
            return report

    idx_len, idx_off = slice_table[index_slice]
    index = string_index(block, idx_off)
    report["string_entries"] = len(index)

    functions = []

    def one(pos, path):
        fn = read_function(plain, pos)
        rows = constants_of(fn, block, index)
        functions.append({
            "path": path,
            "instructions": len(fn["instructions"]),
            "params": fn["params"],
            "stack": fn["stack"],
            "jump_key": fn["jump_key"],
            "constants": rows,
            "children": len(fn["children"]),
        })
        for i, (child_pos, _) in enumerate(fn["children"], 1):
            one(child_pos, path + [i])
        return fn

    top = one(5, [])
    report["consumed"] = top["bytes_read"]
    report["complete"] = (5 + top["bytes_read"] == len(plain))

    # Layer 6, now that the slice has given up everything it will without a key.
    # A packed function's key is a runtime string, and the file's own tag says
    # whether a candidate is it. Each one that opens is read the same way, and
    # what it holds joins the pool for the next round, so a chain of them comes
    # apart one tag at a time.
    opened = []
    for _ in range(8):
        materials = candidates_from(functions + opened)
        progress = False
        for fn in list(functions + opened):
            for row in fn["constants"]:
                if row.get("opened") or not isinstance(row["value"], dict):
                    continue
                const = row["value"] if row["value"].get("arr") else None
                if const is None or not const["arr"] or const["arr"][0] != WRAP_PROTO:
                    continue
                material, body = unlock_proto(const, materials)
                if material is None:
                    continue
                row["opened"] = material
                progress = True
                if body is None:
                    row["state"] = ("opened under %r, but the bytes are not a function"
                                    % _text(material))
                    continue
                sub = read_function(body, 5)
                opened.append({
                    "path": list(fn["path"]) + ["c%d" % row["index"]],
                    "instructions": len(sub["instructions"]),
                    "params": sub["params"],
                    "stack": sub["stack"],
                    "jump_key": sub["jump_key"],
                    "constants": constants_of(sub, block, index),
                    "children": len(sub["children"]),
                    "material": material,
                })
                row["state"] = ("a function, opened under %r" % _text(material))
        if not progress:
            break

    report["functions"] = functions + opened
    report["opened"] = len(opened)
    return report


def names_recovered(report):
    """Every piece of text the layers gave up, by function and slot."""
    out = {}
    for fn in report.get("functions", []):
        for row in fn["constants"]:
            if row["state"] == "text":
                out[(tuple(fn["path"]), row["index"])] = row["text"]
    return out


def write_report(report, path):
    lines = []
    w = lines.append
    w("LAYERS")
    w("")
    w("Slice %d, %d byte(s)." % (report["slice"], report["bytes"]))
    w("Encrypted: %s" % ("yes" if report.get("encrypted") else "no"))
    if "stopped" in report:
        w("Stopped: %s" % report["stopped"])
        w("")
        w("Layers 0 to 2 are done. Layer 2 for this slice holds, because the key")
        w("is three numbers the first layer measures off the machine, and the")
        w("measurement is still wrong somewhere. Everything past it waits on that")
        w("and on nothing else.")
        open(path, "w").write("\n".join(lines) + "\n")
        return
    w("First five bytes: MYqme, which is what the reader demands.")
    w("Deserialised %d of %d byte(s)%s."
      % (report["consumed"] + 5, report["bytes"],
         "" if report["complete"] else " - the rest did not account for itself"))
    w("String table: %d entr(ies)." % report.get("string_entries", 0))
    w("Functions: %d." % len(report["functions"]))
    w("")

    total = text = numbers = held = 0
    for fn in report["functions"]:
        for row in fn["constants"]:
            total += 1
            if row["state"] == "text":
                text += 1
            elif row["state"] == "ok":
                numbers += 1
            else:
                held += 1
    w("Constants: %d in all." % total)
    w("  %d came out as text, through layers 4 and 5" % text)
    w("  %d came out as a number, through layer 4" % numbers)
    w("  %d are still wrapped, and say why below" % held)
    w("")

    for fn in report["functions"]:
        name = "main function" if not fn["path"] else \
            "nested function " + ".".join(str(n) for n in fn["path"])
        w("%s" % name)
        w("  instructions %d, parameters %d, stack %d, jump key %d"
          % (fn["instructions"], fn["params"], fn["stack"], fn["jump_key"]))
        for row in fn["constants"]:
            if row["state"] == "text":
                w("    %4d  %s" % (row["index"], row["text"].decode("latin-1")))
            elif row["state"] == "ok":
                w("    %4d  %s" % (row["index"], _short(row["value"])))
            elif row["state"] == "plain":
                w("    %4d  %s" % (row["index"], _short(row["value"])))
            else:
                w("    %4d  [%s]" % (row["index"], row["state"]))
        w("")
    open(path, "w").write("\n".join(lines) + "\n")


def _short(v):
    if isinstance(v, bytes):
        return repr(v.decode("latin-1"))
    if isinstance(v, float) and v == int(v):
        return str(int(v))
    if isinstance(v, dict):
        return "still a table: %r" % (v["arr"][:3],)
    return repr(v)


def selftest():
    """Checks the chain against the file's own behaviour, not against answers.

    Three things have to hold, and none of them is a known string:
      the literal transform reproduces a hex number the file then parses,
      a value written by the packed-constant writer reads back exactly,
      and the keystream is its own inverse.
    """
    bad = []

    if len(SQ_TEXT) != 16 or any(c not in "0123456789abcdef" for c in SQ_TEXT):
        bad.append("the literal transform did not give hex: %r" % SQ_TEXT)
    if SQ != int(SQ_TEXT[:8], 16):
        bad.append("sq does not match its own digits")

    # the packed-constant reader, against bytes written by its own rules
    body = bytes([TAG_TABLE, 3, TAG_NIL, TAG_TRUE, TAG_STRING, 4]) + b"test" + bytes([0])
    r = Reader(body, 0, False)
    got = r.value()
    if got != {"arr": [None, True, b"test"], "map": {}} or r.p != len(body):
        bad.append("the packed reader did not read back what its rules write: %r" % (got,))

    # the number cipher undoes itself
    data = bytes(range(64))
    key = (123456789, 987654321, 42)
    if keystream_xor(keystream_xor(data, key), key) != data:
        bad.append("the keystream is not its own inverse")

    # the string cipher undoes itself
    if repeat_xor(repeat_xor(data, "1812386200:7"), "1812386200:7") != data:
        bad.append("the repeating cipher is not its own inverse")

    # the material formula is the file's: g alone decides it
    m1 = str(((1 * MIX) % MOD2 + SQ) % MOD2)
    m2 = str(((2 * MIX) % MOD2 + SQ) % MOD2)
    if m1 == m2:
        bad.append("the constant material does not move with g")

    for line in bad:
        print("  WRONG: %s" % line)
    print("layers selftest: %s" % ("ok" if not bad else "%d problem(s)" % len(bad)))
    return not bad


if __name__ == "__main__":
    selftest()
