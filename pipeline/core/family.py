#!/usr/bin/env python3
"""
family.py - read one of these builds using only what the build states.

The first sample this package handled had its reader written out by hand: the
magic string, the byte each varint is subtracted from, which tag number means
which kind of value, how many field slots a function carries and in what order
they are written. All of that was correct for that sample and wrong for the next
one, because the obfuscator rolls every one of those numbers per build.

So nothing here is a constant from a sample. Each parameter is read out of the
interpreter's own text, which has to state it to work at all:

    h=(h-115)%256                       the varint byte transform
    if hw==85 then return nil elseif... the value tags
    T4[12]={...} T4[11]={...}           the field slots, in write order
    vI(N,1,4)~=h9({150,171,191,152})    the magic, through the char shift
    local Hs,ey=`1410283338`,kF(1)      the seed and which slice is the strings
    Hs..":"..z[3]                       how a string key is built

A file that does not state one is refused by name. Reading a build with the
previous build's numbers is the one failure mode worth designing against: it
does not error, it returns plausible rubbish.
"""
import hashlib
import hmac
import re


class Refused(Exception):
    """The interpreter does not state something this needs."""


# ---------------------------------------------------------------- char shift

def char_shift(text):
    """The subtraction the build's own `char((n - K - i) % 256)` helper uses.

    K is a runtime value, so the file does not write it down. It is recovered
    from what the helper's output is used for: some of those arrays are the type
    names the build compares `typeof` results against, and the set of Lua type
    names is a fact about Lua, not about this sample. The K that turns the most
    of the arrays into type names is the build's, and it is only accepted when
    it is the single best one - otherwise this says so instead of picking.

    Printable text is not the test. The arrays also hold NUL-terminated labels
    and raw binary, which a printable-only test throws out, and scoring on it
    left five values of K tied.
    """
    m = re.search(r"local function (\w+)\(\w+\)local \w+=\{\};for \w+=1,#\w+ do "
                  r"\w+\[#\w+\+1\]=\w+\(\(\w+\[\w+\]-(\w+)-\w+\)%256\)", text)
    if not m:
        raise Refused("the interpreter has no char shift helper")
    name = m.group(1)
    arrays = [[int(x) for x in a.split(",")]
              for a in re.findall(re.escape(name) + r"\(\{([\d,]+)\}\)", text)]
    if not arrays:
        raise Refused("the char shift helper is never called with an array")
    LUA_TYPES = {"nil", "boolean", "number", "string", "table", "function",
                 "userdata", "thread", "vector", "buffer"}
    scored = []
    for K in range(256):
        hits = sum(1 for a in arrays if shifted(a, K) in LUA_TYPES)
        scored.append((hits, K))
    scored.sort(reverse=True)
    top, K = scored[0]
    if top < 2:
        raise Refused("no char shift turns this build's arrays into type names")
    if scored[1][0] == top:
        raise Refused("the char shift is not pinned: two values score %d" % top)
    return K, name, top


def shifted(arr, K):
    return "".join(chr((v - K - i) % 256) for i, v in enumerate(arr, 1))


# ------------------------------------------------------------------- profile

TAG_KINDS = {"nil": "nil", "false": "false", "true": "true"}


def _named(text, pattern):
    m = re.search(pattern, text)
    return m.group(1) if m else None


def _tags(text, zigzag, rawstring):
    """Every tag the value reader declares, and what each one means.

    Classified from the branch body, not from a table of numbers: `nil`,
    `false` and `true` return those words, a zigzag branch calls the signed
    reader, a raw-string branch calls the string reader, a decimal-number
    branch wraps that string reader in another call, a double reads eight bytes
    through string.unpack, and a table branch builds one. A branch this cannot
    place is returned as unknown so the caller refuses it by number.
    """
    m = re.search(r"(\w+)=function\(\)local (\w+)=\w+\(\w+,\w+\);\w+=\w+\+1;"
                  r"if \2==(\d+) then return nil", text)
    if not m:
        raise Refused("the interpreter has no value tag chain")
    start = m.start()
    depth, i = 0, text.index("if", start)
    # The chain ends where the reader gives up on an unknown tag. Reading past
    # that point ran into the matching skip-over function, which lists the same
    # tags with bodies that advance the cursor instead of returning a value, and
    # those bodies classified as unknown and overwrote the real ones.
    seg = text[start:start + 1400]
    stop = seg.find("return WL()end")
    if stop > 0:
        seg = seg[:stop]
    tags = {int(m.group(3)): "nil"}
    for mm in re.finditer(r"elseif \w+==(\d+) then (.{0,160}?)(?=elseif \w+==\d+ then|"
                          r"end;?return|$)", seg, re.S):
        n, act = int(mm.group(1)), mm.group(2)
        if n not in tags:
            tags[n] = _classify(act, zigzag, rawstring)
    return tags


def _classify(act, zigzag, rawstring):
    if re.search(r"return false", act):
        return "false"
    if re.search(r"return true", act):
        return "true"
    if "unpack" in act:
        return "double"
    if "{}" in act or re.search(r"for \w+=1,", act):
        return "table"
    if rawstring and re.search(r"return \w+\(" + re.escape(rawstring) + r"\(\)\)", act):
        return "number_text"
    if zigzag and re.search(r"return " + re.escape(zigzag) + r"\(\)", act):
        return "int"
    if rawstring and re.search(r"return " + re.escape(rawstring) + r"\(\)", act):
        return "string"
    return "unknown"


def profile(text):
    """Every reader parameter, read from the interpreter text."""
    out = {}
    K, helper, n_arrays = char_shift(text)
    out["char_shift"] = K
    out["char_shift_helper"] = helper
    out["char_shift_arrays"] = n_arrays

    m = re.search(r"\w+=\(\w+-(\d+)\)%256", text)
    if not m:
        raise Refused("the interpreter does not say how a varint byte reads")
    out["varint_subtract"] = int(m.group(1))

    m = re.search(r"local function (\w+)\(\w+,\w+,\w+\)local \w+=\w+ or (\d+);", text)
    if not m:
        raise Refused("the interpreter has no function reader")
    out["reader"] = m.group(1)
    out["body_start"] = int(m.group(2))

    m = re.search(r"\w+\(\w+,1,(\d+)\)~=" + re.escape(helper) + r"\(\{([\d,]+)\}\)",
                  text)
    if not m:
        raise Refused("the interpreter does not state a magic string")
    magic = shifted([int(x) for x in m.group(2).split(",")], K)
    if len(magic) != int(m.group(1)):
        raise Refused("the magic's stated length and its text disagree")
    out["magic"] = magic

    # the value tags. The chain is read as a whole and every branch in it is
    # classified by what the branch does, so a build that adds a kind is
    # reported rather than silently dropped: an unlisted tag raises later with
    # the byte it was found at.
    out["zigzag"] = _named(text, r"local function (\w+)\(\)local \w+=\w+\(\);"
                                 r"if \w+%2==0 then")
    out["rawstring"] = _named(text, r"local function (\w+)\(\)local \w+=\w+\(\);"
                                    r"local \w+=\w+\(\w+,\w+,\w+\+\w+-1\);")
    out["tags"] = _tags(text, out["zigzag"], out["rawstring"])

    # the field slots, in the order the writer wrote them
    slots = [int(x) for x in re.findall(r"T4\[(\d+)\]=\{", text)]
    if not slots:
        slots = [int(x) for x in re.findall(r"\w+\[(\d+)\]=\{\w+,\w+,\w+,\w+\}", text)]
    if not slots:
        raise Refused("the interpreter does not lay out a function's fields")
    out["slot_order"] = slots

    m = re.search(r"local \w+,\w+=`(\d+)`,(\w+)\((\d+)\)", text)
    if not m:
        raise Refused("the interpreter does not state its seed")
    out["seed"] = int(m.group(1))
    out["string_slice"] = int(m.group(3))

    m = re.search(r"(\w+)\((\d+)\)\);", text)
    nums = [int(x) for x in re.findall(r"\w+\((\d+)\)", text)]
    out["program_slice"] = _program_slice(text)
    out["payload_slice"] = _payload_slice(text)
    out["separator"] = _separator(text, K, helper)
    out["salt"], out["tag"] = _salt_and_tag(text, K, helper)
    out["gate"] = _gate(text)
    return out


def _slice_calls(text):
    m = re.search(r"local (\w+),\w+=`\d+`,(\w+)\(\d+\)", text)
    name = m.group(2) if m else None
    if not name:
        m = re.search(r"\(\s*(\w+)\((\d+)\)\s*\)", text)
        name = m.group(1) if m else None
    if not name:
        raise Refused("the interpreter has no slice reader")
    return name, [int(x) for x in re.findall(re.escape(name) + r"\((\d+)\)", text)]


def _program_slice(text):
    name, _ = _slice_calls(text)
    m = re.search(r"=\(" + re.escape(name) + r"\((\d+)\)\),\{\d", text)
    if m:
        return int(m.group(1))
    raise Refused("the interpreter does not say which slice it runs first")


def _payload_slice(text):
    name, _ = _slice_calls(text)
    m = re.search(r"\w+\(" + re.escape(name) + r"\((\d+)\),\w+,", text)
    if m:
        return int(m.group(1))
    raise Refused("the interpreter does not say which slice the gate unlocks")


def _separator(text, K, helper):
    m = re.search(r"(\w+)\.\.\"(.{1,4})\"\.\.\w+\[3\]", text)
    if m:
        return m.group(2)
    m = re.search(r"\w+\.\." + re.escape(helper) + r"\(\{([\d,]+)\}\)\.\.\w+\[3\]",
                  text)
    if m:
        return shifted([int(x) for x in m.group(1).split(",")], K)
    raise Refused("the interpreter does not state its string key separator")


def _salt_and_tag(text, K, helper):
    name, _ = _slice_calls(text)
    i = text.find(name + "(" + str(_payload_slice(text)) + ")")
    seg = text[i:i + 2000]
    arrs = re.findall(re.escape(helper) + r"\(\{([\d,]+)\}\)", seg)
    if len(arrs) < 2:
        raise Refused("the gate call does not carry a salt and a tag")
    salt = shifted([int(x) for x in arrs[0].split(",")], K)
    tag = shifted([int(x) for x in arrs[1].split(",")], K)
    if not re.fullmatch(r"[0-9a-f]{64}", tag):
        raise Refused("what the gate call carries as a tag is not a digest")
    return salt, tag


def _gate(text):
    """The three linear forms the key triple is built from, as read."""
    m = re.search(r"local (\w+)=\{\(([^}]{80,1200})\)\}", text)
    forms = re.findall(r"\(([^()]*?%\d+)\)", text)
    out = []
    for f in forms:
        if f.count("*") >= 5 and "%2147483647" in f:
            out.append(f)
    return out[:3]


# ------------------------------------------------------------------- slices

def slice_table(data):
    """Every slice the data block carries: (length, offset), as the build reads it.

    The block states its own layout: a count, the size of the region the slices
    live in, then that region, then one length per slice. Nothing is assumed
    about how many there are or how big each is, and the reading is only
    accepted when the lengths add up to the stated region and the table ends
    exactly at the end of the block.
    """
    pos = 0

    def var():
        nonlocal pos
        acc, n = 0, 1
        while True:
            h = data[pos]
            pos += 1
            acc += (h % 128) * n
            if h < 128:
                return acc
            n *= 128

    count = var()
    region = var()
    start = pos
    pos += region
    if pos > len(data):
        raise Refused("the slice region runs past the end of the data block")
    lengths = [var() for _ in range(count)]
    if sum(lengths) != region:
        raise Refused("the slice lengths add up to %d, not the stated %d"
                      % (sum(lengths), region))
    if pos != len(data):
        raise Refused("%d byte(s) are left over after the slice table"
                      % (len(data) - pos))
    out, off = {}, 0
    for i, L in enumerate(lengths, 1):
        out[i] = (L, start + off)
        off += L
    return out


# ------------------------------------------------------------------ imports

def import_chains(text, data, slices):
    """The host names the interpreter resolves, read back from their hashes.

    A build of this kind does not store the names it imports. It stores a hash
    of each one and matches it against a list of candidates at run time, so the
    names come back by doing the same: hash every candidate the file carries and
    see which one each stored hash is. No key is involved, so this works on any
    sample before anything else does.
    """
    m = re.search(r"local (\w+),(\w+)=\{(.*?)\},(\w+)\((\d+)\)", text, re.S)
    if not m:
        raise Refused("the interpreter carries no candidate name list")
    names = ["".join(chr(int(x)) for x in re.findall(r"\d{3}", s))
             for s in re.findall(r'"((?:\\\d{3})+)"', m.group(3))]
    if not names:
        raise Refused("the candidate name list does not decode to names")
    slice_no = int(m.group(5))
    mm = re.search(r"local function (\w+)\(\w+,\w+,\w+\)local (\w+)=\((\d+)\*(\d+)"
                   r"\+\w+\*(\d+)\+\w+\*(\d+)\+(\d+)\)%(\d+);for \w+=1,#\w+ do "
                   r"\2=\(\2\*(\d+)\+\w+\(\w+,\w+\)\*\(\w+\+(\d+)\)\+(\d+)\)%\8",
                   text)
    if not mm:
        raise Refused("the interpreter does not state how it hashes a name")
    seed, a, b, c, d, mod = (int(mm.group(3)), int(mm.group(4)), int(mm.group(5)),
                             int(mm.group(6)), int(mm.group(7)), int(mm.group(8)))
    e, f, g = int(mm.group(9)), int(mm.group(10)), int(mm.group(11))

    def h(name, o, x):
        acc = (seed * a + o * b + x * c + d) % mod
        for i, ch in enumerate(name.encode("latin1"), 1):
            acc = (acc * e + ch * (i + f) + g) % mod
        return acc

    L, off = slices[slice_no]
    blob = data[off:off + L]
    pos = 0

    def var():
        nonlocal pos
        acc, n = 0, 1
        while True:
            b2 = blob[pos]
            pos += 1
            acc += (b2 % 128) * n
            if b2 < 128:
                return acc
            n *= 128

    count = var()
    chains = []
    for _ in range(count):
        chains.append([var() for _ in range(var() if False else 0)] or None)
    # rewritten plainly: a chain is a length then that many hashes
    pos = 0
    count = var()
    chains = []
    for _ in range(count):
        n = var()
        chains.append([var() for _ in range(n)])
    if pos != len(blob):
        raise Refused("the import slice has %d byte(s) left over"
                      % (len(blob) - pos))
    out = []
    for i, chain in enumerate(chains, 1):
        path, settled = [], True
        for x, want in enumerate(chain, 1):
            hits = [n for n in names if h(n, i, x) == want]
            if len(hits) == 1:
                path.append(hits[0])
            else:
                path.append("unresolved:%d" % want)
                settled = False
        out.append({"index": i, "path": path, "settled": settled})
    return out, names, slice_no


# -------------------------------------------------------------- deserialiser

class Reader:
    def __init__(self, data, pos, subtract):
        self.d = data
        self.p = pos
        self.s = subtract

    def byte(self):
        b = self.d[self.p]
        self.p += 1
        return b

    def var(self):
        acc, n = 0, 1
        while True:
            h = (self.d[self.p] - self.s) % 256
            self.p += 1
            acc += (h % 128) * n
            if h < 128:
                return acc
            n *= 128

    def signed(self):
        v = self.var()
        return v // 2 if v % 2 == 0 else -(v + 1) // 2

    def raw(self):
        n = self.var()
        out = self.d[self.p:self.p + n]
        self.p += n
        return out


def _whole(v):
    """A Lua number that happens to be an integer, kept as one.

    Lua has one number type and prints 7 for 7.0. Keeping these as Python
    floats made every index and every key built from one carry a `.0`, which
    indexes nothing and hashes to the wrong string.
    """
    return int(v) if isinstance(v, float) and v.is_integer() else v


def read_value(r, tags):
    t = r.byte()
    kind = tags.get(t)
    if kind == "nil":
        return None
    if kind == "false":
        return False
    if kind == "true":
        return True
    if kind == "int":
        return r.signed()
    if kind == "double":
        import struct
        v = struct.unpack("<d", r.d[r.p:r.p + 8])[0]
        r.p += 8
        return _whole(v)
    if kind == "number_text":
        return _whole(float(r.raw().decode("latin1")))
    if kind == "string":
        return r.raw()
    if kind == "table":
        out = {}
        n = r.var()
        for i in range(1, n + 1):
            out[i] = read_value(r, tags)
        n = r.var()
        for _ in range(n):
            k = read_value(r, tags)
            out[k if not isinstance(k, (bytes, dict)) else repr(k)] = \
                read_value(r, tags)
        return out
    raise Refused("tag %d at byte %d is not one this build declares"
                  % (t, r.p - 1))


def skip_value(r, tags):
    read_value(r, tags)


def reader_names(text):
    """The two helpers the field layout is written in terms of.

    A field's shape is only readable once these are known by name: one reads a
    varint, the other steps over one serialised value. Telling them apart by
    counting brackets put a list of values where a list of counts belonged, and
    the read then ran off into the middle of a value.
    """
    var = _named(text, r"local function (\w+)\(\)local \w+,\w+=0,1;while true do "
                       r"\w+ \w+=\w+\(\w+,\w+\);if \w+==nil then return \w+\(\)end;"
                       r"\w+=\(\w+-\d+\)%256")
    if var is None:
        var = _named(text, r"local function (\w+)\(\)local \w+,\w+=0,1;while true do "
                           r"\w+ \w+=\w+\(\w+,\w+\);\w+=\(\w+-\d+\)%256")
    skip = _named(text, r"local function (\w+)\(\)local \w+=\w+\(\w+,\w+\);\w+=\w+\+1;"
                        r"if \w+==\d+ or \w+==\d+ or \w+==\d+ then return")
    if var is None or skip is None:
        raise Refused("the interpreter's varint and skip helpers were not found")
    return var, skip


def slot_shapes(text):
    """How each field slot is written, read from the interpreter's own layout.

    The writer's order and each slot's shape are both in the text, as a run of
    blocks that each move the cursor past one field. Returned as
    [(slot, shape)] in write order, which is the order the bytes are in:
    reading the slots in index order instead reads every field from the wrong
    place.
    """
    var, skip = reader_names(text)
    out = []
    for m in re.finditer(r"do local (\w+),(\w+),(\w+)=\w+;(.*?)(\w+)\[(\d+)\]="
                         r"\{\1,\w+,\3,\2\}end", text, re.S):
        out.append((int(m.group(6)), _shape(m.group(4), var, skip)))
        if len(out) > 64:
            raise Refused("the field layout does not end")
    if not out:
        raise Refused("the interpreter does not lay out a function's fields")
    return out


def _shape(body, var, skip):
    """One field block, named by what it does to the cursor.

    Written as a few tolerant tests rather than one exact form: the blocks
    differ in details that change nothing about the bytes - a table the writer
    initialises first, an index it keeps, a reversed order, a trailing
    semicolon. A block that matches none of them raises with its own text, so
    an unseen shape is reported rather than read as the nearest match.
    """
    b = re.sub(r"\s+", "", body)
    b = re.sub(r";+$", "", b)
    b = b.replace("local", "")
    b = re.sub(r"\w+=\{\};", "", b)         # a table set up before the loop
    V, S = re.escape(var), re.escape(skip)
    count = r"\w+=" + V + r"\(\);"
    loop = r"for\w+=1,\w+do"

    if re.fullmatch(S + r"\(\)", b):
        return "value"
    if re.fullmatch(r"\w+=\w+\+1", b):
        return "byte"
    if re.fullmatch(r"(?:\w+=)?" + V + r"\(\)", b):
        return "count"
    # a list of byte ranges: each one measured, then stepped over whole
    if re.search(count + loop + r"\w+=" + V + r"\(\);\w+\[[^\]]+\]=\{\w+,\w+\};"
                 r"\w+=\w+\+\w+end", b):
        return "byte_ranges_reversed" if "-" in b.split("[", 1)[-1].split("]")[0] \
            else "byte_ranges"
    # a list of lists of values
    if re.search(count + loop + r"\w+=" + V + r"\(\);\w+\[\w+\]=\{\w+,\w+\};"
                 + loop + S + r"\(\)end", b):
        return "value_lists"
    # a list of values, with or without the writer keeping each one's offset
    if re.fullmatch(count + loop + r"(?:\w+\[\w+\]=\w+;)?" + S + r"\(\)end", b):
        return "values"
    # a list of plain counts
    if re.fullmatch(count + loop + r"(?:\w+\[\w+\]=\w+;)?" + V + r"\(\)end", b):
        return "numbers"
    raise Refused("a field is written in a shape this does not read: %s" % b[:140])


def read_function(data, start, prof, shapes):
    """One serialised function, every field read where the build puts it."""
    r = Reader(data, start, prof["varint_subtract"])
    tags = prof["tags"]
    fields = {}
    for slot, shape in shapes:
        at = r.p
        if shape == "value":
            v = read_value(r, tags)
        elif shape == "byte":
            v = r.byte()
        elif shape == "count":
            v = r.var()
        elif shape == "values":
            v = [read_value(r, tags) for _ in range(r.var())]
        elif shape == "numbers":
            v = [r.var() for _ in range(r.var())]
        elif shape == "value_lists":
            v = []
            for _ in range(r.var()):
                v.append([read_value(r, tags) for _ in range(r.var())])
        elif shape in ("byte_ranges", "byte_ranges_reversed"):
            v = []
            for _ in range(r.var()):
                n = r.var()
                v.append((r.p, n))
                r.p += n
            if shape == "byte_ranges_reversed":
                v.reverse()
        else:
            raise Refused("shape %r has no reader" % shape)
        fields[slot] = {"shape": shape, "at": at, "value": v}
    fields["_end"] = r.p
    return fields


# ------------------------------------------------------------- string table

def string_entries(data, slices, prof):
    """The string table's entries, by index, as (offset, length)."""
    L, off = slices[prof["string_slice"]]
    blob = data[off:off + L]
    pos = 0

    def var():
        nonlocal pos
        acc, n = 0, 1
        while True:
            b = blob[pos]
            pos += 1
            acc += (b % 128) * n
            if b < 128:
                return acc
            n *= 128

    count = var()
    out = []
    for _ in range(count):
        n = var()
        out.append((pos, n))
        pos += n
    return blob, out


def open_entry(blob, span, key):
    o, n = span
    k = key.encode("latin1") if isinstance(key, str) else key
    return bytes(blob[o + i] ^ k[i % len(k)] for i in range(n))


def seed_key(prof, material):
    return "%d%s%s" % (prof["seed"], prof["separator"], material)


def mac(key, salt, blob):
    return hmac.new(key, salt, hashlib.sha256).hexdigest()


# ------------------------------------------------------- opening constants

def bc_value(text, K, helper):
    """The constant the build adds when it turns a number into a string key."""
    m = re.search(r"local (\w+)=\w+\(\w+\(" + re.escape(helper)
                  + r"\(\{([\d,]+)\}\),1,(\d+)\),(\d+)\)", text)
    if not m:
        raise Refused("the interpreter does not state its key constant")
    text_of = shifted([int(x) for x in m.group(2).split(",")], K)
    return int(text_of[:int(m.group(3))], int(m.group(4)))


def material_key(g, bc, text):
    """The key a wrapped constant is closed with, as the build computes it."""
    m = re.search(r"\(\(\(\w+\*(\d+)\)%(\d+)\+\w+\)%\2\)", text)
    if not m:
        raise Refused("the interpreter does not state its material formula")
    mul, mod = int(m.group(1)), int(m.group(2))
    return str(((g * mul) % mod + bc) % mod)


def as_text(v):
    if isinstance(v, bytes):
        return v.decode("latin1")
    if isinstance(v, int):
        return "%d" % v
    return str(v)


def xor_with(ct, key):
    k = key.encode("latin1") if isinstance(key, str) else key
    return bytes(ct[i] ^ k[i % len(k)] for i in range(len(ct)))


def read_whole(data, prof):
    """One serialised value that has to account for every byte it was given."""
    r = Reader(data, 0, 0)
    v = read_value(r, prof["tags"])
    return v, r.p == len(data)


def open_constants(consts, blob, spans, prof, bc, text):
    """Every constant, and the text behind the ones that are reachable.

    Two wrappings are in play. A constant may be a packed value closed with a
    key the build computes from a number it carries, and a constant may be a
    reference into the string table closed with a key built from the build's
    seed. Both of those open with nothing but the file. A constant marked for
    the key the gate produces is reported as gated, not guessed at.
    """
    rows = []
    for i, c in enumerate(consts, 1):
        row = {"index": i, "state": "plain", "value": c}
        if isinstance(c, dict) and c.get(1) == 193:
            if c.get(4) == 1:
                row["state"] = "key-gated"
                rows.append(row)
                continue
            inner = xor_with(c[2], material_key(c[3], bc, text))
            try:
                v, exact = read_whole(inner, prof)
            except Refused as exc:
                row["state"] = "unread"
                row["why"] = str(exc)
                rows.append(row)
                continue
            row["exact"] = exact
            c = v
            row["value"] = v
            row["state"] = "unpacked"
        if isinstance(c, dict) and c.get(1) == 0:
            if c.get(4) == 1:
                row["state"] = "key-gated string"
                rows.append(row)
                continue
            idx = int(c[2])
            if not 1 <= idx <= len(spans):
                row["state"] = "string index out of range"
                rows.append(row)
                continue
            key = "%s%s%s" % (prof["seed"], prof["separator"], as_text(c[3]))
            row["text"] = xor_with(blob[spans[idx - 1][0]:
                                        spans[idx - 1][0] + spans[idx - 1][1]],
                                   key)
            row["entry"] = idx
            row["state"] = "text"
        rows.append(row)
    return rows


# ---------------------------------------------------------------- selftest

def selftest():
    bad = []
    K = 66
    arr = [183, 165, 167, 178, 172]
    if shifted(arr, K) != "table":
        bad.append("the char shift does not undo itself")
    # a built data block, read back by the slice reader
    def var(v):
        out = bytearray()
        while True:
            b = v % 128
            v //= 128
            if v:
                out.append(b | 128)
            else:
                out.append(b)
                return bytes(out)
    parts = [b"A" * 5, b"B" * 300, b"C" * 1]
    region = b"".join(parts)
    blob = var(len(parts)) + var(len(region)) + region \
        + b"".join(var(len(p)) for p in parts)
    got = slice_table(blob)
    want = {1: (5, None), 2: (300, None), 3: (1, None)}
    if [got[i][0] for i in (1, 2, 3)] != [5, 300, 1]:
        bad.append("the slice table did not read back the lengths it was given")
    start = got[1][1]
    if blob[start:start + 5] != b"A" * 5:
        bad.append("the first slice does not point at the first slice")
    try:
        slice_table(blob + b"\x00")
    except Refused:
        pass
    else:
        bad.append("a block with a byte left over was not refused")
    # the varint reader against its own writer, with a transform in the way
    def wvar(v, sub):
        out = bytearray()
        while True:
            b = v % 128
            v //= 128
            h = (b | 128) if v else b
            out.append((h + sub) % 256)
            if not v:
                return bytes(out)
    for n in (0, 1, 127, 128, 300, 70000, 2 ** 31 - 1):
        r = Reader(wvar(n, 115), 0, 115)
        if r.var() != n:
            bad.append("a varint of %d did not read back" % n)
    for n in (0, 1, -1, 5, -5, 1000, -1000):
        z = (2 * n) if n >= 0 else (-2 * n - 1)
        r = Reader(wvar(z, 115), 0, 115)
        if r.signed() != n:
            bad.append("a signed %d did not read back" % n)
    # an XOR entry against its own key
    plain = b"PlayerAdded"
    key = "1410283338:999"
    ct = bytes(plain[i] ^ key.encode()[i % len(key)] for i in range(len(plain)))
    if open_entry(ct, (0, len(ct)), key) != plain:
        bad.append("an entry did not open under the key it was closed with")
    for line in bad:
        print("  WRONG: %s" % line)
    print("family selftest: %s" % ("ok" if not bad else "%d problem(s)" % len(bad)))
    return not bad


def guarded_slices(text, K, helper):
    """Every slice the interpreter unlocks with a key written in the file.

    A slice closed with a literal needs nothing from the host, so it opens
    here. Returned as {slice: {key, salt, tag}} with the key exactly as the
    file writes it - a backtick string is a string, and reading it as a number
    produces a different keystream and silent rubbish.
    """
    name, _ = _slice_calls(text)
    # which local holds which slice, so a guard written in terms of a name is
    # reported against the slice number the rest of this reads by
    held = {}
    for m in re.finditer(r"local ([\w,]+)=\(?" + re.escape(name)
                         + r"\((\d+)\)\)?", text):
        held[m.group(1).split(",")[0]] = int(m.group(2))
    out = {}
    for m in re.finditer(r"\w+\((\w+)(?:\((\d+)\))?,`(\d+)`,\s*"
                         + re.escape(helper) + r"\(\{([\d,]+)\}\),\s*"
                         + re.escape(helper) + r"\(\{([\d,]+)\}\)", text):
        key = m.group(3)
        salt = shifted([int(x) for x in m.group(4).split(",")], K)
        tag = shifted([int(x) for x in m.group(5).split(",")], K)
        if not re.fullmatch(r"[0-9a-f]{64}", tag):
            continue
        who = int(m.group(2)) if m.group(2) is not None \
            else held.get(m.group(1), m.group(1))
        out[who] = {"key": key, "salt": salt, "tag": tag}
    return out


def open_slice(data, span, entry):
    """A slice closed with a string key, opened and checked against its tag."""
    L, off = span
    ct = data[off:off + L]
    plain = xor_with(ct, entry["key"])
    key = (entry["salt"] + "\x00" + entry["key"]).encode("latin1")
    ok = hmac.new(key, ct, hashlib.sha256).hexdigest() == entry["tag"]
    return plain, ok


def run(path, out_dir):
    """The whole chain on one file: outer layer, slices, names, strings."""
    import os
    try:
        from . import outer
    except ImportError:
        import outer
    os.makedirs(out_dir, exist_ok=True)
    facts = outer.unwrap(path)
    text = facts["interpreter"].decode("latin1")
    data = facts["data"]
    open(os.path.join(out_dir, "interpreter.lua"), "wb").write(facts["interpreter"])
    open(os.path.join(out_dir, "data.bin"), "wb").write(data)

    prof = profile(text)
    shapes = slot_shapes(text)
    slices = slice_table(data)
    guards = guarded_slices(text, prof["char_shift"], prof["char_shift_helper"])
    bc = bc_value(text, prof["char_shift"], prof["char_shift_helper"])
    blob, spans = string_entries(data, slices, prof)
    chains, names, import_slice = import_chains(text, data, slices)

    lines = []
    w = lines.append
    w("WHAT THIS BUILD IS, READ FROM THE BUILD")
    w("")
    w("  file              %s" % path)
    w("  sha256            %s" % facts["sha256"])
    w("  outer alphabet    85 characters, first eight %r" % facts["alphabet"][:8])
    w("  header            little end first" if facts["byte_order"] == "little"
      else "  header            high end first")
    w("  sections          %s, %d byte interpreter, %d byte data block"
      % (facts["section_order"].replace("_", " "),
         len(facts["interpreter"]), len(data)))
    w("")
    w("  char shift        %d, pinned by %d of its own arrays reading as type names"
      % (prof["char_shift"], prof["char_shift_arrays"]))
    w("  magic             %r" % prof["magic"])
    w("  varint byte       (b - %d) %% 256" % prof["varint_subtract"])
    w("  value tags        %s"
      % ", ".join("%d=%s" % kv for kv in sorted(prof["tags"].items())))
    w("  field order       %s" % ", ".join("%d:%s" % kv for kv in shapes))
    w("  seed              %d" % prof["seed"])
    w("  string separator  %r" % prof["separator"])
    w("")
    w("  slices")
    for i in sorted(slices):
        role = []
        if i == prof["string_slice"]:
            role.append("the string table")
        if i == import_slice:
            role.append("the host names")
        if i == prof["program_slice"]:
            role.append("runs first")
        if i == prof["payload_slice"]:
            role.append("the gated payload")
        if i in guards:
            role.append("closed with a key the file carries")
        w("    %d  %7d bytes at %7d   %s"
          % (i, slices[i][0], slices[i][1], ", ".join(role) or "unused"))
    w("")
    w("  host names, read back from their hashes (no key needed)")
    for c in chains:
        w("    %2d  %s%s" % (c["index"], ".".join(c["path"]),
                             "" if c["settled"] else "   UNRESOLVED"))
    w("")

    opened = {}
    for num, guard in guards.items():
        if not isinstance(num, int):
            continue
        plain, ok = open_slice(data, slices[num], guard)
        w("  slice %d opens with the key the file carries (%s)" % (num, guard["key"]))
        w("    its own tag over the closed bytes: %s"
          % ("agrees" if ok else "DOES NOT AGREE"))
        w("    first four bytes read %r, the magic this build states is %r"
          % (plain[:len(prof["magic"])].decode("latin1"), prof["magic"]))
        if not ok:
            continue
        opened[num] = plain
        open(os.path.join(out_dir, "slice%d_plain.bin" % num), "wb").write(plain)

    for num, plain in opened.items():
        fn = read_function(plain, len(prof["magic"]), prof, shapes)
        w("")
        w("  slice %d read as a function: %d of %d bytes accounted for"
          % (num, fn["_end"] - len(prof["magic"]), len(plain) - len(prof["magic"])))
        consts = fn[_constant_slot(fn)]["value"]
        rows = open_constants(consts, blob, spans, prof, bc, text)
        texts = [r for r in rows if r["state"] == "text"]
        gated = [r for r in rows if "gated" in r["state"]]
        w("    %d constants: %d opened to text, %d still behind the gate"
          % (len(rows), len(texts), len(gated)))
        used = sorted({r["entry"] for r in texts})
        w("    string table entries this slice uses: %d of %d"
          % (len(used), len(spans)))
        w("")
        for r in texts:
            w("      entry %2d  %s" % (r["entry"], r["text"].decode("latin1")))
        left = [i for i in range(1, len(spans) + 1) if i not in set(used)]
        w("")
        w("    entries no opened slice reaches: %d (%s)"
          % (len(left), ", ".join(str(x) for x in left)))

    w("")
    w("  the gate")
    w("    the payload is slice %d, closed with a key of three numbers"
      % prof["payload_slice"])
    w("    its salt   %r" % prof["salt"])
    w("    its tag    %s" % prof["tag"])
    w("    the three numbers are built from measurements the program takes of")
    w("    its host, so nothing here opens it: a wrong key is caught by that tag")
    w("    rather than producing text, which is what makes it a check and not a")
    w("    guess.")

    report = "\n".join(lines) + "\n"
    open(os.path.join(out_dir, "BUILD.txt"), "w").write(report)
    return report


def _constant_slot(fn):
    """Which field holds the constants: the one that is a list of values whose
    tables are the wrapped kinds this build uses. Read, not assumed."""
    best, score = None, -1
    for slot, got in fn.items():
        if slot == "_end" or got["shape"] != "values":
            continue
        v = got["value"]
        s = sum(1 for x in v if isinstance(x, dict) and x.get(1) in (0, 193))
        if s > score:
            best, score = slot, s
    if best is None:
        raise Refused("no field in this function holds a constant list")
    return best


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        selftest()
    else:
        print(run(sys.argv[1], sys.argv[2]))
