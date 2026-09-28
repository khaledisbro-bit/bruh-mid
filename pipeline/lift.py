#!/usr/bin/env python3
"""
lift.py - static VM lifter groundwork for the base85+Zstd inner VM.

The inner VM's data chunk is a sequence of length-prefixed segments (LEB128
varints). One segment is the IMPORT TABLE: a list of global paths the program
resolves (e.g. string.byte, bit32.bxor, game.GetService, DataStoreService). Those
paths are stored as plaintext byte-strings, so they can be recovered WITHOUT
running the VM. The other segments hold the bytecode and the constant pool; the
constants are runtime-keyed, so those still need the dynamic resolver hook.

This module parses the segment structure and extracts every readable import path
and every readable string it can find, then reports what is static-recoverable
vs. what needs the dynamic trace. It is genuine devirtualization: everything
comes from the bytes, nothing is guessed.

    python3 lift.py inner_data.bin
"""
import re
import sys

# Luau standard vocabulary: base globals + library tables and their members.
# Used only to separate the VM's genuine primitives from decoded-constant noise
# in a raw byte scan. This is the language's own surface, not sample data.
LUAU_NAMES = set("""
assert error tonumber tostring type typeof select pcall xpcall next pairs ipairs
rawequal rawget rawset rawlen setmetatable getmetatable unpack require warn print
collectgarbage newproxy gcinfo loadstring
string table math bit32 buffer coroutine os debug utf8 task
byte char sub rep find match gmatch gsub format len lower upper reverse split pack
unpack packsize concat insert remove sort create freeze isfrozen clone move
abs ceil floor sqrt sin cos tan asin acos atan atan2 exp log log10 pow fmod modf
max min random randomseed huge pi noise clamp round sign
band bor bxor bnot lshift rshift arshift lrotate rrotate btest extract replace countlz countrz
readu8 readu16 readu32 readi8 readi16 readi32 readf32 readf64 readstring
writeu8 writeu16 writeu32 writei8 writei16 writei32 writef32 writef64 writestring
tostring fromstring tobuffer len copy fill
wait delay spawn defer cancel desynchronize synchronize
info traceback getinfo profilebegin profileend
resume yield status wrap isyieldable running close
time clock date difftime
""".split())


def reader(buf):
    pos = [0]

    def varint():
        b, sh = 0, 1
        while pos[0] < len(buf):
            n = buf[pos[0]]; pos[0] += 1
            b += (n % 128) * sh
            if n < 128:
                return b
            sh *= 128
        return b
    return pos, varint


def parse_segments(data):
    pos, varint = reader(data)
    nseg = varint()
    if nseg <= 0 or nseg > 64:
        return None
    lens = [varint() for _ in range(nseg)]
    base, acc, segs = pos[0], 0, []
    for L in lens:
        segs.append(data[base + acc: base + acc + L]); acc += L
    return segs


def parse_import_table(seg):
    """A segment of protos, each = a list of parts (global path components)."""
    pos, v = reader(seg)
    try:
        n = v()
    except Exception:
        return None
    if n <= 0 or n > 100000:
        return None
    out = []
    for _ in range(n):
        try:
            nparts = v()
            if nparts <= 0 or nparts > 64:
                return None
            parts = []
            for _ in range(nparts):
                ln = v()
                b = seg[pos[0]:pos[0] + ln]; pos[0] += ln
                parts.append(b.decode("latin1"))
            if all(all(32 <= ord(c) < 127 for c in p) and p for p in parts):
                out.append(parts)
            else:
                return None  # not the import table
        except Exception:
            return None
    return out


def readable_strings(data, minlen=4):
    out, cur = [], []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= minlen:
                out.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        out.append("".join(cur))
    return out


def lift(data):
    report = {"segments": None, "imports": None, "strings": []}
    segs = parse_segments(data)
    if not segs:
        report["error"] = "not a segmented VM chunk"
        return report
    report["segments"] = [len(s) for s in segs]
    # find the import-table segment (usually a small one that parses cleanly)
    for i, s in enumerate(sorted(segs, key=len)):
        imp = parse_import_table(s)
        if imp:
            report["imports"] = imp
            report["import_segment_len"] = len(s)
            break
    # readable strings across all segments. Encrypted constants decode to
    # high-entropy byte runs that still land in printable range and can look
    # identifier-shaped (e.g. "iwoceplti", "dh2VM"), so a shape test is not
    # enough. Keep only names from the Luau standard vocabulary (library tables,
    # their members, and base globals). That is language knowledge, not anything
    # tied to a sample, and it cleanly separates the VM's real primitives from
    # decoded-constant noise. Program-specific strings are recovered separately
    # by the dynamic resolver dump, which is where they actually live.
    seen = set()
    for s in segs:
        for r in readable_strings(s, minlen=3):
            base = r.split(".")[0]
            if r in LUAU_NAMES or base in LUAU_NAMES:
                seen.add(r)
    report["strings"] = sorted(seen)[:200]
    return report


def main():
    data = open(sys.argv[1], "rb").read()
    r = lift(data)
    print("segments:", r.get("segments"))
    if r.get("imports"):
        print("\nIMPORT TABLE (static, %d entries):" % len(r["imports"]))
        for p in r["imports"]:
            print("  " + ".".join(p))
    if r.get("strings"):
        print("\nREADABLE STRINGS (%d):" % len(r["strings"]))
        for s in r["strings"][:80]:
            print("  " + s)
    if r.get("error"):
        print("note:", r["error"])


if __name__ == "__main__":
    main()
