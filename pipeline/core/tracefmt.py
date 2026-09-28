#!/usr/bin/env python3
"""
tracefmt.py - read a harness capture without knowing anything about the program.

A capture is a flat text stream. Sections announce themselves with ---NAME---
markers; a raw instruction dump has no markers at all. Every line is classified
by its SHAPE, never by what it says:

  instruction row   int ; int ; csv ; int ; text      (3..6 fields)
  constant row      TAG : text                        (single upper-case tag)
  call record       recv : method ( args )            or  NAME : arg
  scalar header     key : value                       at the top of the capture

No list of API names, service names or program strings appears anywhere in this
module, so the same parser reads any sample.
"""
import re

_ROW = re.compile(r"^(-?\d+);(-?\d+);([^;]*)"
                  r"(?:;(-?\d+))?(?:;([^;]*?))?(?:;(.*))?$")
_CONST = re.compile(r"^([A-Z]):(.*)$")
_METHOD = re.compile(r"^([\w.]+):(\w+)\((.*)\)$")
_NAMED = re.compile(r"^([\w.]+):\s*(.+)$")
_SECTION = re.compile(r"^-{2,}([A-Z_]+)-{2,}$")
_BODY = re.compile(r"BEGIN_UNOBF_RESULT\n?(.*?)\n?END_UNOBF_RESULT", re.S)


class Capture:
    """One harness run. Sections are whatever the capture declared."""

    def __init__(self, text, name="capture"):
        self.name = name
        self.raw = text
        m = _BODY.search(text)
        self.body = m.group(1) if m else text
        self.sections = _split(self.body)
        self.headers = _headers(self.sections.get("", []))
        self.rows = _rows(self.body)
        self.constants = _constants(self.sections)
        self.calls, self.notes = _calls(self.sections.get("BEHAVIOR", []))
        self.prints = [l.split("PRINT:", 1)[1].strip()
                       for l in self.sections.get("PRINTS", []) if "PRINT:" in l]

    def has_instructions(self):
        return len(self.rows) > 0

    def summary(self):
        return ("%s: %d instruction rows, %d constants, %d calls, %d prints, "
                "sections=%s" % (self.name, len(self.rows), len(self.constants),
                                 len(self.calls), len(self.prints),
                                 ",".join(k or "head" for k in self.sections)))


def _split(body):
    out, cur = {}, ""
    out[cur] = []
    for ln in body.splitlines():
        m = _SECTION.match(ln.strip())
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
            continue
        out[cur].append(ln)
    return out


def _headers(lines):
    h = {}
    for ln in lines:
        ln = ln.strip()
        if not ln or _ROW.match(ln):
            continue
        m = re.match(r"^([a-z_]+)\s*[:=]\s*(.*)$", ln)
        if m:
            h[m.group(1)] = m.group(2).strip()
    return h


def _rows(body):
    """Instruction rows, wherever they appear (marked section or raw dump).
    Each row: dict(i, pc, opcode, operands, sp, value)."""
    out = []
    for ln in body.splitlines():
        s = ln.strip()
        if not s or s.startswith("-"):
            if not _ROW.match(s):
                continue
        m = _ROW.match(s)
        if not m:
            continue
        ops = []
        for x in m.group(3).split(","):
            if x == "":
                continue
            try:
                ops.append(int(x))
            except ValueError:
                ops.append(x)
        sp = int(m.group(4)) if m.group(4) is not None else None
        val = m.group(5) if m.group(5) not in (None, "") else None
        out.append({"i": len(out), "pc": int(m.group(1)),
                    "opcode": int(m.group(2)), "operands": ops,
                    "sp": sp, "value": val})
    return out


def _constants(sections):
    """Resolver dump entries as (tag, text) in resolution order. The tag is
    whatever single letter the harness used; we do not assume which letters
    exist."""
    out = []
    for key in ("RESOLVED", "CONSTANTS", ""):
        for ln in sections.get(key, []):
            m = _CONST.match(ln.strip())
            if m:
                out.append((m.group(1), m.group(2)))
    return out


def _calls(lines):
    """Structured call records from the proxied-environment log, by syntax only.
    Returns (calls, notes). A call is dict(recv, method, args, raw)."""
    calls, notes = [], []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        m = _METHOD.match(s)
        if m:
            calls.append({"recv": m.group(1), "method": m.group(2),
                          "args": _args(m.group(3)), "raw": s})
            continue
        m = _NAMED.match(s)
        if m and " " not in m.group(1):
            calls.append({"recv": None, "method": m.group(1),
                          "args": _args(m.group(2)), "raw": s})
            continue
        notes.append(s)
    return calls, notes


def _args(text):
    """Split an argument preview at top-level commas (it may hold {a=1, b=2})."""
    out, depth, cur, q = [], 0, "", None
    for ch in text:
        if q:
            cur += ch
            if ch == q:
                q = None
            continue
        if ch in "\"'":
            q = ch; cur += ch; continue
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip()); cur = ""; continue
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def combine(caps):
    """Fold several files of ONE run into a single capture.

    An executor writes a run out in pieces: the console block carries the calls
    and the constants but only the first few thousand instructions, while the
    instruction dump beside it carries all of them. They describe the same
    execution, so analysing them separately would throw away half the evidence
    in each.

    Where two pieces hold the same instructions, the longer one wins - one is
    the truncated copy of the other. Where they hold different instructions,
    they are joined in order. Calls, constants and printed output are unioned,
    keeping the order each piece recorded."""
    if not caps:
        return None
    base = caps[0]
    for other in caps[1:]:
        base.rows = _longer(base.rows, other.rows)
        base.calls = _union(base.calls, other.calls, lambda c: c["raw"])
        base.constants = _union(base.constants, other.constants, lambda c: c)
        base.prints = _union(base.prints, other.prints, lambda p: p)
        base.headers.update(other.headers)
        for k, v in other.sections.items():
            base.sections.setdefault(k, []).extend(v)
        base.name = base.name + "+" + other.name
    for i, r in enumerate(base.rows):
        r["i"] = i
    return base


def _key(rows):
    return [(r["pc"], r["opcode"], tuple(r["operands"])) for r in rows]


def _longer(a, b):
    if not a:
        return b
    if not b:
        return a
    ka, kb = _key(a), _key(b)
    if kb[:len(ka)] == ka:
        return b
    if ka[:len(kb)] == kb:
        return a
    return a + b


def _union(a, b, key):
    seen = {key(x) for x in a}
    out = list(a)
    for x in b:
        if key(x) not in seen:
            seen.add(key(x))
            out.append(x)
    return out


def load(paths, one_run=False):
    """Read captures. Each file is a separate run unless one_run says they are
    pieces of the same one, in which case they are folded together first."""
    import os
    caps = []
    for p in paths:
        with open(p, encoding="latin1") as f:
            caps.append(Capture(f.read(), os.path.basename(p)))
    if one_run and len(caps) > 1:
        return [combine(caps)]
    return caps


if __name__ == "__main__":
    import sys
    for c in load(sys.argv[1:]):
        print(c.summary())
