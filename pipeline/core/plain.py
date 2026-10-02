#!/usr/bin/env python3
"""
plain.py - what the program does, said plainly.

The other reports answer "is this defensible" and they answer it instruction by
instruction, which is the right shape for checking the analysis and the wrong
shape for reading it. Someone asking what the script does cannot get it from 861
lines of verdicts against instruction numbers.

This groups the same evidence by the kind of thing it is and counts it: the
services the program asked for, the objects it created, the fields it touched,
the names and numbers it worked with, the arithmetic it did, and what was found
to do nothing. Every line comes from the capture - a call the environment
recorded, a constant the interpreter decrypted, an operation read from its own
handler - and nothing is grouped that was not observed.

What it deliberately does not do is guess what the script is FOR. Counting four
folders and a data store is evidence; calling it a save system is a story, and
the difference is the whole point.
"""
import re
from collections import Counter

from evidence import DECOY, OBSERVED, UNKNOWN

_ID = re.compile(r"^[A-Za-z_]\w*$")
_NUM = re.compile(r"^-?\d+(\.\d+)?$")
_HEXY = re.compile(r"^[0-9a-fA-F-]{16,}$")


def _count(items):
    c = Counter(items)
    return ", ".join(("%s x%d" % (k, n)) if n > 1 else k
                     for k, n in c.most_common())


def _interesting(text):
    """A name worth showing: readable, not a hash, not machinery noise."""
    if not text or len(text) < 2 or len(text) > 48:
        return False
    if _HEXY.match(text) or _NUM.match(text):
        return False
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 2:
        return False
    # a random anti-tamper name mixes case constantly; a real name does not
    switches = sum(1 for a, b in zip(letters, letters[1:])
                   if a.isupper() != b.isupper())
    return switches < max(2, len(letters) * 0.4)


def build(capture, L, R, calls, unmatched, models, verdicts, slots, env_names,
          webs=None, facts=None):
    services, created, methods = [], [], []
    for rec in list(capture.calls):
        name = rec.get("method") or ""
        args = [a.strip().strip('"') for a in (rec.get("args") or ())]
        if name == "GetService" and args:
            services.append(args[0])
        elif name in ("Instance.new", "new") and args:
            created.append(args[0])
        elif rec.get("recv"):
            methods.append("%s:%s(%s)" % (rec["recv"], name,
                                          ", ".join(rec.get("args") or ())))
        elif name:
            methods.append("%s(%s)" % (name, ", ".join(args)))

    # fields the program reached for: the key of every index operation
    fields = []
    for st in L.steps:
        m = models.get(st.op)
        if m is None or m.operation != "INDEX" or len(st.popped) != 2:
            continue
        key = st.popped[1].runtime
        if key and key.startswith('"'):
            k = key[1:-1]
            if _ID.match(k):
                fields.append(k)

    # every readable name and number the interpreter decrypted
    names, numbers = [], []
    for tag, text in capture.constants:
        t = text.strip()
        if _NUM.match(t):
            numbers.append(t)
        elif _interesting(t):
            names.append(t)
    for v in L.values:
        r = v.runtime
        if r and r.startswith('"'):
            t = r[1:-1].rstrip(".")
            if _interesting(t):
                names.append(t)

    ops = Counter(m.operation for m in models.values() if m.operation)
    dead = [pc for pc, v in verdicts.items() if v.verdict == DECOY]
    unsure = sum(1 for v in verdicts.values() if v.verdict == UNKNOWN)
    real = sum(1 for v in verdicts.values() if v.verdict == OBSERVED)

    out = ["WHAT THE PROGRAM DOES",
           "=" * 46,
           "Grouped and counted from the capture. Every line below is something",
           "the program was observed doing or a value the interpreter was",
           "observed decrypting. What the script is FOR is not guessed here:",
           "that would be a story, and this is the evidence.", ""]

    def section(title, body, note=None):
        out.append(title)
        out.append("-" * len(title))
        if note:
            out.append(note)
        out.append("  " + (body if body else "(none found)"))
        out.append("")

    section("Services it asked the game for (%d)" % len(services),
            _count(services))
    section("Objects it created (%d)" % len(created), _count(created))
    # What became of each one, from the records themselves. The old wording
    # here said a name that "looks random" is anti-tamper noise. That is a
    # guess about a string, and a string is not evidence: a build can give a
    # real object an unreadable name, and a decoy can be called Folder. What
    # the records do say is whether anything ever touched the object again.
    used = {}
    for rec in list(capture.calls):
        r = rec.get("recv") if isinstance(rec, dict) else None
        if r:
            used.setdefault(r, []).append(rec.get("method") or "")
    if created:
        lines = []
        for cls in sorted(set(created)):
            got = used.get(cls) or []
            n = created.count(cls)
            if got:
                what = Counter(got)
                lines.append("  %s x%d - then %s"
                             % (cls, n, ", ".join("%s%s" % (k, "" if v == 1
                                                            else " x%d" % v)
                                                  for k, v in
                                                  what.most_common(6))))
            else:
                lines.append("  %s x%d - nothing recorded ever touched it "
                             "again: not parented, not read, not destroyed. "
                             "The creation is an action the program took and "
                             "stays; nothing in the program was observed "
                             "depending on it" % (cls, n))
        out.append("What became of each object")
        out.append("-" * len("What became of each object"))
        out.append("Taken from the records, not from how the name reads.")
        out += lines
        out.append("")
    if methods:
        section("Other calls it made (%d)" % len(methods), _count(methods))
    section("Fields it read or wrote (%d)" % len(fields), _count(fields),
            "Recovered from index operations the interpreter's own handlers\n"
            "identified, with the key the program used.")
    uniq_names = sorted(set(names))
    section("Names and text it worked with (%d distinct)" % len(uniq_names),
            ", ".join(uniq_names[:80]) +
            (" ... and %d more" % (len(uniq_names) - 80)
             if len(uniq_names) > 80 else ""))
    uniq_nums = sorted(set(numbers), key=lambda x: abs(float(x)))[:40]
    section("Numbers it worked with (%d distinct, smallest first)"
            % len(set(numbers)), ", ".join(uniq_nums))
    section("Operations it performed", _count(
        [k for k, n in ops.items() for _ in range(n)]) if ops else "",
            "Read from the interpreter's own handlers and checked against the\n"
            "values and their types.")

    out.append("How much of it is settled")
    out.append("-" * 25)
    out.append("  %d instruction(s) feed something the program observably did"
               % real)
    out.append("  %d do nothing at all and can affect nothing" % len(dead))
    out.append("  %d are not settled: they produced a value nothing used on the"
               % unsure)
    out.append("    path that ran, which is not enough to call them pointless")
    out.append("")
    if webs is not None and webs.active():
        out.append("Variables, said plainly")
        out.append("-" * 25)
        out.append("  %d variable(s) in all." % len(webs.webs))
        if webs.split:
            out.append("  %d storage slot(s) held more than one thing at "
                       "different" % len(webs.split))
            out.append("    points. Each one is written out separately, so two")
            out.append("    unrelated values are never shown as one being")
            out.append("    reassigned.")
        inbound = [w for w in webs.webs.values() if not w.defs]
        if inbound:
            out.append("  %d value(s) came in from outside this capture - a"
                       % len(inbound))
            out.append("    parameter, something captured from an enclosing")
            out.append("    function, or a write in code this run never ran.")
        if webs.dead:
            out.append("  %d store(s) nothing could ever read: the slot is"
                       % len(webs.dead))
            out.append("    written again, on every path, before anything")
            out.append("    reads it. They are still written out.")
        out.append("")
    if facts is not None and facts.constants:
        out.append("Variables that never changed")
        out.append("-" * 28)
        out.append("  Each of these held one value everywhere it was read, on")
        out.append("  every path through the program, not just the path taken.")
        for slot, v in sorted(facts.constants.items(),
                              key=lambda kv: str(kv[0]))[:40]:
            out.append("    %r" % (v,))
        out.append("")
    if facts is not None and facts.decided:
        settled = [d for d in facts.decided.values()
                   if d.get("verdict") == DECOY]
        out.append("Tests that could only go one way")
        out.append("-" * 32)
        out.append("  %d of %d branch(es) with a side this run did not take"
                   % (len(settled), len(facts.decided)))
        out.append("  were fed a value that was the same on every path into")
        out.append("  them. That side cannot be entered while that holds. It")
        out.append("  is still written out: a test on a fixed value is what a")
        out.append("  programmer writes too, not only an obfuscator.")
        out.append("")
    if unmatched:
        out.append("Calls the program made that could not be placed in the code")
        out.append("-" * 58)
        out.append("  These are the environment's own records. The program made")
        out.append("  them; this capture could not say which instruction did.")
        for rec in unmatched:
            out.append("    " + (rec.get("raw") or ""))
        out.append("")
    return "\n".join(out)
