#!/usr/bin/env python3
"""
exposure.py - what a protected script could still notice about being traced.

Tracing is not invisible. Reading every instruction costs time, hooking a
function replaces it with a different object, and giving a chunk its own
environment leaves that environment looking unlike the real one. A script that
wants to know whether it is being watched can ask about any of those without
naming a single tool.

The harness asks those questions about itself before it runs the payload and
writes the answers into the capture. This turns them into a report. The point
is not to claim the harness is undetectable - it is not, and the report says
which parts are. The point is that the list is measured on the run in front of
you rather than assumed from the last time somebody looked.

A missing PROBE section means an older harness produced the capture, and that
is said plainly rather than reported as a clean result.
"""
from evidence import OBSERVED, UNKNOWN

# tag -> (what it means, what counts as exposed)
_CHECKS = (
    ("globals_not_in_real_env",
     "names in this environment that the real one does not have",
     lambda v: _lead_int(v) > 0),
    ("hooks_visible_to_rawget",
     "the tracer's own hooks, readable straight off the environment",
     lambda v: _lead_int(v) > 0),
    ("env_has_metatable",
     "the environment carries a metatable; a plain one does not",
     lambda v: v.lower() == "true"),
    ("functions_not_identical_to_real",
     "functions that are not the objects they replaced",
     lambda v: _lead_int(v) > 0),
    ("hooks_reachable",
     "the tracer's hooks answer when called by name (they must, or nothing "
     "is logged)",
     lambda v: False),
    ("virtual_seconds_for_200k_adds",
     "what the clock reported for a fixed amount of work; 200 thousand "
     "additions are milliseconds on any real machine, so a large number here "
     "is the tracer's own cost showing through the clock",
     lambda v: _as_float(v) > _SLOW_SECONDS),
    ("clock_is_monotonic",
     "the clock moved forward; one that stands still is its own tell",
     lambda v: v.lower() == "false"),
    ("debug_info_line",
     "the line number the script reads for itself",
     lambda v: v in ("unavailable", "no debug.info")),
)


# 200 thousand integer additions take milliseconds anywhere. Half a second is
# already two orders of magnitude past that, so a reading above it is not a
# slow machine - it is instrumentation being measured.
_SLOW_SECONDS = 0.5


def _as_float(v):
    try:
        return float(v)
    except ValueError:
        return 0.0


def _lead_int(v):
    head = v.split(":", 1)[0].strip()
    try:
        return int(head)
    except ValueError:
        return 0


def assess(probe):
    """(exposed, checked, rows) - rows are (tag, meaning, value, exposed).

    A check that raised inside the harness reports itself as failed. That is
    neither clean nor exposed: it is a question that did not get asked, and
    counting it either way would be a claim about something nobody measured."""
    rows = []
    exposed = 0
    for tag, meaning, is_bad in _CHECKS:
        if tag not in probe:
            continue
        v = probe[tag]
        if v.startswith("check_failed"):
            rows.append((tag, meaning, v, None))
            continue
        bad = bool(is_bad(v))
        exposed += 1 if bad else 0
        rows.append((tag, meaning, v, bad))
    answered = sum(1 for r in rows if r[3] is not None)
    return exposed, answered, rows


def report(probe, hooks_hidden=None):
    """hooks_hidden: what the harness said about its own mode, or None when the
    capture does not say. With the hooks deliberately left visible, two of these
    checks are EXPOSED because that is what was asked for, and reading that as a
    leak sends the reader after a defect that is not there."""
    L = ["WHAT A TRACED SCRIPT COULD NOTICE", "=" * 46, ""]
    if not probe:
        L.append("  This capture carries no probe section, so nothing here was")
        L.append("  measured. That is not a clean result - it means the harness")
        L.append("  that produced the capture predates this check. Re-running")
        L.append("  with the current harness is what fills it in.")
        return "\n".join(L)
    exposed, checked, rows = assess(probe)
    L.append("  The harness asked these about itself before running the")
    L.append("  payload. Every one is a question any script can ask about its")
    L.append("  own environment, with no name of any tool in it.")
    L.append("")
    failed = 0
    for tag, meaning, v, bad in rows:
        if bad is None:
            mark, failed = "NOT ASKED", failed + 1
        else:
            mark = "EXPOSED" if bad else "  ok   "
        L.append("  [%s] %s" % (mark, meaning))
        L.append("           %s = %s" % (tag, v))
    L.append("")
    L.append("  %d of %d answered checks came back exposed." % (exposed, checked))
    if hooks_hidden is False:
        L.append("")
        L.append("  This run was asked for VISIBLE hooks, so the two answers")
        L.append("  about names in the environment are the mode that was")
        L.append("  requested, not a leak. The hidden mode serves those names")
        L.append("  through the environment's metatable, where walking the")
        L.append("  globals does not list them. The visible mode exists for one")
        L.append("  reason: a VM that COPIES its environment copies real fields")
        L.append("  and not metamethod answers, so the hooks would not follow")
        L.append("  it and nothing would be logged. If this run recorded what a")
        L.append("  hidden run did not, the copy is what happened.")
    elif hooks_hidden is True:
        L.append("")
        L.append("  This run hid its hooks behind the environment's metatable.")
    if failed:
        L.append("  %d check(s) raised inside the harness and were not "
                 "answered. Those" % failed)
        L.append("  are counted neither way: a question nobody got to ask is")
        L.append("  not a clean result.")
    L.append("")
    L.append("  A clean line is not proof that nothing is detectable. It is")
    L.append("  proof that this particular question did not give it away. The")
    L.append("  questions here are the ones worth asking that can be asked")
    L.append("  without naming anything, and that is a shorter list than the")
    L.append("  one a determined protection could write.")
    return "\n".join(L)


def _selftest():
    clean = {"globals_not_in_real_env": "0",
             "hooks_visible_to_rawget": "0",
             "hooks_reachable": "4",
             "env_has_metatable": "true",
             "functions_not_identical_to_real": "0",
             "clock_is_monotonic": "true",
             "virtual_seconds_for_200k_adds": "0.000120",
             "debug_info_line": "12"}
    exposed, checked, _ = assess(clean)
    # the metatable is a genuine tell and is counted as one even in the best case
    assert checked == 8 and exposed == 1, (exposed, checked)

    # a check that raised is neither clean nor exposed
    broke = dict(clean)
    broke["globals_not_in_real_env"] = "check_failed: attempt to index nil"
    e2, c2, rows2 = assess(broke)
    assert e2 == 1 and c2 == 7, (e2, c2)
    assert any(r[3] is None for r in rows2)

    leaky = dict(clean)
    leaky["globals_not_in_real_env"] = "4: __OP,__CODE,__SL,__CAP"
    leaky["hooks_visible_to_rawget"] = "4"
    leaky["functions_not_identical_to_real"] = "2"
    exposed, checked, _ = assess(leaky)
    assert exposed == 4, exposed

    # a clock reporting seconds for work that takes milliseconds is the
    # tracer's own cost showing through, and is a finding
    slow = dict(clean)
    slow["virtual_seconds_for_200k_adds"] = "8.412000"
    assert assess(slow)[0] == 2, assess(slow)[0]
    fast = dict(clean)
    fast["virtual_seconds_for_200k_adds"] = "0.004"
    assert assess(fast)[0] == 1, assess(fast)[0]

    # reachable hooks are required, never a finding
    only = {"hooks_reachable": "4"}
    assert assess(only)[0] == 0

    # A run asked for visible hooks must be told apart from a leak, and a
    # capture that does not say which mode it ran in must not be told either way.
    vis = report(leaky, hooks_hidden=False)
    assert "asked for VISIBLE hooks" in vis
    hid = report(clean, hooks_hidden=True)
    assert "hid its hooks" in hid and "VISIBLE" not in hid
    silent = report(leaky, hooks_hidden=None)
    assert "VISIBLE hooks" not in silent and "hid its hooks" not in silent

    assert "no probe section" in report({})
    print("exposure selftest ok")


if __name__ == "__main__":
    _selftest()
