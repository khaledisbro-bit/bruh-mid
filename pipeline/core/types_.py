#!/usr/bin/env python3
"""
types.py - reject a reading the values could never have had.

An operation read from the interpreter's handler is a claim, and value algebra
can test it only where the arithmetic can be recomputed. Most readings are not
of that kind: an index, a call or a constant load cannot be recomputed from what
the capture reports. Those went unchecked, and the output showed it - lines like

    nil[1]        indexing nothing
    1()           calling a number
    nil + u0      adding to nothing
    {} + 8        adding to a table

Each of those is impossible in Lua whatever the program was doing, so the
reading that produced it is wrong: either the opcode is not the operation the
handler suggested, or its inputs were not the values the replay handed it.
Either way the reading has to go, and the instruction keeps its number.

The type of a value comes from what the VM reported for it - a quoted string is
a string, a bare number is a number, "table" is a table - and a value the capture
did not report is unknown and admits anything. Only an impossibility rejects,
never an absence, so this can withhold a reading and never invent one.
"""
import re

NUMBER = "number"
STRING = "string"
BOOLEAN = "boolean"
TABLE = "table"
FUNCTION = "function"
NIL = "nil"
UNKNOWN = "unknown"

_NUM = re.compile(r"^-?\d+(\.\d+)?([eE][-+]?\d+)?$")


def typeof(preview):
    """The type the VM's own report of a value implies."""
    if preview is None:
        return UNKNOWN
    p = preview.strip()
    if p == "" or p == "nil":
        return NIL if p == "nil" else UNKNOWN
    if p.startswith('"'):
        return STRING
    if p in ("true", "false"):
        return BOOLEAN
    if _NUM.match(p):
        return NUMBER
    if p in ("table", "{}"):
        return TABLE
    if p == "function":
        return FUNCTION
    return UNKNOWN


# Lua coerces a numeric string in arithmetic and a number in concatenation, so
# those stay admissible. Nothing else does.
_ARITH_OK = {NUMBER, STRING, UNKNOWN}
_CONCAT_OK = {STRING, NUMBER, UNKNOWN}
_INDEX_OK = {TABLE, STRING, UNKNOWN}
_CALL_OK = {FUNCTION, TABLE, UNKNOWN}
_COMPARE_OK = {NUMBER, STRING, UNKNOWN}

ARITH = {"ADD", "SUB", "MUL", "DIV", "MOD", "POW"}
COMPARE = {"LT", "LE", "GT", "GE"}


def admits(operation, input_previews, result_preview=None):
    """Whether an operation could have been performed on these values.

    Returns (ok, reason). ok is False only when the values make the operation
    impossible; a value the capture did not report never rejects anything."""
    ts = [typeof(p) for p in input_previews]
    if operation in ARITH:
        if len(ts) != 2:
            return True, ""
        for t, p in zip(ts, input_previews):
            if t not in _ARITH_OK:
                return False, "%s cannot take %s (%s)" % (operation, t, p)
        return True, ""
    if operation == "CONCAT":
        for t, p in zip(ts, input_previews):
            if t not in _CONCAT_OK:
                return False, "concatenation cannot take %s (%s)" % (t, p)
        return True, ""
    if operation in COMPARE:
        for t, p in zip(ts, input_previews):
            if t not in _COMPARE_OK:
                return False, "%s cannot compare %s (%s)" % (operation, t, p)
        return True, ""
    if operation == "INDEX":
        if ts and ts[0] not in _INDEX_OK:
            return False, "%s cannot be indexed (%s)" % (ts[0],
                                                         input_previews[0])
        return True, ""
    if operation == "CALL":
        if ts and ts[0] not in _CALL_OK:
            return False, "%s cannot be called (%s)" % (ts[0],
                                                        input_previews[0])
        return True, ""
    if operation == "NEWTABLE":
        if result_preview is not None and typeof(result_preview) not in (
                TABLE, UNKNOWN):
            return False, ("a table constructor cannot produce %s (%s)"
                           % (typeof(result_preview), result_preview))
        return True, ""
    return True, ""


def check(models, lift):
    """Withdraw every reading the values make impossible.

    Returns (withdrawn, examined, reasons)."""
    reasons, bad = {}, {}
    examined = 0
    for st in lift.steps:
        m = models.get(st.op)
        if m is None or not m.operation:
            continue
        ins = [v.runtime for v in st.popped]
        out = st.pushed[0].runtime if st.pushed else None
        examined += 1
        ok, why = admits(m.operation, ins, out)
        if not ok and st.op not in bad:
            bad[st.op] = (m.operation, why, st.pc)
    for op, (sem, why, pc) in bad.items():
        m = models[op]
        m.operation = None
        m.fact.note("types.impossible",
                    "the handler read as %s, but at pc %d %s, which cannot "
                    "happen, so the reading is withdrawn" % (sem, pc, why),
                    opcodes=(op,))
        reasons[op] = "read as %s, withdrawn: %s" % (sem, why)
    return len(bad), examined, reasons
