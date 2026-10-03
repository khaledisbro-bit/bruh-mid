"""The sides of a branch this run did not take, sorted by why.

A capture is one path. Every branch it met has a side it did not take, and those
sides are the largest single thing a one-run analysis does not know. Counting
them says nothing useful; what matters is why each one was not taken, because
the four reasons mean four different things to the reader:

  DECIDED BY THE ENVIRONMENT   the value tested came, through the value graph,
                               from something the host answered - a service, a
                               property, a method's result. The stand-in
                               answered it here. On a real client the answer
                               can differ, and then this is the side that runs.
                               This is the one category a reader must not read
                               as a property of the program.
  ONE WAY ONLY                 the value tested was the same on every path that
                               reaches it. While that holds the other side
                               cannot be entered. It is still written out: a
                               test on a value that never varies is what a
                               programmer writes too, not only an obfuscator.
  NOT REACHED ON THIS PATH     the value tested varied during the run, so the
                               condition is real and the other side is code
                               this one execution did not go through.
  CONDITION UNRESOLVED         nothing is established about the value tested.
                               Not reached and not decided: not known.

None of the four is dead code, and none is removed. The third and fourth are
missing evidence about the program; the first is missing evidence about the
machine it would run on.
"""
from evidence import OBSERVED, INFERRED, UNKNOWN, DECOY

ENVIRONMENT = "decided by the environment"
ONE_WAY = "one way only while that value holds"
NOT_REACHED = "not reached on this path"
UNRESOLVED = "condition unresolved"

NAMED_VARS = "tests a named variable"

ORDER = [ENVIRONMENT, ONE_WAY, NOT_REACHED, NAMED_VARS, UNRESOLVED]


def _ancestors(L, v, limit=400):
    """Every value this one was computed from, as far back as the graph goes."""
    seen, stack = set(), [v.id]
    while stack and len(seen) < limit:
        vid = stack.pop()
        if vid in seen:
            continue
        seen.add(vid)
        for i in L.values[vid].inputs:
            if i not in seen:
                stack.append(i)
    return seen


IN_A_REGISTER = ("this build's branch handler takes nothing off the stack: it "
                 "reads the value it tests from the interpreter's register "
                 "file. So the value is not in the stack graph and nothing "
                 "here settles it. Which register it came from is what would, "
                 "and that is the next thing to establish - not a property of "
                 "the program, a gap in this analysis")


def classify(g, L, predicates, call_rows=(), fiction_row=None, models=None,
             cond_ops=None):
    """One verdict per branch with an untaken side, with the test that gave it."""
    per_pc = {}
    for st in L.steps:
        per_pc.setdefault(st.key(), []).append(st)
    answered = set(r for r in call_rows if r is not None)
    out = {}
    for br in g.branches:
        if not br.get("untaken"):
            continue
        pc = br["pc"]
        steps = per_pc.get(pc, [])
        conds = [st.popped[-1] for st in steps if st.popped]
        # where the tested value came from
        env_row = None
        for c in conds:
            for vid in _ancestors(L, c):
                row = L.values[vid].row
                if row in answered:
                    env_row = row
                    break
                if fiction_row is not None and row is not None \
                        and row >= fiction_row:
                    env_row = row
                    break
            if env_row is not None:
                break
        pred = (predicates or {}).get(pc) or {}
        if env_row is not None:
            out[pc] = {
                "verdict": ENVIRONMENT, "evidence": OBSERVED,
                "why": ("the value this branch tested was computed from "
                        "something the environment answered, at capture row %s. "
                        "Here that answer came from the stand-in, so which side "
                        "runs is a fact about the host and not about the "
                        "program" % env_row),
                "untaken": br["untaken"]}
            continue
        if pred.get("verdict") == DECOY:
            out[pc] = {"verdict": ONE_WAY, "evidence": pred.get("evidence",
                                                                INFERRED),
                       "why": pred.get("why", ""), "untaken": br["untaken"]}
            continue
        if pred.get("verdict") == UNKNOWN or not conds:
            why = pred.get("why") or ("nothing is established about the value "
                                      "this branch tested")
            # WHY nothing is established, where the answer is known. A handler
            # that pops nothing cannot have tested a stack value, so saying
            # only "unresolved" hides a reason that is already in hand.
            m = (models or {}).get(br.get("op"))
            # The handler may name the values it tests outright: `a =
            # BOX[row[4]][1]; b = BOX[row[5]][1]; if (a ~= b) == ...`. Then the
            # condition is not unknowable at all - it is two of the program's
            # own variables, and which two is in the instruction's operands.
            got = (cond_ops or {}).get(br.get("op"))
            if not conds and got and got[0]:
                st0 = steps[0] if steps else None
                which = []
                for i in got[0]:
                    k = i - 2            # row[2] is the first operand
                    if st0 is not None and 0 <= k < len(st0.operands):
                        which.append(str(st0.operands[k]))
                if which:
                    out[pc] = {
                        "verdict": NAMED_VARS, "evidence": OBSERVED,
                        "why": ("its handler tests the program's own "
                                "variable(s) %s, named by this instruction's "
                                "operands rather than taken off the stack. "
                                "Which way it went is decided by what last "
                                "wrote %s"
                                % (", ".join("#" + w for w in which),
                                   "them" if len(which) > 1 else "it")),
                        "untaken": br["untaken"]}
                    continue
            if not conds and m is not None and m.pops == 0:
                why = IN_A_REGISTER
            out[pc] = {"verdict": UNRESOLVED, "evidence": UNKNOWN,
                       "why": why, "untaken": br["untaken"]}
            continue
        seen = {c.runtime for c in conds if c.runtime is not None}
        out[pc] = {
            "verdict": NOT_REACHED, "evidence": OBSERVED,
            "why": ("the value this branch tested %s during the run, so the "
                    "condition is real and the side not taken is code this "
                    "path did not go through"
                    % ("took %d different value(s)" % len(seen) if len(seen) > 1
                       else "was reported and is not fixed across the paths "
                            "into it")),
            "untaken": br["untaken"]}
    return out


def report(verdicts, g):
    counts = {k: 0 for k in ORDER}
    sides = {k: 0 for k in ORDER}
    for pc, d in verdicts.items():
        counts[d["verdict"]] = counts.get(d["verdict"], 0) + 1
        sides[d["verdict"]] = sides.get(d["verdict"], 0) + len(d["untaken"])
    T = ["THE SIDES THIS RUN DID NOT TAKE",
         "=" * 46,
         "A capture is one path through the program. Every branch on it has a",
         "side that was not taken, and what matters is why. None of these is",
         "dead code and none was removed.", ""]
    total = sum(counts.values())
    T.append("%d branch(es) with a side this run did not take, %d side(s) in all"
             % (total, sum(sides.values())))
    T.append("")
    for k in ORDER:
        T.append("  %-4d %-34s %d side(s)" % (counts.get(k, 0), k,
                                              sides.get(k, 0)))
    T += ["",
          "What each one means for reading the reconstruction:",
          "  " + ENVIRONMENT + ": the stand-in decided it. On a real",
          "    client the other side is what may run. Treat it as unknown",
          "    about the program.",
          "  " + ONE_WAY + ": cannot be entered while that",
          "    value holds. A programmer writes such tests too, so this is",
          "    not by itself a sign of obfuscation.",
          "  " + NOT_REACHED + ": the condition is real. Another",
          "    run with other inputs would go there.",
          "  " + NAMED_VARS + ": the handler names the values it",
          "    tests. The side not taken is decided by what last wrote",
          "    those variables, which is where to look next.",
          "  " + UNRESOLVED + ": not decided and not reached - not",
          "    known. More tracing is what closes it.",
          ""]
    for k in ORDER:
        rows = [(pc, d) for pc, d in sorted(verdicts.items())
                if d["verdict"] == k]
        if not rows:
            continue
        T.append("%s (%d)" % (k.upper(), len(rows)))
        T.append("-" * 46)
        for pc, d in rows[:40]:
            T.append("  fn%s pc %s -> never entered: %s"
                     % (pc[0], pc[1],
                        ", ".join("fn%s pc %s" % (t[0], t[1])
                                  for t in d["untaken"])))
            T.append("      " + (d["why"] or ""))
        if len(rows) > 40:
            T.append("  ... %d more" % (len(rows) - 40))
        T.append("")
    return "\n".join(T)


def _selftest():
    import stackint

    class G:
        def __init__(self, branches):
            self.branches = branches

    L = stackint.Lift()
    hostv = L.new_value("computed", op=1, pc=10, row=500, runtime="true")
    derived = L.new_value("computed", op=2, pc=11, row=501,
                          inputs=[hostv.id], runtime="true")
    plain = L.new_value("computed", op=3, pc=20, row=600, runtime="1")
    st1 = stackint.Step(501, 11, 9, [], 1)
    st1.popped = [derived]
    st2 = stackint.Step(600, 20, 9, [], 1)
    st2.popped = [plain]
    L.steps += [st1, st2]
    g = G([{"pc": (0, 11), "untaken": [(0, 40)]},
           {"pc": (0, 20), "untaken": [(0, 50)]}])
    v = classify(g, L, {}, call_rows=[500])
    probs = []
    if v.get((0, 11), {}).get("verdict") != ENVIRONMENT:
        probs.append("a condition computed from the environment's answer was "
                     "not recognised")
    if v.get((0, 20), {}).get("verdict") not in (NOT_REACHED, UNRESOLVED):
        probs.append("a condition with no environment behind it was put in the "
                     "environment group")
    pred = {(0, 20): {"verdict": DECOY, "why": "always 1", "evidence": INFERRED}}
    v2 = classify(g, L, pred, call_rows=[500])
    if v2.get((0, 20), {}).get("verdict") != ONE_WAY:
        probs.append("a settled predicate was not reported as one-way")
    if not report(v2, g).strip():
        probs.append("the report came out empty")
    for p in probs:
        print("  PROBLEM: " + p)
    print("branches selftest %s" % ("ok" if not probs else "FAILED"))
    return bool(probs)


if __name__ == "__main__":
    _selftest()


def standin_instructions(L, call_rows=(), calls=()):
    """Instructions whose values came from something the environment answered.

    One walk back through the value graph per instruction, to the rows where the
    environment answered a call. An instruction that worked on one of those
    values ran and was observed; what it was observed doing depended on an
    answer this tool gave for a host object it had to stand in for. Marking
    those apart is the difference between "the program does this" and "the
    program does this here".
    """
    answered = {r for r in call_rows if r is not None}
    # The calls this analysis already placed on an instruction are the clearest
    # case of all: that instruction asked the environment for something and the
    # stand-in answered. Their rows are added so the walk starts from them too.
    for c in calls or ():
        st = getattr(c, "step", None)
        if st is not None and st.row is not None:
            answered.add(st.row)
    if not answered:
        return set()
    tainted = set()
    for v in L.values:
        if v.row in answered:
            tainted.add(v.id)
    # a value computed from a tainted value is tainted; the graph is in
    # definition order, so one pass forward settles it
    for v in L.values:
        if v.id in tainted:
            continue
        if any(i in tainted for i in v.inputs):
            tainted.add(v.id)
    out = set()
    for st in L.steps:
        if st.row in answered or \
                any(x.id in tainted for x in st.popped) or \
                any(x.id in tainted for x in st.pushed):
            out.add(st.key())
    for c in calls or ():
        st = getattr(c, "step", None)
        if st is not None:
            out.add(st.key())
    return out
