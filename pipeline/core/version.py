#!/usr/bin/env python3
"""
version.py - which engine produced a report.

Three rounds of this project were spent reading reports from an older copy of
the pipeline and reasoning about failures that had already been fixed. A report
that does not say what made it cannot be trusted to describe the code you have,
so every report now says, and the stages it lists are the ones that actually ran.
"""

VERSION = 50

STAGES = (
    "captures read by shape",
    "interpreter split by where control leaves it",
    "arity measured per instruction from the stack pointer",
    "operations read from the interpreter's own handlers, then checked",
    "value graph replayed against the VM's stack",
    "variables proved by read-returns-last-write",
    "calls anchored on names and arguments",
    "frames recovered only where numbers collide",
    "stored slots named from the handlers that read them",
    "decoys decided by influence, withheld when unproven",
    "a runnable rendering, checked to compile, for the behaviour comparison",
    "the program's actions lined up against the reconstruction's, one for one",
    "one harness per nested interpreter, so the program's tail is reachable",
    "calls the program made but nothing could place, quoted rather than written",
    "readings withdrawn when the values make them impossible",
    "each check reported on its own, never as one headline number",
    "behaviour compared by replaying the reconstruction and lining the calls up",
    "verdicts also said in the code's own terms, readable content first",
    "what the program does, grouped and counted in plain terms",
    "the interpreter's whole instruction array, so coverage is of the program",
    "reads and writes grouped by what reaches what, so one slot reused for two "
    "things becomes two variables and not one being reassigned",
    "facts carried along every path into a point, not only the path that ran, "
    "so a condition decided before it is tested is told apart from a real one",
    "counters found from the values themselves, and a loop bound written only "
    "when the inclusive form was checked against what the run entered",
    "calls repeated with the same arguments whose answer nothing took, "
    "reported as that fact and matched against no table of names",
    "the harness shielded where tracing is measurable: a clock that advances "
    "as an untraced run would, and debug reporting the lines the file shipped",
    "the instruction array fed to the graph, so a branch can have a side whose "
    "instructions never appeared in the trace at all",
    "a branch settled only when the run entered it more than once, because a "
    "single pass never varies",
    "machinery still found when the program sits in a loop and is as busy as "
    "the interpreter, decided by the stack pointer being handed back unchanged",
    "the tracer's own hooks served through the environment's metatable, so "
    "walking the globals does not list them",
    "the harness interrogating itself before it runs the payload, so what a "
    "traced script could notice is measured on the run rather than assumed",
    "a call written where it was made, not where its receiver was resolved, "
    "and a direct call written as one rather than as __call",
    "the executor's own folder found by asking the executor, instead of "
    "guessing at folders that already happen to hold an old capture",
    "each self-check in its own guard, so one that raises does not silently "
    "take the rest with it, and an unasked question is not read as a clean one",
    "errors on the script's own spawned threads written into the capture, "
    "instead of surfacing only as an engine message nobody analysing can see",
    "an empty capture told apart into its three causes by what the harness "
    "recorded doing, rather than all three reported as the one nobody can act on",
    "output written as UTF-8, so a folder named in the user's own language "
    "prints instead of ending the run",
    "the behaviour harness written as the Lua it is meant to be, and refusing "
    "to compare an empty rendering as though it had passed",
    "the logger's own read of the register array guarded, so observing the "
    "program cannot be what stops it",
    "a run that raised early said so at the top of the report, rather than its "
    "first few steps being described as the program",
    "the trace's instruction numbers lined up against the array's by matching "
    "the operands both report, rather than assumed to be the same",
    "operations that could only have gone through a metatable told apart from "
    "readings that are simply wrong, by whether the type could carry one",
    "call sites grouped by what each was seen reaching, so one instruction "
    "with several targets is not written as though it had one",
    "every stage asked what it does on a capture with nothing in it, and the "
    "metamethod list asserted to hold nothing that can never fire",
    "Lua's values kept apart where Python would merge them, so a path "
    "carrying 0 and one carrying false are not read as carrying the same thing",
    "a damaged capture read as damaged: a stack depth that is negative or past "
    "anything the run could have built is not believed rather than acted on",
    "the interpreter's helpers found in a short capture too, decided by the "
    "stack pointer coming back unchanged rather than by counts it cannot meet",
    "an arity nobody could measure marked as unmeasured, so an instruction is "
    "not called dead for having been unobservable",
    "a call site taken from instructions a call was matched to, not from every "
    "instruction sharing an opcode the matcher happened to land on",
    "the behaviour comparison itself tested against reconstructions wrong in "
    "known ways, and refusing to call a comparison of nothing a pass",
    "every report built from an empty capture and read for words that assert "
    "a finding, so no verdict is reached on no evidence",
    "the Lua this package writes actually executed, not merely parsed, so a "
    "reconstruction that calls a string or cannot terminate is caught here",
    "a script that dies just after the trace hook goes in named as what it "
    "looks like, with the untraced harness written beside it to settle it",
    "the harness settling that by itself, and all the way down: it makes two "
    "edits to the chunk, and on each round that raises it takes ONE back out - "
    "dispatch logger, then resolver rewrite - until the payload finishes or the "
    "chunk is untouched, so the answer is a finding rather than a suspicion and "
    "no capture has to be identified by hand",
    "the verdict as strong as the rounds and no stronger: a round with the "
    "chunk untouched rules the harness out, and a capture that never reached "
    "one rules out only the edit it removed and says so",
    "every pc the trace visited dumped from the instruction array whatever its "
    "number, because the cap used to cut it off exactly where a run that jumped "
    "past 2000 went, leaving a capture that could not say where it went",
    "each round's constants counted raw rather than from the de-duplicated "
    "list, so a later round is not reported as having got nowhere when it got "
    "exactly as far as the first",
    "each capture stamped with the build of the harness that wrote it, and the "
    "report saying when that is not this one, because the new harness is "
    "written at the moment the old capture is read and three in a row were read "
    "as evidence about code that had already been replaced",
    "every instruction array the run hands over dumped, not the first one: a "
    "build of this class keeps a prototype per function, so one array is one "
    "function and calling it the program is a claim the capture cannot support",
    "each traced instruction saying WHICH array its row came from, so two rows "
    "logged at the same number in different arrays are not read as one",
    "each array read again at the end and compared with what it held when first "
    "seen, so an array that decrypts its rows as it runs is a recorded fact "
    "rather than a contradiction between the dump and the trace",
    "an interpreter reading something that is not an instruction row recorded "
    "as what it actually read, instead of as an instruction with no operands, "
    "which is what a real no-operand instruction looks like",
    "names the payload read that the environment did not carry written down, so "
    "a run that died indexing nil has candidates instead of a shrug",
    "GetService saying whether it handed back the real service or a logging "
    "proxy, because a proxy answers every field with a function and a program "
    "that asked for a service this engine lacks gets nothing like what it "
    "expected",
    "the prototype makers hooked where each closure is BUILT, not only where "
    "instructions run, so the arrays of functions this run never called are seen "
    "too and coverage counts them as never entered rather than as absent",
    "the prototype parameter found by a name-free signature - it is the one "
    "indexed through itself, P[P[k]] - a discriminator taken from the Luraph v15 "
    "devirtualizer (MIT) and not the literal variable names it also carries",
    "four patch levels bisected rather than two, so the outermost edit is taken "
    "back out first and an edit that never went in is never stepped over",
    "a variable named from the value it holds, by rule rather than from a table "
    "of API names: a verb stripped off a method, the last segment of a string "
    "argument, a plural made singular - so GetChildren becomes children because "
    "Get is a verb, and names nobody wrote down are reached too",
    "a name refused where the value says nothing, including the emitter's own "
    "placeholder for an operation it could not read, because a name that "
    "pretends to know is worse than the number it replaces",
    "the same substitution applied to the readable rendering and to the one the "
    "behaviour comparison executes, so a rename cannot make the comparison "
    "measure the rename",
    "the deserialiser's slice accessor watched, found by its SHAPE - a "
    "one-parameter local function that indexes a captured table by that "
    "parameter and returns nil when the entry is absent - so the request a run "
    "dies on is named instead of guessed at",
    "an absent instruction row explained rather than reported: the counter's "
    "type, whether the row is there under that number as an integer, and how "
    "long the array is, which tells a key-type fault apart from an index past "
    "the end",
    "the instruction row read from the ARRAY and the counter, which is what the "
    "interpreter itself indexes, instead of from the loop variable this tool "
    "guessed the name of - that variable was nil on six of nine instructions of "
    "the real sample while the array held a full row at each of them, and the "
    "capture reported the build failing when the fault was here",
    "a disagreement between the array and the loop variable written down as a "
    "limitation of this tool, never as a fact about the program",
    "the slice watch and the prototype hook given a flag each, because sharing "
    "one made a capture say protos_hooked: true three lines under a log saying "
    "no prototype maker matched",
    "every name in the injected logger taken from ONE dispatch loop, anchored on "
    "the opcode expression and found by walking back from it: each name used to "
    "come from the first match in the whole source, which on a one-line file "
    "holding several interpreters is a different loop nearly every time",
    "an injection refused outright when the instruction row is declared after "
    "the point the logger would go, because the name is not in scope there and "
    "Lua resolves it to a nil global",
    "a bulk list never opened among the run headers, so the headers after it are "
    "still read as headers - the slice list had swallowed the attempt lines, the "
    "error and the verdict, exactly as the probe section once did",
    "a standalone harness that carries no script and reads obf.lua from the "
    "executor's own folder, so updating this package means replacing one 60KB "
    "file instead of re-running the analysis - four captures in a row came from "
    "the harness already on disk because getting a new one was work",
    "the no-script message naming obf.lua and where to put it, instead of an "
    "assert that said 'no source' and nothing a person could act on",
    "the row's own encoded opcode field recorded, because a decode can only be "
    "established from it - and NOT read as evidence on its own, since that field "
    "differs per program counter by design",
    "instructions grouped under one decoded opcode checked by their operand "
    "shapes, so six instructions carrying one, two and three operands are not "
    "measured as one instruction, said as an observation with its evidence and "
    "not as a verdict about which of the two reasons it is",
    "each capture naming the harness that made it, because inferring that from "
    "its side effects is how the wrong file came to be read twice",
    "the run's own headers in a section of their own, so run_ok is read at all: "
    "they used to arrive inside the probe section and a clean run was reported "
    "as a run that stopped early",
    "the early-stop warning keyed on which attempt produced the instructions, "
    "not on the headline, so a capture whose untraced retry finished is still "
    "not read as a whole program",
)


def banner():
    return "engine %d" % VERSION


def describe():
    L = ["engine %d - the stages that produced this:" % VERSION]
    for s in STAGES:
        L.append("   " + s)
    return "\n".join(L)
