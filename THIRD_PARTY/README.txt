Ideas taken from other projects, and what was deliberately not taken.

No source file from either project is in this repository. What was used is a
technique, named here so the debt is on the record and so anyone can check that
the rule this project runs on was kept.

caomod2077/Deobfuscator-Luraph-V15  (MIT, LICENSE beside this file)
  TAKEN, in pipeline/universal.lua (patchProtos / HID.__PROTO):
    Hook where each closure is BUILT, not only where instructions run. The
    function that builds a closure receives the prototype, so hooking it sees
    every prototype the program defines - including the functions this run never
    calls, whose instructions no trace can show.

    The prototype parameter is identified by a NAME-FREE signature: it is the
    parameter indexed through itself, P[P[k]], because its fields are keyed by
    its own entries. That is their vmmap._maker_params. It survives renaming,
    which is why it is worth having.

  NOT TAKEN:
    vmmap.loop_names(), and the reg="Z", pc="W" defaults in instrument_post().
    Those are literal variable names from particular builds. A table of names
    that decides how to read a sample is the lookup table this project refuses,
    and it is the one thing that would make the whole pipeline a fake.

    sample/output/ - finished deobfuscations. Copying a prepared reconstruction
    is not analysis.

    Their obfuscator-version detection choosing a strategy per build. This
    harness is deliberately build-agnostic and stays that way.

  DIFFERENT BY NECESSITY:
    They read a real Luau AST from a luau-ast binary. This harness runs inside
    the executor with no parser, so the same discriminator is applied as a text
    pattern. Lua patterns carry back-references, so "indexed through itself" is
    one match and still contains no name.

PumbaaDev/luau-decompiler  (MIT)
  Read for comparison only. Their per-prototype SCCP and dominator-based
  structuring are the same approach this package already takes in
  pipeline/core/sccp.py and pipeline/core/cfgx.py, arrived at independently.
  Nothing was copied. Their opmap_db was deliberately not used: an opcode table
  read from a file is exactly the lookup this project derives from the
  interpreter's own handlers instead.
