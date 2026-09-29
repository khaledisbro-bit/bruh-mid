# VmSmart

A purple-glass desktop app (Electron) over the deobfuscation pipeline. Drop an
obfuscated `.lua`, and VmSmart detects the family, unwraps Layer 1, runs the VM
(auto via the Roblox Executor MCP, or by copy/paste), and verifies the result.

## Features
- Drag and drop, with a live stage timeline: Detect -> Unwrap -> Run VM -> Verify.
- Recovered source in a Lua editor with syntax highlighting; copy in one click.
- VM Structure viewer (resolver, LCG, integrity, classification REAL/SUSPICIOUS/DECOY).
- Constants / behavior viewer from the live run.
- History of runs.
- Auto executor step via MCP, with a manual copy-harness + paste fallback.

## Requirements
- Node.js 18+ and npm.
- Python 3 with `zstandard` (`pip install zstandard`) on PATH.
- The `pipeline/` folder next to this `app/` folder (same repo).
- For auto-run: Roblox Executor MCP running on `localhost:16384`.

## Run
```
cd app
npm install
npm start
```

## Build a Windows installer
```
npm install --save-dev electron-builder
npm run dist
```
The output installer is written under `dist/`.

## How the executor step works
VmSmart generates a harness with the obfuscated source embedded (no readfile).
- MCP connected: it posts the harness to the bridge, reads the printed
  `BEGIN_UNOBF_RESULT..END` block, and finalizes automatically.
- MCP not reachable: open the Executor tab, click Copy harness, run it in your
  executor, paste the printed block, and click Verify & finalize.

The MCP execute endpoint is probed best-effort. If your bridge uses a different
path, set the URL in Settings; the manual fallback always works.

## Notes
- Nothing is hardcoded per sample. The pipeline auto-detects each build's
  alphabet, header, resolver, and keys.
- For programs whose exact source cannot be auto-synthesized, VmSmart shows the
  verified behavior (printed output, API calls, decoded constants) instead of
  guessing.

## Collecting from the executor, without a terminal

The Executor tab now drives the route that does not need CMD.

**Start collecting** writes `harness.lua` and then watches your executor's
folder. Run `harness.lua` once in the executor and the files are picked up as
they land, with the watching run's output shown live rather than buffered until
it exits.

Do not run `harness_chunk2.lua`. It traces a second interpreter nested inside
the first, records nothing on a build that has only one, and - run afterwards -
overwrites the capture that worked.

**Find my executor folder** asks the executor instead of guessing. Run

    writefile("VMSMART_WHERE.txt", "here")

in the executor, press the button, and the folder that file landed in is filled
in for you, whatever the executor is called and wherever it was installed.

**visible hooks** emits a harness whose trace hooks are ordinary globals rather
than being served through the environment's metatable. Try it only when a run
records no instructions although the harness reported placing the hook: a VM
that copies its environment copies real fields and not metamethod answers.

**Behaviour check** is the last step and the one that matters most. Everything
else shows the reconstruction reads like the program. This is the only check
that shows it behaves like it. Copy `behaviour_check.lua`, run it in the
executor, and paste back what it printed.
