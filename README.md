# VmSmart

A Luau deobfuscator for the base85 + Zstd VM obfuscator family (obf2, obf3, and
siblings), with a desktop app and a hybrid static + dynamic pipeline that
recovers genuine program logic and refuses to fabricate.

## Layout
- `app/` - VmSmart, the Electron desktop app (purple glass UI). Drop an
  obfuscated `.lua`, watch the stages, get the verified source.
- `pipeline/` - the engine the app drives:
  - `deob.py` - one-command driver (detect -> unwrap -> harness -> audit).
  - `unobf.py` - static analyzer and Layer-1 unwrapper.
  - `unobf.lua` - dynamic oracle harness (runs in a Roblox executor).
  - `ai.py` - semantic audit; rejects failed runs, verifies output.
  - `obfuscators/` - per-family plugins; add a build type without core changes.
  - `REPORT_obf3.md`, `VERIFICATION_obf3.md` - worked results.
- `deobfuscated.lua` - the trace-verified source recovered for obf3.
- `unmoonveil.py`, `RECONSTRUCTION.md` - a separate tool for a MoonVeil-wrapped
  sample (`word.lua`).

## Quick start (command line)
```
pip install zstandard
python3 pipeline/deob.py obf.lua              # detect, unwrap, make harness
# run the printed harness in your executor, save its output to result.txt
python3 pipeline/deob.py obf.lua --trace result.txt --candidate deobfuscated.lua
```

## Quick start (app)
```
cd app
npm install
npm start
```
Build a Windows installer with `npm run dist` (needs Python 3 + zstandard on the
machine that runs it). See `app/README.md`.

## How it works
The outer wrapper (base85 + EncodingService Zstd + header split) is unwrapped
statically. The inner VM decrypts constants with a runtime key and per-pc LCG, so
there is no static key; the dynamic oracle runs the VM in a real executor and
the audit verifies the result against the observed behavior. Nothing is
hardcoded per sample: the alphabet, header, resolver, and keys are all detected
from each build.
