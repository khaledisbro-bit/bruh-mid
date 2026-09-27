# Reconstruction status - word.lua (MoonVeil Obfuscator v1.4.5)

## What this file is
A single-line Luau script wrapped by MoonVeil Obfuscator v1.4.5
(https://moonveil.cc). The header comment names the tool. The body is one
long line of control-flow-flattened Luau that builds a bytecode VM and runs
an embedded, encrypted program.

## Layer pipeline
The final statement of the file is:

    (function() ... return Qd(Gf'<base64>', {[2]=S,[4]=e_,[3]=Je,[1]=hd}) end)()(...)

Decoding runs through four stages:

1. **Gf** - standard base64 decode. Strips every char outside the standard
   alphabet, then does the normal 6-bit to 8-bit expansion. Alphabet is
   `A-Za-z0-9+/`. No custom permutation.
2. **ze** - LZSS decompressor. Each control byte carries 8 flag bits, read
   LSB first. A set bit copies one literal byte. A clear bit reads a 16-bit
   big-endian token: `distance = token >> 5` (11 bits, 2048-byte window),
   `length = (token & 31) + 3` (3 to 34 bytes), copied from the sliding
   window.
3. **Ia** - a ChaCha20-variant stream cipher. The quarter-round uses the
   ChaCha rotation set 16/12/8/7 and four seed words
   (450898622, 2788171387, 3665530613, 3709022572). It runs 10 double-rounds
   in 64-byte blocks, mixes in unpacked I4 key material, and feeds the result
   through a base conversion. This is the layer that decrypts the VM chunk.
4. **Qd (= Od)** - the VM deserializer and interpreter. It reads the
   decrypted chunk into instruction, constant, and prototype tables, then
   dispatches.

## Fully recovered (deterministic, high confidence)
- **The obfuscator identity**: MoonVeil v1.4.5.
- **Every inline string constant**: 159 `yf()` calls, 53 unique values, all
  decoded. See `out/constants.txt`. These are stdlib names
  (`string.unpack`, `bit32.lshift`, `table.concat`, `coroutine.close`,
  `getfenv`, ...) plus pack formats (`>I2`, `<I4`, `<d`) and the VM helper
  table used to build the interpreter.
- **The `yf` string cipher**: repeating-key XOR.
  `out[i] = cipher[i] XOR key[i mod len(key)]`. The state-machine loop around
  it is pure control-flow flattening.
- **The base64 payload**: 34,068 chars -> `out/payload.bin` (25,549 bytes).
- **The LZSS decompression**: `out/payload_dec.bin` (152,128 bytes). This is
  the VM chunk before the ChaCha layer.

## Why byte-exact source cannot be dumped straight out
This build layers anti-analysis on top of the VM:

1. The 152 KB chunk stays **ChaCha-encrypted**. The key and nonce are derived
   by `Od` at load time from state that only exists while the VM runs, so
   there is no static key to apply.
2. The script targets **Roblox Luau**, not standard Lua. It relies on
   `bit32`, `string.pack`, `getfenv`, `table.create`, `table.move`, and
   `coroutine.close`. Standard Lua 5.1 through 5.4 do not match Luau
   semantics, so faithful execution needs the Luau VM.
3. The interpreter itself is **control-flow flattened**. Every function body
   is a `while` loop over a numeric state variable, with jump targets
   computed through `bit32.bxor` of large constants.

## What full source recovery requires
One of two paths:

1. **Run it in Luau.** Load the file in a Roblox Luau environment, hook the
   VM dispatch, and log the decrypted instruction stream and each resolved
   constant. This is the reliable route and matches how the reference build
   was traced.
2. **Static VM lifter.** Reimplement `Od` and the `Ia` key derivation in
   Python, decrypt the chunk, map the opcode set, then lift the instruction
   stream to Lua. This is a large effort because the opcodes are virtualized
   through the dispatch layer.

## Note on the two attached reference docs
The attached `README.md` and `RECONSTRUCTION.md` describe a different script
(`25ms_obf`) built by a custom hybrid obfuscator plus a 2023
executor-simulator VM. This file (`word.lua`) is a MoonVeil v1.4.5 build. The
tooling here is written for MoonVeil and does not apply to that other script.
