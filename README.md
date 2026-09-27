# unmoonveil - static unpacker for MoonVeil Obfuscator v1.4.5

`word.lua` is a Luau script wrapped by MoonVeil Obfuscator v1.4.5. This tool
peels back every deterministic layer without a Lua runtime, then documents
what the final layer needs.

## Files
- `word.lua` - the obfuscated input.
- `unmoonveil.py` - the unpacker. Pure Python, no dependencies.
- `RECONSTRUCTION.md` - the layer pipeline and recovery status.
- `out/` - generated output (created by the tool).

## Usage
```
python3 unmoonveil.py word.lua out
```
Writes to `out/`:
- `payload.bin` - the base64-decoded VM chunk (25,549 bytes).
- `payload_dec.bin` - the LZSS-decompressed chunk (152,128 bytes).
- `constants.txt` - all 159 decoded `yf()` string constants (53 unique).

## The layers
```
(function() ... return Qd(Gf'<base64>', {handlers}) end)()(...)
```
1. `Gf` - base64 decode (standard alphabet).
2. `ze` - LZSS decompress (2048-byte window, 11-bit distance, 5-bit length).
3. `Ia` - ChaCha20-variant stream cipher (rotations 16/12/8/7).
4. `Qd` - VM deserializer and interpreter.

Inline strings use `yf(cipher, key)`, a repeating-key XOR.

## What is recovered vs not
- **Recovered (deterministic):** obfuscator identity, all string constants,
  the `yf` XOR cipher, the base64 payload, and the LZSS-decompressed VM
  chunk.
- **Not source-level:** the VM program. The 152 KB chunk stays
  ChaCha-encrypted under a key `Qd` derives at runtime, and the code is
  Roblox Luau. Getting readable Lua back needs either a Luau runtime to trace
  the VM, or a full static lifter that reproduces the key derivation and the
  opcode set. See `RECONSTRUCTION.md`.
