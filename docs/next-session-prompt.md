# Next Session Prompt — Xbox 360 LZX + Wii U + PS3 + PS4/PS5

> Copy the block below into a fresh Cline session to pick up where this one left off.
> Written after commit `35f311d` ("Add OG Xbox (XBE) and Xbox 360 (XEX) support...").

```markdown
# Mission: extend Aura Decomp Tool — Xbox 360 LZX decompression + Wii U + PS3 + PS4/PS5

## Context
The repo lives at /workspace (git remote origin = https://github.com/danny199012/Aura-Decomp-Tool.git, branch main).
All prior work is committed and pushed (HEAD = 35f311d "Add OG Xbox (XBE) and Xbox 360 (XEX) support...").
Existing backend modules in src-tauri/src/:
- main.rs — all tauri commands, identify_file, get_supported_formats, ELF32/PS-X EXE/GB ROM handling
- xbox.rs — OG Xbox XBE parser + 32-bit x86 disasm (iced-x86)
- xbox360.rs — Xbox 360 XEX0/1/2 parser, optional headers, security info, embedded PE extraction (raw + "basic" zero-fill compression ONLY), PE sections/exports, BE PPC disasm
- ppc_disasm.rs — SHARED PowerPC decoder (big-endian AND little-endian aware), opcode values verified against GNU binutils ppc-opc.c; Gekko/Xenon/Espresso compatible; public API: disassemble_ppc_at(data, file_offset, display_address, max_instr, PpcEndian) and legacy disassemble_ppc_instruction
- gamecube.rs (ELF64 PPC — NOTE: its parser reads little-endian; do NOT trust it for BE), sega_genesis.rs (68k), ps1_* / sce_symbol_scanner (MIPS PS1)
- Cargo.toml already has: serde, serde_json, sha1, iced-x86 = { features = ["decoder","intel","std"] }, tauri 2

## CRITICAL gotchas learned in earlier sessions (read before coding)
1. Fresh sandboxes have NO Rust/cargo. Install first: curl -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal, then export PATH="$HOME/.cargo/bin:$PATH".
2. The Tauri crate CANNOT compile here (no system GTK/webkit libs, no sudo). You cannot `cargo check` main.rs. Verify your new modules with a standalone harness instead:
   - /tmp/xcheck/Cargo.toml: deps = serde, serde_json, iced-x86, plus a tiny fake-tauri proc-macro crate (path dep "tauri" whose lib.rs is `#[proc_macro_attribute] pub fn command(_a, item) -> TokenStream { item }`) so #[tauri::command]-annotated module files compile standalone.
   - main.rs of the harness does `#[path = "/workspace/src-tauri/src/<file>.rs"] mod <name>;` for each module you touch, and contains unit tests that build synthetic binaries in memory and assert on parse/disasm output.
   - Keep the harness updated with a test for every new format; run `cargo run --bin <harness>` and require ALL PASS before pushing.
3. Several uploaded files were NEVER compiled before and were full of corrupt/latent bugs (mangled comment in sega_genesis.rs, 180+ type errors, wrong opcode dispatch). ALWAYS build + test every module you touch; do not assume committed code compiles.
4. The old PowerPC decoder was fundamentally broken (primary-opcode dispatch table was wrong). ALWAYS verify decode behavior against a known-good reference (binutils ppc-opc.c, real binaries) and with synthetic test cases.
5. iced-x86 supports bitness 32 AND 64 via Decoder::with_ip(bitness, ...) — PS4/PS5 (x86-64) reuse it with bitness=64.
6. PS3/Wii U/Xbox 360 are big-endian PowerPC64 — reuse ppc_disasm.rs (PpcEndian::Big). PS4/PS5 are little-endian x86-64.
7. git identity is Daniel Robson <danny199012@users.noreply.github.com> (run git config if a fresh sandbox complains). Commit and push to origin main at the end.
8. Never overwrite/rebuild xbox.rs or xbox360.rs public APIs without updating main.rs call sites; keep graceful errors (Err(String)) for anything undecryptable/unsupported instead of panicking.

## Phase 1 — Xbox 360 LZX decompression (fully implementable, do first)
Goal: make disassemble_xex_section work for XEX images with compression "normal (LZX)" and, where possible, encrypted images.
- Add a pure-Rust LZX decompressor (Microsoft LZX as used by XEX/CAB). References: xenia's src/xenia/base/lzx.(cc|h) and the decompression path in xenia/src/xenia/cpu/xex_module.cc (search LZX_Decompress / multi-block logic); MS LZX specification (CAB/CHM). XEX "normal" compression uses block descriptors from security info page descriptors + xex2_file_normal_compression_info { window_size u32, first_block { block_size u32, block_hash[20] } } followed by (block_size + 20-byte hash) entries; each block decompresses independently with window_size context.
- Integrate into xbox360.rs extract_pe_image / disassemble_xex_section so compression "normal (LZX)" is handled, not just "none"/"basic".
- Try AES-128-CBC decryption using the title-key derivation scheme (keys/derivation per free60wiki and xenia) so encrypted retail XEXs become disassemblable too. If key derivation can't be completed, keep a clear, graceful error message.
- Tests: decode at least one known-good LZX stream (build a tiny hand-crafted LZX stream or round-trip against a reference implementation you write a tiny encoder for, or use a known test vector from xenia); assert decompressed output matches expected bytes; add a synthetic LZX-compressed XEX to the harness.

## Phase 2 — Wii U (RPX/RPL) support
- New module wiiu.rs: parse RPX (main executable) / RPL (libraries): ELF64 big-endian PowerPC64 (e_machine = 21 / EM_PPC64), load segments, entry point (Cafe typically maps images at ~0x02000000 — verify from references), code sections, symbol table if present, AND the Cafe-specific .fimports / .fexports sections to resolve function names where possible.
- Disassembly: reuse ppc_disasm.rs with PpcEndian::Big.
- References: wiiubrew.org RPX/RPL pages (also "Cafe ELF"), decaf-emu's loader (src/libdecaf ...), the "wut" toolchain docs.
- Wire into main.rs: identify_file already returns "elf64-be" — add routing to a wiiu path (best-effort: check machine==21 and section names), plus tauri commands parse_wiiu_file / disassemble_wiiu_section; update get_supported_formats with Wii U entry.
- Harness test: synthetic ELF64 BE PPC64 with a .fimports-style section; assert parse + PPC disasm of a small code section (blr / li / stwu).

## Phase 3 — PS3
- New module ps3.rs: parse PlayStation 3 executables — plain BE ELF32/ELF64 PowerPC64 (homebrew) AND the SELF wrapper format (metadata: header parse, identify the embedded ELF; unencrypted/homebrew SELFs may be fully parseable; encrypted retail should degrade gracefully).
- Disassembly via ppc_disasm.rs (PpcEndian::Big). Note SPU/SPE disassembly is OUT OF SCOPE (different ISA).
- References: psdevwiki SELF/PS3 pages, RPCS3's loaders (ELF/SELF handling).
- Wire into main.rs: commands parse_ps3_file / disassemble_ps3_section; identify_file additions if a distinct magic exists; get_supported_formats gets PS3 row (ELF entries exist already — improve them).
- Harness test: synthetic BE ELF64 PPC64 (and a minimal SELF wrapper for the container-parse path).

## Phase 4 — PS4 & PS5
- New module ps4ps5.rs: parse both systems' ELF (little-endian x86-64, EM_X86_64) for homebrew executables (PS4/PS5 plain ELF "eboot.bin" homebrew; PS4 ELF often carries an ORBIS ELF note — detect if present). Parse sections, symbols, entry point, relocations (a recomp-friendly foundation).
- SELF wrapper for PS4/PS5: parse container metadata; decrypt only if keys/derivation is available, otherwise graceful error (retail is key-gated; that is expected and acceptable).
- Disassembly: reuse iced-x86 at bitness 64, Intel syntax (mirror xbox.rs's disassemble_x86 but for 64-bit).
- Wire into main.rs: commands parse_ps4ps5_file / disassemble_ps4ps5_section (or per-platform command names); identify_file additions; get_supported_formats improved PS4/PS5 rows.
- Harness test: synthetic little-endian ELF64 x86-64 with a small .text (e.g., push rbp; mov rbp,rsp; pop rbp; ret = 55 48 89 E5 5D C3) asserting iced-x86 disasm output and correct addresses.

## Phase 5 (optional, only if earlier phases are solid) — recomp-export groundwork
- Mirror the existing ps1_recomp_export.rs / generate_config_toml pattern: add a recomp config-export command for one new platform (e.g., PS3 or PS4) that emits the same style of TOML/CSV the tool already produces, setting up future recomp tooling. DO NOT attempt real recompilation.

## Definition of Done (per phase, in order)
- Module compiles in the harness with zero errors (warnings from pre-existing files are acceptable).
- Harness tests for the phase run green.
- main.rs wiring added (mod declarations, identify_file, tauri commands registered in generate_handler!, get_supported_formats) — reviewed by eye since the full Tauri crate can't build here.
- README.md updated with the new platform features (match the existing Xbox section style).
- Commit and push to origin main: `git add -A && git commit -m "<platform>: <summary>" && git push origin main`.
- Final message to the user: what shipped, what's verified, and any remaining known limits (especially key-gated retail PS4/PS5/PS3 SELF and any remaining LZX edge cases).
```
