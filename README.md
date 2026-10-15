# 🌟 Aura Decomp Tool

A cross-platform decompiler and reverse-engineering toolkit for PlayStation (PS1/PS2) MIPS binaries, designed as a streamlined alternative to Ghidra. Parse ELF files, detect functions, resolve SDK symbols via SHA-1 fingerprinting, build call graphs, and export results — all in one focused tool.

---

## Features

### Binary Parsing
- **ELF32 (PS1/PS2)** — Full parsing of sections, symbol tables, relocations, and entry points for both big-endian and little-endian MIPS binaries.
- **Raw binary fallback** — Loads `.bin`, `.dat`, `.img` files at conventional base addresses (`0x80000000` for raw, `0x00010000` for PS-X EXE).
- **64-bit ELF detection** — Identifies PS3/PS4/PS5 binaries and loads them in fallback mode.

### MIPS R3000 Disassembly
- Complete disassembly of the full MIPS instruction set: I-type, J-type, R-type, COP0/COP1/COP2/COP3, branch delay slots, LWC1/STC1 coprocessor loads/stores, LL/SC atomic operations, and CACHE instructions.
- Virtualized rendering for handling binaries with hundreds of thousands of instructions without UI lag.

### Function Detection
- **Symbol-table driven** — When named symbols are present (dev builds), functions are extracted directly from the ELF symbol table.
- **JAL/J scan heuristics** — For stripped retail binaries, scans executable sections for `JAL` and `J` instructions to detect function entry points using the same approach as [ps2recomp](https://github.com/ps2dev/ps2recomp).

### SCE SDK Symbol Matching
- Embedded database of ~12,000+ Sony Computer Entertainment SDK symbols (`printf`, `PadInit`, `FlushCache`, etc.) from libc, libpad, libkernl, libcdvd, and crt0.
- **Three-stage matching pipeline:**
  1. Trie traversal over masked instruction words to narrow candidate symbols.
  2. SHA-1 verification — masks relocated words in the candidate function body and compares against precomputed hashes.
  3. Disambiguation — selects the best match by static-bit count, size, and library/name uniqueness.
- **Extensible without rebuilding** — point the `AURA_SCE_DB_DIR` environment variable at a directory containing your own `symbols.json` + `tree.json` (same schema as the embedded snapshot) and they are merged *on top of* the built-in database, adding new fingerprints and overriding existing ones. Inspect the loaded state with `aura-cli sdk-db [--json]`. This is the community-contribution path for SDK symbol data (mirroring how Ghidra loads external `.fidb` files).

### PS4/PS5 NID Database
PS4/PS5 Orbis binaries identify SDK imports and exports by **NID** (a 64-bit identifier) rather than by name — stripped retail `.sprx`/`.self` carry NIDs where a normal ELF carries symbol names. The community **aerolib.csv** database (~97,000 entries) maps those NIDs back to real C symbol names (`printf`, `scePadRead`, …) — the PS4/PS5 analogue of the PS2 SCE SDK SHA-1 fingerprint DB.
- **Embedded + overridable** — Aura ships with the aerolib.csv database embedded (it's GPL-3.0, same as Aura), so PS4 NID resolution works out of the box, no setup. To use a different/newer snapshot or a private NID set, point `AURA_PS4_NID_DB` at an `aerolib.csv` and it overrides the embedded copy (a missing/bad override falls back to embedded). Inspect the loaded state with `aura-cli nid-db [--json]`.
- **`.dynsym` NID extraction** — `aura-cli ps4-nid-scan <file> [--json]` parses a PS4/PS5 binary's dynamic symbol table, extracts the NID from each symbol name (the first 11 chars, the base64 token), looks it up in the aerolib DB, and reports each symbol's address + NID + resolved name. Symbols the binary already names (non-NID strings) pass through unchanged. This is the PS4 analogue of `aura-cli sdk-scan` for PS2.
- With the embedded DB, NID-based renaming works out of the box — no setup required.

### Call Graph Analysis
- Builds a directed graph of all direct `JAL`/`J` call edges across detected functions.
- Enriches external targets with import names via dynamic relocations (`R_MIPS_26`).
- Identifies unreachable functions (potential stubs, interrupt handlers, or dead code).

### Control-Flow Graph & Cross-References (Tier 1)
The analysis core that makes Aura behave like Ghidra / Binary Ninja instead of a flat linear-sweep disassembler:
- **Recursive-descent basic-block construction** — per-function CFGs built by walking from each entry, splitting at branches/jumps/returns, and following direct targets. Respects the MIPS branch-delay slot (the instruction after a branch stays in the branch's block, exactly as it executes).
- **Edge kinds** — fallthrough, branch-taken, branch-not-taken, unconditional jump, and call — the same structure Ghidra/BN use for decompilation and analysis.
- **Return detection** — flags functions that reach a `jr $ra`, distinguishing real functions from tail-calls/stubs.
- **Global cross-reference index** — for every address, the list of instructions that call/jump/branch to it. This is the "X" navigation primitive Ghidra/BN users rely on. Available in the GUI ("CFG & xrefs" tab) and the CLI (`aura-cli xrefs <file> --at 0xADDR`).
- **Indirect-call resolution groundwork** — recognises the canonical PS2 import-thunk pattern (`lw $t9, [import]; jalr $t9`) for later import-target recovery.
- Available headlessly: `aura-cli cfg <file> --json` and `aura-cli xrefs <file> --at 0x80123456 --json`.

### Decompiler — MIPS → pseudocode (Tier 2)
The headline feature that closes the biggest gap with Ghidra and Binary Ninja: lifting MIPS disassembly to C-like pseudocode. A pattern-based lifter (like Binary Ninja's first IL pass) that walks the per-function CFG and raises each instruction to typed IR, then renders readable code:
- **Instruction lifting** — every MIPS instruction (R-type, I-type, J-type, loads/stores, branches, calls) is lifted to a typed IR statement (`Assign`, `BinOp`, `Load`, `Store`, `Call`, `Return`, `CondGoto`, `Goto`).
- **Control-flow structuring** — block starts that are branch targets get labels; conditional branches become `if (cond) goto label`; `jr $ra` becomes `return`; `jal` becomes `target()`.
- **Call resolution** — `jal` targets are resolved to function names when known (from the symbol table or SDK scan), otherwise rendered as addresses.
- **MIPS idioms** — `nop` delay slots are suppressed; `lui` renders as a high-half constant; loads/stores render as `*(u32*)(base + offset)`.
- **GUI** — "Decompiler" tab: decompile a single function by address, or decompile all detected functions at once.
- **CLI** — `aura-cli decompile <file> --at 0xADDR` (one function) or `aura-cli decompile <file>` (all, capped by `--max`), with `--json`.

Example output:
```c
// Decompiled from 0x80010000 (2 blocks)
void sub_80010000() {
  sub_80010010();
  return;
}
```

### Decompiler — PowerPC → pseudocode (PS3 / Wii U)
The first **non-MIPS** decompiler front-end — extends the same typed IR and renderer used by the MIPS lifter to big-endian PowerPC, so PS3 and Wii U binaries get C-like pseudocode instead of stopping at disassembly:
- **`lift_ppc_instruction`** — lifts the common PPC integer ISA to the shared `IrStmt` IR: immediate arithmetic (`li`/`addi`/`lis`/`mulli`), D-form loads/stores (`lwz`/`lbz`/`stw`/`stb`/`lhz`/`sth`), register-form logic/arith (`add`/`subf`/`and`/`or`/`xor`/`slw`/`srw`/`divw`), branches (`b`/`bl`/`bc`), and returns (`blr`). Float/vector/supervisor instructions fall through to a `Raw` comment.
- **`decompile_ppc_section`** — a linear first-pass sweep that lifts every word and renders readable pseudocode, emitting `loc_` labels at branch targets so the output stays navigable. (A recursive-descent PPC CFG is the natural follow-up — PPC has no delay slots, so it is simpler than the MIPS CFG.)
- **CLI** — `aura-cli decompile-ppc <file> [--json]` decompiles the first executable section of a PS3 or Wii U binary.

```c
// PPC decompilation (linear first-pass) from 0x00010000
void sub_00010000() {
  $r3 = 5;
  return;
}
```

### Project save/load & scripting (Tier 3)
The extensibility layer that makes Aura a real reverse-engineering tool rather than a viewer:
- **`.aura` project format** — a tiny JSON file that layers user annotations (renamed functions, address comments, type signatures) and binary patches on top of a binary. It stores only the deltas, not the binary itself, so projects stay small and the binary can be re-analyzed as the engine improves. This is Ghidra's `.gpr` equivalent.
- **Lua scripting API** — a Lua 5.4 interpreter (vendored, no system Lua needed) with bindings to the analysis engine: `aura.functions`, `aura.rename(addr, name)`, `aura.comment(addr, text)`, `aura.signature(addr, sig)`, `aura.name_at(addr)`. Scripts can batch-rename functions, propagate comments, or run custom analysis passes — the same automation GhidraScript / Binary Ninja's Python API provide.
- **GUI** — "Project & script" tab: create/open/save projects, view annotations, and run Lua scripts in an editor.
- **CLI** — `aura-cli project <file> --section save|apply --out FILE` and `aura-cli script <file> --script script.lua --out project.aura --json`.

Example Lua script:
```lua
-- Rename all detected functions by their address
for _, f in ipairs(aura.functions) do
  aura.rename(f.addr, "func_" .. string.format("%08X", f.addr))
end
return "renamed " .. #aura.functions .. " functions"
```

### Search, strings & patching (Tier 4)
The day-to-day UX polish that makes Aura pleasant to use:
- **String scan** — finds printable ASCII and UTF-16LE (wide) strings across the binary, with their addresses and offsets. This is Ghidra's "Defined Strings" window equivalent.
- **Binary search** — locate hex byte patterns, ASCII strings (optionally case-insensitive), or 32-bit immediate values (endianness-aware) anywhere in the file.
- **String xrefs** — finds code that references each string via the canonical MIPS `lui`+`addiu`/`ori` address-build idiom, producing a "references to this string" list.
- **Binary patching** — apply a project's byte patches and write a patched binary (`aura-cli patch-export`), or record patches from a Lua script with `aura.patch(addr, {bytes}, note)`.
- **Annotation overlay** — the Disassembly view can load a `.aura` project and show your renames/comments in an "Annotation" column next to each instruction.
- **Undo/redo** — the Project & script tab keeps a history stack of your edits with Undo/Redo buttons and `Ctrl/Cmd+Z` / `Ctrl/Cmd+Shift+Z` shortcuts.
- **GUI** — "Search & strings" tab: strings table, pattern/string/immediate search, and string-xrefs view.
- **CLI** — `aura-cli strings <file> --json`, `aura-cli search <file> --section pattern|string|immediate --at VALUE`, `aura-cli string-xrefs <file> --json`, `aura-cli patch-export <file> --out project.aura --section patched.elf`.

### Export & Integration
- **Ghidra-compatible TOML config** — Generates `[general]` and `[ghidra_export]` sections matching ps2recomp's `ConfigManager::loadConfig`, including `input`, `output`, `ghidra_output`, `single_file_output`, `patch_cop0`, `stubs`, `skip`, and `untracked_stubs`.
- **CSV export** — Exports function names, start/end addresses (hex), and sizes in the format expected by Ghidra's `ExportPS2Functions.java`.

### User Interface
- **Drag-and-drop file loading** — Drop ELF or binary files directly onto the window.
- **Multi-tab sidebar** — File tree, functions list, named symbols, memory map, call graph, and disassembly views.
- **Theme system** — Four built-in themes (Midnight, Aurora, Synthwave, Carbon) with persistent selection via `localStorage`.
- **Bottom console panel** — Timestamped log entries at INFO/WARN/ERROR/DEBUG levels with color-coded severity.

### Original Xbox (XBE)
- **XBE parsing** — Header, certificate (title ID + UTF-16 title name, region, allowed media), sections, library versions, and xboxkrnl.exe imports.
- **XOR-key decoding** — Entry point and kernel thunk addresses decoded with the correct retail/debug/beta keys; build type auto-detected.
- **Import resolution** — Kernel thunk table resolved against the full 375-entry xboxkrnl ordinal table (`DbgPrint`, `NtCreateFile`, etc.).
- **x86 disassembly** — 32-bit Intel-syntax disassembly via `iced-x86` (the OG Xbox runs a Pentium III).

### Xbox 360 (XEX)
- **XEX parsing** — XEX0/XEX1/XEX2 headers, all optional headers (entry point, image base, TLS, system flags), execution info (title ID, media/version/disc), static + import libraries.
- **Security info** — Load address, image flags, region decoding, page descriptors, image size.
- **Embedded PE extraction** — Unencrypted raw, basic (zero-fill), and **normal (LZX)** compressed images are fully parsed: PE sections, image base, entry point, and exports by name.
- **LZX decompression** — A pure-Rust Microsoft LZX decompressor (`lzx.rs`, ported from libmspack's `lzxd.c`) handles XEX "normal" compression. It supports all window sizes (15–21 bits), VERBATIM/ALIGNED/UNCOMPRESSED block types, and multi-frame streams with window wrap. Validated against genuine LZX data compressed by the `liblzx` compressor (CAB DELTA variant) and cross-checked with libmspack's C decompressor.
- **PowerPC disassembly** — Shared big-endian PowerPC disassembler (Gekko/Xenon), covering integer, float, CR/branch, and 64-bit (ld/std) instructions, with common assembler aliases.
- **Encrypted note** — Retail images protected with AES-128-CBC encryption are identified and reported gracefully (metadata always parses; code disassembly requires an unencrypted image). Decryption of retail XEX keys is not yet implemented.

### GameCube & Sega Genesis (backend-level)
- GameCube ELF parser + PowerPC disassembly, and a Sega Genesis 68k decoder ship in the repo (`gamecube.rs`, `sega_genesis.rs`, `ppc_disasm.rs`).

### Wii U (RPX/RPL)
- **Cafe ELF64 parsing** — Big-endian ELF64 with e_machine = EM_PPC64 (21). RPX (main executable) and RPL (shared library) files are identified and parsed: entry point, section headers, code/data sections.
- **.fimports / .fexports** — Best-effort extraction of function import/export names from the Cafe-specific `.fimports` and `.fexports` sections, plus `.symtab`/`.strtab` symbol resolution when present.
- **PowerPC disassembly** — Shared big-endian PPC disassembler (`ppc_disasm.rs` with `PpcEndian::Big`).

### PlayStation 3 (SELF / ELF)
- **SELF wrapper parsing** — Identifies the SCE magic, scans for the embedded ELF, and parses it when unencrypted. Encrypted retail SELFs return a graceful error.
- **BE ELF parsing** — Both ELF32 and ELF64 big-endian PowerPC executables (homebrew) are fully parsed: entry point, section headers, code sections.
- **PowerPC disassembly** — Shared big-endian PPC disassembler. SPU/SPE disassembly is out of scope (different ISA).

### PlayStation 4 & PlayStation 5 (SELF / ELF / eboot.bin)
- **LE ELF64 x86-64 parsing** — Little-endian ELF64 with e_machine = EM_X86_64 (62) for homebrew executables. Sections, entry point, and ORBIS ELF note detection.
- **SELF wrapper parsing** — Identifies the SCE magic, scans for the embedded ELF, and parses it when unencrypted. Retail PS4/PS5 SELFs are key-gated and return a graceful error.
- **eboot.bin (fake-SELF) parsing** — The OpenOrbis homebrew container (`4F 15 3D 1D` magic) is parsed directly: header, self-entries, embedded ELF + program headers, and the raw (uncompressed, unencrypted) segment data are mapped into sections for disassembly and export. Encrypted retail eboot.bin files are detected and rejected with a clear key-gated message.
- **x86-64 disassembly** — 64-bit Intel-syntax disassembly via `iced-x86` (reusing the same crate as the OG Xbox 32-bit decoder, at bitness 64).

### Cross-Platform SDK Symbol Database
- **Auto-naming** — A built-in database of 346+ SDK function names across all supported platforms (PS1, PS2, PS3, PS4/PS5, Xbox, Xbox 360, Wii U, GameCube/Wii). When a binary is loaded, import-table names are matched against the database, instantly identifying functions like `VPADRead`, `cellPadInit`, `NtCreateFile`, `GX2Init`, etc. — no manual symbol import required.
- **Library detection** — Matched functions are attributed to their source library (e.g. `coreinit`, `libcd`, `xboxkrnl`, `libScePad`), giving an instant overview of which SDKs the binary uses.
- **Multi-method matching** — By name (import tables, .fimports, .dynsym), by ordinal (Xbox kernel thunk tables), and by instruction-pattern signature (common libc functions like memcpy/memset/strlen on all platforms).
- **Tauri commands** — `scan_sdk_symbols(path, platform)` returns matched symbols with descriptions; `get_sdk_db_stats(platform)` returns database coverage per platform.

### One-Click Decomp Project Export
- **Complete project scaffold** — Generates a ready-to-build decomp project in one click: `config.toml` (recompiler config), `functions.csv` (Name,Start,End,Size), `symbol_addrs.txt` (address to name mappings), `undefined_syms.txt` (unnamed function addresses), `splat.yaml` (segment splitter config), `functions.json` (machine-readable export), `symbols.idc` (IDA Pro symbol import script), `build/Makefile` (platform-aware toolchain), and `README.md` (project-specific instructions with named function list and section table).
- **Cross-platform routing** — `export_decomp_project` now routes to each platform's own parser, so PS1/PS2 (MIPS ELF), PS3 (BE ELF/SELF), PS4/PS5 (LE x86-64 ELF / SELF / fake-SELF eboot.bin), Wii U (RPX/RPL), Xbox (XBE), and Xbox 360 (XEX) all export a full scaffold — not just PS2. Wii U imports/exports and Xbox 360 PE exports are carried into the function tables where available.
- **Platform-aware build** — The Makefile auto-selects the correct cross-compiler toolchain (mips-elf for PS1/PS2, ppu-lv2 for PS3, powerpc-eabi for Wii U/GameCube, x86_64 for PS4/PS5, etc.).
- **splat-compatible** — The `splat.yaml` output is structured for use with the popular [splat](https://github.com/ethteck/splat) segment splitter, with per-function subsegments in code sections.
- **Tauri command** — `export_decomp_project(path, platform, output_dir)` writes all files and returns a summary with function counts and named/SDK-matched statistics.

### One-Click Disc Wizard (PS2)
Point Aura at a PS2 disc image you own and it builds a ready-to-run [`ps2_recomp`](https://github.com/ran-j/PS2Recomp) project — in the GUI (**One-click disc wizard**, the landing page on first launch) or from the command line (`aura-cli ps2-ingest`).
- **Disc-image reader** (`disc.rs`) — a streaming ISO9660 reader that never loads the whole image into RAM (PS2 DVDs are up to ~8 GB). Sector layouts are auto-detected: cooked 2048-byte `.iso`, raw MODE1/2352 and MODE2-form1/2352 `.bin`/`.img`/`.mdf`, MODE2/2336 and 2448-byte-with-subchannel. `.cue` sheets are followed to their data track. Handles nested and multi-sector directories and multi-extent files.
- **Hostile-input safe** — every length from the image is bounds-checked: truncated images, directory loops, garbage directories and absurd extents produce a clear error, not a panic, a hang or an unbounded allocation. Extracted names are sanitised (no `..`, separators, reserved characters or Windows device names) and collisions never overwrite each other.
- **Boot detection** — parses `SYSTEM.CNF` (`BOOT2 = cdrom0:\SLUS_203.12;1`), resolves the boot ELF case-insensitively, validates it is a 32-bit little-endian MIPS ELF, derives the product serial (`SLUS-20312`) and a coarse region, and reports PS1 discs (`BOOT =`) and non-PlayStation discs clearly instead of failing obscurely.
- **Extract what's needed** — *Executables only* (default: `SYSTEM.CNF`, the boot ELF and every ELF/IRX on the disc, a few MB) or *Entire disc*. Cancellable, with live progress.
- **Analysis + config** — runs the existing function detection and SCE SDK symbol matching on the boot ELF and writes `recomp/config.toml` + `recomp/functions.csv` in the schema `ps2_recomp` consumes, plus `game.json` (a manifest) and a project `README.md` with the next steps.
- **Optional recompiler run** — if you point the wizard at a `ps2_recomp` binary (or set `AURA_PS2RECOMP` / put it on `PATH`), it runs it for you and shows the log tail.
- **Retail-ELF fix** — ELFs with no section headers (common in retail PS2 executables) now fall back to their `PT_LOAD` program headers, so function detection no longer finds nothing on them.
- **Pointer-reachable functions** — the `JAL`/`J` scan only finds functions that are *called*. Static constructors, C++ vtables and callback tables are reached through data, so a call-only map missed them and `ps2_recomp` refused the config (\"Initializer table target has no discovered guest function\"). Aura now also takes any aligned word that points at code as a function entry when the target begins with a stack-frame setup (`addiu/daddiu $sp,$sp,-N`) or directly follows a `jr $ra` + delay slot (frameless thunks and leaf functions, which callback tables are full of). Measured against `ps2_recomp`'s own discovery on a retail game (7,920 functions): 99.0% of Aura's starts are confirmed and Aura finds 93% of upstream's functions, up from 64% with calls alone. The second rule is needed in practice: without it the game's first indirect call through a callback table landed on a thunk the map lacked and the program stalled.
- **BIOS-patching routines are stubbed** — SDK routines that scan or patch the EE kernel cannot work in a recompiled program (there is no BIOS). `InitSystemCallTableAddress` was observed to spin forever in two unrelated games with no GS activity; Aura writes `stubs = ["ret0@0xADDR"]` for it so the generic `ret0` handler replaces it. The list (`KERNEL_PATCH_ROUTINES` in `ps2_ingest.rs`) only grows by observed, verified cases.

What this does **not** do: compile the generated C++ or supply the PS2 runtime. Those come from the upstream ps2recomp project (CMake + a C++20 compiler + its `ps2xRuntime` library), which describes itself as experimental. Aura prepares and organises the project; it does not (yet) produce a finished game executable. CHD, CSO/ZSO and archive containers are detected and rejected with instructions to convert them first. No game data, keys or BIOS are bundled — you supply your own disc image.

### Double-Click Game Folder (PS2)
Turns an ingested disc plus a runtime executable *you* built from [PS2Recomp](https://github.com/ran-j/PS2Recomp) into a folder you can start with a double-click, instead of running the executable from a command prompt.
- **Why the executable alone does not double-click** — upstream's runtime takes the guest ELF path as `argv[1]` (or a compile-time default), has no file dialog or settings file, and has no ISO reader: it maps `cdrom0:` to the directory that contains the ELF. So the *whole* disc has to be extracted next to the boot ELF (the wizard's **Entire disc** mode) and something has to pass the path.
- **What Aura builds** — `<workspace>/package/` with `game.exe` (your runtime, copied), any DLLs found beside it (FFmpeg etc.), `disc/` (hard-linked from the workspace when on the same volume, so no extra disk space; copied otherwise), `mc0/` for saves, `launch.json`, `README.txt`, and the launcher.
- **Launcher** — `aura-launch` (built alongside `aura-cli`, ~350 KB) is a GUI-subsystem program: no console window. It reads `launch.json` from its own folder, starts the runtime with the boot ELF as an absolute path and the folder as working directory, writes the runtime's output to `aura-last-run.log`, and shows a message box with the exit code and log tail if the game stops with an error. Paths in `launch.json` must be relative and may not leave the folder, so the folder can be moved or renamed freely. When `aura-launch` is not found, a `Play <game>.cmd` fallback is written (names are checked so nothing is ever interpolated into `cmd.exe` unescaped).
- **Honest status of the executable itself** — Aura packages and launches it; it does not make the runtime faster or more complete. Tested with two real games built from Aura's output with upstream's runtime: the executable starts, opens its window and runs the game's code, but the upstream runtime is experimental and neither reaches gameplay yet (it reports unimplemented IOP/SPU stubs and stops). Packaging is not the bottleneck; runtime completeness is. Upstream leaves ~130 SDK routines as hard-failing TODO stubs (`TODO_NAMED` in `ps2xRuntime/src/lib/Kernel/Stubs`). Binding the one that stopped the homebrew game (`sceSdTransToIOP`, sound) to a no-op lets it run past that point, but it then sits on a black frame — so Aura does not bypass such stubs by default: a clear "the runtime does not implement X yet" message beats a silent blank window.
- **Failures are explained, not silent** — the upstream runtime reports its own fatal errors and still exits with code 0. If a game exits within 20 seconds and its log contains such a message, the launcher shows it (with the log path) instead of letting the window vanish.
- **CLI** — `aura-cli ps2-package <workspace> --exe <built exe> [--out DIR] [--copy] [--launcher PATH]`. **GUI** — the *Make a double-click game folder* panel on the wizard's last screen (with *Play* and *Show game folder*), including a one-click *Extract the entire disc now* when only the executables were extracted.
- **Do not distribute the result** — it contains code translated from the game plus the game's own data. It is generated on your machine from your own disc and is for use there.

### One-Click Build (PS2)
Compiles an ingested workspace into a game executable and packages it, so the wizard can end with a double-click folder without any manual build. In the GUI it is the *Build the game (one click)* panel on the last wizard screen; from the command line it is `aura-cli ps2-build`.
- **What it does** — finds CMake, git and a Visual Studio C++ toolchain; fetches the tested PS2Recomp commit (`eb8688b`, pinned) into a cache folder; builds `ps2_recomp` once; recompiles the game; puts the generated `*.cpp` in `ps2xRuntime/src/runner/` and the generated `*.h` in `ps2xRuntime/include/`; configures and builds `ps2EntryRunner` (Release, multi-processor); packages the result with the launcher.
- **Nothing downloads without a click** — `aura-cli ps2-build <workspace> --plan` (and the panel) list exactly what a first build fetches: about **1 GB** from GitHub (CMake clones full repositories: raylib ~490 MB, toml11 ~370 MB, …) plus a 34 MB FFmpeg archive. Without consent (`--yes` / the *Download … and build* button) the build refuses before creating anything. Later builds reuse the cache and need no consent.
- **Cache** — `%LOCALAPPDATA%\AuraDecompTool\ps2recomp` by default (`AURA_BUILD_CACHE` or `--cache DIR` to move it; pick another drive if C: is tight — the plan checks free space). One runtime build tree is shared between games, so later games only recompile their own code.
- **Measured** on a 20-core machine, cold cache, homebrew (586 functions): source 2 s · recompiler 103 s · recompile 1 s · configure 30 s · compile 116 s · package <1 s = **4 min 13 s** end to end. Warm cache: ~75–110 s. A retail game with ~7,000 functions (190 MB of generated C++) took ~16 min to compile.
- **Native feel** (on by default) — turns off upstream's debug overlay (`PS2X_ENABLE_DEBUG_UI`), console window (`PS2X_SHOW_WINDOWS_CONSOLE`) and very verbose logging. Runtime logging stays on because the launcher explains failures from it. `--upstream-defaults` keeps upstream's defaults.
- **Fast release** (`--fast`, off by default) — upstream's whole-program release mode (`/GL /LTCG /arch:AVX2 /fp:fast`, GUI subsystem). It sits behind `CMAKE_BUILD_TYPE=Release`, which the Visual Studio generator leaves empty, so without this flag none of it applies. Faster game; longer, more memory-hungry link.
- **Cancel** kills the whole process tree (CMake spawns MSBuild which spawns compilers). **Progress** is driven by the compile's batch lines, with a time-based creep because MSBuild's output is block-buffered through the pipe.
- **Honest status** — a successful build means the game's code compiled and starts. The upstream runtime is experimental; built games open and draw but are not playable yet (see *Double-Click Game Folder*). Windows (MSVC) only for now.

### One-Click Build (PS1)
Point the wizard (or `aura-cli ps1-ingest` / `ps1-build`) at a PS1 disc image and Aura drives [PSXRecomp](https://github.com/RetroPortingToolKit/psxrecomp) — a general-purpose PS1 static recompiler — end to end. The result is a native Windows program whose launcher asks for your disc the first time it starts.
- **Reads what collections actually contain** — `.chd` (every codec `chdman createcd` writes: LZMA, zlib, FLAC, zstd), `.cue/.bin`, and bare `.iso/.bin`. CHDs are decompressed on demand by a pure-Rust reader; nothing is converted by hand. The image is only ever read.
- **Recognises PS1 discs properly** — `SYSTEM.CNF` `BOOT =`, the boot **PS-X EXE** header (load address, entry point, licence marker), serial and region (falling back to the licence marker when the boot file has no serial), multi-disc names, truncated dumps.
- **`ps1-ingest`** writes `<out>/<SERIAL>/{source/, game.json}`. PSXRecomp's project setup only accepts a `.cue`, so a CHD's data track is decompressed to a `.cue`+`.bin` pair in `source/` (a `.cue` you pass is used in place; a bare image gets a generated sheet). Re-running reuses an up-to-date export.
- **`ps1-build`** — `--plan` lists exactly what a build would download and does nothing; `--yes` agrees to it. It detects git, Windows Python, PowerShell and Git's bash, then:
  1. downloads the authors' portable CMake + Ninja + clang bundle (~209 MB) **only if no toolchain is found**, and verifies its published SHA-256 before using it;
  2. fetches the pinned framework commit and the launcher sources into a cache;
  3. runs PSXRecomp's own setup script non-interactively — answering every prompt, with GitHub, CI, netplay and boxart switched off;
  4. gathers the built program (+ DLLs, BIOS) into `<workspace>/package` with a README.
- **Things the driver works around** (each found by running it for real): Windows PowerShell 5.1 silently drops empty arguments (the script forwards `--description ""` to a Python tool, which then fails), so metadata is always non-empty; a default Git for Windows (`core.autocrlf=true`) prints a warning per generated file and the script's `git add … 2>$null` then never returns under PowerShell 5.1, so CRLF handling is switched off for the run; `MSYS_NO_PATHCONV` in the environment would break Git-bash path conversion, so it is removed; Git's `bash` is put ahead of any other `bash` on `PATH`.
- **Measured** — Mega Man X4 (USA, 1.18 MB boot program) from its `.chd` on a 20-core machine with a warm toolchain: **203 s** end to end (code generation ~70 s → 148 shards, 8.1M lines of C, 8,984 dispatch entries; compile ~130 s), a 95 MB / 395-file game folder. Started with `--disc` pointing at the original `.chd`, the game's launcher opened, and after *Play* the native window ran at 60 Hz and rendered the game's intro. Not yet verified: playing past the intro, audio, and any other title — PSXRecomp itself says validation varies by game.
- **Cache** — `%LOCALAPPDATA%\AuraDecompTool\psxrecomp` (override with `--cache DIR` or `AURA_PS1_BUILD_CACHE`). Cancelling kills the whole process tree.
- **Licence note** — PSXRecomp is PolyForm Noncommercial 1.0.0. Aura fetches it at your request and never bundles it. The generated program contains code translated from your disc: keep it to yourself.
- **Also relevant: PsyCross** ([OpenDriver2](https://github.com/OpenDriver2/PsyCross), MIT; [SlickAmogus fork](https://github.com/SlickAmogus/PsyCross) tuned for Silent Hill) reimplements the PSY-Q SDK so a game's *decompiled source* can be built for PC. It is not part of this disc-to-exe pipeline, which has no source; it would suit a future "build a matching decompilation" backend.

### Interactive Call Graph
- **D3.js-ready data** — Produces a JSON-serializable graph (nodes + edges) optimized for force-directed visualization in the web UI. Each node carries function name, address, size, library attribution, call count, called-by count, and entry-point/external flags. Each edge carries source/target IDs, callsite address, and call kind (jal/jump).
- **Graph statistics** — Includes summary stats: total/named/external function counts, total edges, max call depth (BFS from entry point), detected libraries, and top-20 hub functions (ranked by call + called-by score).
- **SDK integration** — Nodes with SDK-matched names carry their library attribution (e.g. `vpad`, `libc`, `coreinit`), enabling library-colored rendering in the frontend.
- **Tauri command** — `get_interactive_call_graph(path)` returns the complete graph structure for D3.js rendering.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + TypeScript + Vite + Tailwind CSS |
| Desktop Shell | Tauri 2 (Rust) — native window, file dialogs, and shell integration |
| Binary Parsing | Custom MIPS ELF32 parser in Rust (no external dependencies beyond `sha1`) |
| Symbol Matching | Embedded SCE SDK database (~12 MB trie + symbol records), compiled into the binary at build time via `include_str!` |

---

## Getting Started

### Prerequisites

- **Node.js** 18+ and npm
- **Rust** 1.70+ ([rustup](https://rustup.rs/) recommended)
- **Git** (for cloning)

### Installation & Build

```bash
# Clone the repository
git clone <repo-url>
cd Aura-Decomp-Tool

# Quick build (frontend + native app)
.\build.bat
```

Or step by step:

```bash
# Install frontend dependencies
npm install

# Build the Rust binary and bundle the app
npm run tauri build
```

The packaged installer will be available at `src-tauri/target/release/bundle/nsis/`.

### Development

```bash
# 1. Install frontend dependencies first (one time, after clone)
npm install

# 2. Starts the Vite dev server automatically, then opens the Tauri window
npm run tauri dev

# Frontend-only development (browser preview; backend commands won't run here)
npm run dev
```

> **'vite' is not recognized?** That just means `npm install` hasn't been run
> yet — `vite` lives in `node_modules`. Run `npm install` once, then
> `npm run tauri dev` again.
>
> The UI talks to the backend exclusively through Tauri `invoke` commands, so
> most features need the desktop shell (`npm run tauri dev`). A plain-browser
> `npm run dev` renders the layout + theme but shows a friendly
> "backend unavailable" state until the shell hosts it.
>
> `tauri.conf.json` wires `beforeDevCommand` → `npm run dev` and
> `devUrl` → `http://localhost:1420`, so a plain `npm run tauri dev` works out
> of the box; `beforeBuildCommand` ensures `dist/` exists for
> `npm run tauri build`.

### Verify the backend without a webview

The Tauri crate can't be compiled in CI/sandboxes (no GTK/WebKit). The
standalone harness in `/tmp/xcheck` verifies the backend two ways, using fake
`tauri`/`tauri-plugin-dialog`/`tauri-plugin-shell` crates + real `tokio`:

- `cargo build --bin fullapp -p fullapp` — type-checks the **real
  `src-tauri/src/main.rs`** (with every backend module) exactly as a real build
  does: `#[tauri::command]` signatures, `generate_handler!` command list,
  ELF/GB disassembly, exports, and all cross-module paths.
- `cargo test --bin xcheck` — runs 15 smoke tests covering LZX decoding, PPC
  disassembly, SDK symbol matching, decomp-project export, interactive call
  graph, and the PS1 symbol scanner.

The full `tauri build` (webview bundling + installer) still must be run on a
real desktop machine — on Windows that's automatic; on macOS/Linux install the
system webview libraries listed earlier.

---

## User Interface Overview

Aura ships as a single-page React 18 + TypeScript + Tailwind app with a sidebar
that drives seven views:

| View | What it does | Main backend commands |
|------|---------------|-----------------------|
| **Home / Open** | Open a file (native dialog or path), list supported formats, auto-identify the container and route it to the right parser. | `open_file_dialog`, `open_file`, `identify_file`, `get_supported_formats` |
| **Binary info** | File type / magic, endianness, entry point, and the full section table with address + size + code/data role. | `parse_elf_file`, `parse_xbe_file`, `parse_xex_file`, `parse_wiiu_file`, `parse_ps3_file`, `parse_ps4ps5_file`, `identify_gb_rom` |
| **Disassembly** | Pick a code section and disassemble it — big-endian PPC (Xbox 360/Wii U/PS3), 32/64-bit x86 (Xbox/PS4/PS5), MIPS (PS1/PS2) or Z80 (GameBoy). Also lists detected functions. | `disassemble_xex`, `disassemble_wiiu_section`, `disassemble_ps3_section`, `disassemble_ps4ps5_section`, `disassemble_xbe`, `disassemble_section`, `disassemble_gb_rom`, `detect_functions`, `read_raw_binary` |
| **Call graph** | Interactive D3.js force-directed graph of detected functions, colored by library, with click-through callers/callees, hub ranking and stats. | `get_interactive_call_graph`, `get_call_graph` |
| **SDK scan** | Match binary import names against the 346-entry cross-platform SDK database (auto-naming + library attribution) with a per-platform DB coverage overview. | `scan_sdk_symbols`, `get_sdk_db_stats` |
| **Export project** | One-click decomp project export (config.toml, functions.csv, symbol_addrs.txt, undefined_syms.txt, splat.yaml, Makefile, README) plus a ps2recomp config bundle. | `export_decomp_project`, `generate_config_toml`, `pick_output_folder` |
| **PS1 analysis** | String extraction, LUI+ORI constant pools, interrupt-handler & state-machine heuristics, PS1 SDK symbol references, enhanced call graph and recomp config. | `analyze_ps1_binary`, `scan_ps1_symbols`, `get_enhanced_call_graph`, `generate_ps1_recomp_config` |

Every view is reachable from the sidebar and, when applicable, is pre-populated
with the currently loaded file. The call graph view is ELF-backed (PS1/PS2);
the other platforms show a note until that backend path is extended.

### Theming

The window honours the `<html data-theme>` attribute with four themes —
**Midnight** (default), **Aurora**, **Synthwave** and **Carbon**. Use the
switcher in the top-right; the choice persists in `localStorage` and is applied
before first paint (no flash).

---

## Project Structure

```
Aura-Decomp-Tool/
├── src/                      # React frontend (single-page app)
│   ├── main.tsx              # React entry point
│   ├── App.tsx               # App shell: sidebar + header + theme switcher + view router
│   ├── index.css             # Theme CSS variables + Tailwind directives
│   ├── types.ts              # Typings mirroring every backend command return
│   ├── lib/
│   │   ├── tauri.ts          # invoke wrapper + binary probe/router + disasm dispatch
│   │   ├── ingest.ts         # disc-wizard commands, progress + drag-drop events
│   │   ├── themes.ts         # data-theme switcher (midnight/aurora/synthwave/carbon)
│   │   ├── format.ts         # hex/byte formatting helpers
│   │   └── FileContext.ts    # React context holding the currently-loaded binary
│   └── components/
│       ├── Sidebar.tsx       # navigation (7 views)
│       ├── ThemeSwitcher.tsx # theme picker
│       ├── ui.tsx            # shared Panel/Button/Stat/Spinner primitives
│       ├── HomeView.tsx      # file open + supported formats
│       ├── BinaryView.tsx    # summary + section table
│       ├── DisasmView.tsx    # code-section disassembly + detected functions
│       ├── CallGraphView.tsx # D3.js force-directed call graph + node detail
│       ├── callgraph/ForceGraph.tsx
│       ├── SdkScanView.tsx   # SDK symbol scan + DB coverage
│       ├── ExportView.tsx    # decomp project + ps2recomp config export
│       ├── IsoWizardView.tsx # one-click disc wizard (first-run landing page)
│       └── Ps1View.tsx       # PS1 analysis + symbols + enhanced graph
├── src-tauri/                # Rust backend
│   ├── src/
│   │   ├── main.rs           # Tauri commands + generate_handler register
│   │   ├── disc.rs           # streaming ISO9660 disc-image reader + extractor
│   │   ├── ps2_package.rs    # double-click game folder: exe + disc tree + launcher
│   │   ├── ps2_build.rs      # one-click build: toolchain, pinned upstream, recompile, runtime exe
│   │   ├── build_common.rs   # shared process runner (progress, cancel, tree-kill), pinned git checkout
│   │   ├── chd_disc.rs       # CHD reader: first data track as a sector stream, cue/bin export
│   │   ├── psx_exe.rs        # PS-X EXE header parsing
│   │   ├── ps1_ingest.rs     # PS1 disc -> workspace (cue/bin + manifest)
│   │   ├── ps1_build.rs      # PSXRecomp driver: toolchain, setup script, packaging
│   │   ├── launcher_core.rs  # shared by the aura-launch binary (cli/src/launch.rs)
│   │   ├── ps2_ingest.rs     # PS2 disc -> boot ELF -> ps2_recomp project pipeline
│   │   ├── lzx.rs            # pure-Rust LZX decompressor (Xbox 360 XEX)
│   │   ├── xbox.rs           # Original Xbox XBE parser + 32-bit x86 disasm
│   │   ├── xbox360.rs        # Xbox 360 XEX parser + BE PPC disasm
│   │   ├── wiiu.rs           # Wii U RPX/RPL parser (PPC64)
│   │   ├── ps3.rs            # PS3 SELF/ELF parser (PPC)
│   │   ├── ps4ps5.rs         # PS4/PS5 SELF/ELF parser (x86-64)
│   │   ├── sdk_symbols.rs    # 346-entry cross-platform SDK symbol DB
│   │   ├── decomp_export.rs  # one-click decomp project export
│   │   ├── call_graph.rs     # D3.js-ready interactive call graph
│   │   └── ppc_disasm.rs     # shared big/little-endian PowerPC decoder
│   ├── Cargo.toml            # Rust dependencies
│   └── tauri.conf.json       # Tauri app configuration
├── docs/
├── build.bat                 # Windows one-click build script
└── package.json              # Node.js project manifest (React + vite + tailwind + d3)
```

---

## Supported Formats

| Format | Extension | Notes |
|--------|-----------|-------|
| ELF32 (MIPS BE) | `.elf` | PS1/PS2 big-endian MIPS binaries |
| ELF32 (MIPS LE) | `.elf` | PS2 little-endian MIPS binaries |
| Raw binary | `.bin`, `.dat`, `.img` | Loaded at conventional base address |
| PlayStation EXE | `.bin` | PS-X EXE format (base `0x00010000`) |

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+O` | Open file dialog |
| `1`–`9` | Jump to a sidebar view (1=Home, 2=Binary info, 3=Disasm, 4=Hex, 5=Call graph, 6=CFG/xrefs, 7=Decompiler, 8=Project, 9=Search). Views that need a loaded file are skipped when none is open. |
| `Ctrl+F` | Search & strings |
| `Ctrl+G` | Go to disassembly |
| `Ctrl+Shift+G` | Call graph |
| `Ctrl+Shift+X` | CFG & xrefs |
| `Ctrl+E` | Decompiler |
| `?` | Show the keyboard-shortcuts overlay (Esc to close) |

Single-key shortcuts are suppressed while typing in a text field so they never hijack input.

---

## License

## License

**GNU General Public License v3.0 (GPL-3.0)** — see [LICENSE](LICENSE).

Aura is free and open-source software. This mirrors the licensing of the
console-reversing ecosystem it's built on (ps2recomp, OpenOrbis, and the
`ps4_module_loader`/aerolib project, whose NID database Aura embeds). You are
free to use, study, modify, and redistribute it under the terms of GPL-3.0.

---

## CLI / headless (`aura-cli`)

The same analysis engine is available as a standalone command-line binary, ideal for scripting, CI, and headless servers — with **zero GUI runtime** (it compiles without Tauri/webview).

```
aura-cli info eboot.bin --json
aura-cli sections game.elf --json
aura-cli disasm game.elf --section .text --out out.asm
aura-cli sdk-scan game.elf --platform PS2 --json
aura-cli callgraph game.elf
aura-cli cfg game.elf --json
aura-cli xrefs game.elf --at 0x80123456 --json
aura-cli decompile game.elf --at 0x80123456
aura-cli decompile game.elf --json --max 100
aura-cli decompile-ppc ps3.elf --json
aura-cli project game.elf --section save --out game.aura
aura-cli project game.elf --section apply --out game.aura --json
aura-cli script game.elf --script rename.lua --out game.aura --json
aura-cli strings game.elf --json
aura-cli search game.elf --section string --at "HELLO"
aura-cli search game.elf --section pattern --at 0x0F 0x00
aura-cli string-xrefs game.elf --json
aura-cli patch-export game.elf --out game.aura --section game_patched.elf
aura-cli export game.elf --platform PS4 --out ./decomp
aura-cli formats --json
aura-cli sdk-db --json
aura-cli nid-db --json
aura-cli ps4-nid-scan eboot.bin --json
aura-cli disc-info game.iso --json
aura-cli disc-ls game.iso
aura-cli disc-extract game.iso --out ./disc        # executables only; add --all for everything
aura-cli ps2-ingest game.iso --out ./games          # one-click: extract + analyse + ps2_recomp project
aura-cli ps2-ingest game.iso --out ./games --recompiler /path/to/ps2_recomp
aura-cli ps2-package ./games/SLUS-20312 --exe /path/to/built/ps2EntryRunner.exe   # -> ./games/SLUS-20312/package
aura-cli ps2-build ./games/SLUS-20312 --plan                                     # what a build would download/do
aura-cli ps2-build ./games/SLUS-20312 --yes                                      # one click: compile + package
aura-cli ps1-ingest "Game (USA).chd" --out ./games                               # PS1: CHD/cue/bin/iso -> workspace
aura-cli ps1-build ./games/SLUS-00561 --plan                                     # what a PS1 build would download
aura-cli ps1-build ./games/SLUS-00561 --yes                                      # one click: native PS1 game
```

Commands: `info`, `sections`, `disasm`, `sdk-scan`, `ps4-nid-scan`, `callgraph`, `cfg`, `xrefs`, `decompile`, `decompile-ppc`, `project`, `script`, `strings`, `search`, `string-xrefs`, `patch-export`, `export`, `formats`, `sdk-db`, `nid-db`, `disc-info`, `disc-ls`, `disc-extract`, `ps2-ingest`, `ps2-package`, `ps2-build`, `ps1-ingest`, `ps1-build`. Common flags: `--json`, `--out PATH`, `--section NAME` (section name / project action / search kind / patch output), `--at ADDR` (for xrefs/decompile/search), `--script PATH`, `--platform NAME`, `--max N`, `--all` (disc-extract / ps2-ingest: whole disc), `--recompiler PATH` (ps2-ingest), `--exe PATH` / `--launcher PATH` / `--copy` (ps2-package), `--plan` / `--yes` / `--cache DIR` / `--no-package` / `--jobs N` / `--fast` / `--upstream-defaults` (ps2-build; `--plan/--yes/--cache/--no-package/--jobs` also apply to ps1-build). Exit codes: **0** ok, **1** analysis error, **2** usage error. Set `AURA_SCE_DB_DIR` to a directory with `symbols.json` + `tree.json` to extend the SDK symbol database; set `AURA_PS4_NID_DB` to an `aerolib.csv` to override the embedded PS4/PS5 NID database; set `AURA_PS2RECOMP` to the path of a `ps2_recomp` binary so the wizard/CLI can find it without `PATH`; set `AURA_LAUNCHER` to an `aura-launch` binary if it is not beside the program running the packaging; set `AURA_BUILD_CACHE` (PS2) or `AURA_PS1_BUILD_CACHE` (PS1) to move the one-click build cache.

Build it with `./build.bat` (Windows) or `./build.sh` (Unix) — it produces `cli/target/release/aura-cli`.
