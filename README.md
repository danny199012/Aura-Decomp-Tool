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

### Call Graph Analysis
- Builds a directed graph of all direct `JAL`/`J` call edges across detected functions.
- Enriches external targets with import names via dynamic relocations (`R_MIPS_26`).
- Identifies unreachable functions (potential stubs, interrupt handlers, or dead code).

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

### PlayStation 4 & PlayStation 5 (SELF / ELF)
- **LE ELF64 x86-64 parsing** — Little-endian ELF64 with e_machine = EM_X86_64 (62) for homebrew executables. Sections, entry point, and ORBIS ELF note detection.
- **SELF wrapper parsing** — Identifies the SCE magic, scans for the embedded ELF, and parses it when unencrypted. Retail PS4/PS5 SELFs are key-gated and return a graceful error.
- **x86-64 disassembly** — 64-bit Intel-syntax disassembly via `iced-x86` (reusing the same crate as the OG Xbox 32-bit decoder, at bitness 64).

### Cross-Platform SDK Symbol Database
- **Auto-naming** — A built-in database of 346+ SDK function names across all supported platforms (PS1, PS2, PS3, PS4/PS5, Xbox, Xbox 360, Wii U, GameCube/Wii). When a binary is loaded, import-table names are matched against the database, instantly identifying functions like `VPADRead`, `cellPadInit`, `NtCreateFile`, `GX2Init`, etc. — no manual symbol import required.
- **Library detection** — Matched functions are attributed to their source library (e.g. `coreinit`, `libcd`, `xboxkrnl`, `libScePad`), giving an instant overview of which SDKs the binary uses.
- **Multi-method matching** — By name (import tables, .fimports, .dynsym), by ordinal (Xbox kernel thunk tables), and by instruction-pattern signature (common libc functions like memcpy/memset/strlen on all platforms).
- **Tauri commands** — `scan_sdk_symbols(path, platform)` returns matched symbols with descriptions; `get_sdk_db_stats(platform)` returns database coverage per platform.

### One-Click Decomp Project Export
- **Complete project scaffold** — Generates a ready-to-build decomp project in one click: `config.toml` (recompiler config), `functions.csv` (Name,Start,End,Size), `symbol_addrs.txt` (address to name mappings), `undefined_syms.txt` (unnamed function addresses), `splat.yaml` (segment splitter config), `build/Makefile` (platform-aware toolchain), and `README.md` (project-specific instructions with named function list and section table).
- **Platform-aware build** — The Makefile auto-selects the correct cross-compiler toolchain (mips-elf for PS1/PS2, ppu-lv2 for PS3, powerpc-eabi for Wii U/GameCube, x86_64 for PS4/PS5, etc.).
- **splat-compatible** — The `splat.yaml` output is structured for use with the popular [splat](https://github.com/ethteck/splat) segment splitter, with per-function subsegments in code sections.
- **Tauri command** — `export_decomp_project(path, platform, output_dir)` writes all files and returns a summary with function counts and named/SDK-matched statistics.

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
# Start the dev server with hot-reload (Tauri window)
npm run tauri dev

# Frontend-only development (browser preview)
npm run dev
```

> The UI talks to the backend exclusively through Tauri `invoke` commands, so
> most features need the desktop shell (`npm run tauri dev`). A plain-browser
> `npm run dev` renders the layout + theme but shows a friendly
> "backend unavailable" state until the shell hosts it.

### Verify the backend without a webview

The Tauri crate can't be compiled in CI/sandboxes (no GTK/WebKit). Use the
standalone harness in [`/tmp/xcheck`] to type-check the backend modules and run
their smoke tests with a fake `#[tauri::command]` proc-macro:

```bash
cd /tmp/xcheck && cargo run && cargo test
```

The full `tauri build` (webview bundling) must be run on a real desktop machine.

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
│       └── Ps1View.tsx       # PS1 analysis + symbols + enhanced graph
├── src-tauri/                # Rust backend
│   ├── src/
│   │   ├── main.rs           # Tauri commands + generate_handler register
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

---

## License

Private — Aura Project
