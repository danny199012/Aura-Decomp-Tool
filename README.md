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

---

## Project Structure

```
Aura-Decomp-Tool/
├── src/                      # React frontend
│   ├── App.tsx               # Main application component (UI, disassembly, state management)
│   └── index.css             # Theme CSS variables and Tailwind directives
├── src-tauri/                # Rust backend
│   ├── src/
│   │   ├── main.rs           # Tauri commands: ELF parsing, function detection, call graph, config export
│   │   └── sce_symbol_scanner.rs  # SCE SDK symbol matcher (trie + SHA-1 pipeline)
│   ├── resources/sce_sdk/    # Embedded symbol database (symbols.json + tree.json)
│   ├── Cargo.toml            # Rust dependencies
│   └── tauri.conf.json       # Tauri app configuration
├── scripts/                  # Build/utility scripts
├── build.bat                 # Windows one-click build script
└── package.json              # Node.js project manifest
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
