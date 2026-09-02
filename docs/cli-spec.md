# Aura Decomp Tool — CLI / Headless Spec

> Status: **proposal** (not yet implemented)
> Goal: give Aura a command-line / headless interface so it can be scripted,
> CI'd, and used in the same automated ways Ghidra's headless analyzer is used.

---

## 1. What "CLI / headless" means

Today Aura is a **GUI app**: you click in a window; a human has to be present.

- **CLI (command-line interface)** — a program you run by typing a command in
  PowerShell / terminal, no window:
  ```powershell
  aura info game.elf
  aura disasm game.elf --section .text --out asm.txt
  aura export game.elf --platform PS4 --out .\decomp
  aura sdk-scan game.elf --platform PS2 --json
  ```
- **Headless** — running with no display at all (a server, a CI runner, a script).

They're the same thing for us: a second entry point that reuses Aura's existing
Rust analysis engine and prints / writes results instead of rendering a UI.

## 2. Why it matters for the "move away from Ghidra" goal

Ghidra's **headless analyzer** is one of the biggest reasons teams adopt it —
you can run `analyzeHeadless` over thousands of binaries on a build server.
If Aura has no CLI, anyone who needs automation has to keep Ghidra around for
that one job. A CLI removes the last blocker:

- batch-processing a whole library of ROMs / executables
- CI: auto-disassemble + export every commit
- research pipelines: feed Aura output (JSON) into other tools
- server / cloud usage with no desktop

## 3. Current architecture (what we're working with)

```
src-tauri/
  Cargo.toml            # single binary crate, package "aura-decomp-tool"
  src/
    main.rs             # THE binary. mod * for every module + #[tauri::command]
                        # wrappers + tauri::Builder + fn main()
    ps4ps5.rs           # parse_ps4ps5(data, filename) -> Ps4Ps5FileInfo  [pub]
    ps3.rs              # parse_ps3(data, filename) -> Ps3FileInfo       [pub]
    wiiu.rs             # parse_rpx_rpl(data, filename) -> WiiUFileInfo  [pub]
    xbox.rs             # parse_xbe(data, filename) -> XbeFileInfo       [pub]
    xbox360.rs          # parse_xex(data, filename) -> XexFileInfo       [pub]
    decomp_export.rs    # generate_decomp_project(...)                   [pub]
    call_graph.rs, sdk_symbols.rs, ppc_disasm.rs, ps1_* , gamecube.rs, ...
```

**Good news:** the analysis engine is already split into standalone `.rs` files
with pure functions that take `(&[u8], &str)` and return `Result<_, String>`.
The `#[tauri::command]` wrappers are thin — they read the file, call the pure
function, return the struct. A CLI can call the exact same functions.

**The one real friction point:** there is **no `lib.rs`**. The module files use
`crate::...` paths (e.g. `crate::ElfSection`, `crate::parse_elf_file`,
`crate::ppc_disasm`) that only resolve inside the *binary* crate. To add a
second binary we must first expose the shared code as a library.

## 4. The approaches & trade-offs

### Approach A — new library + separate CLI binary (recommended)

1. Create `src-tauri/src/lib.rs` that declares `pub mod ps4ps5;`, `pub mod ps3;`,
   … and re-exports the shared types/functions the GUI's `main.rs` also needs
   (move `parse_elf_data`, `detect_functions_inner`, `build_config_toml`,
   structs `ElfSection`/`ElfFileInfo`/etc. into the lib).
2. `main.rs` becomes a thin Tauri shell that consumes the library
   (`use aura_decomp_tool::…`) instead of declaring modules itself.
3. Add `src-tauri/src/bin/aura-cli.rs` — a plain Rust binary (no Tauri deps)
   that also consumes the library and implements subcommands.

**Pros**
- Clean, idiomatic Rust; GUI and CLI share *one* code path → identical behavior.
- `aura-cli` builds without any Tauri/webview/system libs → compiles fast,
  cross-compiles easily, and can be built **in this sandbox** for real tests.
- Output formats (JSON/text) belong to the CLI layer; engine stays UI-agnostic.
- Doesn't change the GUI app for existing users at all.

**Cons**
- One-time refactor: converting a single binary crate into lib+bin touches
  `mod` declarations and `crate::` paths (mostly mechanical, ~a few hours).
- Bigger diff; needs a careful pass so the GUI still compiles unchanged.

**Cost estimate:** refactor ~half a day; CLI subcommands ~1–2 days.

### Approach B — headless flag inside the existing GUI binary

Keep one binary; detect `--cli` in `fn main()` and run a command-line path
before `tauri::Builder` starts, or skip the GUI entirely.

**Pros**
- Smallest change: no lib refactor, no new binary target. Just an early
  `args()` check at the top of `fn main()`.
- Ships as one `.exe`.

**Cons**
- The binary still depends on all of Tauri (big compile, GTK/WebView libs on
  Linux, bigger exe). "Headless" still needs Tauri built.
- Cannot compile/test the CLI in this sandbox.
- Messy long-term: GUI concerns (dialogs, windows, plugins) stay coupled to
  the CLI path; hard to grow a clean subcommand surface.

**Cost estimate:** ~1 day but with ceiling; not the right foundation.

### Approach C — separate CLI crate (workspace)

Move shared code into a new shared crate that both the GUI and `aura-cli`
depend on.

**Pros**
- Strongest isolation; third parties could embed Aura as a library.
- Neither binary can accidentally tangle.

**Cons**
- Biggest restructuring; most Cargo plumbing; most churn for zero user-visible
  benefit right now. Better as a *later* step once a CLI exists.

**Recommendation: Approach A.** It gives the cleanest growth path, is fully
testable here, and is a modest mechanical refactor. Approach C can come later.

## 5. Proposed CLI command surface (v1)

```
aura <command> [options] <file>

Commands
  info <file>                Show file identification + section table
  sections <file>            List sections (address/size/type)
  disasm <file> [--section NAME] [--max N]   Disassemble a section
                             (default: first code section, 5000 insns)
  sdk-scan <file> --platform NAME [--json]   Run SDK symbol matching
  callgraph <file> [--json]  Print call graph (nodes/edges/stats)
  export <file> --platform NAME --out DIR    Write full decomp project
  formats                   List supported formats

Global options
  --json            machine-readable output (JSON) where supported
  --out PATH        write output to file (default: stdout)
  --debug           verbose diagnostics
  -h, --help        help
  -V, --version     version
```

Exit codes: `0` success, `1` analysis error, `2` usage error — so scripts
and CI can branch on failure cleanly.

Example flows:
```powershell
# One-liner info dump
aura info eboot.bin --json

# Batch disassemble every PS2 ELF in a folder
Get-ChildItem *.elf | ForEach-Object { aura disasm $_.FullName --out "$($_.BaseName).asm" }

# CI export
aura export game.elf --platform PS2 --out .\decomp
```

## 6. What maps to what (reuse matrix)

| CLI command          | Existing function(s)                                        |
|----------------------|-------------------------------------------------------------|
| `info` / `sections`  | `identify_file` logic + `parse_ps4ps5` / `parse_ps3` / `parse_rpx_rpl` / `parse_xbe` / `parse_xex` / `parse_elf_data` |
| `disasm`             | `disassemble_*_section` per platform (iced-x86 / ppc_disasm / mips) |
| `sdk-scan`           | `scan_sdk_symbols` / `sdk_symbols::match_by_names`          |
| `callgraph`          | `get_call_graph` + `call_graph::build_interactive_graph`    |
| `export`             | `export_decomp_project` body (already platform-routing)     |
| `formats`            | `get_supported_formats`                                     |

## 7. Packaging / distribution

- `cargo build --release` produces `aura-cli` (Windows: `aura-cli.exe`) next to
  the existing GUI binary — no extra runtime needed.
- Optional later: ship as a standalone `aura.exe` via a tiny wrapper, or release
  both binaries in the same GitHub release.

## 8. Risks & gotchas

- **GUI regression risk** from the lib refactor → mitigate by keeping the
  refactor purely mechanical and running `cargo check` for the GUI where a
  Tauri-capable machine is available before shipping.
- **SDK DB loading** (`sce_db`) is lazy + `OnceLock` in main.rs; must move with
  the code and keep the same embedded resource path so CLI parity is exact.
- **Paged/IO behaviors** (hex view paging, dialog-based file pickers) are
  GUI-only and intentionally not part of the CLI.
- **Windows/Linux parity** — CLI is a normal Rust binary, so it should build
  on all three platforms with no extra system deps (unlike the GUI).

## 9. Suggested rollout

1. **Phase 1:** lib refactor (mechanical) — GUI still builds & runs identically.
2. **Phase 2:** `aura-cli` with `info`, `sections`, `disasm`, `export`
   (text output). Verified in sandbox with existing harness fixtures. Push.
3. **Phase 3:** `--json` output for `info`/`sections`/`sdk-scan`/`callgraph`.
4. **Phase 4:** packaging (release both binaries) + README/CLI docs.

Each phase is independently shippable; the user can use the CLI as soon as
Phase 2 lands.

## 10. Open questions for the user

- Command name: `aura` vs `aura-cli` vs `aura-decomp`?
- Do you want JSON output from day one (pull Phase 3 earlier)?
- Should `export` also emit the new `functions.json`/`symbols.idc` in CLI mode
  (it will, since it's the same engine)?
- Windows-only first, or all platforms (macOS/Linux) in the first release?