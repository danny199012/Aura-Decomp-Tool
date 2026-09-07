//! `aura_cli` — shared analysis library + command-line interface for the
//! Aura Decomp Tool.
//!
//! # Architecture
//! This crate is a **library + binary**. The library (`lib.rs`) is the single
//! source of truth for the analysis engine: it `#[path]`-includes the exact
//! same modules the Tauri GUI (`src-tauri/src/main.rs`) uses, re-exporting
//! them as a clean `pub` API. The binary (`main.rs`) is a thin shell that
//! parses arguments and dispatches to the library — it contains *no* analysis
//! logic of its own.
//!
//! This eliminates the fragile `#[path]` duplication that previously lived in
//! `main.rs`: the module wiring now exists in exactly one place, and the test
//! suite (`tests`) compiles against the library's public API.
//!
//! Building without Tauri: because the analysis modules are pure Rust (no
//! `tauri` dependency), this crate compiles on any platform with a Rust
//! toolchain and produces a tiny standalone `aura-cli` binary.

#![allow(dead_code, clippy::too_many_arguments)]

#[path = "../../src-tauri/src/engine.rs"]
pub mod engine;
pub use engine::*;

#[path = "../../src-tauri/src/ps4ps5.rs"] pub mod ps4ps5;
#[path = "../../src-tauri/src/ps3.rs"] pub mod ps3;
#[path = "../../src-tauri/src/wiiu.rs"] pub mod wiiu;
#[path = "../../src-tauri/src/xbox.rs"] pub mod xbox;
#[path = "../../src-tauri/src/xbox360.rs"] pub mod xbox360;
#[path = "../../src-tauri/src/gamecube.rs"] pub mod gamecube;
#[path = "../../src-tauri/src/lzx.rs"] pub mod lzx;
#[path = "../../src-tauri/src/ppc_disasm.rs"] pub mod ppc_disasm;
#[path = "../../src-tauri/src/ps1_exe.rs"] pub mod ps1_exe;
#[path = "../../src-tauri/src/ps1_memory_map.rs"] pub mod ps1_memory_map;
#[path = "../../src-tauri/src/ps1_disasm.rs"] pub mod ps1_disasm;
#[path = "../../src-tauri/src/call_graph.rs"] pub mod call_graph;
#[path = "../../src-tauri/src/cfg.rs"] pub mod cfg;
#[path = "../../src-tauri/src/decomp.rs"] pub mod decomp;
#[path = "../../src-tauri/src/project.rs"] pub mod project;
#[path = "../../src-tauri/src/search.rs"] pub mod search;
#[path = "../../src-tauri/src/sdk_symbols.rs"] pub mod sdk_symbols;
#[path = "../../src-tauri/src/sce_symbol_scanner.rs"] pub mod sce_symbol_scanner;
#[path = "../../src-tauri/src/decomp_export.rs"] pub mod decomp_export;
#[path = "../../src-tauri/src/ps1_symbols.rs"] pub mod ps1_symbols;

#[cfg(test)]
mod tests;
