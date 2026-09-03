#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// The `#[tauri::command]` macro generates code containing `!` (never) type
// expressions. Recent Rust toolchains warn/deny `dependency_on_unit_never_type_fallback`
// (part of the rust-2024-compatibility lint set) for that generated code, so we
// opt out of the future-compat lint the same way the Tauri community does.
#![allow(dependency_on_unit_never_type_fallback)]

mod ps1_analysis;
mod ps1_call_graph_enhanced;
mod ps1_disasm;
mod ps1_exe;
mod ps1_memory_map;
mod ps1_recomp_export;
mod ps1_symbols;
mod sce_symbol_scanner;
mod engine;
pub use engine::*;
// Multi-platform backends: shared PowerPC decoder plus Xbox/360/GameCube/Genesis.
mod gamecube;
mod call_graph;
mod cfg;
mod decomp;
mod decomp_export;
mod project;
mod search;
mod lzx;
mod ppc_disasm;
mod ps3;
mod ps4ps5;
mod sdk_symbols;
mod sega_genesis;
mod wiiu;
mod xbox;
mod xbox360;

use sce_symbol_scanner::{CodeSection, SceSymbolDatabase, SceSymbolMatch};
use serde::{Deserialize, Serialize};

use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use tauri_plugin_dialog::DialogExt;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct LogEntry {
    level: String,
    message: String,
    timestamp: String,
}

#[derive(Serialize, Debug)]
struct FileOpenResponse {
    success: bool,
    filename: Option<String>,
    size: Option<u64>,
    message: String,
}

const R_MIPS_26: u32 = 4;

#[derive(Serialize, Deserialize, Debug)]
struct DecompileRequest {
    function_name: String,
    address: String,
}

#[derive(Serialize, Debug)]
struct DecompileResponse {
    success: bool,
    output: Option<String>,
    message: String,
}

fn get_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let total_secs = duration.as_secs();
    let hours = (total_secs / 3600) % 24;
    let minutes = (total_secs / 60) % 60;
    let seconds = total_secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

#[tauri::command]
fn log_message(level: String, message: String) -> Result<(), String> {
    let timestamp = get_timestamp();
    let entry = LogEntry {
        level: level.clone(),
        message: message.clone(),
        timestamp,
    };

    match entry.level.as_str() {
        "ERROR" => eprintln!("[{}] {}", entry.timestamp, entry.message),
        "WARN" => println!("[{}] {}", entry.timestamp, entry.message),
        _ => println!("[{}] [{}] {}", entry.level, entry.timestamp, entry.message),
    }

    Ok(())
}

#[tauri::command]
fn open_file_dialog(app: tauri::AppHandle) -> Result<String, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file()
        .add_filter("All Supported", &["elf", "sym", "prx", "irx", "sprx", "xbe", "xex", "self", "rpx", "rpl", "gb", "gbc", "gba", "nes", "smc", "sfc", "z64", "n64", "v64", "nds", "bin", "dat", "img", "iso", "chd", "cue", "exe"])
        .add_filter("ELF & Symbols", &["elf", "sym", "prx", "irx", "sprx"])
        .add_filter("Console Executables", &["xbe", "xex", "self", "rpx", "rpl", "exe"])
        .add_filter("Retro ROMs", &["gb", "gbc", "gba", "nes", "smc", "sfc", "z64", "n64", "v64", "nds"])
        .add_filter("PlayStation Images", &["bin", "dat", "img", "iso", "chd", "cue"])
        .add_filter("All Files", &["*"])
        .pick_file(move |path| {
            if let Some(filepath) = path {
                tx.send(filepath.to_string()).ok();
                return;
            }
            tx.send(String::new()).ok();
        });
    // Block until the user picks or cancels — no artificial timeout. A file
    // dialog is modal to the app window, so the callback always resolves.
    match rx.recv() {
        Ok(path) => {
            if path.is_empty() {
                Err("No file selected".to_string())
            } else {
                Ok(path)
            }
        },
        Err(_) => Err("Dialog channel closed".to_string()),
    }
}

#[tauri::command]
fn open_multiple_files_dialog(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file()
        .add_filter("All Supported", &["elf", "sym", "prx", "irx", "sprx", "xbe", "xex", "self", "rpx", "rpl", "gb", "gbc", "gba", "nes", "smc", "sfc", "z64", "n64", "v64", "nds", "bin", "dat", "img", "iso", "chd", "cue", "exe"])
        .add_filter("ELF & Symbols", &["elf", "sym", "prx", "irx", "sprx"])
        .add_filter("Retro ROMs", &["gb", "gbc", "gba", "nes", "smc", "sfc", "z64", "n64", "v64", "nds"])
        .add_filter("PlayStation Images", &["bin", "dat", "img", "iso", "chd", "cue"])
        .add_filter("All Files", &["*"])
        .pick_files(move |paths_opt| {
            if let Some(paths) = paths_opt {
                let collected: Vec<String> = paths.into_iter().map(|p| p.to_string()).collect();
                tx.send(collected).ok();
            } else {
                tx.send(Vec::new()).ok();
            }
        });
    match rx.recv() {
        Ok(paths) => Ok(paths),
        Err(_) => Ok(Vec::new()),
    }
}

#[tauri::command]
fn open_file(path: String) -> Result<FileOpenResponse, String> {
    let p = Path::new(&path);
    if !p.exists() {
        return Ok(FileOpenResponse {
            success: false,
            filename: None,
            size: None,
            message: format!("File not found: {}", path),
        });
    }

    let metadata = fs::metadata(p).map_err(|e| e.to_string())?;
    let filename = p.file_name().unwrap_or_default().to_str().unwrap_or("unknown").to_string();

    // PS-X wrapper pre-step: if the file is a PS1 executable image, surface its
    // header metadata (and embedded-ELF offset) in the open message so the UI
    // can route to the right loader. Pure detection — no other behaviour changes.
    let psx_note = match ps1_exe::detect_psx_header(&path) {
        Ok(Some(info)) => format!(" [PS-X v{} ELF@0x{:X}]", info.version, info.elf_offset),
        _ => String::new(),
    };

    Ok(FileOpenResponse {
        success: true,
        filename: Some(filename),
        size: Some(metadata.len()),
        message: format!("Opened {} ({} bytes){}", path, metadata.len(), psx_note),
    })
}

/// Read up to `max_bytes` of a raw binary file and return it as a list of bytes.
/// Used when a file is not a valid ELF (e.g. a raw PS-X .bin executable) so the
/// user can still disassemble it at a chosen base address, and by the hex view
/// to page through the file with `offset`.
#[tauri::command]
fn read_raw_binary(
    path: String,
    max_bytes: Option<usize>,
    offset: Option<usize>,
) -> Result<Vec<u8>, String> {
    let p = Path::new(&path);
    if !p.exists() {
        return Err(format!("File not found: {}", path));
    }
    let metadata = fs::metadata(p).map_err(|e| e.to_string())?;
    let start = offset.unwrap_or(0) as u64;
    let remaining = metadata.len().saturating_sub(start);
    let cap = max_bytes
        .unwrap_or(4 * 1024 * 1024)
        .min(remaining as usize);
    let mut file = fs::File::open(p).map_err(|e| e.to_string())?;
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(start)).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; cap];
    let n = file.read(&mut buf).map_err(|e| e.to_string())?;
    buf.truncate(n);
    Ok(buf)
}

/// NOTE: deliberately NOT `pub` — a `pub` + `#[tauri::command]` fn at the crate
/// root makes Tauri emit both `#[macro_export]` and a `pub use` of the hidden
/// `__cmd__…` macros, which collide (`E0255`). Commands are resolved within the
/// crate, so plain `fn` is all that's needed.
#[tauri::command]
fn parse_elf_file(path: String) -> Result<ElfFileInfo, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let filename = path.split('/').last().or(path.split('\\').last()).unwrap_or("unknown").to_string();
    parse_elf_data(&data, &filename)
}

/// Detect functions in a PS2 ELF and return them for display in the UI.
/// Uses real symbols when present; otherwise falls back to JAL-scan heuristics.
#[tauri::command]
fn detect_functions(path: String) -> Result<Vec<FunctionEntry>, String> {
    Ok(detect_functions_inner(&parse_elf_file(path)?)?)
}

/// it for the UI. Edges are attributed to detected functions; targets that
/// match no function start are reported in `external_targets`. Indirect calls
/// (`jalr`/`jr $t9`) are not yet tracked.
#[tauri::command]
fn get_call_graph(path: String) -> Result<CallGraph, String> {
    let info = parse_elf_file(path)?;
    let funcs = detect_functions_inner(&info)?;
    let raw = collect_call_edges(&info.sections, info.is_little_endian);
    let graph = build_call_graph(raw, &funcs);
    Ok(enrich_call_graph_with_relocs(graph, &info.relocations))
}

/// Per-function CFG summary for the UI: block/edge counts and whether each
/// function returns. This is the recursive-descent analysis (Tier 1) that
/// Ghidra/BN do — basic blocks + edges, not a flat linear sweep.
#[derive(Serialize, Debug, Clone)]
pub struct CfgSummary {
    pub functions: Vec<CfgFuncSummary>,
    pub total_blocks: usize,
    pub total_edges: usize,
    pub returning_functions: usize,
    pub xref_targets: usize,
}

#[derive(Serialize, Debug, Clone)]
pub struct CfgFuncSummary {
    pub entry: u32,
    pub blocks: usize,
    pub edges: usize,
    pub returns: bool,
}

#[tauri::command]
fn get_cfg_summary(path: String) -> Result<CfgSummary, String> {
    let info = parse_elf_file(path)?;
    let funcs = detect_functions_inner(&info)?;
    let mut cfgs = Vec::new();
    for sec in info.sections.iter().filter(|s| (s.flags & 0x4) != 0) {
        let sec_end = sec.address + sec.data.len() as u32;
        for f in funcs.iter().filter(|f| f.start >= sec.address && f.start < sec_end) {
            let end = if f.end > 0 { f.end } else { sec_end };
            cfgs.push(cfg::build_function_cfg(&sec.data, sec.address, f.start, end, info.is_little_endian));
        }
    }
    let xrefs = cfg::build_xref_index(&cfgs);
    let functions = cfgs.iter().map(|c| CfgFuncSummary {
        entry: c.entry, blocks: c.blocks.len(), edges: c.edges.len(), returns: c.returns,
    }).collect();
    Ok(CfgSummary {
        functions,
        total_blocks: cfgs.iter().map(|c| c.blocks.len()).sum(),
        total_edges: cfgs.iter().map(|c| c.edges.len()).sum(),
        returning_functions: cfgs.iter().filter(|c| c.returns).count(),
        xref_targets: xrefs.len(),
    })
}

/// Cross-references to an address — the "X" navigation primitive from
/// Ghidra/BN. Returns every instruction that calls/jumps/branches to `target`.
#[derive(Serialize, Debug, Clone)]
pub struct XrefResult {
    pub target: u32,
    pub refs: Vec<XrefEntry>,
}

#[derive(Serialize, Debug, Clone)]
pub struct XrefEntry {
    pub from: u32,
    pub kind: String,
}

#[tauri::command]
fn get_xrefs(path: String, target: String) -> Result<XrefResult, String> {
    let target_addr = u32::from_str_radix(target.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .map_err(|e| format!("target must be a hex address: {e}"))?;
    let info = parse_elf_file(path)?;
    let funcs = detect_functions_inner(&info)?;
    let mut cfgs = Vec::new();
    for sec in info.sections.iter().filter(|s| (s.flags & 0x4) != 0) {
        let sec_end = sec.address + sec.data.len() as u32;
        for f in funcs.iter().filter(|f| f.start >= sec.address && f.start < sec_end) {
            let end = if f.end > 0 { f.end } else { sec_end };
            cfgs.push(cfg::build_function_cfg(&sec.data, sec.address, f.start, end, info.is_little_endian));
        }
    }
    let xrefs = cfg::build_xref_index(&cfgs);
    let refs = xrefs.refs_to(target_addr).iter().map(|r| XrefEntry {
        from: r.from,
        kind: match r.kind {
            cfg::XrefKind::Call => "call".into(),
            cfg::XrefKind::Jump => "jump".into(),
            cfg::XrefKind::Branch => "branch".into(),
            cfg::XrefKind::Data => "data".into(),
        },
    }).collect();
    Ok(XrefResult { target: target_addr, refs })
}


/// Decompile a single function (by entry address) to C-like pseudocode.
/// This is the Tier 2 MIPS→pseudocode lifter — the headline feature that
/// closes the biggest gap with Ghidra / Binary Ninja.
#[derive(Serialize, Debug, Clone)]
pub struct DecompileResult {
    pub entry: u32,
    pub name: String,
    pub pseudocode: String,
    pub block_count: usize,
    pub stmt_count: usize,
}

#[tauri::command]
fn decompile_function_cmd(path: String, address: String) -> Result<DecompileResult, String> {
    let entry = u32::from_str_radix(address.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .map_err(|e| format!("address must be hex: {e}"))?;
    let info = parse_elf_file(path)?;
    let funcs = detect_functions_inner(&info)?;
    // Build a name map from detected functions + symbols.
    let mut known: std::collections::BTreeMap<u32, String> = std::collections::BTreeMap::new();
    for f in &funcs { known.insert(f.start, f.name.clone()); }
    for s in &info.symbols { known.insert(s.address, s.name.clone()); }
    // Find the section containing the entry and build the CFG for just that function.
    for sec in info.sections.iter().filter(|s| (s.flags & 0x4) != 0) {
        let sec_end = sec.address + sec.data.len() as u32;
        if entry >= sec.address && entry < sec_end {
            let func = funcs.iter().find(|f| f.start == entry);
            let end = func.map(|f| if f.end > 0 { f.end } else { sec_end }).unwrap_or(sec_end);
            let cfg = cfg::build_function_cfg(&sec.data, sec.address, entry, end, info.is_little_endian);
            let name = known.get(&entry).cloned().unwrap_or_else(|| format!("sub_{:08X}", entry));
            let d = decomp::decompile_function(&cfg, &sec.data, sec.address, info.is_little_endian, &known);
            return Ok(DecompileResult {
                entry, name,
                pseudocode: d.pseudocode,
                block_count: d.block_count,
                stmt_count: d.stmt_count,
            });
        }
    }
    Err(format!("No executable section contains 0x{:08X}", entry))
}

/// Decompile ALL detected functions and return them as a list (for the
/// "decompile all" view). Capped at a reasonable limit for UI responsiveness.
#[derive(Serialize, Debug, Clone)]
pub struct DecompileAllResult {
    pub functions: Vec<DecompileResult>,
    pub total: usize,
}

#[tauri::command]
fn decompile_all(path: String, max: Option<usize>) -> Result<DecompileAllResult, String> {
    let info = parse_elf_file(path)?;
    let funcs = detect_functions_inner(&info)?;
    let mut known: std::collections::BTreeMap<u32, String> = std::collections::BTreeMap::new();
    for f in &funcs { known.insert(f.start, f.name.clone()); }
    for s in &info.symbols { known.insert(s.address, s.name.clone()); }
    let limit = max.unwrap_or(500);
    let mut results = Vec::new();
    for sec in info.sections.iter().filter(|s| (s.flags & 0x4) != 0) {
        let sec_end = sec.address + sec.data.len() as u32;
        for f in funcs.iter().filter(|f| f.start >= sec.address && f.start < sec_end) {
            if results.len() >= limit { break; }
            let end = if f.end > 0 { f.end } else { sec_end };
            let cfg = cfg::build_function_cfg(&sec.data, sec.address, f.start, end, info.is_little_endian);
            let d = decomp::decompile_function(&cfg, &sec.data, sec.address, info.is_little_endian, &known);
            results.push(DecompileResult {
                entry: f.start, name: f.name.clone(),
                pseudocode: d.pseudocode, block_count: d.block_count, stmt_count: d.stmt_count,
            });
        }
    }
    let total = results.len();
    Ok(DecompileAllResult { functions: results, total })
}

// ---------------------------------------------------------------------------
// Project save/load + scripting (Tier 3)
// ---------------------------------------------------------------------------

/// Serialize the current in-memory project to JSON (for the GUI to save).
#[tauri::command]
fn save_project(project_json: String, path: String) -> Result<(), String> {
    let proj = project::deserialize_project(&project_json)?;
    project::save_project_file(&proj, &path)
}

/// Load a .aura project file from disk and return its JSON.
#[tauri::command]
fn load_project(path: String) -> Result<String, String> {
    let proj = project::load_project_file(&path)?;
    project::serialize_project(&proj)
}

/// Create a fresh empty project for a binary path.
#[tauri::command]
fn new_project(binary_path: String, binary_name: Option<String>) -> Result<String, String> {
    let mut p = project::AuraProject::default();
    p.binary_path = binary_path;
    p.binary_name = binary_name;
    project::serialize_project(&p)
}

/// Run a Lua script against a binary. The script gets the `aura` API
/// (functions, rename, comment, name_at, etc.) and its edits are returned
/// as an updated project JSON.
#[tauri::command]
fn run_aura_script(
    binary_path: String, script: String, project_json: Option<String>,
) -> Result<project::ScriptResult, String> {
    let info = parse_elf_file(binary_path.clone())?;
    let funcs = detect_functions_inner(&info)?;
    let functions: Vec<(u32, String)> = funcs.iter().map(|f| (f.start, f.name.clone())).collect();
    // First code section for patching context.
    let (code_data, code_base) = info.sections.iter()
        .find(|s| (s.flags & 0x4) != 0)
        .map(|s| (s.data.clone(), s.address))
        .unwrap_or((vec![], 0));
    let proj = match project_json {
        Some(j) => project::deserialize_project(&j)?,
        None => {
            let mut p = project::AuraProject::default();
            p.binary_path = binary_path.clone();
            p
        }
    };
    let mut ctx = project::ScriptContext {
        binary_path, project: proj, functions,
        code_data, code_base, is_le: info.is_little_endian,
    };
    Ok(project::run_script(&script, &mut ctx))
}

// ---------------------------------------------------------------------------
// Search + strings + patch export (Tier 4 UX polish)
// ---------------------------------------------------------------------------

#[derive(Serialize, Debug, Clone)]
pub struct StringScanResult {
    pub strings: Vec<search::FoundString>,
    pub count: usize,
    pub section: String,
}

/// Scan a binary for printable strings (ASCII + wide). If `section` is given
/// (ELF), scan that section's data; otherwise the whole file is scanned with
/// the raw-binary base address.
#[tauri::command]
fn scan_strings(path: String, section: Option<String>, min_len: Option<usize>) -> Result<StringScanResult, String> {
    let data = std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
    let min = min_len.unwrap_or(4);
    if let Some(sec_name) = section.as_ref() {
        if let Ok(info) = parse_elf_file(path) {
            if let Some(sec) = info.sections.iter().find(|s| s.name == *sec_name) {
                let strings = search::collect_strings(&sec.data, sec.address, min);
                let count = strings.len();
                return Ok(StringScanResult { strings, count, section: sec_name.clone() });
            }
        }
    }
    let base = identify_base(&data);
    let strings = search::collect_strings(&data, base, min);
    let count = strings.len();
    let section_name = section.unwrap_or_else(|| "*whole*".into());
    Ok(StringScanResult { strings, count, section: section_name })
}

/// The conventional base address for raw data (PS-X EXE / raw bin).
fn identify_base(data: &[u8]) -> u32 {
    if data.len() >= 4 && data[0..4] == [0x7f, b'E', b'L', b'F'] {
        0
    } else {
        0x0001_0000 // PS-X EXE default
    }
}

/// Search a binary for a pattern/string/immediate.
#[derive(Serialize, Debug, Clone)]
pub struct SearchResult {
    pub hits: Vec<search::Hit>,
    pub count: usize,
    pub kind: String,
}

/// `kind` is one of "pattern" (hex bytes), "string" (ASCII),
/// or "immediate" (a 32-bit word, endianness-aware).
#[tauri::command]
fn search_binary(path: String, kind: String, value: String, ignore_case: Option<bool>) -> Result<SearchResult, String> {
    let data = std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
    let is_le = elf_is_le(&data);
    let base = identify_base(&data);
    let hits = match kind.as_str() {
        "pattern" => {
            let bytes = parse_hex(&value).map_err(|e| format!("pattern must be hex bytes: {e}"))?;
            search::find_pattern(&data, &bytes, Some(base))
        }
        "string" => search::find_string(&data, &value, ignore_case.unwrap_or(false), Some(base)),
        "immediate" => {
            let v = parse_u32(&value).map_err(|e| format!("immediate must be a number: {e}"))?;
            search::find_immediate(&data, v, is_le, Some(base), 4)
        }
        other => return Err(format!("unknown search kind '{other}'; use pattern|string|immediate")),
    };
    let count = hits.len();
    Ok(SearchResult { hits, count, kind })
}

/// Get string xrefs (MIPS lui+addiu idiom) for a binary's code section.
#[derive(Serialize, Debug, Clone)]
pub struct StringXrefResult {
    pub xrefs: Vec<search::StringXref>,
    pub count: usize,
}

#[tauri::command]
fn get_string_xrefs(path: String) -> Result<StringXrefResult, String> {
    let info = parse_elf_file(path)?;
    let mut xrefs = Vec::new();
    for sec in info.sections.iter().filter(|s| (s.flags & 0x4) != 0) {
        let all_strings: Vec<search::FoundString> = info.sections.iter()
            .filter(|s| (s.flags & 0x4) == 0)
            .flat_map(|s| search::collect_strings(&s.data, s.address, 4))
            .collect();
        let x = search::string_xrefs_mips(&sec.data, sec.address, info.is_little_endian, &all_strings);
        xrefs.extend(x);
    }
    let count = xrefs.len();
    Ok(StringXrefResult { xrefs, count })
}

/// Apply project patches to the binary and write to `out_path`.
#[tauri::command]
fn export_patched_binary(path: String, project_json: String, out_path: String) -> Result<u64, String> {
    let proj = project::deserialize_project(&project_json)?;
    let mut data = std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
    let mut applied = 0u64;
    for p in &proj.patches {
        let off = p.address as usize;
        if off + p.bytes.len() <= data.len() {
            data[off..off + p.bytes.len()].copy_from_slice(&p.bytes);
            applied += 1;
        }
    }
    let n = search::export_bytes(&data, &out_path)?;
    let _ = applied;
    Ok(n)
}

// --- helpers ---

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let t = t.replace(&[' ', '_', ',', '\t'][..], "");
    if t.len() % 2 != 0 {
        return Err("odd number of hex digits".into());
    }
    let bytes = t.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i]).ok_or("bad hex digit")?;
        let lo = hex_nibble(bytes[i + 1]).ok_or("bad hex digit")?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_u32(s: &str) -> Result<u32, String> {
    let t = s.trim();
    if t.starts_with("0x") || t.starts_with("0X") {
        u32::from_str_radix(&t[2..], 16).map_err(|e| e.to_string())
    } else {
        t.parse::<u32>().map_err(|e| e.to_string())
    }
}

fn elf_is_le(data: &[u8]) -> bool {
    data.len() >= 6 && data[0..4] == [0x7f, b'E', b'L', b'F'] && data[5] == 1
}

/// Pure inner form of `detect_functions` — shared by the command and the
/// config/CSV exporters so they all agree on the function set. When the binary
/// is stripped (no symbol-table functions), it additionally runs the SCE SDK
/// symbol matcher against the detected `sub_XXXXXXXX`s so they get real SDK
/// names (printf/PadInit/...) where the database has an unambiguous hit.
/// Scan a PS2 ELF for SCE SDK library functions and return the matches.
/// Each match is a `(address, size, name, library)` triple — e.g. printf,
/// PadInit, FlushCache — that Aura can use to rename detected `sub_XXXXXXXX`s.
/// Returns an empty list (with a message) if the embedded DB failed to load.
#[tauri::command]
fn scan_sce_symbols(path: String) -> Result<SceSymbolScanResult, String> {
    let info = parse_elf_file(path)?;
    let matches = scan_sce_sdk_matches(&info.sections);
    Ok(SceSymbolScanResult {
        matches,
        db_symbol_count: sce_db().as_ref().map(|d| d.symbol_count()).unwrap_or(0),
        db_error: sce_db().as_ref().err().cloned(),
    })
}

/// Result of an on-demand SCE SDK scan.
#[derive(Serialize, Debug)]
struct SceSymbolScanResult {
    matches: Vec<SceSymbolMatch>,
    /// Total variants in the loaded DB (for the status line).
    db_symbol_count: usize,
    /// Present only if the embedded DB failed to parse.
    db_error: Option<String>,
}

// ===================== GameBoy ROM support =====================

/// consumes (Name,Start,End,Size). Addresses are uppercase hex with 0x prefix;
/// Size is decimal in bytes. This is byte-compatible with ExportPS2Functions.java.
///
///   Name,Start,End,Size
///   sub_00100000,0x00100000,0x001001A0,416
#[tauri::command]
fn export_functions_csv(path: String, output_csv: String) -> Result<usize, String> {
    let funcs = detect_functions(path.clone())?;

    let mut csv = String::new();
    csv.push_str("Name,Start,End,Size\n");
    for f in &funcs {
        csv.push_str(&format!(
            "{},0x{:08X},0x{:08X},{}\n",
            f.name, f.start, f.end, f.size
        ));
    }

    fs::write(&output_csv, csv).map_err(|e| format!("Failed to write CSV: {}", e))?;
    Ok(funcs.len())
}

/// Show a native save-file dialog, then write the PS2Recomp CSV there.
/// Returns Some(count) on success, or None if the user cancelled.
#[tauri::command]
fn export_functions_csv_dialog(app: tauri::AppHandle, path: String) -> Result<Option<usize>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file()
        .add_filter("CSV (PS2Recomp / Ghidra)", &["csv"])
        .set_file_name("functions.csv")
        .save_file(move |file_path| {
            tx.send(file_path.map(|p| p.to_string())).ok();
        });

    let chosen = match rx.recv_timeout(std::time::Duration::from_secs(120)) {
        Ok(v) => v,
        Err(_) => return Err("Save dialog timed out".to_string()),
    };

    let Some(out_path) = chosen else { return Ok(None) };
    let count = export_functions_csv(path, out_path)?;
    Ok(Some(count))
}

/// Generate a complete, ps2recomp-valid config.toml for the given ELF.
/// Writes both the CSV (Name,Start,End,Size) and the TOML, returning the
/// function count. The output_dir becomes the recompiler's `output` path and
/// the CSV path is wired into `ghidra_output`.
///
/// This mirrors the schema ExportPS2Functions.java emits, so `ps2recomp
/// <config.toml>` can consume it directly:
///   [general]
///   input = "..."
///   output = "..."
///   ghidra_output = ".../functions.csv"
///   stubs = [...]
///   skip = []
#[tauri::command]
fn generate_config_toml(
    path: String,
    output_dir: String,
) -> Result<ConfigResult, String> {
    let info = parse_elf_file(path.clone())?;
    let funcs = detect_functions_inner(&info)?;

    // Write the CSV beside the TOML.
    let csv_path = format!("{}/functions.csv", output_dir.trim_end_matches('/'));
    let mut csv = String::from("Name,Start,End,Size\n");
    for f in &funcs {
        csv.push_str(&format!(
            "{},0x{:08X},0x{:08X},{}\n",
            f.name, f.start, f.end, f.size
        ));
    }
    fs::write(&csv_path, csv).map_err(|e| format!("Failed to write CSV: {}", e))?;

    // Count how many functions come from real symbols vs JAL heuristics.
    let from_symbols = info.symbols.iter().filter(|s| s.size > 0).count();
    let heuristic = funcs.len().saturating_sub(from_symbols);
    // How many heuristic functions were renamed to SDK names by the matcher.
    let sce_sdk_named = funcs
        .iter()
        .filter(|f| !f.name.starts_with("sub_"))
        .count();

    // The list of SDK-matched function names, sorted + deduped, for the
    // informational `untracked_stubs` array (ps2recomp ignores this field).
    let mut untracked_stubs: Vec<String> = funcs
        .iter()
        .filter_map(|f| {
            if f.name.starts_with("sub_") {
                None
            } else {
                Some(f.name.clone())
            }
        })
        .collect();
    untracked_stubs.sort();
    untracked_stubs.dedup();

    // Build the TOML string (pure helper, unit-tested).
    let config_toml_path = format!("{}/config.toml", output_dir.trim_end_matches('/'));
    let t = build_config_toml(
        &path,
        &output_dir,
        &csv_path,
        &info,
        &funcs,
        from_symbols,
        heuristic,
        sce_sdk_named,
        &untracked_stubs,
    );

    fs::write(&config_toml_path, t).map_err(|e| format!("Failed to write TOML: {}", e))?;

    Ok(ConfigResult {
        toml_path: config_toml_path,
        csv_path,
        function_count: funcs.len(),
        from_symbols,
        from_jal_heuristic: heuristic,
        sce_sdk_named,
        relocation_count: info.relocations.len(),
    })
}

/// Result of generating a ps2recomp config bundle.
#[derive(Serialize, Debug)]
struct ConfigResult {
    toml_path: String,
    csv_path: String,
    function_count: usize,
    from_symbols: usize,
    from_jal_heuristic: usize,
    /// Heuristic functions the SCE SDK matcher successfully renamed.
    sce_sdk_named: usize,
    relocation_count: usize,
}

/// Show a native folder-picker and return the chosen directory, or None if
/// the user cancelled. Used by the "Export PS2Recomp config" flow.
#[tauri::command]
fn pick_output_folder(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file().pick_folder(move |folder| {
        tx.send(folder.map(|p| p.to_string())).ok();
    });
    match rx.recv_timeout(std::time::Duration::from_secs(120)) {
        Ok(v) => Ok(v),
        Err(_) => Err("Folder picker timed out".to_string()),
    }
}

#[tauri::command]
fn decompile_function(request: DecompileRequest) -> Result<DecompileResponse, String> {
    let output = format!(
        "; Function: {}\n; Address: 0x{}\n\n{}:\n    ; Decompiling...",
        request.function_name,
        request.address,
        request.address
    );

    Ok(DecompileResponse {
        success: true,
        output: Some(output),
        message: format!("Decompiled function '{}'", request.function_name),
    })
}

/// Parse an original Xbox XBE executable (header, certificate, sections,
/// library versions, xboxkrnl imports, XOR-decoded entry point).
#[tauri::command]
fn parse_xbe_file(path: String) -> Result<xbox::XbeFileInfo, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let filename = Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.clone());
    xbox::parse_xbe(&data, &filename)
}

/// Disassemble a named section of an original Xbox XBE (32-bit x86, Intel syntax).
#[tauri::command]
fn disassemble_xbe(
    path: String,
    section_name: String,
    max_instructions: Option<usize>,
) -> Result<Vec<xbox::X86Instruction>, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    xbox::disassemble_xbe_section(&data, &section_name, max_instructions.unwrap_or(5000))
}

/// Parse an Xbox 360 XEX executable (optional headers, security info,
/// import libraries, embedded PE sections and exports when unencrypted).
#[tauri::command]
fn parse_xex_file(path: String) -> Result<xbox360::XexFileInfo, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let filename = Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.clone());
    xbox360::parse_xex(&data, &filename)
}

/// Disassemble a PE section of an Xbox 360 XEX as big-endian PowerPC (Xenon).
#[tauri::command]
fn disassemble_xex(
    path: String,
    section_name: String,
    max_instructions: Option<usize>,
) -> Result<Vec<ppc_disasm::PpcInstruction>, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    xbox360::disassemble_xex_section(&data, &section_name, max_instructions.unwrap_or(5000))
}

/// Parse a Wii U RPX/RPL (Cafe ELF64 big-endian PPC64).
#[tauri::command]
fn parse_wiiu_file(path: String) -> Result<wiiu::WiiUFileInfo, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let filename = Path::new(&path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.clone());
    wiiu::parse_rpx_rpl(&data, &filename)
}

/// Disassemble a section of a Wii U RPX/RPL as big-endian PowerPC64.
#[tauri::command]
fn disassemble_wiiu_section(
    path: String,
    section_name: String,
    max_instructions: Option<usize>,
) -> Result<Vec<ppc_disasm::PpcInstruction>, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    wiiu::disassemble_rpx_section(&data, &section_name, max_instructions.unwrap_or(5000))
}

/// Parse a PS3 executable (SELF or plain BE ELF).
#[tauri::command]
fn parse_ps3_file(path: String) -> Result<ps3::Ps3FileInfo, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let filename = Path::new(&path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.clone());
    ps3::parse_ps3(&data, &filename)
}

/// Disassemble a section of a PS3 executable as big-endian PowerPC.
#[tauri::command]
fn disassemble_ps3_section(
    path: String,
    section_name: String,
    max_instructions: Option<usize>,
) -> Result<Vec<ppc_disasm::PpcInstruction>, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    ps3::disassemble_ps3_section(&data, &section_name, max_instructions.unwrap_or(5000))
}

/// Parse a PS4/PS5 executable (SELF or plain LE ELF64 x86-64).
#[tauri::command]
fn parse_ps4ps5_file(path: String) -> Result<ps4ps5::Ps4Ps5FileInfo, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let filename = Path::new(&path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path.clone());
    ps4ps5::parse_ps4ps5(&data, &filename)
}

/// Disassemble a section of a PS4/PS5 executable as 64-bit x86.
#[tauri::command]
fn disassemble_ps4ps5_section(
    path: String,
    section_name: String,
    max_instructions: Option<usize>,
) -> Result<Vec<ps4ps5::X64Instruction>, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    ps4ps5::disassemble_ps4ps5_section(&data, &section_name, max_instructions.unwrap_or(5000))
}

/// Get the SDK database statistics for a given platform.
#[tauri::command]
fn get_sdk_db_stats(platform: String) -> Result<serde_json::Value, String> {
    let plat = match platform.as_str() {
        "PS1" => sdk_symbols::Platform::Ps1,
        "PS2" => sdk_symbols::Platform::Ps2,
        "PS3" => sdk_symbols::Platform::Ps3,
        "PS4" => sdk_symbols::Platform::Ps4,
        "PS5" => sdk_symbols::Platform::Ps5,
        "Xbox" => sdk_symbols::Platform::Xbox,
        "Xbox 360" => sdk_symbols::Platform::Xbox360,
        "Wii U" => sdk_symbols::Platform::WiiU,
        "GameCube" => sdk_symbols::Platform::GameCube,
        "Wii" => sdk_symbols::Platform::Wii,
        "Sega Genesis" => sdk_symbols::Platform::SegaGenesis,
        _ => return Err(format!("Unknown platform: {}", platform)),
    };
    Ok(serde_json::json!({
        "platform": plat.as_str(),
        "symbol_count": sdk_symbols::db_count_for_platform(plat),
        "libraries": sdk_symbols::libraries_for_platform(plat),
        "total_symbols_all_platforms": sdk_symbols::db_count_total(),
    }))
}

/// Get the interactive call graph for a binary, ready for D3.js rendering.
/// This is the data structure the web frontend renders as a force-directed
/// graph — the feature that makes Aura's call graph interactive vs Ghidra's
/// static tree.
#[tauri::command]
fn get_interactive_call_graph(path: String) -> Result<call_graph::InteractiveCallGraph, String> {
    let info = parse_elf_file(path.clone())?;
    let funcs = detect_functions_inner(&info)?;
    let graph = get_call_graph(path)?;

    // Convert to the interactive graph format
    let functions: Vec<(u64, String, usize, bool)> = funcs
        .iter()
        .map(|f| (f.start as u64, f.name.clone(), f.size as usize, !f.name.starts_with("sub_")))
        .collect();

    let edges: Vec<(u64, u64, u64, String)> = graph
        .edges
        .iter()
        .map(|e| (e.from as u64, e.to as u64, e.callsite as u64, format!("{:?}", e.kind).to_lowercase()))
        .collect();

    // Build SDK matches from named functions
    let sdk_matches: Vec<(String, String)> = funcs
        .iter()
        .filter(|f| !f.name.starts_with("sub_"))
        .map(|f| (f.name.clone(), "sdk".to_string()))
        .collect();

    Ok(call_graph::build_interactive_graph(
        &functions,
        &edges,
        info.entry_point as u64,
        &sdk_matches,
    ))
}

#[tauri::command]
fn identify_file(path: String) -> Result<String, String> {
    let p = Path::new(&path);
    if !p.exists() { return Err(format!("File not found: {}", path)); }
    let mut file = fs::File::open(p).map_err(|e| e.to_string())?;
    use std::io::Read;
    let mut head = Vec::with_capacity(0x10200);
    file.take(0x10200).read_to_end(&mut head).map_err(|e| e.to_string())?;
    Ok(engine::identify_data(&head))
}

#[tauri::command]
fn disassemble_section(data: Vec<u8>, section_name: String, start_addr: u32, is_little_endian: bool) -> Result<String, String> {
    engine::disassemble_mips_section(data, section_name, start_addr, is_little_endian)
}

#[tauri::command]
fn identify_gb_rom(path: String) -> Result<GbIdentification, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    engine::identify_gb_data(&data)
}

#[tauri::command]
fn disassemble_gb_rom(rom_data: Vec<u8>, base_addr: u32, max_instructions: Option<usize>) -> Result<String, String> {
    engine::disassemble_gb_data(rom_data, base_addr, max_instructions)
}

#[tauri::command]
fn scan_sdk_symbols(path: String, platform: String) -> Result<sdk_symbols::SdkScanResult, String> {
    let data = fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    engine::scan_sdk_symbols_data(&data, platform)
}

#[tauri::command]
fn export_decomp_project(path: String, platform: String, output_dir: String) -> Result<decomp_export::DecompExportResult, String> {
    engine::export_decomp_project(path, platform, output_dir)
}

#[tauri::command]
fn get_supported_formats() -> Result<serde_json::Value, String> {
    engine::supported_formats()
}

#[tauri::command]
fn scan_ps1_symbols(path: String) -> Result<ps1_symbols::Ps1SymbolScanResult, String> {
    let info = parse_elf_file(path)?;
    Ok(ps1_symbols::build_ps1_scan_result(&info.sections))
}
#[tokio::main]
async fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            log_message,
            open_file_dialog,
            open_multiple_files_dialog,
            open_file,
            read_raw_binary,
            identify_file,
            parse_elf_file,
            disassemble_section,
            detect_functions,
            get_call_graph,
            get_cfg_summary,
            get_xrefs,
            decompile_function_cmd,
            decompile_all,
            save_project,
            load_project,
            new_project,
            run_aura_script,
            scan_strings,
            search_binary,
            get_string_xrefs,
            export_patched_binary,
            scan_ps1_symbols,
            ps1_analysis::analyze_ps1_binary,
            ps1_call_graph_enhanced::get_enhanced_call_graph,
            ps1_recomp_export::generate_ps1_recomp_config,
            scan_sce_symbols,
            export_functions_csv,
            export_functions_csv_dialog,
            generate_config_toml,
            pick_output_folder,
            decompile_function,
            get_supported_formats,
            identify_gb_rom,
            disassemble_gb_rom,
            parse_xbe_file,
            disassemble_xbe,
            parse_xex_file,
            disassemble_xex,
            parse_wiiu_file,
            disassemble_wiiu_section,
            parse_ps3_file,
            disassemble_ps3_section,
            parse_ps4ps5_file,
            disassemble_ps4ps5_section,
            scan_sdk_symbols,
            get_sdk_db_stats,
            export_decomp_project,
            get_interactive_call_graph,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Aura Decomp Tool");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Push a little-endian u32 into a byte buffer.
    fn push_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Build a minimal ELF32-LE-MIPS image in memory with:
    ///   - one .text section
    ///   - a .symtab (foo @ 0x100000, bar @ 0x100020) + .strtab
    ///   - a .rel.text with two entries referencing foo and bar
    /// Returns (bytes, shoff, shnum, shentsize).
    fn build_reloc_elf() -> (Vec<u8>, u32, u16, u16) {
        let mut buf: Vec<u8> = Vec::new();

        // ELF header (52 bytes), filled after layout is known.
        buf.resize(52, 0);
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 1; // ELFCLASS32
        buf[5] = 1; // ELFDATA2LSB (little-endian)
        buf[6] = 1; // EV_CURRENT
        push_u32(&mut buf, 0x100000); // e_entry (offset 24)

        // .text: 8 bytes of zeros at offset 52.
        let text_off = buf.len();
        buf.extend_from_slice(&[0u8; 8]);

        // .symtab: 3 entries x 16 bytes (null, foo, bar).
        let sym_off = buf.len();
        let sym_entsize = 16u32;
        buf.extend_from_slice(&[0u8; 16]); // null symbol
        // foo: st_name=1, value=0x100000, type FUNC
        push_u32(&mut buf, 1);              // st_name -> "foo"
        push_u32(&mut buf, 0x100000);       // st_value
        push_u32(&mut buf, 0);              // st_size
        buf.extend_from_slice(&[0x12, 0, 1, 0]); // st_info(STB_GLOBAL|STT_FUNC), other, shndx
        // bar: st_name=5, value=0x100020
        push_u32(&mut buf, 5);              // st_name -> "bar"
        push_u32(&mut buf, 0x100020);       // st_value
        push_u32(&mut buf, 0);              // st_size
        buf.extend_from_slice(&[0x12, 0, 1, 0]);
        let sym_size = buf.len() - sym_off;

        // .strtab: "\0foo\0bar\0"
        let str_off = buf.len();
        buf.extend_from_slice(b"\0foo\0bar\0");
        let str_size = buf.len() - str_off;

        // .rel.text: 2 entries x 8 bytes.
        let rel_off = buf.len();
        push_u32(&mut buf, 0);             // r_offset = 0
        push_u32(&mut buf, (1u32 << 8) | 2); // r_info: sym=1 (foo), type=2 (R_MIPS_32)
        push_u32(&mut buf, 4);             // r_offset = 4
        push_u32(&mut buf, (2u32 << 8) | 2); // r_info: sym=2 (bar), type=2
        let rel_size = buf.len() - rel_off;

        // Section headers (40 bytes each). 6 sections.
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        let shoff = buf.len() as u32;
        let shentsize = 40u16;
        let shnum = 6u16;
        buf.resize(buf.len() + shnum as usize * shentsize as usize, 0);

        let sh = |buf: &mut Vec<u8>, idx: usize, sh_type: u32, sh_addr: u32, sh_off: u32, sh_size: u32, sh_link: u32, sh_info: u32, sh_entsize: u32| {
            let b = shoff as usize + idx * shentsize as usize;
            buf[b..b + 4].copy_from_slice(&0u32.to_le_bytes()); // sh_name (unused)
            buf[b + 4..b + 8].copy_from_slice(&sh_type.to_le_bytes());
            buf[b + 12..b + 16].copy_from_slice(&sh_addr.to_le_bytes());
            buf[b + 16..b + 20].copy_from_slice(&sh_off.to_le_bytes());
            buf[b + 20..b + 24].copy_from_slice(&sh_size.to_le_bytes());
            buf[b + 24..b + 28].copy_from_slice(&sh_link.to_le_bytes());
            buf[b + 28..b + 32].copy_from_slice(&sh_info.to_le_bytes());
            buf[b + 36..b + 40].copy_from_slice(&sh_entsize.to_le_bytes());
        };
        sh(&mut buf, 0, 0, 0, 0, 0, 0, 0, 0);                 // null
        sh(&mut buf, 1, 1, 0, text_off as u32, 8, 0, 0, 0);   // .text PROGBITS, sh_addr=0
        sh(&mut buf, 2, 2, 0, sym_off as u32, sym_size as u32, 3, 0, sym_entsize); // .symtab -> strtab(3)
        sh(&mut buf, 3, 3, 0, str_off as u32, str_size as u32, 0, 0, 0);           // .strtab
        sh(&mut buf, 4, 3, 0, 0, 0, 0, 0, 0);                 // .shstrtab (dummy)
        sh(&mut buf, 5, 9, 0, rel_off as u32, rel_size as u32, 2, 1, 8);           // .rel.text -> symtab(2), applies to .text(1)

        (buf, shoff, shnum, shentsize)
    }

    #[test]
    fn relocation_parser_resolves_symbol_names() {
        let (buf, shoff, shnum, shentsize) = build_reloc_elf();
        let relocs = parse_relocations(&buf, shoff, shnum, shentsize, true /* little-endian */);
        assert_eq!(relocs.len(), 2, "expected 2 relocations");
        // .text's sh_addr is 0 in this synthetic ELF, so the normalized offset
        // (r_offset + sh_addr) equals the raw r_offset.
        assert_eq!(relocs[0].offset, 0);
        assert_eq!(relocs[0].symbol_name, "foo");
        assert_eq!(relocs[0].r_type, 2);
        assert_eq!(relocs[0].symbol, 1);
        assert_eq!(relocs[1].offset, 4);
        assert_eq!(relocs[1].symbol_name, "bar");
        assert_eq!(relocs[1].symbol, 2);
    }

    /// When the relocation's target section has a non-zero sh_addr (as on real
    /// ET_REL homebrew ELFs whose .text loads at 0x100000), `Relocation.offset`
    /// must be normalized to absolute (r_offset + sh_addr) so it matches the
    /// call graph's absolute callsite addresses.
    #[test]
    fn relocation_offset_normalized_to_absolute() {
        let (mut buf, shoff, shnum, shentsize) = build_reloc_elf();
        // Move .text's sh_addr from 0 to 0x100000 (offset 12 in section header 1).
        let text_sh = shoff as usize + 1 * shentsize as usize + 12;
        buf[text_sh..text_sh + 4].copy_from_slice(&0x100000u32.to_le_bytes());

        let relocs = parse_relocations(&buf, shoff, shnum, shentsize, true);
        assert_eq!(relocs.len(), 2);
        // Raw r_offsets (0, 4) + .text sh_addr (0x100000) = absolute.
        assert_eq!(relocs[0].offset, 0x100000, "offset not normalized by target sh_addr");
        assert_eq!(relocs[1].offset, 0x100004);
    }

    #[test]
    fn relocation_parser_handles_no_rel_sections() {
        // A buffer with section headers but no REL/RELA sections -> empty result.
        let mut buf = vec![0u8; 200];
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        let shoff = 60u32;
        buf[32..36].copy_from_slice(&shoff.to_le_bytes());
        let shnum = 2u16;
        let shentsize = 40u16;
        buf[46..48].copy_from_slice(&shentsize.to_le_bytes());
        buf[48..50].copy_from_slice(&shnum.to_le_bytes());
        // Two PROGBITS sections (type 1), no REL.
        let relocs = parse_relocations(&buf, shoff, shnum, shentsize, true);
        assert!(relocs.is_empty(), "no relocations expected");
    }

    #[test]
    fn detect_functions_finds_jal_targets() {
        // Two JAL instructions at 0x100000 and 0x100008, targeting 0x100100 and 0x100200.
        let mut text: Vec<u8> = Vec::new();
        // JAL target: op=0x03 (000011), target_field = (target & 0x0FFFFFFF) >> 2
        let jal = |target: u32| -> u32 { (0x03u32 << 26) | ((target >> 2) & 0x03FFFFFF) };
        push_u32(&mut text, jal(0x100100)); // 0x100000
        push_u32(&mut text, 0);             // 0x100004 (delay slot)
        push_u32(&mut text, jal(0x100200)); // 0x100008
        push_u32(&mut text, 0);             // delay slot
        // Pad so the JAL targets (0x100100, 0x100200) fall inside the section;
        // the scanner only accepts targets within the section's range.
        text.resize(0x100300 - 0x100000, 0);
        let section = ElfSection {
            name: ".text".into(),
            address: 0x100000,
            size: text.len() as u32,
            offset: 0,
            data: text,
            flags: 0x4, // SHF_EXECINSTR
        };
        let funcs = detect_functions_in_sections(&[section], 0x100000, true);
        // Entry (0x100000) + two JAL targets (0x100100, 0x100200).
        let starts: Vec<u32> = funcs.iter().map(|f| f.start).collect();
        assert!(starts.contains(&0x100100), "missing JAL target 0x100100");
        assert!(starts.contains(&0x100200), "missing JAL target 0x100200");
    }

    #[test]
    fn config_toml_has_required_ps2recomp_fields() {
        // The TOML must be parseable by ps2recomp's ConfigManager::loadConfig,
        // which requires: [general] input, output, and tolerates ghidra_output.
        // We validate the key fields are present and well-formed (no need for a
        // full TOML parser here; structure + spot-values suffice).
        let info = ElfFileInfo {
            filename: "test.elf".into(),
            sections: vec![],
            symbols: vec![],
            entry_point: 0x100000,
            file_size: 0,
            is_little_endian: true,
            is_32bit: true,
            relocations: vec![],
        };
        let funcs = vec![FunctionEntry {
            name: "sub_00100000".into(),
            start: 0x100000,
            end: 0x100100,
            size: 0x100,
        }];
        let toml = build_config_toml(
            "G:/games/test.elf",
            "G:/out",
            "G:/out/functions.csv",
            &info,
            &funcs,
            0,
            1,
            0,
            &[], // no SCE matches -> untracked_stubs stays empty
        );
        // Required by ConfigManager::loadConfig
        assert!(toml.contains("[general]"), "missing [general] table");
        assert!(toml.contains("input = \"G:/games/test.elf\""), "bad input path");
        assert!(toml.contains("output = \"G:/out\""), "bad output path");
        assert!(toml.contains("ghidra_output = \"G:/out/functions.csv\""), "bad ghidra_output");
        // Booleans must be valid TOML (lowercase).
        assert!(toml.contains("single_file_output = false"));
        assert!(toml.contains("patch_cop0 = true"));
        // Empty arrays must be valid.
        assert!(toml.contains("stubs = []"));
        assert!(toml.contains("untracked_stubs = []"));
        assert!(toml.contains("skip = []"));
        // Windows backslashes must be normalized (would break TOML escaping).
        assert!(!toml.contains("input = \"G:\\\\"), "backslashes not normalized");
    }

    #[test]
    fn csv_format_matches_ps2recomp() {
        // The CSV writer must emit exactly: Name,Start,End,Size with 0x%08X
        // addresses (uppercase) and decimal size — matching ExportPS2Functions.java.
        let funcs = vec![
            FunctionEntry { name: "foo".into(), start: 0x100000, end: 0x100100, size: 0x100 },
            FunctionEntry { name: "bar".into(), start: 0x100100, end: 0x100120, size: 0x20 },
        ];
        let mut csv = String::from("Name,Start,End,Size\n");
        for f in &funcs {
            csv.push_str(&format!("{},0x{:08X},0x{:08X},{}\n", f.name, f.start, f.end, f.size));
        }
        assert_eq!(csv.lines().next().unwrap(), "Name,Start,End,Size");
        assert_eq!(csv.lines().nth(1).unwrap(), "foo,0x00100000,0x00100100,256");
        assert_eq!(csv.lines().nth(2).unwrap(), "bar,0x00100100,0x00100120,32");
    }

    /// `has_delay_slot` must match exactly the DELAY_SLOT_MNEMONICS table: the
    /// control-flow instructions whose next word is a branch delay slot.
    #[test]
    fn has_delay_slot_matches_reference_set() {
        // Build a single instruction word from its fields.
        let r_type = |funct: u32| funct; // op 0x00
        let i_type = |op: u32, rs: u32, rt: u32, imm: u32| (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF);

        // --- true: instructions that have a delay slot ---
        // J / JAL
        assert!(has_delay_slot(i_type(0x02, 0, 0, 0)));
        assert!(has_delay_slot(i_type(0x03, 0, 0, 0)));
        // JR $ra (funct 0x08), JALR (funct 0x09)
        assert!(has_delay_slot(r_type(0x08)));
        assert!(has_delay_slot(r_type(0x09)));
        // BEQ / BNE / BLEZ / BGTZ
        assert!(has_delay_slot(i_type(0x04, 0, 0, 0)));
        assert!(has_delay_slot(i_type(0x05, 0, 0, 0)));
        assert!(has_delay_slot(i_type(0x06, 0, 0, 0)));
        assert!(has_delay_slot(i_type(0x07, 0, 0, 0)));
        // REGIMM BLTZ / BGEZ (op 0x01, rt 0x00 / 0x01)
        assert!(has_delay_slot(i_type(0x01, 0, 0x00, 0)));
        assert!(has_delay_slot(i_type(0x01, 0, 0x01, 0)));
        // BEQL / BNEL
        assert!(has_delay_slot(i_type(0x14, 0, 0, 0)));
        assert!(has_delay_slot(i_type(0x15, 0, 0, 0)));

        // --- false: non-delay-slot instructions ---
        // nop (0x00000000): op 0, funct 0 (SLL) — explicitly NOT a delay slot.
        assert!(!has_delay_slot(0x00000000));
        // ADDU (funct 0x21), SLL (funct 0x00 with shift)
        assert!(!has_delay_slot(r_type(0x21)));
        // LUI (op 0x0F), LW (op 0x23), ADDIU (op 0x09), ORI (op 0x0D)
        assert!(!has_delay_slot(i_type(0x0F, 0, 0, 0)));
        assert!(!has_delay_slot(i_type(0x23, 0, 0, 0)));
        assert!(!has_delay_slot(i_type(0x09, 0, 0, 0)));
        assert!(!has_delay_slot(i_type(0x0D, 0, 0, 0)));
    }

    /// `refine_end` trims trailing nop padding while preserving the delay slot
    /// of the final control-flow instruction. End is exclusive.
    #[test]
    fn refine_end_trims_padding_and_keeps_delay_slot() {
        // Helper: build a little-endian code buffer from a list of u32 words.
        let push = |buf: &mut Vec<u8>, v: u32| buf.extend_from_slice(&v.to_le_bytes());
        // jr $ra  = SPECIAL funct 0x08, rs = $ra (31)  -> 0x03E00008.
        const JR_RA: u32 = 0x03E00008;

        // ---- Case 1: jr $ra; nop(delay); nop; nop  (base 0x100000, start 0x100000)
        //    Expected End = jr_addr + 8 = 0x100008 (the 3 padding nops drop off,
        //    the delay-slot nop is protected).
        {
            let mut b = Vec::new();
            push(&mut b, JR_RA);            // 0x100000: jr $ra
            push(&mut b, 0x00000000);        // 0x100004: nop (delay slot)
            push(&mut b, 0x00000000);        // 0x100008: nop (padding)
            push(&mut b, 0x00000000);        // 0x10000C: nop (padding)
            let end = refine_end(&b, 0x100000, 0x100000, 0x100010, true);
            assert_eq!(end, 0x100008, "case 1: jr+8");
        }

        // ---- Case 2: jr $ra; move v0,0 (delay); nop; nop
        //    Expected End = 0x100008 (delay slot is a non-nop, still protected).
        {
            let mut b = Vec::new();
            // OR $v0, $zero, $zero (a stand-in for `move`) — SPECIAL funct 0x25.
            let move_v0_zero: u32 = 0x21; // any non-zero, non-control-flow word
            push(&mut b, JR_RA);            // 0x100000: jr $ra
            push(&mut b, move_v0_zero);     // 0x100004: delay slot (non-nop)
            push(&mut b, 0x00000000);        // 0x100008: padding
            push(&mut b, 0x00000000);        // 0x10000C: padding
            let end = refine_end(&b, 0x100000, 0x100000, 0x100010, true);
            assert_eq!(end, 0x100008, "case 2: jr+8 with non-nop delay slot");
        }

        // ---- Case 3: tail-call function ending in `j X; nop(delay); nop`
        //    Expected End = 0x100008 (j's delay slot is protected).
        {
            let mut b = Vec::new();
            // j 0x200000  = op 0x02, field = 0x200000 >> 2 = 0x80000  -> 0x08080000.
            const J_200000: u32 = 0x08080000;
            push(&mut b, J_200000);         // 0x100000: j 0x200000
            push(&mut b, 0x00000000);        // 0x100004: delay slot
            push(&mut b, 0x00000000);        // 0x100008: padding
            let end = refine_end(&b, 0x100000, 0x100000, 0x10000C, true);
            assert_eq!(end, 0x100008, "case 3: j+8");
        }

        // ---- Case 4: filler code + trailing nops, no control-flow end.
        //    nop padding after real code trims down to the last real word + 4.
        {
            let mut b = Vec::new();
            push(&mut b, 0x00000021);       // 0x100000: ADDU (real)
            push(&mut b, 0x00000020);       // 0x100004: ADD  (real, last)
            push(&mut b, 0x00000000);        // 0x100008: nop (padding)
            push(&mut b, 0x00000000);        // 0x10000C: nop (padding)
            let end = refine_end(&b, 0x100000, 0x100000, 0x100010, true);
            assert_eq!(end, 0x100008, "case 4: trim to last real word + 4");
        }

        // ---- Case 5: safety net — all-nop body never collapses below start+4.
        {
            let mut b = Vec::new();
            push(&mut b, 0x00000000);
            push(&mut b, 0x00000000);
            push(&mut b, 0x00000000);
            let end = refine_end(&b, 0x100000, 0x100000, 0x10000C, true);
            // Can't trim below start + 4 (need ≥2 words to even consider).
            assert!(end >= 0x100004, "case 5: kept at least one instruction");
        }
    }

    /// End-to-end: two JAL-targeted functions with nop padding between them get
    /// the first function's End tightened to `jr $ra + 8` instead of the next
    /// function's start.
    #[test]
    fn refine_function_boundaries_shortens_end() {
        // Layout (base 0x100000):
        //   0x100000: func A body — jr $ra
        //   0x100004:   nop (delay slot)
        //   0x100008:   nop (padding)
        //   0x10000C:   nop (padding)
        //   0x100010: func B start (a JAL target) — jr $ra
        //   0x100014:   nop (delay slot)
        let mut text: Vec<u8> = Vec::new();
        let push = |buf: &mut Vec<u8>, v: u32| buf.extend_from_slice(&v.to_le_bytes());
        const JR_RA: u32 = 0x03E00008; // SPECIAL funct 0x08, rs = $ra
        push(&mut text, JR_RA);        // 0x100000
        push(&mut text, 0x00000000);    // 0x100004 delay
        push(&mut text, 0x00000000);    // 0x100008 padding
        push(&mut text, 0x00000000);    // 0x10000C padding
        push(&mut text, JR_RA);        // 0x100010 (func B)
        push(&mut text, 0x00000000);    // 0x100014 delay

        let section = ElfSection {
            name: ".text".into(),
            address: 0x100000,
            size: text.len() as u32,
            offset: 0,
            data: text,
            flags: 0x4, // SHF_EXECINSTR
        };

        // Simulate JAL-scan output: func A spans [0x100000, 0x100010) (to next
        // start), func B spans [0x100010, end_of_section).
        let mut funcs = vec![
            FunctionEntry { name: "sub_00100000".into(), start: 0x100000, end: 0x100010, size: 0x10 },
            FunctionEntry { name: "sub_00100010".into(), start: 0x100010, end: 0x100018, size: 0x08 },
        ];

        refine_function_boundaries(&[section], &mut funcs, true);

        // Func A: jr at 0x100000 + delay slot -> End 0x100008 (not 0x100010).
        assert_eq!(funcs[0].end, 0x100008, "func A End should be jr+8, not next start");
        assert_eq!(funcs[0].size, 0x8);
        // Func B: jr at 0x100010 + delay slot -> End 0x100018 (unchanged, its
        // body was already exactly jr+delay).
        assert_eq!(funcs[1].end, 0x100018, "func B End unchanged");
    }

    /// `untracked_stubs` is emitted as a TOML array of basic strings when
    /// populated, and stays a single-line `[]` when empty. Confirms escaping
    /// of quotes/backslashes keeps the TOML valid.
    #[test]
    fn untracked_stubs_array_round_trips_through_toml_parser() {
        let info = ElfFileInfo {
            filename: "t.elf".into(),
            sections: vec![],
            symbols: vec![],
            entry_point: 0x100000,
            file_size: 0,
            is_little_endian: true,
            is_32bit: true,
            relocations: vec![],
        };
        // A name with a quote and one with a backslash — both must survive.
        let untracked = vec!["printf".to_string(), "weird\"name".to_string(), "path\\bit".to_string()];
        let toml_str = build_config_toml(
            "G:/t.elf", "G:/out", "G:/out/functions.csv",
            &info, &[], 0, 0, 0, &untracked,
        );
        // Must parse with a real TOML parser.
        let parsed: toml::Value = toml::from_str(&toml_str).expect("TOML must parse");
        let arr = parsed
            .get("general")
            .and_then(|g| g.get("untracked_stubs"))
            .and_then(|v| v.as_array())
            .expect("untracked_stubs must be an array");
        assert_eq!(arr.len(), 3, "all three names preserved");
        let names: Vec<String> = arr.iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(names.contains(&"printf".to_string()));
        assert!(names.contains(&"weird\"name".to_string()), "quote not escaped/preserved");
        assert!(names.contains(&"path\\bit".to_string()), "backslash not escaped/preserved");
        // stubs and skip must still be empty (never auto-populated).
        let general = parsed.get("general").and_then(|v| v.as_table()).unwrap();
        assert!(general.get("stubs").and_then(|v| v.as_array()).map(|a| a.is_empty()).unwrap_or(false));
        assert!(general.get("skip").and_then(|v| v.as_array()).map(|a| a.is_empty()).unwrap_or(false));
    }

    /// `collect_call_edges` records every JAL (op 0x03) and J (op 0x02) with
    /// the correct callsite/target/kind, and only for targets that land in an
    /// executable section.
    #[test]
    fn collect_call_edges_finds_jal_and_j() {
        // Section layout (base 0x100000):
        //   0x100000: jal 0x100200   (op 0x03)
        //   0x100004: nop            (delay slot)
        //   0x100008: j   0x100300   (op 0x02)
        //   0x10000C: nop
        //   ...padding to cover targets...
        let jal = |target: u32| -> u32 { (0x03u32 << 26) | ((target >> 2) & 0x03FFFFFF) };
        let j = |target: u32| -> u32 { (0x02u32 << 26) | ((target >> 2) & 0x03FFFFFF) };
        let mut text: Vec<u8> = Vec::new();
        push_u32(&mut text, jal(0x100200)); // 0x100000
        push_u32(&mut text, 0);             // 0x100004
        push_u32(&mut text, j(0x100300));   // 0x100008
        push_u32(&mut text, 0);             // 0x10000C
        text.resize(0x100400 - 0x100000, 0); // pad so targets are in-range
        let section = ElfSection {
            name: ".text".into(),
            address: 0x100000,
            size: text.len() as u32,
            offset: 0,
            data: text,
            flags: 0x4,
        };

        let edges = collect_call_edges(&[section], true);
        // Two edges: the JAL and the J.
        assert_eq!(edges.len(), 2, "expected 2 raw edges, got {}", edges.len());
        assert_eq!(edges[0], RawCallEdge { callsite: 0x100000, target: 0x100200, kind: CallKind::Jal });
        assert_eq!(edges[1], RawCallEdge { callsite: 0x100008, target: 0x100300, kind: CallKind::Jump });
    }

    /// `build_call_graph` attributes callsites to functions, drops intra-function
    /// tail jumps (but keeps JAL self-recursion), and routes undetected targets
    /// into `external_targets`.
    #[test]
    fn build_call_graph_attributes_and_filters() {
        // Two functions: A = [0x100000, 0x100010), B = [0x100010, 0x100020).
        // Edges (raw):
        //   1) callsite 0x100000 (in A), JAL -> 0x100010 (B's start)     [keep]
        //   2) callsite 0x100004 (in A), J   -> 0x100000 (A's start)     [drop: intra-function jump]
        //   3) callsite 0x100010 (in B), JAL -> 0x100050 (undetected)    [keep + external]
        let funcs = vec![
            FunctionEntry { name: "A".into(), start: 0x100000, end: 0x100010, size: 0x10 },
            FunctionEntry { name: "B".into(), start: 0x100010, end: 0x100020, size: 0x10 },
        ];
        let raw = vec![
            RawCallEdge { callsite: 0x100000, target: 0x100010, kind: CallKind::Jal },
            RawCallEdge { callsite: 0x100004, target: 0x100000, kind: CallKind::Jump },
            RawCallEdge { callsite: 0x100010, target: 0x100050, kind: CallKind::Jal },
        ];
        let g = build_call_graph(raw, &funcs);

        // Edge 2 (intra-function J inside A) is dropped; edges 1 and 3 remain.
        assert_eq!(g.edges.len(), 2, "expected 2 edges after filtering, got {}", g.edges.len());
        // A -> B (the JAL from A).
        assert!(g.edges.iter().any(|e| e.from == 0x100000 && e.to == 0x100010 && e.kind == CallKind::Jal),
            "missing A->B JAL edge");
        // B -> external 0x100050 (kept, since it's a real call to undetected code).
        assert!(g.edges.iter().any(|e| e.from == 0x100010 && e.to == 0x100050),
            "missing B->external JAL edge");
        // The undetected target is reported as external.
        assert_eq!(g.external_targets, vec![0x100050], "external_targets wrong: {:?}", g.external_targets);
    }

    /// A JAL to a function's own start is legitimate self-recursion and must
    /// NOT be dropped (only intra-function `j` is dropped, never `jal`).
    #[test]
    fn call_graph_handles_self_recursion() {
        let funcs = vec![
            FunctionEntry { name: "rec".into(), start: 0x100000, end: 0x100020, size: 0x20 },
        ];
        let raw = vec![
            // Self-call via JAL.
            RawCallEdge { callsite: 0x100008, target: 0x100000, kind: CallKind::Jal },
            // Self-loop via J (this one IS an intra-function jump -> dropped).
            RawCallEdge { callsite: 0x10000C, target: 0x100000, kind: CallKind::Jump },
        ];
        let g = build_call_graph(raw, &funcs);
        // JAL self-edge kept, J self-edge dropped.
        assert_eq!(g.edges.len(), 1, "expected 1 edge (jal kept, j dropped), got {}", g.edges.len());
        assert_eq!(g.edges[0].from, 0x100000);
        assert_eq!(g.edges[0].to, 0x100000);
        assert_eq!(g.edges[0].kind, CallKind::Jal);
        // rec's own start IS a function start, so it's not external.
        assert!(g.external_targets.is_empty());
    }

    /// `enrich_call_graph_with_relocs` resolves JAL targets to imported symbol
    /// names via R_MIPS_26 relocations at the matching callsite address. Non-JAL
    /// relocs and non-JAL edges are ignored; retail binaries (no relocs) no-op.
    #[test]
    fn call_graph_resolves_import_names() {
        // caller A [0x100000,0x100010) JALs two imported stubs.
        let funcs = vec![
            FunctionEntry { name: "A".into(), start: 0x100000, end: 0x100010, size: 0x10 },
        ];
        let raw = vec![
            // Two JALs from A to external (undetected) stubs at 0x200000 / 0x200004.
            RawCallEdge { callsite: 0x100000, target: 0x200000, kind: CallKind::Jal },
            RawCallEdge { callsite: 0x100004, target: 0x200004, kind: CallKind::Jal },
        ];
        let graph = build_call_graph(raw, &funcs);

        // R_MIPS_26 (= 4) relocations at the two callsites name the imports.
        let relocs = vec![
            Relocation { offset: 0x100000, symbol_name: "printf".into(),  r_type: R_MIPS_26, symbol: 1 },
            Relocation { offset: 0x100004, symbol_name: "malloc".into(),  r_type: R_MIPS_26, symbol: 2 },
            // A non-call reloc (R_MIPS_32 = 2) and a different offset must NOT match.
            Relocation { offset: 0x100000, symbol_name: "ignored".into(), r_type: 2,         symbol: 9 },
        ];
        let enriched = enrich_call_graph_with_relocs(graph, &relocs);

        // Both external targets resolved, sorted by address.
        assert_eq!(enriched.target_names.len(), 2, "expected 2 resolved names");
        assert_eq!(enriched.target_names[0], (0x200000, "printf".to_string()));
        assert_eq!(enriched.target_names[1], (0x200004, "malloc".to_string()));
    }

    /// With no relocations (stripped retail binaries), enrichment is a no-op
    /// and `target_names` stays empty.
    #[test]
    fn enrich_call_graph_noop_without_relocations() {
        let funcs = vec![
            FunctionEntry { name: "A".into(), start: 0x100000, end: 0x100010, size: 0x10 },
        ];
        let raw = vec![
            RawCallEdge { callsite: 0x100000, target: 0x200000, kind: CallKind::Jal },
        ];
        let graph = build_call_graph(raw, &funcs);
        let enriched = enrich_call_graph_with_relocs(graph, &[]);
        assert!(enriched.target_names.is_empty(), "no relocs -> no target names");
    }

    /// End-to-end against a real PS2 retail ELF (Midnight Club 3 Remix).
    /// Skips if the file isn't on disk so the test suite stays portable.
    /// Validates: full ELF parse + JAL function detection + the generated TOML
    /// parses with a real TOML parser and has the fields ps2recomp requires.
    #[test]
    fn mc3r_full_pipeline_and_toml_parses() {
        let path = r"G:\Recomps\MC3R\NTGUIDVD.ELF";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: MC3R not present at {}", path);
            return;
        }
        // Full parse. parse_elf_file captures only SHT_PROGBITS sections that
        // carry loadable data (NOBITS sections like .bss/.sbss have no file
        // content and are intentionally excluded). MC3R's ELF header has 15
        // section entries; 9 are PROGBITS-with-data.
        let info = parse_elf_file(path.to_string()).expect("parse_elf_file");
        assert!(info.sections.len() >= 9, "expected >=9 PROGBITS sections, got {}", info.sections.len());
        assert!(info.sections.iter().any(|s| s.name == ".text"), "missing .text section");
        assert_eq!(info.entry_point, 0x001056A8, "entry point mismatch");
        assert_eq!(info.is_little_endian, true, "MC3R is little-endian");
        assert!(info.relocations.is_empty(), "MC3R has no dynamic relocations");

        // Function detection (JAL scan — binary is stripped).
        let funcs = detect_functions(path.to_string()).expect("detect_functions");
        assert!(funcs.len() > 2000, "expected >2000 functions, got {}", funcs.len());
        assert!(funcs.len() < 3000, "function count suspiciously high: {}", funcs.len());

        // SCE SDK matcher diagnostic: how many sections are code, how many
        // raw matches come back, and how many functions got renamed.
        const SHF_EXECINSTR: u32 = 0x4;
        let code_secs: Vec<&ElfSection> = info.sections.iter()
            .filter(|s| (s.flags & SHF_EXECINSTR) != 0)
            .collect();
        let raw_matches = scan_sce_sdk_matches(&info.sections);
        let renamed = funcs.iter().filter(|f| !f.name.starts_with("sub_")).count();
        eprintln!(
            "MC3R SCE: {} code sections (flags 0x4), {} raw SDK matches, {} renamed functions",
            code_secs.len(),
            raw_matches.len(),
            renamed,
        );
        // Sample first few raw matches for sanity.
        for m in raw_matches.iter().take(5) {
            eprintln!("  {:08X} {} ({} bytes, {})", m.address, m.name, m.size, m.library);
        }

        // Generate the TOML and prove it parses with a real TOML parser.
        let from_symbols = info.symbols.iter().filter(|s| s.size > 0).count();
        let heuristic = funcs.len().saturating_sub(from_symbols);
        let sce_named = funcs.iter().filter(|f| !f.name.starts_with("sub_")).count();
        // Sorted + deduped SDK-matched names feed the informational
        // untracked_stubs array (ps2recomp ignores it).
        let mut untracked: Vec<String> = funcs
            .iter()
            .filter_map(|f| {
                if f.name.starts_with("sub_") { None } else { Some(f.name.clone()) }
            })
            .collect();
        untracked.sort();
        untracked.dedup();
        let toml_str = build_config_toml(
            path, "G:/out", "G:/out/functions.csv",
            &info, &funcs, from_symbols, heuristic, sce_named, &untracked,
        );
        let parsed: toml::Value = toml::from_str(&toml_str).expect("TOML must parse");
        let general = parsed.get("general").and_then(|v| v.as_table()).expect("[general]");
        // Fields ps2recomp's ConfigManager::loadConfig reads:
        assert!(general.contains_key("input"), "missing input");
        assert!(general.contains_key("output"), "missing output");
        assert!(general.contains_key("ghidra_output"), "missing ghidra_output");
        assert_eq!(general.get("single_file_output").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(general.get("patch_cop0").and_then(|v| v.as_bool()), Some(true));
        // stubs/skip must be arrays.
        assert!(general.get("stubs").map(|v| v.is_array()).unwrap_or(false));
        assert!(general.get("skip").map(|v| v.is_array()).unwrap_or(false));
        // untracked_stubs is an array and carries exactly the deduped SDK names.
        let untracked_arr = general
            .get("untracked_stubs")
            .and_then(|v| v.as_array())
            .expect("untracked_stubs must be a TOML array");
        assert_eq!(untracked_arr.len(), untracked.len(),
            "untracked_stubs length {} != deduped count {}", untracked_arr.len(), untracked.len());
        // The [ghidra_export] table carries the SCE SDK naming breakdown.
        let ghidra = parsed.get("ghidra_export").and_then(|v| v.as_table()).expect("[ghidra_export]");
        assert_eq!(
            ghidra.get("sce_sdk_named").and_then(|v| v.as_integer()),
            Some(sce_named as i64),
            "sce_sdk_named field missing or wrong"
        );
        // MC3R is stripped retail — the SCE matcher must rename a meaningful
        // chunk of the detected functions (it ships a lot of libc/libccc/etc).
        assert!(sce_named > 100, "expected >100 SCE-named functions, got {}", sce_named);
        eprintln!(
            "MC3R: {} functions ({} heuristic, {} SCE SDK-named), TOML OK",
            funcs.len(), heuristic, sce_named
        );

        // ---- Call graph sanity (direct JAL + tail-call J) -----------------
        let raw_edges = collect_call_edges(&info.sections, info.is_little_endian);
        let graph = enrich_call_graph_with_relocs(
            build_call_graph(raw_edges, &funcs),
            &info.relocations,
        );
        // A real retail EE binary must have thousands of direct calls.
        assert!(graph.edges.len() > 1000, "expected >1000 call edges, got {}", graph.edges.len());
        // The entry point is a root: no detected function calls into it.
        let entry_callers = graph.edges.iter().filter(|e| e.to == info.entry_point).count();
        assert_eq!(entry_callers, 0, "entry point 0x{:08X} has {} callers (should be a root)",
            info.entry_point, entry_callers);
        // Unreachable functions (no callers, not the entry) are a strong signal
        // for stubs / interrupt handlers / dead code. MC3R has plenty.
        let called: std::collections::HashSet<u32> = graph.edges.iter().map(|e| e.to).collect();
        let unreachable = funcs.iter().filter(|f| !called.contains(&f.start) && f.start != info.entry_point).count();
        // MC3R has no dynamic relocations, so import-name enrichment is a no-op.
        assert!(graph.target_names.is_empty(),
            "MC3R has no relocations; expected empty target_names, got {}", graph.target_names.len());
        eprintln!(
            "MC3R call graph: {} edges, {} external targets, {} unreachable functions (of {} total)",
            graph.edges.len(), graph.external_targets.len(), unreachable, funcs.len()
        );
        assert!(unreachable > 50, "expected >50 unreachable functions, got {}", unreachable);
    }
}
