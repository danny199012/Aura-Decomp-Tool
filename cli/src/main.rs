//! aura-cli — command-line interface for Aura Decomp Tool.
//!
//! Shares the exact analysis engine with the GUI binary: it #[path]-includes
//! `engine.rs` (the moved core from src-tauri/src/main.rs) and the pure
//! platform modules, so behavior matches the GUI one-to-one.
#![allow(dead_code, clippy::too_many_arguments)]

#[path = "../../src-tauri/src/engine.rs"]
mod engine;
pub use engine::*;

#[path = "../../src-tauri/src/ps4ps5.rs"] mod ps4ps5;
#[path = "../../src-tauri/src/ps3.rs"] mod ps3;
#[path = "../../src-tauri/src/wiiu.rs"] mod wiiu;
#[path = "../../src-tauri/src/xbox.rs"] mod xbox;
#[path = "../../src-tauri/src/xbox360.rs"] mod xbox360;
#[path = "../../src-tauri/src/gamecube.rs"] mod gamecube;
#[path = "../../src-tauri/src/lzx.rs"] mod lzx;
#[path = "../../src-tauri/src/ppc_disasm.rs"] mod ppc_disasm;
#[path = "../../src-tauri/src/ps1_exe.rs"] mod ps1_exe;
#[path = "../../src-tauri/src/ps1_memory_map.rs"] mod ps1_memory_map;
#[path = "../../src-tauri/src/ps1_disasm.rs"] mod ps1_disasm;
#[path = "../../src-tauri/src/call_graph.rs"] mod call_graph;
#[path = "../../src-tauri/src/cfg.rs"] mod cfg;
#[path = "../../src-tauri/src/decomp.rs"] mod decomp;
#[path = "../../src-tauri/src/project.rs"] mod project;
#[path = "../../src-tauri/src/sdk_symbols.rs"] mod sdk_symbols;
#[path = "../../src-tauri/src/sce_symbol_scanner.rs"] mod sce_symbol_scanner;
#[path = "../../src-tauri/src/decomp_export.rs"] mod decomp_export;
#[path = "../../src-tauri/src/ps1_symbols.rs"] mod ps1_symbols;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Argument parsing (tiny, no extra deps)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Args {
    command: String,
    file: Option<String>,
    section: Option<String>,
    /// Address argument for `xrefs --at 0xADDR` (stored as a hex string).
    at: Option<String>,
    /// Script path for `script --script PATH`.
    script: Option<String>,
    platform: Option<String>,
    out: Option<String>,
    max: usize,
    json: bool,
    help: bool,
    version: bool,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args { max: 5000, ..Default::default() };
    let mut i = 1;
    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "-h" | "--help" => a.help = true,
            "-V" | "--version" => a.version = true,
            "--json" => a.json = true,
            "--section" => { a.section = Some(argv.get(i + 1).cloned().ok_or("--section needs a value")?); i += 1; }
            "--at" => { a.at = Some(argv.get(i + 1).cloned().ok_or("--at needs a value (hex address)")?); i += 1; }
            "--script" => { a.script = Some(argv.get(i + 1).cloned().ok_or("--script needs a value (path)")?); i += 1; }
            "--platform" => { a.platform = Some(argv.get(i + 1).cloned().ok_or("--platform needs a value")?); i += 1; }
            "--out" => { a.out = Some(argv.get(i + 1).cloned().ok_or("--out needs a value")?); i += 1; }
            "--max" => { a.max = argv.get(i + 1).and_then(|x| x.parse::<usize>().ok()).ok_or("--max needs a number")?; i += 1; }
            _ if a.command.is_empty() && !arg.starts_with('-') => a.command = arg.clone(),
            _ if a.file.is_none() && !arg.starts_with('-') => a.file = Some(arg.clone()),
            other => return Err(format!("Unknown argument: {other}")),
        }
        i += 1;
    }
    Ok(a)
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

fn emit(out: &Option<String>, text: String) -> i32 {
    match out {
        Some(path) => match std::fs::write(path, &text) {
            Ok(_) => { println!("{path}"); 0 }
            Err(e) => { eprintln!("failed to write {path}: {e}"); 2 }
        },
        None => { println!("{text}"); 0 }
    }
}

fn json_or_text(json: bool, value: serde_json::Value, plain: String) -> String {
    if json { serde_json::to_string_pretty(&value).unwrap_or_default() } else { plain }
}

fn usage_string() -> String {
    "aura-cli — Aura Decomp Tool command-line interface\n\nUSAGE\n  aura-cli <command> [options] <file>\n\nCOMMANDS\n  info            Identify the file and print a summary\n  sections        List the binary's sections (address / size / type)\n  disasm          Disassemble a section (default: first code section)\n  sdk-scan        Run the SDK symbol database against the binary\n  callgraph       Build the direct call graph (JAL/J edges)\n  cfg             Build per-function control-flow graphs (recursive-descent)\n  xrefs           List cross-references to an address (--at 0xADDR)\n  decompile       Lift MIPS to C-like pseudocode (--at 0xADDR for one func, or all)\n  project         Create/apply a .aura project (--section save|apply --out FILE)\n  script          Run a Lua analysis script (--script PATH [--out PROJECT])\n  export          Write a complete decomp project scaffold to --out DIR\n  formats         List the supported container formats\n\nGLOBAL OPTIONS\n  --section NAME  Section to disassemble (or save|apply action for project)\n  --at ADDR       Hex address (for xrefs/decompile)\n  --script PATH   Lua script path (for script)\n  --platform NAME PS1|PS2|PS3|PS4|PS5|Wii U|Xbox|Xbox 360\n  --out PATH      Write output to file (default: stdout)\n  --max N         Max instructions for disasm / max funcs for decompile (default: 5000)\n  --json          Machine-readable JSON output\n  -h, --help      Show this help\n  -V, --version   Show version\n\nEXAMPLES\n  aura-cli info game.elf --json\n  aura-cli disasm eboot.bin --section seg0 --out disasm.txt\n  aura-cli sdk-scan game.elf --platform PS2 --json\n  aura-cli cfg game.elf --json\n  aura-cli xrefs game.elf --at 0x80123456 --json\n  aura-cli decompile game.elf --at 0x80123456\n  aura-cli decompile game.elf --json --max 100\n  aura-cli project game.elf --section save --out game.aura\n  aura-cli project game.elf --section apply --out game.aura --json\n  aura-cli script game.elf --script rename.lua --out game.aura --json\n  aura-cli export game.elf --platform PS2 --out ./decomp\n  aura-cli formats --json".to_string()
}

// ---------------------------------------------------------------------------
// Commands: info / sections / formats
// ---------------------------------------------------------------------------

fn cmd_info(a: &Args) -> Result<String, String> {
    let file = a.file.as_ref().ok_or("info needs a file path")?;
    let data = std::fs::read(file).map_err(|e| format!("Cannot read {file}: {e}"))?;
    let head_len = data.len().min(0x10200);
    let identify = engine::identify_data(&data[..head_len]);
    let filename = std::path::Path::new(file).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| file.clone());

    let (platform, entry, sections, extra): (String, u64, usize, serde_json::Value) = match identify.as_str() {
        "elf32-le" | "elf32-be" => {
            let info = engine::parse_elf_file_engine(file.clone())?;
            (format!("ELF32 ({identify})"), info.entry_point as u64, info.sections.len(),
             serde_json::json!({ "sections": info.sections.iter().map(|s| serde_json::json!({"name": s.name, "address": s.address, "size": s.size, "code": (s.flags & 0x4) != 0 })).collect::<Vec<_>>() }))
        }
        "self" | "ps4-self" => {
            if let Ok(info) = ps3::parse_ps3(&data, &filename) {
                (format!("PS3 SELF ({identify})"), info.entry_point, info.sections.len(), serde_json::json!({ "file_type": info.file_type }))
            } else {
                let info = ps4ps5::parse_ps4ps5(&data, &filename)?;
                (format!("PS4/PS5 SELF ({identify})"), info.entry_point, info.sections.len(), serde_json::json!({ "file_type": info.file_type }))
            }
        }
        "ps4-encrypted" => (String::from("PS4 SELF (encrypted)"), 0, 0, serde_json::json!({ "error": "Encrypted - requires Sony keys" })),
        "xbe" => {
            let info = xbox::parse_xbe(&data, &filename)?;
            (String::from("Xbox XBE"), info.entry_point as u64, info.sections.len(), serde_json::json!({ "title": info.certificate.as_ref().map(|c| c.title_name.clone()) }))
        }
        "xex" => {
            let info = xbox360::parse_xex(&data, &filename)?;
            (String::from("Xbox 360 XEX"), info.entry_point.unwrap_or(0) as u64, info.pe_sections.len(), serde_json::json!({ "file_type": info.file_type }))
        }
        "gb-rom" => {
            let gb = engine::identify_gb_data(&data)?;
            (String::from("GameBoy ROM"), 0, 0, serde_json::json!({ "header": gb.header }))
        }
        _ => (format!("Unknown ({identify})"), 0, 0, serde_json::json!({})),
    };

    Ok(json_or_text(
        a.json,
        serde_json::json!({
            "file": file, "size": data.len(), "identify": identify,
            "platform": platform, "entry_point": format!("0x{:08X}", entry),
            "section_count": sections, "details": extra,
        }),
        format!("File:      {file}\nSize:      {} bytes\nIdentify:  {identify}\nPlatform:  {platform}\nEntry:     0x{entry:08X}\nSections:  {sections}", data.len()),
    ))
}

fn cmd_sections(a: &Args) -> Result<String, String> {
    let file = a.file.as_ref().ok_or("sections needs a file path")?;
    let data = std::fs::read(file).map_err(|e| format!("Cannot read {file}: {e}"))?;
    let identify = engine::identify_data(&data[..data.len().min(0x10200)]);
    let filename = std::path::Path::new(file).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| file.clone());

    #[derive(serde::Serialize)]
    struct Row { name: String, address: u64, size: u64, kind: String, file_offset: u64 }

    let rows: Vec<Row> = match identify.as_str() {
        "elf32-le" | "elf32-be" => {
            let info = engine::parse_elf_file_engine(file.clone())?;
            info.sections.iter().map(|s| Row { name: s.name.clone(), address: s.address as u64, size: s.size as u64, kind: if (s.flags & 0x4) != 0 { "code".into() } else { "data".into() }, file_offset: s.offset as u64 }).collect()
        }
        "self" | "ps4-self" => {
            if let Ok(info) = ps3::parse_ps3(&data, &filename) {
                info.sections.iter().map(|s| Row { name: s.name.clone(), address: s.sh_addr, size: s.sh_size, kind: if s.is_code { "code".into() } else { "data".into() }, file_offset: s.sh_offset }).collect()
            } else {
                let info = ps4ps5::parse_ps4ps5(&data, &filename)?;
                info.sections.iter().map(|s| Row { name: s.name.clone(), address: s.sh_addr, size: s.sh_size, kind: if s.is_code { "code".into() } else { "data".into() }, file_offset: s.sh_offset }).collect()
            }
        }
        "xbe" => {
            let info = xbox::parse_xbe(&data, &filename)?;
            info.sections.iter().map(|s| Row { name: s.name.clone(), address: s.virtual_address as u64, size: s.virtual_size as u64, kind: if s.executable { "code".into() } else { "data".into() }, file_offset: s.raw_offset as u64 }).collect()
        }
        "xex" => {
            let info = xbox360::parse_xex(&data, &filename)?;
            let base = info.image_base.unwrap_or(info.load_address) as u64;
            info.pe_sections.iter().map(|s| Row { name: s.name.clone(), address: base + s.virtual_address as u64, size: s.virtual_size as u64, kind: if s.executable { "code".into() } else { "data".into() }, file_offset: s.raw_offset as u64 }).collect()
        }
        _ => Vec::new(),
    };

    if a.json { return Ok(serde_json::to_string_pretty(&rows).unwrap_or_default()); }
    let mut text = format!("Sections of {file} ({identify}) - {} entries\n", rows.len());
    text.push_str(&format!("{:<20} {:<12} {:<12} {:<6} {:<10}\n", "Name", "Address", "Size", "Kind", "File off"));
    for r in &rows {
        text.push_str(&format!("{:<20} 0x{:08X} 0x{:08X} {:<6} 0x{:X}\n", r.name, r.address, r.size, r.kind, r.file_offset));
    }
    Ok(text)
}

fn cmd_formats(a: &Args) -> Result<String, String> {
    let v = engine::supported_formats()?;
    Ok(serde_json::to_string_pretty(&v).unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Commands: disasm / sdk-scan / callgraph / export
// ---------------------------------------------------------------------------

/// Render one serialized instruction (address/bytes/text or mnemonic+operands)
/// into a single text line, regardless of which platform decoder produced it.
fn insn_to_text(v: &serde_json::Value) -> String {
    let addr = v.get("address").and_then(|x| x.as_u64()).unwrap_or(0);
    let bytes = v.get("bytes").and_then(|x| x.as_array()).map(|arr| {
        arr.iter().filter_map(|b| b.as_u64()).map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
    }).unwrap_or_default();
    let text = v.get("text").and_then(|x| x.as_str()).map(String::from).unwrap_or_else(|| {
        let m = v.get("mnemonic").and_then(|x| x.as_str()).unwrap_or("");
        let o = v.get("operands").and_then(|x| x.as_str()).unwrap_or("");
        format!("{m} {o}").trim().to_string()
    });
    format!("{addr:08X}  {bytes:<24}  {text}")
}

fn insns_to_text(insns: &[serde_json::Value], title: &str) -> String {
    let mut out = format!("{title} ({} instructions)\n\n", insns.len());
    for v in insns {
        out.push_str(&insn_to_text(v));
        out.push('\n');
    }
    out
}

fn cmd_disasm(a: &Args) -> Result<String, String> {
    let file = a.file.as_ref().ok_or("disasm needs a file path")?;
    let data = std::fs::read(file).map_err(|e| format!("Cannot read {file}: {e}"))?;
    let identify = engine::identify_data(&data[..data.len().min(0x10200)]);
    let filename = std::path::Path::new(file).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| file.clone());
    let max = a.max;

    // Pick the target section (default: first code section) per platform and
    // disassemble it. We produce JSON values so the output is format-neutral.
    let (insns, section_name): (Vec<serde_json::Value>, String) = match identify.as_str() {
        "elf32-le" | "elf32-be" => {
            let info = engine::parse_elf_file_engine(file.clone())?;
            let sec = match &a.section {
                Some(name) => info.sections.iter().find(|s| &s.name == name).ok_or_else(|| format!("Section '{name}' not found"))?,
                None => info.sections.iter().find(|s| (s.flags & 0x4) != 0).ok_or("No code section found")?,
            };
            let text = engine::disassemble_mips_section(sec.data.clone(), sec.name.clone(), sec.address, info.is_little_endian)?;
            // The MIPS listing is already text; wrap it as a single blob.
            return Ok(if a.json { serde_json::to_string_pretty(&serde_json::json!({"section": sec.name, "listing": text})).unwrap_or_default() } else { text });
        }
        "ps4-self" => {
            let info = ps4ps5::parse_ps4ps5(&data, &filename)?;
            let sec = info.sections.iter().find(|s| s.is_code).ok_or("No code section")?;
            let name = a.section.clone().unwrap_or_else(|| sec.name.clone());
            let insns = ps4ps5::disassemble_ps4ps5_section(&data, &name, max)?;
            (insns.iter().map(|i| serde_json::to_value(i).unwrap_or_default()).collect(), name)
        }
        "self" => {
            // PS3 SELF (BE ELF) vs PS4 homebrew SELF: try PS3 first.
            if let Ok(info) = ps3::parse_ps3(&data, &filename) {
                let sec = info.sections.iter().find(|s| s.is_code).ok_or("No code section")?;
                let name = a.section.clone().unwrap_or_else(|| sec.name.clone());
                let insns = ps3::disassemble_ps3_section(&data, &name, max)?;
                (insns.iter().map(|i| serde_json::to_value(i).unwrap_or_default()).collect(), name)
            } else {
                let info = ps4ps5::parse_ps4ps5(&data, &filename)?;
                let sec = info.sections.iter().find(|s| s.is_code).ok_or("No code section")?;
                let name = a.section.clone().unwrap_or_else(|| sec.name.clone());
                let insns = ps4ps5::disassemble_ps4ps5_section(&data, &name, max)?;
                (insns.iter().map(|i| serde_json::to_value(i).unwrap_or_default()).collect(), name)
            }
        }
        "xbe" => {
            let info = xbox::parse_xbe(&data, &filename)?;
            let sec = info.sections.iter().find(|s| s.executable).ok_or("No code section")?;
            let name = a.section.clone().unwrap_or_else(|| sec.name.clone());
            let insns = xbox::disassemble_xbe_section(&data, &name, max)?;
            (insns.iter().map(|i| serde_json::to_value(i).unwrap_or_default()).collect(), name)
        }
        "xex" => {
            let info = xbox360::parse_xex(&data, &filename)?;
            let sec = info.pe_sections.iter().find(|s| s.executable).ok_or("No code section")?;
            let name = a.section.clone().unwrap_or_else(|| sec.name.clone());
            let insns = xbox360::disassemble_xex_section(&data, &name, max)?;
            (insns.iter().map(|i| serde_json::to_value(i).unwrap_or_default()).collect(), name)
        }
        "elf64-be" => {
            let info = wiiu::parse_rpx_rpl(&data, &filename)?;
            let sec = info.sections.iter().find(|s| s.is_code).ok_or("No code section")?;
            let name = a.section.clone().unwrap_or_else(|| sec.name.clone());
            let insns = wiiu::disassemble_rpx_section(&data, &name, max)?;
            (insns.iter().map(|i| serde_json::to_value(i).unwrap_or_default()).collect(), name)
        }
        "gb-rom" => {
            let text = engine::disassemble_gb_data(data.clone(), 0, Some(max))?;
            return Ok(if a.json { serde_json::to_string_pretty(&serde_json::json!({"section": "rom", "listing": text})).unwrap_or_default() } else { text });
        }
        other => return Err(format!("Disassembly not supported for '{other}'")),
    };

    if a.json { return Ok(serde_json::to_string_pretty(&insns).unwrap_or_default()); }
    Ok(insns_to_text(&insns, &format!("{file} : {section_name}")))
}

fn cmd_sdk_scan(a: &Args) -> Result<String, String> {
    let file = a.file.as_ref().ok_or("sdk-scan needs a file path")?;
    let platform = a.platform.clone().ok_or("sdk-scan needs --platform NAME")?;
    let data = std::fs::read(file).map_err(|e| format!("Cannot read {file}: {e}"))?;
    let result = engine::scan_sdk_symbols_data(&data, platform)?;
    if a.json { return Ok(serde_json::to_string_pretty(&result).unwrap_or_default()); }
    let mut text = format!("SDK scan of {file}: {} matches across {} scanned names\n", result.matched_count, result.total_functions_scanned);
    text.push_str(&format!("Libraries: {}\n\n", result.detected_libraries.join(", ")));
    for m in &result.matches {
        text.push_str(&format!("0x{:08X}  {:<32} {} ({})\n", m.address, m.name, m.library, m.description));
    }
    Ok(text)
}

fn cmd_callgraph(a: &Args) -> Result<String, String> {
    let file = a.file.as_ref().ok_or("callgraph needs a file path")?;
    let data = std::fs::read(file).map_err(|e| format!("Cannot read {file}: {e}"))?;
    let identify = engine::identify_data(&data[..data.len().min(0x10200)]);
    if !(identify.starts_with("elf32")) {
        return Err(format!("callgraph currently supports MIPS ELF32 (PS1/PS2); got '{identify}'"));
    }
    let info = engine::parse_elf_file_engine(file.clone())?;
    let funcs = engine::detect_functions_inner(&info)?;
    let raw = engine::collect_call_edges(&info.sections, info.is_little_endian);
    let graph = engine::build_call_graph(raw, &funcs);
    let graph = engine::enrich_call_graph_with_relocs(graph, &info.relocations);

    let functions: Vec<(u64, String, usize, bool)> = funcs.iter().map(|f| (f.start as u64, f.name.clone(), f.size as usize, !f.name.starts_with("sub_"))).collect();
    let edges: Vec<(u64, u64, u64, String)> = graph.edges.iter().map(|e| (e.from as u64, e.to as u64, e.callsite as u64, format!("{:?}", e.kind).to_lowercase())).collect();
    let sdk_matches: Vec<(String, String)> = funcs.iter().filter(|f| !f.name.starts_with("sub_")).map(|f| (f.name.clone(), "sdk".to_string())).collect();
    let graph2 = call_graph::build_interactive_graph(&functions, &edges, info.entry_point as u64, &sdk_matches);

    if a.json { return Ok(serde_json::to_string_pretty(&graph2).unwrap_or_default()); }
    let mut text = format!("Call graph of {file}: {} nodes, {} edges (entry 0x{:08X})\n", graph2.statistics.total_functions, graph2.statistics.total_edges, info.entry_point);
    for e in &graph.edges.iter().take(200).collect::<Vec<_>>() {
        text.push_str(&format!("  0x{:08X} -> 0x{:08X} ({:?}, @0x{:08X})\n", e.from, e.to, e.kind, e.callsite));
    }
    if graph.edges.len() > 200 { text.push_str(&format!("  ... and {} more\n", graph.edges.len() - 200)); }
    Ok(text)
}

fn cmd_export(a: &Args) -> Result<String, String> {
    let file = a.file.as_ref().ok_or("export needs a file path")?;
    let platform = a.platform.clone().ok_or("export needs --platform NAME")?;
    let out_dir = a.out.clone().ok_or("export needs --out DIR")?;
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("Cannot create output dir {out_dir}: {e}"))?;
    let res = engine::export_decomp_project(file.clone(), platform, out_dir)?;
    if a.json { return Ok(serde_json::to_string_pretty(&res).unwrap_or_default()); }
    let mut text = format!("Exported decomp project to {}: {} files, {} functions ({} named, {} SDK-named)\n", res.project_dir, res.files_written.len(), res.function_count, res.named_count, res.sdk_named_count);
    for f in &res.files_written { text.push_str(&format!("  + {}\n", f)); }
    Ok(text)
}

// ---------------------------------------------------------------------------
// CFG + xref commands (Tier 1: recursive-descent analysis, like Ghidra/BN)
// ---------------------------------------------------------------------------

/// Build per-function CFGs for a MIPS ELF32 (PS1/PS2). Returns the list of
/// (entry, block_count, edge_count, returns) plus the global xref index.
fn build_cfgs_for_elf(file: &str) -> Result<(Vec<cfg::FunctionCfg>, cfg::XrefIndex, engine::ElfFileInfo), String> {
    let info = engine::parse_elf_file_engine(file.to_string())?;
    let funcs = engine::detect_functions_inner(&info)?;
    // Build (start, end) pairs per executable section.
    let mut cfgs = Vec::new();
    for sec in info.sections.iter().filter(|s| (s.flags & 0x4) != 0) {
        let sec_end = sec.address + sec.data.len() as u32;
        for f in funcs.iter().filter(|f| f.start >= sec.address && f.start < sec_end) {
            let end = if f.end > 0 { f.end } else { sec_end };
            cfgs.push(cfg::build_function_cfg(&sec.data, sec.address, f.start, end, info.is_little_endian));
        }
    }
    let xrefs = cfg::build_xref_index(&cfgs);
    Ok((cfgs, xrefs, info))
}

fn cmd_cfg(a: &Args) -> Result<String, String> {
    let file = a.file.as_ref().ok_or("cfg needs a file path")?;
    let data = std::fs::read(file).map_err(|e| format!("Cannot read {file}: {e}"))?;
    let identify = engine::identify_data(&data[..data.len().min(0x10200)]);
    if !identify.starts_with("elf32") {
        return Err(format!("cfg currently supports MIPS ELF32 (PS1/PS2); got '{identify}'"));
    }
    let (cfgs, xrefs, info) = build_cfgs_for_elf(file)?;
    let total_blocks: usize = cfgs.iter().map(|c| c.blocks.len()).sum();
    let total_edges: usize = cfgs.iter().map(|c| c.edges.len()).sum();
    let returning = cfgs.iter().filter(|c| c.returns).count();

    if a.json {
        let summary = serde_json::json!({
            "file": file,
            "functions": cfgs.len(),
            "total_blocks": total_blocks,
            "total_edges": total_edges,
            "returning_functions": returning,
            "xref_targets": xrefs.len(),
            "entry_point": info.entry_point,
            "per_function": cfgs.iter().map(|c| serde_json::json!({
                "entry": c.entry,
                "blocks": c.blocks.len(),
                "edges": c.edges.len(),
                "returns": c.returns,
            })).collect::<Vec<_>>(),
        });
        return Ok(serde_json::to_string_pretty(&summary).unwrap_or_default());
    }

    let mut text = format!("CFG analysis of {file}: {} functions, {} blocks, {} edges ({} returning)\n",
        cfgs.len(), total_blocks, total_edges, returning);
    text.push_str(&format!("Cross-references: {} distinct targets\n\n", xrefs.len()));
    for c in cfgs.iter().take(200) {
        text.push_str(&format!("  func 0x{:08X}: {} blocks, {} edges, {}\n",
            c.entry, c.blocks.len(), c.edges.len(), if c.returns { "returns" } else { "no-return" }));
    }
    if cfgs.len() > 200 { text.push_str(&format!("  ... and {} more\n", cfgs.len() - 200)); }
    Ok(text)
}

fn cmd_xrefs(a: &Args) -> Result<String, String> {
    let file = a.file.as_ref().ok_or("xrefs needs a file path")?;
    let at = a.at.as_ref().or(a.section.as_ref()).ok_or("xrefs needs --at ADDR (the address to look up references to)")?;
    let target = u32::from_str_radix(at.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .map_err(|e| format!("--at must be a hex address, e.g. 0x80123456: {e}"))?;
    let data = std::fs::read(file).map_err(|e| format!("Cannot read {file}: {e}"))?;
    let identify = engine::identify_data(&data[..data.len().min(0x10200)]);
    if !identify.starts_with("elf32") {
        return Err(format!("xrefs currently supports MIPS ELF32 (PS1/PS2); got '{identify}'"));
    }
    let (_cfgs, xrefs, _info) = build_cfgs_for_elf(file)?;
    let refs = xrefs.refs_to(target);
    if a.json {
        let v: Vec<_> = refs.iter().map(|r| serde_json::json!({
            "from": r.from, "to": r.to, "kind": format!("{:?}", r.kind).to_lowercase()
        })).collect();
        return Ok(serde_json::to_string_pretty(&serde_json::json!({ "target": target, "refs": v })).unwrap_or_default());
    }
    if refs.is_empty() {
        return Ok(format!("No cross-references to 0x{:08X} in {file}.\n", target));
    }
    let mut text = format!("Cross-references to 0x{:08X} ({}):\n", target, refs.len());
    for r in refs {
        let kind = match r.kind {
            cfg::XrefKind::Call => "call",
            cfg::XrefKind::Jump => "jump",
            cfg::XrefKind::Branch => "branch",
            cfg::XrefKind::Data => "data",
        };
        text.push_str(&format!("  0x{:08X}  {}\n", r.from, kind));
    }
    Ok(text)
}

// ---------------------------------------------------------------------------
// Decompile command (Tier 2: MIPS -> pseudocode)
// ---------------------------------------------------------------------------

fn cmd_decompile(a: &Args) -> Result<String, String> {
    let file = a.file.as_ref().ok_or("decompile needs a file path")?;
    let data = std::fs::read(file).map_err(|e| format!("Cannot read {file}: {e}"))?;
    let identify = engine::identify_data(&data[..data.len().min(0x10200)]);
    if !identify.starts_with("elf32") {
        return Err(format!("decompile currently supports MIPS ELF32 (PS1/PS2); got '{identify}'"));
    }
    let info = engine::parse_elf_file_engine(file.to_string())?;
    let funcs = engine::detect_functions_inner(&info)?;
    let mut known: std::collections::BTreeMap<u32, String> = std::collections::BTreeMap::new();
    for f in &funcs { known.insert(f.start, f.name.clone()); }
    for s in &info.symbols { known.insert(s.address, s.name.clone()); }

    // If --at is given, decompile that one function; otherwise decompile all (capped by --max).
    if let Some(at) = &a.at {
        let entry = u32::from_str_radix(at.trim_start_matches("0x").trim_start_matches("0X"), 16)
            .map_err(|e| format!("--at must be a hex address: {e}"))?;
        for sec in info.sections.iter().filter(|s| (s.flags & 0x4) != 0) {
            let sec_end = sec.address + sec.data.len() as u32;
            if entry >= sec.address && entry < sec_end {
                let func = funcs.iter().find(|f| f.start == entry);
                let end = func.map(|f| if f.end > 0 { f.end } else { sec_end }).unwrap_or(sec_end);
                let cfg = cfg::build_function_cfg(&sec.data, sec.address, entry, end, info.is_little_endian);
                let d = decomp::decompile_function(&cfg, &sec.data, sec.address, info.is_little_endian, &known);
                if a.json {
                    return Ok(serde_json::to_string_pretty(&serde_json::json!({
                        "entry": d.entry, "pseudocode": d.pseudocode,
                        "blocks": d.block_count, "statements": d.stmt_count,
                    })).unwrap_or_default());
                }
                return Ok(d.pseudocode);
            }
        }
        return Err(format!("No executable section contains 0x{:08X}", entry));
    }

    // Decompile all functions (up to --max).
    let limit = a.max.min(500);
    let mut results = Vec::new();
    for sec in info.sections.iter().filter(|s| (s.flags & 0x4) != 0) {
        let sec_end = sec.address + sec.data.len() as u32;
        for f in funcs.iter().filter(|f| f.start >= sec.address && f.start < sec_end) {
            if results.len() >= limit { break; }
            let end = if f.end > 0 { f.end } else { sec_end };
            let cfg = cfg::build_function_cfg(&sec.data, sec.address, f.start, end, info.is_little_endian);
            let d = decomp::decompile_function(&cfg, &sec.data, sec.address, info.is_little_endian, &known);
            results.push(serde_json::json!({
                "entry": d.entry, "name": known.get(&f.start).cloned().unwrap_or_default(),
                "pseudocode": d.pseudocode, "blocks": d.block_count, "statements": d.stmt_count,
            }));
        }
    }
    if a.json {
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "functions": results.len(), "results": results,
        })).unwrap_or_default());
    }
    let mut text = format!("Decompiled {} functions from {file}:\n\n", results.len());
    for r in &results {
        text.push_str(r["pseudocode"].as_str().unwrap_or(""));
        text.push('\n');
    }
    Ok(text)
}


// ---------------------------------------------------------------------------
// Project + script commands (Tier 3)
// ---------------------------------------------------------------------------

fn cmd_project(a: &Args) -> Result<String, String> {
    let file = a.file.as_ref().ok_or("project needs a binary file path")?;
    let out = a.out.as_ref().ok_or("project needs --out PATH (the .aura file)")?;
    // Sub-action via --section: "save" (create empty) or "apply" (load + merge).
    let action = a.section.as_deref().unwrap_or("save");
    match action {
        "save" => {
            let mut p = project::AuraProject::default();
            p.binary_path = file.clone();
            p.binary_name = Some(std::path::Path::new(file).file_name()
                .map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
            project::save_project_file(&p, out)?;
            if a.json {
                return Ok(serde_json::to_string_pretty(&p).unwrap_or_default());
            }
            Ok(format!("Created empty project: {out}"))
        }
        "apply" => {
            let proj = project::load_project_file(out)?;
            let info = engine::parse_elf_file_engine(file.clone())?;
            let funcs = engine::detect_functions_inner(&info)?;
            let func_list: Vec<(u32, String)> = funcs.iter().map(|f| (f.start, f.name.clone())).collect();
            let merged = project::apply_project_to_functions(&func_list, &proj);
            if a.json {
                return Ok(serde_json::to_string_pretty(&serde_json::json!({
                    "binary": file, "project": out,
                    "annotations": proj.annotations.len(),
                    "patches": proj.patches.len(),
                    "functions": merged.iter().map(|(a,n)| serde_json::json!({"addr": a, "name": n})).collect::<Vec<_>>(),
                })).unwrap_or_default());
            }
            let mut text = format!("Applied project {out} to {file}: {} annotations, {} patches\n",
                proj.annotations.len(), proj.patches.len());
            for (addr, name) in &merged {
                if proj.name_at(*addr).is_some() {
                    text.push_str(&format!("  0x{:08X} -> {}\n", addr, name));
                }
            }
            Ok(text)
        }
        other => Err(format!("project action must be save|apply (via --section), got '{other}'")),
    }
}

fn cmd_script(a: &Args) -> Result<String, String> {
    let file = a.file.as_ref().ok_or("script needs a binary file path")?;
    let script_path = a.script.as_ref().ok_or("script needs --script PATH (a .lua file)")?;
    let script = std::fs::read_to_string(script_path).map_err(|e| format!("read script {script_path}: {e}"))?;
    let info = engine::parse_elf_file_engine(file.clone())?;
    let funcs = engine::detect_functions_inner(&info)?;
    let functions: Vec<(u32, String)> = funcs.iter().map(|f| (f.start, f.name.clone())).collect();
    let (code_data, code_base) = info.sections.iter()
        .find(|s| (s.flags & 0x4) != 0)
        .map(|s| (s.data.clone(), s.address))
        .unwrap_or((vec![], 0));
    // Load an existing project if --out points to one (optional).
    let proj = a.out.as_ref()
        .and_then(|p| project::load_project_file(p).ok())
        .unwrap_or_else(|| { let mut p = project::AuraProject::default(); p.binary_path = file.clone(); p });
    let mut ctx = project::ScriptContext {
        binary_path: file.clone(), project: proj, functions,
        code_data, code_base, is_le: info.is_little_endian,
    };
    let r = project::run_script(&script, &mut ctx);
    // Persist the updated project if --out is a path.
    if r.success && a.out.is_some() {
        project::save_project_file(&ctx.project, a.out.as_ref().unwrap())
            .map_err(|e| format!("failed to save project: {e}"))?;
    }
    if a.json {
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "success": r.success, "output": r.output,
            "annotations": r.annotation_count, "patches": r.patch_count,
        })).unwrap_or_default());
    }
    if r.success {
        Ok(format!("Script OK: {} ({} annotations, {} patches)\n{}", r.output, r.annotation_count, r.patch_count, r.output))
    } else {
        Err(format!("Script failed: {}", r.output))
    }
}


// ---------------------------------------------------------------------------
// Main dispatch
// ---------------------------------------------------------------------------

fn run(argv: &[String]) -> Result<i32, String> {
    let a = parse_args(argv)?;
    if a.version { println!("aura-cli {VERSION}"); return Ok(0); }
    if a.help || a.command.is_empty() { println!("{}", usage_string()); return Ok(0); }

    match a.command.as_str() {
        "info" => cmd_info(&a).and_then(|t| Ok(emit(&a.out, t))),
        "sections" => cmd_sections(&a).and_then(|t| Ok(emit(&a.out, t))),
        "disasm" => cmd_disasm(&a).and_then(|t| Ok(emit(&a.out, t))),
        "sdk-scan" => cmd_sdk_scan(&a).and_then(|t| Ok(emit(&a.out, t))),
        "callgraph" => cmd_callgraph(&a).and_then(|t| Ok(emit(&a.out, t))),
        "cfg" => cmd_cfg(&a).and_then(|t| Ok(emit(&a.out, t))),
        "xrefs" => cmd_xrefs(&a).and_then(|t| Ok(emit(&a.out, t))),
        "decompile" => cmd_decompile(&a).and_then(|t| Ok(emit(&a.out, t))),
        "project" => cmd_project(&a).and_then(|t| Ok({ println!("{t}"); 0 })),
        "script" => cmd_script(&a).and_then(|t| Ok({ println!("{t}"); 0 })),
        // Export writes its own files into --out DIR; emit would just try to
        // overwrite the directory, so print the summary text instead.
        "export" => cmd_export(&a).and_then(|t| Ok({ println!("{t}"); 0 })),
        "formats" => cmd_formats(&a).and_then(|t| Ok(emit(&a.out, t))),
        cmd => Err(format!("Unknown command: {cmd}. Try --help")),
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    match run(&argv) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}
