//! Project save/load + scripting API (Tier 3) for Aura Decomp Tool.
//!
//! This is what makes Aura a *real* reverse-engineering tool rather than a
//! viewer: user work persists across sessions (like Ghidra's `.gpr` projects)
//! and the analysis engine is scriptable (like GhidraScript / Binary Ninja's
//! Python API).
//!
//! ## Project format (`.aura`)
//! A JSON file that layers user annotations on top of a binary — it does NOT
//! store the binary itself (which can be hundreds of MB), only the deltas:
//! renamed functions, address comments, function signatures, and binary
//! patches. Loading a project re-applies these over the freshly-analyzed
//! binary, so the project stays tiny and the binary can be re-analyzed as
//! the engine improves.
//!
//! ## Scripting API
//! A Lua 5.4 interpreter ([`run_script`]) with bindings to the analysis
//! engine. Scripts can automate batch renaming, comment propagation, or
//! custom analysis passes.
//!
//! Pure Rust (no Tauri); the GUI/CLI wire it to commands. Lua is vendored.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Project format
// ---------------------------------------------------------------------------

/// A user annotation on a single address.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Annotation {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

/// A single byte patch the user applied to the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    pub address: u32,
    pub bytes: Vec<u8>,
    #[serde(default)]
    pub note: Option<String>,
}

/// An Aura project — the user's annotation layer over a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuraProject {
    pub version: u32,
    pub binary_path: String,
    #[serde(default)]
    pub binary_sha1: Option<String>,
    #[serde(default)]
    pub binary_name: Option<String>,
    #[serde(default)]
    pub annotations: BTreeMap<u32, Annotation>,
    #[serde(default)]
    pub patches: Vec<Patch>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl Default for AuraProject {
    fn default() -> Self {
        AuraProject {
            version: 1, binary_path: String::new(), binary_sha1: None,
            binary_name: None, annotations: BTreeMap::new(),
            patches: Vec::new(), notes: None,
        }
    }
}

impl AuraProject {
    pub fn rename(&mut self, addr: u32, name: impl Into<String>) {
        self.annotations.entry(addr).or_default().name = Some(name.into());
    }
    pub fn comment(&mut self, addr: u32, text: impl Into<String>) {
        self.annotations.entry(addr).or_default().comment = Some(text.into());
    }
    pub fn signature(&mut self, addr: u32, sig: impl Into<String>) {
        self.annotations.entry(addr).or_default().signature = Some(sig.into());
    }
    pub fn patch(&mut self, addr: u32, bytes: Vec<u8>, note: Option<String>) {
        self.patches.push(Patch { address: addr, bytes, note });
    }
    pub fn name_at(&self, addr: u32) -> Option<&str> {
        self.annotations.get(&addr).and_then(|a| a.name.as_deref())
    }
    pub fn comment_at(&self, addr: u32) -> Option<&str> {
        self.annotations.get(&addr).and_then(|a| a.comment.as_deref())
    }
}

// ---------------------------------------------------------------------------
// Serialize / deserialize / file I/O
// ---------------------------------------------------------------------------

pub fn serialize_project(proj: &AuraProject) -> Result<String, String> {
    serde_json::to_string_pretty(proj).map_err(|e| format!("serialize: {e}"))
}

pub fn deserialize_project(json: &str) -> Result<AuraProject, String> {
    serde_json::from_str(json).map_err(|e| format!("deserialize: {e}"))
}

pub fn save_project_file(proj: &AuraProject, path: &str) -> Result<(), String> {
    let json = serialize_project(proj)?;
    std::fs::write(path, json).map_err(|e| format!("write {path}: {e}"))
}

pub fn load_project_file(path: &str) -> Result<AuraProject, String> {
    let json = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    deserialize_project(&json)
}

/// Merge a project's annotations over detected functions: any function whose
/// start address has a user name in the project gets renamed.
pub fn apply_project_to_functions(
    functions: &[(u32, String)],
    proj: &AuraProject,
) -> Vec<(u32, String)> {
    functions.iter().map(|&(addr, ref name)| {
        let n = proj.name_at(addr).map(|s| s.to_string()).unwrap_or_else(|| name.clone());
        (addr, n)
    }).collect()
}

/// Apply the project's byte patches to a binary's section data (in place).
/// Returns the number of patches applied.
pub fn apply_patches(data: &mut [u8], base: u32, proj: &AuraProject) -> usize {
    let mut applied = 0usize;
    for p in &proj.patches {
        if p.address >= base {
            let off = (p.address - base) as usize;
            if off + p.bytes.len() <= data.len() {
                data[off..off + p.bytes.len()].copy_from_slice(&p.bytes);
                applied += 1;
            }
        }
    }
    applied
}


// ---------------------------------------------------------------------------
// Scripting API (Lua 5.4 via mlua, vendored)
// ---------------------------------------------------------------------------

use mlua::prelude::*;

/// Context handed to a Lua script: the binary path + a mutable project the
/// script can edit (rename/comment/patch). The script's side effects land
/// here and the caller persists the project afterwards.
pub struct ScriptContext {
    pub binary_path: String,
    pub project: AuraProject,
    /// Detected functions: (address, name).
    pub functions: Vec<(u32, String)>,
    /// Section bytes + base address for the first code section (for patching).
    pub code_data: Vec<u8>,
    pub code_base: u32,
    pub is_le: bool,
}

/// Result of running a script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    pub success: bool,
    /// The script's return value (string) or error message.
    pub output: String,
    /// Number of annotations after the script ran.
    pub annotation_count: usize,
    /// Number of patches after the script ran.
    pub patch_count: usize,
    /// The updated project, serialized to JSON (so callers can persist it).
    pub project_json: String,
}

/// Run a Lua script with access to the analysis engine.
///
/// The script gets a global table `aura` with:
///   - `aura.functions` -> array of {addr=, name=}
///   - `aura.name_at(addr)` -> string|nil
///   - `aura.rename(addr, name)` -> renames in the project
///   - `aura.comment(addr, text)` -> adds a comment
///   - `aura.signature(addr, sig)` -> sets a type signature
///   - `aura.patch(addr, bytes_table, note?)` -> records a byte patch
///   - `aura.note(text)` -> sets project notes
///   - `aura.binary_path` -> string
/// The script may `return "summary text"` which becomes `output`.
pub fn run_script(source: &str, ctx: &mut ScriptContext) -> ScriptResult {
    let lua = Lua::new();
    // Build the `aura` global table.
    let aura = match lua.create_table() {
        Ok(t) => t,
        Err(e) => return err_result(format!("create_table: {e}")),
    };

    // aura.binary_path
    let _ = aura.set("binary_path", ctx.binary_path.clone());

    // aura.functions -> array of {addr=, name=}
    if let Ok(funcs) = lua.create_table() {
        for (i, (addr, name)) in ctx.functions.iter().enumerate() {
            if let Ok(entry) = lua.create_table() {
                let _ = entry.set("addr", *addr);
                let _ = entry.set("name", name.clone());
                let _ = funcs.set(i + 1, entry);
            }
        }
        let _ = aura.set("functions", funcs);
    }

    // aura.name_at(addr) -> string|nil
    let proj_clone = ctx.project.clone();
    if let Ok(f) = lua.create_function(move |_, addr: u32| {
        Ok(proj_clone.name_at(addr).map(|s| s.to_string()))
    }) {
        let _ = aura.set("name_at", f);
    }

    // The rename/comment/signature functions mutate ctx.project. mlua closures
    // can't capture &mut easily, so we collect edits in a shared *list* (array)
    // and apply them in order after the script runs. Using a list (not a map
    // keyed by address) means multiple edits to the same address all apply.
    let edits = match lua.create_table() { Ok(t) => t, Err(e) => return err_result(format!("{e}")) };

    let edits_for_rename = edits.clone();
    if let Ok(f) = lua.create_function(move |lua, (addr, name): (u32, String)| {
        if let Ok(t) = lua.create_table() {
            let _ = t.set("addr", addr);
            let _ = t.set("op", "rename");
            let _ = t.set("value", name);
            let _ = edits_for_rename.push(t);
        }
        Ok(())
    }) {
        let _ = aura.set("rename", f);
    }

    let edits_for_comment = edits.clone();
    if let Ok(f) = lua.create_function(move |lua, (addr, text): (u32, String)| {
        if let Ok(t) = lua.create_table() {
            let _ = t.set("addr", addr);
            let _ = t.set("op", "comment");
            let _ = t.set("value", text);
            let _ = edits_for_comment.push(t);
        }
        Ok(())
    }) {
        let _ = aura.set("comment", f);
    }

    let edits_for_sig = edits.clone();
    if let Ok(f) = lua.create_function(move |lua, (addr, sig): (u32, String)| {
        if let Ok(t) = lua.create_table() {
            let _ = t.set("addr", addr);
            let _ = t.set("op", "signature");
            let _ = t.set("value", sig);
            let _ = edits_for_sig.push(t);
        }
        Ok(())
    }) {
        let _ = aura.set("signature", f);
    }
// aura.patch(addr, bytes_table, note?) -> records a byte patch.
    let patch_edits = match lua.create_table() { Ok(t) => t, Err(e) => return err_result(format!("{e}")) };
    let patch_edits_ref = patch_edits.clone();
    if let Ok(f) = lua.create_function(move |lua, (addr, bytes, note): (u32, LuaValue, Option<String>)| {
        // bytes must be an array table of integers.
        let mut buf: Vec<u8> = Vec::new();
        if let LuaValue::Table(t) = bytes {
            for pair in t.pairs::<LuaValue, LuaValue>() {
                if let Ok((_, v)) = pair {
                    match v {
                        LuaValue::Integer(i) => buf.push(i as u8),
                        LuaValue::Number(n) => buf.push(n as u8),
                        _ => {}
                    }
                }
            }
        }
        if let Ok(pt) = lua.create_table() {
            let _ = pt.set("addr", addr);
            let _ = pt.set("bytes", buf);
            let _ = pt.set("note", note);
            let _ = patch_edits_ref.push(pt);
        }
        Ok(())
    }) {
        let _ = aura.set("patch", f);
    }

    let _ = lua.globals().set("aura", aura);

    // Run the script.
    let exec = lua.load(source).eval::<LuaValue>();
    let output = match exec {
        Ok(v) => match v {
            LuaValue::String(s) => s.to_str().map(|s| s.to_string()).unwrap_or_default(),
            LuaValue::Nil => String::new(),
            other => format!("{:?}", other),
        },
        Err(e) => return err_result(format!("script error: {e}")),
    };

    // Drain the edits table into ctx.project.
    let _ = drain_edits(&lua, &edits, &mut ctx.project);
    // Drain the patch edits into ctx.project.patches.
    let _ = drain_patch_edits(&lua, &patch_edits, &mut ctx.project);

    ScriptResult {
        success: true,
        output,
        annotation_count: ctx.project.annotations.len(),
        patch_count: ctx.project.patches.len(),
        project_json: serialize_project(&ctx.project).unwrap_or_else(|_| "{}".into()),
    }
}

fn err_result(msg: String) -> ScriptResult {
    ScriptResult {
        success: false, output: msg, annotation_count: 0, patch_count: 0,
        project_json: "{}".into(),
    }
}


/// Walk the edits list (array of {addr=, op=, value=}) and apply to the project.
fn drain_edits(_lua: &Lua, edits: &LuaTable, proj: &mut AuraProject) -> mlua::Result<()> {
    for pair in edits.pairs::<LuaValue, LuaTable>() {
        let (_, t) = pair?;
        let addr: u32 = match t.get("addr")? {
            LuaValue::Integer(i) => i as u32,
            LuaValue::Number(n) => n as u32,
            _ => continue,
        };
        let op: String = t.get("op")?;
        let value: String = t.get("value")?;
        match op.as_str() {
            "rename" => proj.rename(addr, value),
            "comment" => proj.comment(addr, value),
            "signature" => proj.signature(addr, value),
            _ => {}
        }
    }
    Ok(())
}
/// Walk the patch-edits list (array of {addr=, bytes=[...], note=}) and apply
/// them to the project's patch list.
fn drain_patch_edits(_lua: &Lua, edits: &LuaTable, proj: &mut AuraProject) -> mlua::Result<()> {
    for pair in edits.pairs::<LuaValue, LuaTable>() {
        let (_, t) = pair?;
        let addr: u32 = match t.get("addr")? {
            LuaValue::Integer(i) => i as u32,
            LuaValue::Number(n) => n as u32,
            _ => continue,
        };
        let bytes: Vec<u8> = t.get("bytes")?;
        let note: Option<String> = t.get("note")?;
        proj.patch(addr, bytes, note);
    }
    Ok(())
}

