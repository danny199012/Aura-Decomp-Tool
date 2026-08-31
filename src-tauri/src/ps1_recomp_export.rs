//! PS1 recompilation configuration export.
//!
//! Generates configuration files (TOML) that describe the binary's structure
//! for use with recompilation tools, including function boundaries, symbol
//! mappings, and section metadata.

use serde::Serialize;

/// A single function entry in the recomp config.
#[derive(Serialize, Debug)]
pub struct RecompFunctionEntry {
    pub address: u32,
    pub name: Option<String>,
    pub size: usize,
}

/// Section descriptor for the recomp config.
#[derive(Serialize, Debug)]
pub struct RecompSectionInfo {
    pub name: String,
    pub address: u32,
    pub size: usize,
}

/// The full recompilation configuration document.
#[derive(Serialize, Debug)]
pub struct RecompConfig {
    pub binary_name: String,
    pub sections: Vec<RecompSectionInfo>,
    pub functions: Vec<RecompFunctionEntry>,
    /// Total number of functions identified.
    pub function_count: usize,
}

/// Generate a recompilation configuration from parsed ELF data.
pub fn generate_recomp_config(
    binary_name: &str,
    sections: &[crate::ElfSection],
    functions: &[(u32, Option<String>)],
) -> RecompConfig {
    let section_infos: Vec<RecompSectionInfo> = sections
        .iter()
        .map(|s| RecompSectionInfo {
            name: s.name.clone(),
            address: s.address,
            size: s.data.len(),
        })
        .collect();

    let func_entries: Vec<RecompFunctionEntry> = functions
        .iter()
        .map(|(addr, name)| RecompFunctionEntry {
            address: *addr,
            name: name.clone(),
            size: 0, // Size not computed here; would require disassembly.
        })
        .collect();

    let function_count = func_entries.len();
    RecompConfig {
        binary_name: binary_name.to_string(),
        sections: section_infos,
        functions: func_entries,
        function_count,
    }
}

/// Tauri command wrapper for generating a recomp config.
#[tauri::command]
pub fn generate_ps1_recomp_config(
    binary_name: String,
    sections: Vec<crate::ElfSection>,
    functions: Vec<(u32, Option<String>)>,
) -> Result<RecompConfig, String> {
    Ok(generate_recomp_config(&binary_name, &sections, &functions))
}