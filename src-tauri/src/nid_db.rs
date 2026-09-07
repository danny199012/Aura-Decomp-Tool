//! PS4/PS5 NID → symbol-name database (aerolib-compatible).
//!
//! PS4/PS5 Orbis binaries identify SDK imports and exports by **NID** (a
//! 64-bit identifier, base64-encoded by tooling), not by name — stripped
//! retail `.sprx` / `.self` modules carry NIDs where a normal ELF would carry
//! symbol-name string offsets. The community **aerolib.csv** database maps
//! those NIDs back to real C symbol names (`printf`, `scePadRead`, …), the
//! PS4/PS5 analogue of the PS2 SCE SDK SHA-1 fingerprint database.
//!
//! # Format
//! aerolib.csv is, despite the extension, **whitespace-delimited** (one record
//! per line, `NID<space>NAME`, Windows `\r\n` endings). This loader also
//! accepts a `,` delimiter for robustness. ~97k records, ~3.5 MB.
//!
//! # Licensing note
//! aerolib.csv is distributed by the `ps4_module_loader` project under
//! **GPL-3.0**. To keep Aura's own licensing uncompromised, this module does
//! **not** embed the database; it loads it from an external file the user
//! supplies via `AURA_PS4_NID_DB` (a path to an `aerolib.csv`). When the env
//! var is unset the DB is empty and PS4 NID renaming is a no-op.

use std::collections::HashMap;
use std::path::Path;

/// A loaded NID → symbol-name database.
#[derive(Debug, Clone, Default)]
pub struct NidDb {
    nids: HashMap<String, String>,
}

impl NidDb {
    /// An empty database (no NIDs known).
    pub fn empty() -> Self {
        Self { nids: HashMap::new() }
    }

    /// Parse an aerolib.csv-style text blob into a database. Each non-empty
    /// line is `NID<delim>NAME` where `<delim>` is the first comma or
    /// whitespace. Blank/comment/delimiter-less lines are skipped (never panic).
    pub fn load_from_csv(text: &str) -> Result<Self, String> {
        let mut nids: HashMap<String, String> = HashMap::new();
        for raw in text.lines() {
            let line = raw.trim_matches(|c| c == '\r' || c == '\n' || c == ' ' || c == '\t');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let delim = line.find(|c: char| c == ',' || c.is_whitespace());
            let Some(idx) = delim else { continue };
            let nid = line[..idx].trim();
            let name = line[idx..].trim_start_matches(|c: char| c == ',' || c.is_whitespace());
            if nid.is_empty() || name.is_empty() {
                continue;
            }
            nids.insert(nid.to_string(), name.to_string());
        }
        Ok(Self { nids })
    }

    /// Load a database from a file on disk (an `aerolib.csv`).
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("reading NID DB: {e}"))?;
        Self::load_from_csv(&text)
    }

    /// Look up the symbol name for a NID, if known.
    pub fn lookup(&self, nid: &str) -> Option<&str> {
        self.nids.get(nid).map(|s| s.as_str())
    }

    /// Number of NID → name entries in the database.
    pub fn len(&self) -> usize {
        self.nids.len()
    }

    /// Whether the database has any entries.
    pub fn is_empty(&self) -> bool {
        self.nids.is_empty()
    }
}

/// Lazily-loaded NID database.
///
/// On first use this reads `AURA_PS4_NID_DB` (a path to an `aerolib.csv`) and
/// loads it. If the env var is unset or the file is missing, the DB is empty
/// and a warning is printed once — the tool never crashes because a community
/// data file is absent. The result is cached for the process.
pub fn ps4_nid_db() -> &'static Result<NidDb, String> {
    static DB: std::sync::OnceLock<Result<NidDb, String>> = std::sync::OnceLock::new();
    DB.get_or_init(|| {
        match std::env::var_os("AURA_PS4_NID_DB") {
            Some(path) => {
                let p = Path::new(&path);
                if !p.exists() {
                    eprintln!(
                        "aura: AURA_PS4_NID_DB set to {} but the file is absent; \
                         PS4 NID renaming disabled",
                        p.display()
                    );
                    return Ok(NidDb::empty());
                }
                NidDb::load_from_file(p)
            }
            None => Ok(NidDb::empty()),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_space_delimited_records() {
        let csv = "ys1W6EwuVw4 __absvdi2\n2HED9ow7Zjc __absvsi2\n";
        let db = NidDb::load_from_csv(csv).unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(db.lookup("ys1W6EwuVw4"), Some("__absvdi2"));
        assert_eq!(db.lookup("2HED9ow7Zjc"), Some("__absvsi2"));
    }

    #[test]
    fn handles_windows_crlf_endings() {
        let csv = "AAA111aaaBB name1\r\nBBB222bbbCC name2\r\n";
        let db = NidDb::load_from_csv(csv).unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(db.lookup("AAA111aaaBB"), Some("name1"));
    }

    #[test]
    fn accepts_comma_delimiter() {
        let csv = "nidA,printf\nnidB,scePadRead\n";
        let db = NidDb::load_from_csv(csv).unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(db.lookup("nidA"), Some("printf"));
        assert_eq!(db.lookup("nidB"), Some("scePadRead"));
    }

    #[test]
    fn skips_blank_and_comment_lines() {
        let csv = "\n# a comment\nnidA nameA\n   \nnidB nameB\n";
        let db = NidDb::load_from_csv(csv).unwrap();
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn skips_lines_without_a_delimiter() {
        let csv = "orphanednid\nnidA nameA\n";
        let db = NidDb::load_from_csv(csv).unwrap();
        assert_eq!(db.len(), 1);
        assert_eq!(db.lookup("orphanednid"), None);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let db = NidDb::load_from_csv("nidA nameA").unwrap();
        assert_eq!(db.lookup("does-not-exist"), None);
    }

    #[test]
    fn empty_db() {
        let db = NidDb::empty();
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
        assert_eq!(db.lookup("anything"), None);
    }

    #[test]
    fn load_from_file_round_trips() {
        let dir = std::env::temp_dir().join("aura_nid_db_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("aerolib.csv");
        std::fs::write(&path, "nidA nameA\nnidB nameB\n").unwrap();
        let db = NidDb::load_from_file(&path).unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(db.lookup("nidA"), Some("nameA"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ps4_nid_db_without_env_var_is_ok() {
        // ps4_nid_db must never return Err when the env var is unset — a
        // missing community data file must not break the tool.
        let db = ps4_nid_db();
        assert!(db.is_ok(), "ps4_nid_db must never return Err when env unset");
    }
}
