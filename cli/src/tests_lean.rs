//! Tests for "lean indirect calls": the analyzer patch, the recompiler
//! variants built from it, and the ingest-time profile that motivates it.
//!
//! CMake is replaced by a script that decides what the "recompiler" it
//! produces is (`standard` or `lean`) by looking for the patch marker in the
//! upstream source it was configured against, so the whole variant logic —
//! including that the pinned source is always restored — runs without a
//! compiler.

use crate::build_common::{BuildProgress, Runner};
use crate::engine::{ElfSection, FunctionEntry};
use crate::ps2_build::{self, LeanState, LEAN_MARKER, LEAN_PATCH_FILE};
use crate::ps2_ingest::{indirect_profile, IndirectProfile};
use crate::tests_disc::TempDir;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A slice of upstream's analyzer containing the code the patch targets.
fn analyzer_source(crlf: bool) -> String {
    let lines = [
        "void ControlFlowAnalyzer::analyze() {",
        "        if (hasIndirectRegisterJump)",
        "        {",
        "            bool needsIndirectFallback = false;",
        "            for (const Instruction *jrInst : indirectJumps)",
        "            {",
        "                if (jrInst->function == SPECIAL_JALR)",
        "                {",
        "                    queueResumeEntryTarget(jrInst->address + 8u);",
        "                }",
        "",
        "                bool foundTable = false;",
        "            }",
        "        }",
        "}",
        "",
    ];
    lines.join(if crlf { "\r\n" } else { "\n" })
}

fn script(dir: &Path, name: &str, win: &str, unix: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let _ = unix;
        let p = dir.join(format!("{name}.cmd"));
        std::fs::write(&p, win.replace('\n', "\r\n")).unwrap();
        p
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = win;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{unix}")).unwrap();
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
        p
    }
}

/// Fake `cmake`. Configure remembers the source dir; build writes
/// `ps2xRecomp/Release/ps2_recomp.exe` whose text is `lean` when the source
/// currently carries the patch marker and `standard` otherwise. A
/// `fail-lean` file in the build dir makes a build of patched source fail.
fn fake_cmake(dir: &Path) -> PathBuf {
    let win = format!(
        "@echo off\nsetlocal\necho %* >> \"%~dp0cmake-args.log\"\nset MODE=configure\nset BDIR=\nset SRC=\n:loop\nif \"%~1\"==\"\" goto done\nif \"%~1\"==\"--build\" (\n  set MODE=build\n  set BDIR=%~2\n  shift\n)\nif \"%~1\"==\"-B\" (\n  set BDIR=%~2\n  shift\n)\nif \"%~1\"==\"-S\" (\n  set SRC=%~2\n  shift\n)\nshift\ngoto loop\n:done\nif \"%MODE%\"==\"configure\" (\n  mkdir \"%BDIR%\" 2>nul\n  echo ok> \"%BDIR%\\CMakeCache.txt\"\n  echo %SRC%> \"%BDIR%\\src.txt\"\n  exit /b 0\n)\nset /p SRC=<\"%BDIR%\\src.txt\"\nset KIND=standard\nfindstr /c:\"{LEAN_MARKER}\" \"%SRC%\\{file}\" >nul && set KIND=lean\nif \"%KIND%\"==\"lean\" if exist \"%BDIR%\\fail-lean\" (\n  echo error: lean build failed\n  exit /b 1\n)\nmkdir \"%BDIR%\\ps2xRecomp\\Release\" 2>nul\necho %KIND%> \"%BDIR%\\ps2xRecomp\\Release\\ps2_recomp.exe\"\nexit /b 0\n",
        file = LEAN_PATCH_FILE.replace('/', "\\")
    );
    let unix = format!(
        "echo \"$@\" >> \"$(dirname \"$0\")/cmake-args.log\"\nmode=configure\nbdir=\nsrc=\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    --build) mode=build; bdir=\"$2\"; shift ;;\n    -B) bdir=\"$2\"; shift ;;\n    -S) src=\"$2\"; shift ;;\n  esac\n  shift\ndone\nif [ \"$mode\" = configure ]; then\n  mkdir -p \"$bdir\"; echo ok > \"$bdir/CMakeCache.txt\"; echo \"$src\" > \"$bdir/src.txt\"; exit 0\nfi\nsrc=$(cat \"$bdir/src.txt\")\nkind=standard\ngrep -q \"{LEAN_MARKER}\" \"$src/{LEAN_PATCH_FILE}\" && kind=lean\nif [ \"$kind\" = lean ] && [ -e \"$bdir/fail-lean\" ]; then echo 'error: lean build failed'; exit 1; fi\nmkdir -p \"$bdir/ps2xRecomp/Release\"\necho $kind > \"$bdir/ps2xRecomp/Release/ps2_recomp\"\nexit 0\n"
    );
    script(dir, "cmake", &win, &unix)
}

struct Rig {
    t: TempDir,
    cmake: PathBuf,
    src: PathBuf,
    cache: PathBuf,
}

fn rig(source_text: &str) -> Rig {
    let t = TempDir::new("lean");
    let tools = t.path().join("tools");
    std::fs::create_dir_all(&tools).unwrap();
    let cmake = fake_cmake(&tools);
    let src = t.path().join("PS2Recomp");
    let file = src.join(LEAN_PATCH_FILE);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, source_text).unwrap();
    std::fs::write(src.join("CMakeLists.txt"), "project(fake)\n").unwrap();
    let cache = t.path().join("cache");
    Rig { t, cmake, src, cache }
}

fn ensure(rg: &Rig, lean: bool) -> Result<PathBuf, String> {
    let mut cb = |_: &BuildProgress| true;
    let mut r = Runner::new(&mut cb, None);
    ps2_build::ensure_recompiler(&mut r, &rg.cmake, &rg.src, &rg.cache, 2, lean)
}

fn text_of(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap().trim().to_string()
}

fn cmake_calls(rg: &Rig) -> usize {
    std::fs::read_to_string(rg.cmake.parent().unwrap().join("cmake-args.log"))
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The patch (pure)
// ---------------------------------------------------------------------------

mod patch_tests {
    use super::*;

    #[test]
    fn a_jalr_ra_keeps_its_resume_entry_and_skips_the_table_search() {
        let src = analyzer_source(false);
        assert_eq!(ps2_build::lean_patch_state(&src), LeanState::Pristine);
        let patched = ps2_build::apply_lean_patch(&src).unwrap();
        assert_eq!(ps2_build::lean_patch_state(&patched), LeanState::Patched);
        assert!(patched.contains(LEAN_MARKER));
        assert!(patched.contains("if (jrInst->rd == 31)"));
        // the resume entry upstream already queued is still there, before the skip
        let resume = patched.find("queueResumeEntryTarget(jrInst->address + 8u);").unwrap();
        let skip = patched.find("if (jrInst->rd == 31)").unwrap();
        assert!(resume < skip);
        // everything else is untouched
        assert!(patched.contains("bool foundTable = false;"));
        assert!(patched.len() > src.len());
    }

    #[test]
    fn apply_then_revert_restores_the_exact_text() {
        for crlf in [false, true] {
            let src = analyzer_source(crlf);
            let patched = ps2_build::apply_lean_patch(&src).unwrap();
            assert_eq!(patched.contains("\r\n"), crlf, "line endings are preserved");
            assert!(!patched.contains(if crlf { "\n\n" } else { "\r\n" }) || crlf, "no mixed endings introduced");
            assert_eq!(ps2_build::revert_lean_patch(&patched).unwrap(), src, "crlf={crlf}");
        }
    }

    #[test]
    fn crlf_sources_are_recognised() {
        let src = analyzer_source(true);
        assert_eq!(ps2_build::lean_patch_state(&src), LeanState::Pristine);
        let patched = ps2_build::apply_lean_patch(&src).unwrap();
        assert!(patched.lines().any(|l| l.contains(LEAN_MARKER)));
    }

    #[test]
    fn patching_twice_or_reverting_a_pristine_file_is_refused() {
        let src = analyzer_source(false);
        let patched = ps2_build::apply_lean_patch(&src).unwrap();
        assert!(ps2_build::apply_lean_patch(&patched).unwrap_err().contains("already"));
        assert!(ps2_build::revert_lean_patch(&src).is_err());
    }

    #[test]
    fn an_upstream_that_changed_is_reported_not_guessed_at() {
        let other = "void analyze() { if (x) { y(); } }\n";
        assert_eq!(ps2_build::lean_patch_state(other), LeanState::Unavailable);
        let e = ps2_build::apply_lean_patch(other).unwrap_err();
        assert!(e.contains("not available") && e.contains(LEAN_PATCH_FILE), "{e}");
        // a hand-edited marker region cannot be auto-reverted
        let tampered = format!("// {LEAN_MARKER} but edited\n");
        assert!(ps2_build::revert_lean_patch(&tampered).is_err());
    }
}

// ---------------------------------------------------------------------------
// Recompiler variants
// ---------------------------------------------------------------------------

mod variant_tests {
    use super::*;

    #[test]
    fn standard_then_lean_are_built_once_each_and_the_source_is_restored() {
        let original = analyzer_source(false);
        let rg = rig(&original);

        let std_exe = ensure(&rg, false).unwrap();
        assert_eq!(std_exe, ps2_build::recompiler_variant(&rg.cache, false));
        assert_eq!(text_of(&std_exe), "standard");
        let after_standard = cmake_calls(&rg);
        assert_eq!(after_standard, 2, "configure + build");

        let lean_exe = ensure(&rg, true).unwrap();
        assert_eq!(lean_exe, ps2_build::recompiler_variant(&rg.cache, true));
        assert_eq!(text_of(&lean_exe), "lean", "built from the patched source");
        assert_eq!(text_of(&std_exe), "standard", "the standard variant is untouched");
        assert_eq!(cmake_calls(&rg), after_standard + 1, "only an incremental build, no reconfigure");
        assert_eq!(
            std::fs::read_to_string(rg.src.join(LEAN_PATCH_FILE)).unwrap(),
            original,
            "the pinned source is restored byte for byte"
        );

        // both are cached: asking again runs nothing
        let calls = cmake_calls(&rg);
        assert_eq!(ensure(&rg, true).unwrap(), lean_exe);
        assert_eq!(ensure(&rg, false).unwrap(), std_exe);
        assert_eq!(cmake_calls(&rg), calls);
    }

    #[test]
    fn asking_for_lean_first_builds_the_standard_variant_too() {
        let rg = rig(&analyzer_source(true)); // CRLF, as upstream's checkout on Windows
        let lean = ensure(&rg, true).unwrap();
        assert_eq!(text_of(&lean), "lean");
        assert_eq!(text_of(&ps2_build::recompiler_variant(&rg.cache, false)), "standard");
        assert!(!std::fs::read_to_string(rg.src.join(LEAN_PATCH_FILE)).unwrap().contains(LEAN_MARKER));
    }

    #[test]
    fn an_existing_cache_from_before_variants_is_adopted_without_rebuilding() {
        let rg = rig(&analyzer_source(false));
        let legacy = rg.cache.join("build-recomp").join("ps2xRecomp").join("Release");
        std::fs::create_dir_all(&legacy).unwrap();
        let exe = legacy.join(if cfg!(windows) { "ps2_recomp.exe" } else { "ps2_recomp" });
        std::fs::write(&exe, "legacy-standard\n").unwrap();

        let got = ensure(&rg, false).unwrap();
        assert_eq!(text_of(&got), "legacy-standard");
        assert_eq!(cmake_calls(&rg), 0, "nothing was rebuilt");
    }

    #[test]
    fn a_failed_lean_build_still_restores_the_source_and_reports_the_error() {
        let original = analyzer_source(false);
        let rg = rig(&original);
        ensure(&rg, false).unwrap();
        std::fs::write(rg.cache.join("build-recomp").join("fail-lean"), b"x").unwrap();
        let e = ensure(&rg, true).unwrap_err();
        assert!(e.contains("lean recompiler") && e.contains("lean build failed"), "{e}");
        assert_eq!(std::fs::read_to_string(rg.src.join(LEAN_PATCH_FILE)).unwrap(), original);
        assert!(!ps2_build::recompiler_variant(&rg.cache, true).exists(), "no half-built variant is left behind");
    }

    #[test]
    fn lean_is_refused_when_upstream_is_not_the_tested_version() {
        let other = "void analyze() {}\n";
        let rg = rig(other);
        ensure(&rg, false).unwrap();
        let e = ensure(&rg, true).unwrap_err();
        assert!(e.contains("not available"), "{e}");
        assert_eq!(std::fs::read_to_string(rg.src.join(LEAN_PATCH_FILE)).unwrap(), other);
        assert_eq!(text_of(&ps2_build::recompiler_variant(&rg.cache, false)), "standard", "standard still works");
        let _ = &rg.t;
    }
}

// ---------------------------------------------------------------------------
// Indirect-call profile
// ---------------------------------------------------------------------------

mod profile_tests {
    use super::*;

    const JR_RA: u32 = 0x03E0_0008;
    const NOP: u32 = 0;
    fn jr(rs: u32) -> u32 {
        (rs << 21) | 0x08
    }
    fn jalr(rd: u32, rs: u32) -> u32 {
        (rs << 21) | (rd << 11) | 0x09
    }
    fn addiu(rt: u32, rs: u32, imm: u32) -> u32 {
        (0x09 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)
    }

    fn section(words: &[u32], base: u32, le: bool) -> ElfSection {
        let mut data = Vec::new();
        for w in words {
            data.extend_from_slice(&if le { w.to_le_bytes() } else { w.to_be_bytes() });
        }
        ElfSection { name: ".text".into(), address: base, size: data.len() as u32, offset: 0, data, flags: 0 }
    }

    fn func(name: &str, start: u32, words: u32) -> FunctionEntry {
        FunctionEntry { name: name.into(), start, end: start + words * 4, size: words * 4 }
    }

    #[test]
    fn calls_jumps_and_plain_functions_are_told_apart() {
        // plain: 3 insns | virtual call: 4 insns | switch jump: 5 insns | jalr without link: 2 insns
        let words = [
            addiu(2, 0, 1), NOP, JR_RA, // plain
            addiu(2, 0, 1), jalr(31, 2), NOP, JR_RA, // jalr $ra
            addiu(8, 0, 4), jr(8), NOP, NOP, JR_RA, // jr $t0
            jalr(0, 25), NOP, // jalr $zero, $t9 acts as a jump
        ];
        let sec = section(&words, 0x100000, true);
        let funcs = vec![
            func("plain", 0x100000, 3),
            func("virt", 0x10000C, 4),
            func("switch", 0x10001C, 5),
            func("tail", 0x100030, 2),
        ];
        let p = indirect_profile(&[sec], &funcs, true);
        assert_eq!(p.functions, 4);
        assert_eq!(p.instructions, 14);
        assert_eq!(p.functions_with_indirect_calls, 1);
        assert_eq!(p.functions_with_indirect_jumps, 2);
        assert_eq!(p.fallback_entries_standard, 4 + 5 + 2, "every function with any indirect jump or call");
        assert_eq!(p.fallback_entries_lean, 5 + 2, "calls no longer count");
        assert!(p.fallback_entries_lean <= p.fallback_entries_standard);
    }

    #[test]
    fn jr_ra_is_a_return_not_an_indirect_jump() {
        let sec = section(&[addiu(2, 0, 1), JR_RA, NOP], 0x1000, true);
        let p = indirect_profile(&[sec], &[func("f", 0x1000, 3)], true);
        assert_eq!((p.functions_with_indirect_calls, p.functions_with_indirect_jumps, p.fallback_entries_standard), (0, 0, 0));
    }

    #[test]
    fn byte_order_is_honoured() {
        let words = [jalr(31, 25), NOP, JR_RA, NOP];
        for le in [true, false] {
            let p = indirect_profile(&[section(&words, 0x2000, le)], &[func("f", 0x2000, 4)], le);
            assert_eq!(p.functions_with_indirect_calls, 1, "le={le}");
        }
        // read with the wrong byte order the same bytes are not a jalr
        let wrong = indirect_profile(&[section(&words, 0x2000, true)], &[func("f", 0x2000, 4)], false);
        assert_eq!(wrong.functions_with_indirect_calls, 0);
    }

    #[test]
    fn functions_outside_any_section_or_past_its_end_do_not_panic() {
        let sec = section(&[jalr(31, 2), NOP, JR_RA, NOP], 0x4000, true);
        let funcs = vec![
            func("gone", 0x9000, 8),         // no section
            func("overrun", 0x4004, 100),    // runs past the section end: clipped
            FunctionEntry { name: "empty".into(), start: 0x4000, end: 0x4000, size: 0 },
            FunctionEntry { name: "odd".into(), start: 0x4002, end: 0x400C, size: 10 }, // misaligned start
        ];
        let p = indirect_profile(&[sec], &funcs, true);
        assert_eq!(p.functions, 4);
        assert!(p.instructions <= 8, "never counts beyond the section: {}", p.instructions);
    }

    fn sltiu(rt: u32, rs: u32, imm: u32) -> u32 {
        (0x0b << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)
    }
    fn sll(rd: u32, rt: u32, sa: u32) -> u32 {
        (rt << 16) | (rd << 11) | (sa << 6)
    }
    fn lui(rt: u32, imm: u32) -> u32 {
        (0x0f << 26) | (rt << 16) | (imm & 0xFFFF)
    }
    fn addu(rd: u32, rs: u32, rt: u32) -> u32 {
        (rs << 21) | (rt << 16) | (rd << 11) | 0x21
    }
    fn lw(rt: u32, rs: u32, off: u32) -> u32 {
        (0x23 << 26) | (rs << 21) | (rt << 16) | (off & 0xFFFF)
    }

    /// `switch (a0)` as GCC emits it: bound, scale, table base, add, load, jump.
    fn switch_idiom(with_bound: bool) -> Vec<u32> {
        let mut w = vec![];
        if with_bound {
            w.push(sltiu(9, 4, 5)); // t1 = a0 < 5
        } else {
            w.push(addiu(9, 0, 1)); // unrelated
        }
        w.extend([
            sll(10, 4, 2),          // t2 = a0 << 2
            lui(11, 0x40),          // t3 = 0x400000
            addiu(11, 11, 0x100),   // t3 += 0x100
            addu(10, 11, 10),       // t2 = t3 + t2
            lw(12, 10, 0),          // t4 = *t2
            jr(12),                 // jr t4
            NOP,
            JR_RA,
        ]);
        w
    }

    #[test]
    fn a_switch_with_the_full_idiom_is_resolved_by_the_recompiler_and_not_counted() {
        let words = switch_idiom(true);
        let n = words.len() as u32;
        let p = indirect_profile(&[section(&words, 0x1000, true)], &[func("sw", 0x1000, n)], true);
        assert_eq!(p.functions_with_indirect_jumps, 0, "{p:?}");
        assert_eq!(p.fallback_entries_standard, 0);
    }

    #[test]
    fn an_incomplete_switch_idiom_stays_an_unresolved_jump() {
        let words = switch_idiom(false); // no sltiu bound on the index
        let n = words.len() as u32;
        let p = indirect_profile(&[section(&words, 0x1000, true)], &[func("sw", 0x1000, n)], true);
        assert_eq!(p.functions_with_indirect_jumps, 1);
        assert_eq!(p.fallback_entries_standard, n as u64);
        assert_eq!(p.fallback_entries_lean, n as u64, "an unresolved jump is not helped by lean mode");
    }

    #[test]
    fn a_virtual_call_is_never_mistaken_for_a_switch() {
        // lw v0, 0(a0); lw v0, 8(v0); jalr v0 — the C++ virtual call shape
        let words = [lw(2, 4, 0), lw(2, 2, 8), NOP, jalr(31, 2), NOP, JR_RA, NOP];
        let p = indirect_profile(&[section(&words, 0x1000, true)], &[func("v", 0x1000, 7)], true);
        assert_eq!((p.functions_with_indirect_calls, p.functions_with_indirect_jumps), (1, 0));
        assert_eq!((p.fallback_entries_standard, p.fallback_entries_lean), (7, 0));
    }

    #[test]
    fn the_profile_round_trips_through_the_manifest_json() {
        let p = IndirectProfile {
            functions: 10,
            functions_with_indirect_calls: 3,
            functions_with_indirect_jumps: 1,
            instructions: 500,
            fallback_entries_standard: 120,
            fallback_entries_lean: 20,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(serde_json::from_value::<IndirectProfile>(v).unwrap(), p);
    }

    /// Manual check against a real retail ELF: `AURA_PROFILE_ELF=<path> cargo test
    /// --test-threads=1 -- --ignored real_elf_profile --nocapture`. On the
    /// Midnight Club 3 Remix ELF the recompiler reported 947,446 fallback entries.
    #[test]
    #[ignore]
    fn real_elf_profile() {
        let Ok(path) = std::env::var("AURA_PROFILE_ELF") else {
            eprintln!("set AURA_PROFILE_ELF to an ELF to profile");
            return;
        };
        let bytes = std::fs::read(&path).unwrap();
        let info = crate::engine::parse_elf_data(&bytes, "real.elf").unwrap();
        let funcs = crate::engine::detect_functions_inner(&info).unwrap();
        let p = indirect_profile(&info.sections, &funcs, info.is_little_endian);
        eprintln!("{p:#?}");
        assert!(p.functions > 0);
    }
}
