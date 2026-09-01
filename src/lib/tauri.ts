// ============================================================================
// Lightweight wrapper around the Tauri `invoke` IPC bridge.
// Every helper maps to a `#[tauri::command]` registered in
// src-tauri/src/main.rs. When running under `vite dev` in a plain browser the
// bridge is absent, so `call()` transparently rejects; views surface that as a
// clear "backend unavailable" state rather than crashing.
//
// `probeBinary()` is the frontend router: it runs `identify_file(path)` and
// then, based on the identified magic, tries the platform parser(s) that could
// own the file. The first one that answers becomes the ruling `BinarySummary`,
// which the summary / disassembly / call-graph / export views all consume.
// ============================================================================

import { invoke } from '@tauri-apps/api/core';
import type {
  BinaryKind,
  ElfFileInfo,
  FileOpenResponse,
  Ps3FileInfo,
  Ps4Ps5FileInfo,
  WiiUFileInfo,
  XbeFileInfo,
  XexFileInfo,
} from '../types';

export interface SectionDef {
  name: string;
  address: number;
  size: number;
  isCode: boolean;
}

export interface BinarySummary {
  kind: BinaryKind;
  platform: string;
  identify: string;
  filename: string;
  path: string;
  entryPoint: number | null;
  littleEndian: boolean;
  sections: SectionDef[];
  codeSections: SectionDef[];
  meta: Record<string, string | number | boolean | null>;
  raw: unknown;
}

export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(command, args as Record<string, unknown>);
}

export const isBackendAvailable = () =>
  (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== undefined;

/** Open the native file picker (open_file_dialog) and return a path, or '' if cancelled/errored. */
export async function openFileDialog(): Promise<string> {
  try {
    return await call<string>('open_file_dialog', {});
  } catch {
    // Cancelled or dialog unavailable — treat as "no selection", never as a path.
    return '';
  }
}

/** Identify a path's container via the `identify_file` command. */
export async function identifyFile(path: string): Promise<string> {
  return call<string>('identify_file', { path });
}

export async function getSupportedFormats(): Promise<{ name: string; extensions: string[]; platforms: string[] }[]> {
  const r =
    (await call<{ formats: { name: string; extensions: string[]; platforms: string[] }[] }>('get_supported_formats', {})) ||
    { formats: [] };
  return r.formats ?? [];
}

export async function openFileMeta(path: string): Promise<FileOpenResponse> {
  return call<FileOpenResponse>('open_file', { path });
}

// ---------------------------------------------------------------------------
// Platform parsers
// ---------------------------------------------------------------------------

function elfToSections(info: ElfFileInfo): SectionDef[] {
  return info.sections.map((s) => ({
    name: s.name,
    address: s.address,
    size: s.size ?? 0,
    isCode: ((s.flags ?? 0) & 0x4) !== 0,
  }));
}

function normSections(
  sections: Array<{ name: string; sh_addr?: number; address?: number; sh_size?: number; size?: number; is_code?: boolean; executable?: boolean }>,
): SectionDef[] {
  return (sections ?? []).map((s) => ({
    name: s.name,
    address: s.sh_addr ?? s.address ?? 0,
    size: s.sh_size ?? s.size ?? 0,
    isCode: !!s.is_code || !!s.executable,
  }));
}
// ---------------------------------------------------------------------------
// probeBinary — identify + route to the owning parser.
// ---------------------------------------------------------------------------

export async function probeBinary(path: string): Promise<BinarySummary> {
  const identify = await identifyFile(path);
  const candidates: Array<() => Promise<Partial<BinarySummary>>> = [];

  if (identify.startsWith('elf')) {
    if (identify.includes('64-le')) {
      candidates.push(() => buildPs4Ps5(path));
      candidates.push(() => buildElf(path));
    } else if (identify.includes('64-be')) {
      candidates.push(() => buildPs3(path));
      candidates.push(() => buildWiiU(path));
      candidates.push(() => buildElf(path));
    } else {
      candidates.push(() => buildElf(path));
      candidates.push(() => buildPs3(path));
    }
  } else if (identify === 'xbe') {
    candidates.push(() => buildXbe(path));
  } else if (identify === 'xex') {
    candidates.push(() => buildXex(path));
  } else if (identify === 'self') {
    candidates.push(() => buildPs3(path));
    candidates.push(() => buildPs4Ps5(path));
  } else if (identify === 'psx-exe' || identify === 'ps1-disc') {
    candidates.push(() => buildPs1(path));
    candidates.push(() => buildElf(path));
  } else if (identify === 'gb-rom' || identify === 'gba-rom' || identify === 'nes-rom' || identify === 'n64-rom' || identify === 'nds-rom' || identify === 'snes-rom') {
    candidates.push(() => buildRetroRom(path, identify));
  } else if (identify === 'ps4-self') {
    candidates.push(() => buildPs4Ps5(path));
  } else if (identify === 'ps4-encrypted') {
    throw new Error('This is an encrypted PS4 retail game executable (eboot.bin). Decryption requires Sony\u2019s private keys and is not supported. Homebrew (OpenOrbis / fake-SELF) eboot.bin files and plain unencrypted PS4 ELF files are supported.');
  } else if (identify === 'chd') {
    throw new Error('CHD is a compressed disc image. Convert to .iso/.bin first, then open the resulting image.');
  } else {
    // raw / unknown — try console parsers. Wii U is LAST so its error isn't shown.
    candidates.push(() => buildElf(path));
    candidates.push(() => buildPs4Ps5(path));
    candidates.push(() => buildPs3(path));
    candidates.push(() => buildRetroRom(path, identify));
    candidates.push(() => buildWiiU(path));
  }

  const errors: string[] = [];
  for (const c of candidates) {
    try {
      const partial = await c();
      const base: BinarySummary = {
        kind: partial.kind ?? 'elf',
        platform: partial.platform ?? identify,
        identify,
        filename: partial.filename ?? path,
        path,
        entryPoint: partial.entryPoint ?? null,
        littleEndian: partial.littleEndian ?? false,
        sections: partial.sections ?? [],
        codeSections: partial.codeSections ?? [],
        meta: partial.meta ?? {},
        raw: partial.raw,
      };
      return base;
    } catch (e) {
      errors.push(String(e));
    }
  }
  // Show the most informative error, not just the first parser that ran.
  const best = errors
    .slice()
    .sort((a, b) => scoreError(b) - scoreError(a))[0];
  // If all errors are "not this format" messages, show a clear summary instead
  // of a single misleading one (e.g. "Not a Wii U RPX/RPL" for a PS1 .bin).
  const allFormatErrors = errors.every((e) => /not a|expected|magic/i.test(e));
  throw new Error(
    allFormatErrors
      ? `Could not identify this file (detected: ${identify}). It doesn't match any supported format (ELF, PS-X EXE, XBE, XEX, SELF, GameBoy ROM, or PlayStation disc image). Try opening it as a raw binary.`
      : `Could not identify this file (detected: ${identify}). ${best ?? 'No parser could read it.'}`,
  );
}

/// Rank parser errors so the most meaningful one is shown.
function scoreError(msg: string): number {
  let s = 0;
  // Penalize "Not a Wii U RPX/RPL" — it's the most misleading error for
  // non-Wii-U files since Wii U is the last parser tried.
  if (/wii u/i.test(msg)) s -= 10;
  if (/too small/i.test(msg)) s -= 2;
  if (/not a|expected|magic/i.test(msg)) s += 1;
  return s;
}

async function buildElf(path: string): Promise<Partial<BinarySummary>> {
  const info = await call<ElfFileInfo>('parse_elf_file', { path });
  const sections = elfToSections(info);
  return {
    kind: 'elf',
    platform: info.is_32bit ? 'PS1 / PS2 MIPS ELF' : 'ELF',
    filename: info.filename,
    entryPoint: info.entry_point,
    littleEndian: info.is_little_endian,
    sections,
    codeSections: sections.filter((s) => s.isCode),
    meta: {
      'entry point': `0x${(info.entry_point >>> 0).toString(16).toUpperCase()}`,
      symbols: info.symbols.length,
      relocations: info.relocations?.length ?? 0,
      'is 32-bit': info.is_32bit,
    },
    raw: info,
  };
}

async function buildPs1(path: string): Promise<Partial<BinarySummary>> {
  // The PS1 Analysis view calls analyze_ps1_binary, which handles bare ELF,
  // PS-X EXE, and disc images. Here we just provide a routing summary.
  return {
    kind: 'ps1',
    platform: 'PlayStation 1',
    filename: path.split(/[\\/]/).pop() ?? path,
    sections: [],
    codeSections: [],
    meta: { hint: 'Analyse via the PS1 Analysis view' },
  };
}

async function buildXbe(path: string): Promise<Partial<BinarySummary>> {
  const info = await call<XbeFileInfo>('parse_xbe_file', { path });
  const sections = (info.sections ?? []).map((s) => ({
    name: s.name,
    address: s.virtual_address,
    size: s.raw_size,
    isCode: s.executable,
  }));
  return {
    kind: 'xbe',
    platform: 'Original Xbox (XBE)',
    filename: info.filename,
    entryPoint: info.entry_point,
    littleEndian: true,
    sections,
    codeSections: sections.filter((s) => s.isCode),
    meta: {
      'base address': `0x${info.base_address.toString(16).toUpperCase()}`,
      'image size': info.size_of_image,
      title: info.certificate?.title_name ?? '(none)',
      'title id': info.certificate?.title_id_str ?? '',
      'kernel imports': info.kernel_imports.length,
      libraries: info.library_versions.length,
    },
    raw: info,
  };
}

async function buildXex(path: string): Promise<Partial<BinarySummary>> {
  const info = await call<XexFileInfo>('parse_xex_file', { path });
  const sections = (info.pe_sections ?? []).map((s) => ({
    name: s.name,
    address: s.virtual_address,
    size: s.raw_size || s.virtual_size,
    isCode: s.executable,
  }));
  return {
    kind: 'xex',
    platform: 'Xbox 360 (XEX)',
    filename: info.filename,
    entryPoint: info.entry_point,
    littleEndian: false,
    sections,
    codeSections: sections.filter((s) => s.isCode),
    meta: {
      encryption: info.encryption,
      compression: info.compression,
      'load address': `0x${info.load_address.toString(16).toUpperCase()}`,
      'image size': info.image_size,
      'import libraries': info.import_libraries.length,
      'PE sections': info.pe_sections.length,
      'PE extractable': info.pe_extractable,
    },
    raw: info,
  };
}

async function buildWiiU(path: string): Promise<Partial<BinarySummary>> {
  const info = await call<WiiUFileInfo>('parse_wiiu_file', { path });
  const sections = normSections(info.sections);
  return {
    kind: 'wiiu',
    platform: 'Wii U RPX / RPL (PPC64)',
    filename: info.filename,
    entryPoint: info.entry_point,
    littleEndian: false,
    sections,
    codeSections: sections.filter((s) => s.isCode),
    meta: {
      machine: info.machine,
      'function imports': info.fimports.length,
      'function exports': info.fexports.length,
      symbols: info.symbols.length,
    },
    raw: info,
  };
}

async function buildPs3(path: string): Promise<Partial<BinarySummary>> {
  const info = await call<Ps3FileInfo>('parse_ps3_file', { path });
  const sections = normSections(info.sections);
  return {
    kind: 'ps3',
    platform: 'PlayStation 3 (SELF / BE ELF)',
    filename: info.filename,
    entryPoint: info.entry_point,
    littleEndian: false,
    sections,
    codeSections: sections.filter((s) => s.isCode),
    meta: {
      'file type': info.file_type,
      machine: info.machine,
      encrypted: info.encrypted,
    },
    raw: info,
  };
}

async function buildPs4Ps5(path: string): Promise<Partial<BinarySummary>> {
  const info = await call<Ps4Ps5FileInfo>('parse_ps4ps5_file', { path });
  const sections = normSections(info.sections);
  return {
    kind: 'ps4ps5',
    platform: 'PlayStation 4 / 5 (SELF / LE ELF x86-64)',
    filename: info.filename,
    entryPoint: info.entry_point,
    littleEndian: true,
    sections,
    codeSections: sections.filter((s) => s.isCode),
    meta: {
      'file type': info.file_type,
      machine: info.machine,
      encrypted: info.encrypted,
      'orbis note': info.has_orbis_note,
    },
    raw: info,
  };
}

async function buildRetroRom(path: string, identify: string): Promise<Partial<BinarySummary>> {
  // For GameBoy/GBC, use the dedicated identify_gb_rom command which returns
  // header metadata. For other retro ROMs (NES/SNES/N64/GBA/NDS), build a
  // summary from the identify type — the file dialog already identified it.
  if (identify === 'gb-rom') {
    try {
      interface GbId {
        is_gameboy: boolean;
        header: {
          title: string; manufacturer_code: string; cgb_flag: number; mode: string;
          sgb_flag: number; version: number; rom_size: number; ram_size: number; destination: number;
        } | null;
      }
      const gb = await call<GbId>('identify_gb_rom', { path });
      if (!gb.is_gameboy || !gb.header) throw new Error('Not a GameBoy ROM');
      const h = gb.header;
      return {
        kind: 'gameboy' as BinaryKind,
        platform: `GameBoy${h.cgb_flag ? ' Color' : ''} (${h.mode.toUpperCase()})`,
        filename: path,
        entryPoint: 0,
        littleEndian: false,
        sections: [],
        codeSections: [],
        meta: {
          title: h.title,
          'manufacturer code': h.manufacturer_code,
          'rom size (KB)': h.rom_size,
          'ram size (KB)': h.ram_size,
          version: h.version,
        },
        raw: gb,
      };
    } catch (e) { throw e; }
  }
  // NES / SNES / N64 / GBA / NDS — basic identification summary.
  // Only succeed for ACTUAL retro ROM types; if identify is "raw" (unknown),
  // throw so the router tries the next candidate.
  const platforms: Record<string, string> = {
    'nes-rom': 'Nintendo (NES)',
    'snes-rom': 'Super Nintendo (SNES)',
    'n64-rom': 'Nintendo 64',
    'gba-rom': 'GameBoy Advance',
    'nds-rom': 'Nintendo DS',
  };
  const platform = platforms[identify];
  if (!platform) {
    throw new Error(`Not a recognized retro ROM type (got: ${identify})`);
  }
  return {
    kind: 'gameboy' as BinaryKind, // reuse the 'gameboy' kind for the retro ROM summary path
    platform,
    filename: path,
    entryPoint: 0,
    littleEndian: false,
    sections: [],
    codeSections: [],
    meta: {
      format: identify,
      hint: 'ROM loaded — use the Disassembly view for raw hex/byte view',
    },
  };
}

// ---------------------------------------------------------------------------
// Disassembly dispatch — maps a summary kind to the right section command.
// ---------------------------------------------------------------------------

export interface DisasmLoader {
  (path: string, section: string): Promise<import('../types').DisassembledInstruction[]>;
}

export function disassemblerFor(summary: BinarySummary): DisasmLoader {
  switch (summary.kind) {
    case 'xbe':
      return (p, s) => call<import('../types').DisassembledInstruction[]>('disassemble_xbe', { path: p, sectionName: s });
    case 'xex':
      return (p, s) => call<import('../types').DisassembledInstruction[]>('disassemble_xex', { path: p, sectionName: s });
    case 'wiiu':
      return (p, s) => call<import('../types').DisassembledInstruction[]>('disassemble_wiiu_section', { path: p, sectionName: s });
    case 'ps3':
      return (p, s) => call<import('../types').DisassembledInstruction[]>('disassemble_ps3_section', { path: p, sectionName: s });
    case 'ps4ps5':
      return (p, s) => call<import('../types').DisassembledInstruction[]>('disassemble_ps4ps5_section', { path: p, sectionName: s });
    case 'elf':
    case 'ps1':
      return async (p) => {
        const bin = await call<number[]>('read_raw_binary', { path: p, maxBytes: 0x200000 });
        const sec = summary.sections.find((c) => c.isCode);
        const text = await call<string>('disassemble_section', {
          data: bin, sectionName: sec?.name ?? '', startAddr: sec?.address ?? 0, isLittleEndian: summary.littleEndian,
        });
        return parseTextListing(text);
      };
    case 'gameboy':
    default:
      return async (p) => {
        const bin = await call<number[]>('read_raw_binary', { path: p, maxBytes: 0x8000 });
        const text = await call<string>('disassemble_gb_rom', { romData: bin, baseAddr: 0, maxInstructions: 4096 });
        return parseTextListing(text);
      };
  }
}

/** Best-effort parser for the backend's text-based disassembly listings. */
function parseTextListing(text: string): import('../types').DisassembledInstruction[] {
  const out: import('../types').DisassembledInstruction[] = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*([0-9A-Fa-f]{8})\s+(.+?)\s+([a-z][a-z0-9.]+)\s+(.*)$/);
    if (m) {
      out.push({ address: parseInt(m[1], 16), bytes: [], mnemonic: m[3], operands: m[4], text: line, size: 4 });
      continue;
    }
    const m2 = line.match(/^\s*0x([0-9A-Fa-f]+)\s+(.+)$/);
    if (m2) {
      out.push({ address: parseInt(m2[1], 16), bytes: [], mnemonic: m2[2], operands: '', text: line, size: 4 });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// SDK / call-graph / export conveniences.
// ---------------------------------------------------------------------------

export async function scanSdk(path: string, platform: string): Promise<import('../types').SdkScanResult> {
  return call<import('../types').SdkScanResult>('scan_sdk_symbols', { path, platform });
}

export async function sdkDbStats(platform: string): Promise<import('../types').SdkDbStats> {
  return call<import('../types').SdkDbStats>('get_sdk_db_stats', { platform });
}

export async function interactiveCallGraph(path: string): Promise<import('../types').InteractiveCallGraph> {
  return call<import('../types').InteractiveCallGraph>('get_interactive_call_graph', { path });
}

export async function exportDecompProject(path: string, platform: string, outputDir: string) {
  return call<{
    project_dir: string; files_written: string[]; function_count: number; named_count: number;
    sdk_named_count: number; section_count: number; platform: string;
  }>('export_decomp_project', { path, platform, outputDir });
}

export async function pickOutputFolder(): Promise<string | null> {
  try {
    const r = await call<string | null>('pick_output_folder', {});
    return r;
  } catch {
    return null;
  }
}

/** The platform list the backend SDK DB + export commands accept. */
export const SDK_PLATFORMS = [
  'PS1', 'PS2', 'PS3', 'PS4', 'PS5',
  'Xbox', 'Xbox 360', 'Wii U', 'GameCube', 'Wii', 'Sega Genesis',
] as const;

