// ============================================================================
// Disc-image ingest API — typed wrappers over the `disc_inspect` /
// `ps2_ingest_*` Tauri commands (src-tauri/src/main.rs → ps2_ingest.rs).
// Field names mirror the Rust `serde` output, hence snake_case.
// ============================================================================

import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { getCurrentWebview } from '@tauri-apps/api/webview';
import { call, isBackendAvailable } from './tauri';

export interface ExecutableFile {
  path: string;
  size: number;
  kind: string;
}

/** Header fields of a PS1 boot executable (PS-X EXE). */
export interface PsxExeInfo {
  entry_pc: number;
  gp: number;
  load_addr: number;
  text_size: number;
  initial_sp: number;
  region_marker: string;
}

export interface DiscInfo {
  image_path: string;
  opened_path: string;
  image_size: number;
  layout: string;
  platform: 'PS2' | 'PS1' | 'Unknown';
  volume_id: string;
  system_id: string;
  display_name: string;
  serial: string | null;
  region: string;
  boot_key: string | null;
  boot_value: string | null;
  boot_file: string | null;
  boot_size: number;
  boot_is_ps2_elf: boolean;
  /** PS1 discs: the boot file is a PS-X EXE. */
  boot_is_psx_exe: boolean;
  psx_exe: PsxExeInfo | null;
  ver: string | null;
  vmode: string | null;
  file_count: number;
  dir_count: number;
  total_bytes: number;
  executable_count: number;
  executables: ExecutableFile[];
  truncated: boolean;
  /** Sectors the volume descriptor claims beyond what the image holds. */
  missing_sectors: number;
  /** Files that reach into the missing part of a truncated image. */
  files_past_cut: number;
  /** The boot file itself reaches into the missing part. */
  boot_past_cut: boolean;
  warnings: string[];
  can_ingest: boolean;
}

export type ExtractMode = 'executables' | 'all';

export interface IngestProgress {
  stage: 'open' | 'inspect' | 'extract' | 'analyze' | 'config' | 'recompile' | 'done' | string;
  message: string;
  fraction: number;
  files_done: number;
  files_total: number;
  bytes_done: number;
  bytes_total: number;
}

export interface RecompilerRun {
  executable: string;
  command: string;
  success: boolean;
  exit_code: number | null;
  log_path: string;
  log_tail: string[];
  generated_files: number;
  error: string | null;
}

/** What indirect calls/jumps cost the recompiler, measured before it runs. */
export interface IndirectProfile {
  functions: number;
  functions_with_indirect_calls: number;
  functions_with_indirect_jumps: number;
  instructions: number;
  fallback_entries_standard: number;
  fallback_entries_lean: number;
}

export interface IngestResult {
  workspace: string;
  manifest_path: string;
  display_name: string;
  serial: string | null;
  region: string;
  platform: string;
  boot_file: string;
  elf_path: string;
  disc_dir: string;
  config_toml: string;
  functions_csv: string;
  recomp_output_dir: string;
  entry_point: number;
  function_count: number;
  sdk_named: number;
  extracted_files: number;
  extracted_bytes: number;
  /** "all" or "executables" — packaging a game needs "all". */
  extract_mode: 'all' | 'executables' | string;
  /** `ret0@0xADDR` bindings written to the config's `stubs` (BIOS-patching SDK routines). */
  stubbed: string[];
  indirect_profile: IndirectProfile;
  recompiler: RecompilerRun | null;
  next_steps: string[];
  warnings: string[];
}

export const inspectDisc = (path: string) => call<DiscInfo>('disc_inspect', { path });

export const runPs2Ingest = (
  path: string,
  outRoot: string,
  mode: ExtractMode,
  recompiler: string | null,
) => call<IngestResult>('ps2_ingest_run', { path, outRoot, mode, recompiler });

export const cancelPs2Ingest = () => call<void>('ps2_ingest_cancel', {});

export async function pickDiscImage(): Promise<string | null> {
  try {
    return await call<string | null>('pick_disc_image', {});
  } catch {
    return null;
  }
}

export async function pickRecompiler(): Promise<string | null> {
  try {
    return await call<string | null>('pick_recompiler', {});
  } catch {
    return null;
  }
}

export async function findRecompiler(): Promise<string | null> {
  try {
    return await call<string | null>('find_ps2_recompiler', {});
  } catch {
    return null;
  }
}

export const revealInFileManager = (path: string) => call<void>('reveal_in_file_manager', { path });

/** Subscribe to `ingest-progress` events. Returns an unsubscribe function. */
export async function onIngestProgress(cb: (p: IngestProgress) => void): Promise<UnlistenFn> {
  if (!isBackendAvailable()) return () => {};
  return listen<IngestProgress>('ingest-progress', (e) => cb(e.payload));
}

/**
 * Subscribe to files dropped onto the window. With `dragDropEnabled` the
 * webview never sees HTML5 file drops, so paths arrive via this Tauri event.
 */
export async function onFileDrop(cb: (paths: string[]) => void): Promise<UnlistenFn> {
  if (!isBackendAvailable()) return () => {};
  return getCurrentWebview().onDragDropEvent((e) => {
    if (e.payload.type === 'drop') cb(e.payload.paths);
  });
}

// ---------------------------------------------------------------------------
// Packaging: workspace + built runtime exe -> double-clickable game folder
// ---------------------------------------------------------------------------

export interface PackageResult {
  package_dir: string;
  game_exe: string;
  /** The file to double-click (aura-launch .exe when available, else a .cmd). */
  launcher: string;
  launcher_kind: 'exe' | 'cmd';
  cmd_launcher: string | null;
  boot_elf: string;
  disc_files: number;
  disc_bytes: number;
  disc_method: 'hardlink' | 'copy' | 'mixed' | 'in-place';
  dlls: string[];
  complete: boolean;
  extract_mode: string;
  display_name: string;
  serial: string | null;
  warnings: string[];
}

export interface PackageProgress {
  files_done: number;
  files_total: number;
  bytes_done: number;
  bytes_total: number;
  current: string;
}

export const packageGame = (workspace: string, exe: string, outDir: string | null, copy: boolean) =>
  call<PackageResult>('package_ps2_game', { workspace, exe, outDir, copy });

export async function pickRuntimeExe(): Promise<string | null> {
  try {
    return await call<string | null>('pick_runtime_exe', {});
  } catch {
    return null;
  }
}

export async function findAuraLauncher(): Promise<string | null> {
  try {
    return await call<string | null>('find_aura_launcher', {});
  } catch {
    return null;
  }
}

export const playPackagedGame = (launcher: string) => call<void>('play_packaged_game', { launcher });

/** Subscribe to `package-progress` events. Returns an unsubscribe function. */
export async function onPackageProgress(cb: (p: PackageProgress) => void): Promise<UnlistenFn> {
  if (!isBackendAvailable()) return () => {};
  return listen<PackageProgress>('package-progress', (e) => cb(e.payload));
}

// ---------------------------------------------------------------------------
// One-click build: generated C++ + upstream runtime -> exe -> game folder
// ---------------------------------------------------------------------------

export interface ToolStatus {
  name: string;
  found: boolean;
  path: string | null;
  detail: string;
}

export interface Toolchain {
  supported_os: boolean;
  cmake: ToolStatus;
  git: ToolStatus;
  compiler: ToolStatus;
  ready: boolean;
  problems: string[];
}

export interface DownloadItem {
  what: string;
  from: string;
  approx_mb: number;
}

export interface BuildPlan {
  toolchain: Toolchain;
  cache_dir: string;
  downloads: DownloadItem[];
  download_mb: number;
  source_cached: boolean;
  recompiler_cached: boolean;
  runtime_configured: boolean;
  functions: number;
  estimate_secs: number;
  cores: number;
  free_bytes: number | null;
  required_bytes: number;
  blockers: string[];
  can_build: boolean;
  pinned_commit: string;
  lean_indirect_calls: boolean;
  lean_ready: boolean;
  indirect_profile: IndirectProfile | null;
}

export interface BuildProgress {
  stage: string;
  message: string;
  fraction: number;
  elapsed_secs: number;
  log_tail: string[];
}

export interface BuildResult {
  exe: string;
  runtime_build_dir: string;
  cache_dir: string;
  log_path: string;
  generated_sources: number;
  elapsed_secs: number;
  stage_secs: [string, number][];
  native_feel: boolean;
  fast_release: boolean;
  lean_indirect_calls: boolean;
  package: PackageResult | null;
  warnings: string[];
}

export const planBuild = (workspace: string, cacheDir: string | null) =>
  call<BuildPlan>('plan_ps2_build', { workspace, cacheDir });

export const buildGame = (
  workspace: string,
  cacheDir: string | null,
  allowDownloads: boolean,
  nativeFeel: boolean,
  fastRelease: boolean,
  leanIndirectCalls: boolean,
) =>
  call<BuildResult>('build_ps2_game', {
    workspace,
    cacheDir,
    allowDownloads,
    nativeFeel,
    fastRelease,
    leanIndirectCalls,
  });

/** Subscribe to `build-progress` events. Returns an unsubscribe function. */
export async function onBuildProgress(cb: (p: BuildProgress) => void): Promise<UnlistenFn> {
  if (!isBackendAvailable()) return () => {};
  return listen<BuildProgress>('build-progress', (e) => cb(e.payload));
}

// ---------------------------------------------------------------------------
// PS1: disc -> workspace (cue/bin) -> PSXRecomp build -> game folder
// ---------------------------------------------------------------------------

export interface Ps1IngestResult {
  workspace: string;
  manifest_path: string;
  display_name: string;
  /** Readable title taken from the file name. */
  title: string;
  serial: string | null;
  region: string;
  platform: string;
  boot_file: string;
  psx_exe: PsxExeInfo;
  source_image: string;
  cue_path: string;
  /** "original" | "decompressed" | "generated" | "reused" */
  source_kind: string;
  source_bytes: number;
  disc_number: number | null;
  next_steps: string[];
  warnings: string[];
}

export interface Ps1Toolchain {
  supported_os: boolean;
  git: ToolStatus;
  python: ToolStatus;
  powershell: ToolStatus;
  bash: ToolStatus;
  build_tools: ToolStatus;
  /** "env" | "cache" | "system" | "missing" */
  build_tools_source: string;
  toolchain_dir: string | null;
  ready_apart_from_build_tools: boolean;
  problems: string[];
}

export interface Ps1BuildPlan {
  toolchain: Ps1Toolchain;
  cache_dir: string;
  display_name: string;
  serial: string | null;
  cue_path: string;
  downloads: DownloadItem[];
  download_mb: number;
  framework_cached: boolean;
  toolchain_cached: boolean;
  estimate_secs: number;
  cores: number;
  free_bytes: number | null;
  required_bytes: number;
  blockers: string[];
  can_build: boolean;
  pinned_commit: string;
  project_dir: string;
}

export interface Ps1Package {
  package_dir: string;
  exe: string;
  files: number;
  bytes: number;
}

export interface Ps1BuildResult {
  exe: string;
  project_dir: string;
  build_dir: string;
  cache_dir: string;
  log_path: string;
  /** The user's own disc image, to hand to the game (`--disc`). */
  source_image: string;
  elapsed_secs: number;
  stage_secs: [string, number][];
  package: Ps1Package | null;
  warnings: string[];
}

export const runPs1Ingest = (path: string, outRoot: string) =>
  call<Ps1IngestResult>('ps1_ingest_run', { path, outRoot });

export const planPs1Build = (workspace: string, cacheDir: string | null) =>
  call<Ps1BuildPlan>('plan_ps1_build', { workspace, cacheDir });

export const buildPs1Game = (workspace: string, cacheDir: string | null, allowDownloads: boolean) =>
  call<Ps1BuildResult>('build_ps1_game', { workspace, cacheDir, allowDownloads });

export const playPs1Game = (exe: string, disc: string | null) => call<void>('play_ps1_game', { exe, disc });

// ---------------------------------------------------------------------------
// PS1: play options, enhancements, diagnosis and state reset for a built game
// ---------------------------------------------------------------------------

export interface Ps1PlayOptions {
  /** "software" | "opengl" | "vulkan" */
  renderer: string;
  /** A preset ("native", "720p", "1080p", "1440p", "4k"…), "3x", or a line count. */
  internal_resolution: string;
  /** "W:H"; only honoured when the game has a widescreen mod. */
  aspect_ratio: string;
  /** 0 windowed, 1 borderless, 2 exclusive. */
  fullscreen: number;
  /** "on" | "off" | "immediate" | "adaptive" | "vrr" */
  vsync: string;
  /** 0 leaves the runtime's own choice alone. */
  window_width: number;
}

export interface Ps1Choice {
  value: string;
  label: string;
  detail: string;
}

export interface Ps1OptionChoices {
  renderers: Ps1Choice[];
  resolutions: Ps1Choice[];
  fullscreen: Ps1Choice[];
  vsync: Ps1Choice[];
  /** Things people ask for that this runtime cannot do, with the reason. */
  unavailable: Ps1Choice[];
}

export interface Ps1Preset {
  id: string;
  label: string;
  detail: string;
  renderer: string | null;
  internal_resolution: string;
  vsync: string | null;
}

export interface Ps1ModFeature {
  package_id: string;
  feature_id: string;
  name: string;
  description: string;
  enabled: boolean;
  default_enabled: boolean;
  deprecated: boolean;
}

export interface Ps1Finding {
  severity: 'error' | 'warn' | 'info';
  code: string;
  title: string;
  detail: string;
  fix: string | null;
}

export interface Ps1StateSummary {
  cache_bytes: number;
  cache_files: number;
  overlay_captures: boolean;
  freeze_dumps: number;
  has_last_report: boolean;
  stale_locks: number;
  saves_bytes: number;
}

export interface Ps1OptionsInfo {
  package_dir: string;
  title: string;
  exe: string;
  game_running: boolean;
  settings_path: string;
  settings_exists: boolean;
  options: Ps1PlayOptions;
  resolution_label: string;
  internal_scale: number | null;
  disc_path: string | null;
  widescreen_available: boolean;
  widescreen_mods: string[];
  /** game.toml offers Vulkan; without it the runtime ignores the setting. */
  vulkan_offered: boolean;
  mods: Ps1ModFeature[];
  choices: Ps1OptionChoices;
  presets: Ps1Preset[];
  findings: Ps1Finding[];
  state: Ps1StateSummary;
}

export interface Ps1WriteReport {
  settings_path: string;
  backup_path: string | null;
  changed: string[];
  warnings: string[];
}

export interface Ps1ModReport {
  state_path: string;
  backup_path: string | null;
  package_id: string;
  feature_id: string;
  enabled: boolean;
  changed: boolean;
}

export interface Ps1ResetReport {
  backup_dir: string | null;
  moved: string[];
  bytes: number;
  skipped: string[];
}

export const readPs1Options = (packageDir: string) => call<Ps1OptionsInfo>('ps1_options_read', { packageDir });

export const applyPs1Options = (packageDir: string, options: Ps1PlayOptions) =>
  call<Ps1WriteReport>('ps1_options_apply', { packageDir, options });

export const setPs1Mod = (packageDir: string, packageId: string, featureId: string, enabled: boolean) =>
  call<Ps1ModReport>('ps1_options_set_mod', { packageDir, packageId, featureId, enabled });

export const resetPs1State = (packageDir: string, includeSaves: boolean) =>
  call<Ps1ResetReport>('ps1_options_reset_state', { packageDir, includeSaves });
