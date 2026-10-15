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
  ver: string | null;
  vmode: string | null;
  file_count: number;
  dir_count: number;
  total_bytes: number;
  executable_count: number;
  executables: ExecutableFile[];
  truncated: boolean;
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
