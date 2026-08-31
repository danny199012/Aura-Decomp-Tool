// ============================================================================
// Typings mirroring the Rust/Tauri backend command returns (src-tauri/src/).
// These are deliberately lenient (some numeric fields are u32/u64/usize that
// serialize as JS numbers; occasionally a field is omitted on some platforms).
// ============================================================================

export type BinaryKind =
  | 'elf'      // PS1 / PS2 MIPS ELF (parse_elf_file)
  | 'xbe'      // Original Xbox XBE (parse_xbe_file)
  | 'xex'      // Xbox 360 XEX (parse_xex_file)
  | 'wiiu'     // Wii U RPX / RPL (parse_wiiu_file)
  | 'ps3'      // PS3 SELF / ELF (parse_ps3_file)
  | 'ps4ps5'   // PS4 / PS5 SELF / ELF (parse_ps4ps5_file)
  | 'ps1'      // PS1 binary / PS-X EXE / ELF
  | 'gameboy'; // GameBoy ROM

export interface FileOpenResponse {
  success: boolean;
  filename: string | null;
  size: number | null;
  message: string;
}

export interface ElfSection {
  name: string;
  address: number;
  size: number;
  offset: number;
  flags?: number;
}

export interface ElfSymbol {
  name: string;
  address: number;
  size: number;
  section: string;
}

export interface Relocation {
  offset: number;
  symbol_name: string;
  r_type: number;
  symbol: number;
}

export interface ElfFileInfo {
  filename: string;
  sections: ElfSection[];
  symbols: ElfSymbol[];
  entry_point: number;
  file_size: number;
  is_little_endian: boolean;
  is_32bit: boolean;
  relocations?: Relocation[];
}

export interface FunctionEntry {
  name: string;
  start: number;
  end: number;
  size: number;
}

export interface XbeSection {
  name: string;
  virtual_address: number;
  virtual_size: number;
  raw_offset: number;
  raw_size: number;
  flags: number;
  writable: boolean;
  preload: boolean;
  executable: boolean;
}

export interface XbeKernelImport {
  ordinal: number;
  name: string;
  thunk_address: number;
}

export interface XbeCertificate {
  title_id: number;
  title_id_str: string;
  title_name: string;
  version: number;
  game_region: number;
  game_region_names: string[];
  allowed_media: number;
  allowed_media_names: string[];
  alternate_title_ids: number[];
}

export interface XbeLibraryVersion {
  name: string;
  major: number;
  minor: number;
  build: number;
  qfe: number;
  approved: number;
  debug_build: boolean;
}

export interface XbeFileInfo {
  filename: string;
  file_type: string;
  base_address: number;
  size_of_image: number;
  size_of_headers: number;
  timestamp: number;
  entry_point: number;
  kernel_thunk_address: number;
  tls_address: number;
  certificate: XbeCertificate | null;
  sections: XbeSection[];
  library_versions: XbeLibraryVersion[];
  kernel_imports: XbeKernelImport[];
  has_logo_bitmap: boolean;
}
export interface XexPeSection {
  name: string;
  virtual_address: number;
  virtual_size: number;
  raw_offset: number;
  raw_size: number;
  characteristics: number;
  executable: boolean;
}

export interface XexImportLibrary {
  name: string;
  id: number;
  version: string;
  version_min: string;
  import_count: number;
}

export interface XexStaticLibrary {
  name: string;
  version_major: number;
  version_minor: number;
  version_build: number;
  approval_type: number;
  version_qfe: number;
}

export interface XexExecutionInfo {
  media_id: number;
  version: string;
  base_version: string;
  title_id: number;
  title_id_str: string;
  platform: number;
  executable_table: number;
  disc_number: number;
  disc_count: number;
  savegame_id: number;
}

export interface XexExport {
  name: string;
  ordinal: number;
  rva: number;
}

export interface XexFileInfo {
  filename: string;
  file_type: string;
  module_flags: number;
  module_flag_names: string[];
  data_offset: number;
  security_offset: number;
  load_address: number;
  image_size: number;
  image_flags: number;
  image_flag_names: string[];
  region: number;
  region_names: string[];
  entry_point: number | null;
  image_base: number | null;
  original_pe_name: string | null;
  default_stack_size: number | null;
  default_heap_size: number | null;
  system_flags: number | null;
  execution_info: XexExecutionInfo | null;
  static_libraries: XexStaticLibrary[];
  import_libraries: XexImportLibrary[];
  encryption: string;
  compression: string;
  pe_extractable: boolean;
  pe_sections: XexPeSection[];
  pe_exports: XexExport[];
}

export interface GenericSection {
  name: string;
  sh_addr: number;
  sh_offset: number;
  sh_size: number;
  is_code: boolean;
}

export interface WiiUFunctionName {
  name: string;
  address: number;
}

export interface WiiUFileInfo {
  filename: string;
  file_type: string;
  entry_point: number;
  machine: number;
  sections: GenericSection[];
  fimports: WiiUFunctionName[];
  fexports: WiiUFunctionName[];
  symbols: WiiUFunctionName[];
}

export interface Ps3FileInfo {
  filename: string;
  file_type: string;
  entry_point: number;
  machine: number;
  sections: GenericSection[];
  encrypted: boolean;
}

export interface Ps4Ps5FileInfo {
  filename: string;
  file_type: string;
  entry_point: number;
  machine: number;
  sections: GenericSection[];
  has_orbis_note: boolean;
  encrypted: boolean;
}

export interface DisassembledInstruction {
  address: number;
  bytes: number[];
  mnemonic: string;
  operands: string;
  text: string;
  size: number;
}

// ---- SDK scan -------------------------------------------------------------

export interface SdkSymbolMatch {
  address: number;
  name: string;
  library: string;
  description: string;
  platform: string;
  match_method: string;
}

export interface SdkScanResult {
  platform: string;
  total_functions_scanned: number;
  matched_count: number;
  matches: SdkSymbolMatch[];
  detected_libraries: string[];
}

export interface SdkDbStats {
  platform: string;
  symbol_count: number;
  libraries: string[];
  total_symbols_all_platforms: number;
}

// ---- Decomp project export ------------------------------------------------

export interface DecompExportResult {
  project_dir: string;
  files_written: string[];
  function_count: number;
  named_count: number;
  sdk_named_count: number;
  section_count: number;
  platform: string;
  binary_name: string;
  entry_point: number;
}

// ---- Interactive call graph (D3.js-ready) ---------------------------------

export interface GraphNode {
  id: string;
  address: number;
  name: string;
  size: number;
  is_named: boolean;
  library: string | null;
  call_count: number;
  called_by_count: number;
  is_entry: boolean;
  is_external: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  callsite: number;
  kind: string;
}

export interface HubFunction {
  name: string;
  address: number;
  call_count: number;
  called_by_count: number;
  score: number;
}

export interface GraphStatistics {
  total_functions: number;
  named_functions: number;
  external_functions: number;
  total_edges: number;
  max_call_depth: number;
  libraries: string[];
  hub_functions: HubFunction[];
}

export interface InteractiveCallGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  statistics: GraphStatistics;
}

// ---- PS1 analysis ---------------------------------------------------------

export interface SupportedFormat {
  name: string;
  extensions: string[];
  platforms: string[];
}

