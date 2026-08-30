//! Cross-platform SDK symbol database.
//!
//! This is the "killer feature" that makes Aura stand out from Ghidra: every
//! platform's common SDK/library exports are pre-loaded, so functions get
//! named automatically on file load.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkSymbolEntry {
    pub library: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub platform: Platform,
    pub match_method: MatchMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Platform {
    Ps1, Ps2, Ps3, Ps4, Ps5, Xbox, Xbox360, WiiU, GameCube, Wii, SegaGenesis,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Ps1 => "PS1", Platform::Ps2 => "PS2", Platform::Ps3 => "PS3",
            Platform::Ps4 => "PS4", Platform::Ps5 => "PS5", Platform::Xbox => "Xbox",
            Platform::Xbox360 => "Xbox 360", Platform::WiiU => "Wii U",
            Platform::GameCube => "GameCube", Platform::Wii => "Wii",
            Platform::SegaGenesis => "Sega Genesis",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchMethod {
    Ordinal(u32),
    Name,
    Signature,
    StringReference,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkSymbolMatch {
    pub address: u64, pub name: String, pub library: String,
    pub description: String, pub platform: String, pub match_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkScanResult {
    pub platform: String, pub total_functions_scanned: usize,
    pub matched_count: usize, pub matches: Vec<SdkSymbolMatch>,
    pub detected_libraries: Vec<String>,
}

static SDK_DATABASE: &[SdkSymbolEntry] = &[
    SdkSymbolEntry { library: "libapi", name: "ResetEntryInt", description: "Reset interrupt entry", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "ResetGraph", description: "Reset graphics pipeline", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "VSync", description: "Wait for vertical sync", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "VSyncCallback", description: "Register VSync callback", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "DrawSync", description: "Wait for GPU drawing completion", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "DrawSyncCallback", description: "Register draw-sync callback", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "PutDrawEnv", description: "Set the drawing environment", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "PutDispEnv", description: "Set the display environment", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "GetDrawEnv", description: "Get current drawing environment", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "GetDispEnv", description: "Get current display environment", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "ClearImage", description: "Clear a rectangular area of VRAM", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "LoadImage", description: "Load image data to VRAM", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "StoreImage", description: "Store image data from VRAM", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "MoveImage", description: "Copy a rectangular area in VRAM", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "DrawPrim", description: "Draw a primitive", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "DrawOTag", description: "Draw an ordering table", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "AddPrim", description: "Add a primitive to an OT", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "AddSprt", description: "Add a sprite to an OT", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "CatPrim", description: "Concatenate ordering tables", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetPolyF3", description: "Set flat-shaded triangle", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetPolyF4", description: "Set flat-shaded quad", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetPolyFT3", description: "Set textured triangle", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetPolyFT4", description: "Set textured quad", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetPolyG3", description: "Set gouraud-shaded triangle", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetPolyG4", description: "Set gouraud-shaded quad", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetPolyGT3", description: "Set gouraud-textured triangle", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetPolyGT4", description: "Set gouraud-textured quad", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetTile1", description: "Set 1x1 tile primitive", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetTile8", description: "Set 8x8 tile primitive", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetTile16", description: "Set 16x16 tile primitive", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetLineF2", description: "Set flat line (2 points)", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetLineF3", description: "Set flat line (3 points)", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetLineF4", description: "Set flat line (4 points)", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetLineG2", description: "Set gouraud line (2 points)", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetLineG3", description: "Set gouraud line (3 points)", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetSprt8", description: "Set 8x8 sprite", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libapi", name: "SetSprt16", description: "Set 16x16 sprite", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libgpu", name: "ResetGPU", description: "Reset the GPU", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libgpu", name: "SendGPUStatus", description: "Send command to GPU status register", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libgpu", name: "GetGPUStatus", description: "Read the GPU status register", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libgpu", name: "LoadImage", description: "DMA load image to VRAM", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libgpu", name: "StoreImage", description: "DMA store image from VRAM", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libgpu", name: "MoveImage", description: "GPU move image in VRAM", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libgpu", name: "DrawSync", description: "Wait for GPU to finish drawing", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libgpu", name: "DrawOTag", description: "Draw ordering table (GPU DMA)", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuInit", description: "Initialize the SPU", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuSetTransferMode", description: "Set SPU transfer mode", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuSetTransferStartAddr", description: "Set SPU transfer start address", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuWrite", description: "Write data to SPU memory", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuRead", description: "Read data from SPU memory", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuSetVoiceVolume", description: "Set SPU voice volume", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuSetVoicePitch", description: "Set SPU voice pitch", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuSetKey", description: "Key on/off SPU voices", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuGetKeyStatus", description: "Get SPU key status", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuSetReverb", description: "Set SPU reverb mode", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuSetReverbDepth", description: "Set SPU reverb depth", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuClearReverbWorkArea", description: "Clear SPU reverb work area", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libspu", name: "SpuIsTransferCompleted", description: "Check if SPU DMA transfer is done", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libpad", name: "PadInit", description: "Initialize controller pads", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libpad", name: "PadStop", description: "Stop controller pads", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libpad", name: "PadGetState", description: "Get controller state", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libpad", name: "PadRead", description: "Read controller data", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libpad", name: "PadSetActAlign", description: "Set controller actuator alignment", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libpad", name: "PadSetActDirect", description: "Set controller actuator directly", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libpad", name: "PadGetState2", description: "Get controller state (mode 2)", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libpad", name: "PadInfoMode", description: "Query controller mode info", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libcd", name: "CdInit", description: "Initialize CD-ROM subsystem", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libcd", name: "CdControl", description: "Send CD control command", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libcd", name: "CdControlB", description: "Send CD control (blocking)", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libcd", name: "CdSync", description: "Synchronize CD operations", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libcd", name: "CdReady", description: "Check if CD data is ready", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libcd", name: "CdGetStatus", description: "Get CD drive status", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libcd", name: "CdGetDiskType", description: "Get disk type", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libcd", name: "CdSearchFile", description: "Search for file on disk", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libcd", name: "CdRead", description: "Read sectors from CD", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libcd", name: "CdReadSync", description: "Sync CD read operations", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libcd", name: "CdGetSector", description: "Get CD sector address", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libcd", name: "CdSetDebug", description: "Set CD debug mode", platform: Platform::Ps1, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libc", name: "printf", description: "Formatted print", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "sprintf", description: "Formatted print to string", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "strlen", description: "String length", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memcpy", description: "Copy memory block", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memset", description: "Set memory block", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memcmp", description: "Compare memory blocks", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "strcpy", description: "Copy string", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "strcat", description: "Concatenate strings", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "strcmp", description: "Compare strings", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "strncmp", description: "Compare strings (bounded)", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "malloc", description: "Allocate memory", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "free", description: "Free allocated memory", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "qsort", description: "Quick sort", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "rand", description: "Random number generator", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "srand", description: "Seed random number generator", platform: Platform::Ps1, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libkernel", name: "FlushCache", description: "Flush CPU cache", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "CreateThread", description: "Create a new thread", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "DeleteThread", description: "Delete a thread", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "StartThread", description: "Start a thread", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "ExitThread", description: "Exit current thread", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "SleepThread", description: "Sleep current thread", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "WakeupThread", description: "Wake up a thread", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "iWakeupThread", description: "Wake up a thread (interrupt)", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "RotateThreadReadyQueue", description: "Rotate thread ready queue", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "ChangeThreadPriority", description: "Change thread priority", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "iChangeThreadPriority", description: "Change thread priority (interrupt)", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "GetThreadId", description: "Get current thread ID", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "ReferThreadStatus", description: "Get thread status", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "iReferThreadStatus", description: "Get thread status (interrupt)", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "DelayThread", description: "Delay current thread", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "SignalSemaphore", description: "Signal a semaphore", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "iSignalSemaphore", description: "Signal semaphore (interrupt)", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "WaitSema", description: "Wait on a semaphore", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "PollSema", description: "Poll a semaphore", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "CreateSema", description: "Create a semaphore", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "DeleteSema", description: "Delete a semaphore", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "CreateEventFlag", description: "Create an event flag", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "DeleteEventFlag", description: "Delete an event flag", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "SetEventFlag", description: "Set event flag bits", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "iSetEventFlag", description: "Set event flag (interrupt)", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "ClearEventFlag", description: "Clear event flag bits", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "WaitEventFlag", description: "Wait on event flag", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "PollEventFlag", description: "Poll event flag", platform: Platform::Ps2, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libc", name: "printf", description: "Formatted print", platform: Platform::Ps2, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "sprintf", description: "Formatted print to string", platform: Platform::Ps2, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memcpy", description: "Copy memory block", platform: Platform::Ps2, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memset", description: "Set memory block", platform: Platform::Ps2, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "strlen", description: "String length", platform: Platform::Ps2, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "malloc", description: "Allocate memory", platform: Platform::Ps2, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "free", description: "Free allocated memory", platform: Platform::Ps2, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "liblv2", name: "Lv2Syscall", description: "LV2 system call", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "ppu_thread_create", description: "Create a PPU thread", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "ppu_thread_exit", description: "Exit PPU thread", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "ppu_thread_join", description: "Join PPU thread", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "ppu_thread_yield", description: "Yield PPU thread", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_semaphore_create", description: "Create LV2 semaphore", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_semaphore_destroy", description: "Destroy LV2 semaphore", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_semaphore_wait", description: "Wait on LV2 semaphore", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_semaphore_post", description: "Signal LV2 semaphore", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_mutex_create", description: "Create LV2 mutex", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_mutex_destroy", description: "Destroy LV2 mutex", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_mutex_lock", description: "Lock LV2 mutex", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_mutex_unlock", description: "Unlock LV2 mutex", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_event_queue_create", description: "Create LV2 event queue", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_event_queue_destroy", description: "Destroy LV2 event queue", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_event_queue_receive", description: "Receive from LV2 event queue", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_timer_sleep", description: "Sleep via LV2 timer", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "liblv2", name: "sys_timer_usleep", description: "Microsecond sleep via LV2", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "gcmSys", name: "cellGcmInit", description: "Initialize RSX (GCM)", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "rsx", name: "cellGcmSetFlipMode", description: "Set GCM flip mode", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "rsx", name: "cellGcmSetDisplayBuffer", description: "Set GCM display buffer", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "gcmSys", name: "cellGcmFlush", description: "Flush GCM command buffer", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "gcmSys", name: "cellGcmFinish", description: "Finish GCM command buffer", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "io", name: "cellFsOpen", description: "Open a file (CELL FS)", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "io", name: "cellFsClose", description: "Close a file (CELL FS)", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "io", name: "cellFsRead", description: "Read from file (CELL FS)", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "io", name: "cellFsWrite", description: "Write to file (CELL FS)", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "io", name: "cellFsLseek", description: "Seek in file (CELL FS)", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "pad", name: "cellPadInit", description: "Initialize controller pads", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "pad", name: "cellPadEnd", description: "Finalize controller pads", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "pad", name: "cellPadGetData", description: "Read controller data", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "pad", name: "cellPadGetDataExtra", description: "Read controller extra data", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "pad", name: "cellPadSetActAlign", description: "Set controller actuator align", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "pad", name: "cellPadInfoPressMode", description: "Query controller press mode", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "audio", name: "cellAudioInit", description: "Initialize CELL audio", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "audio", name: "cellAudioPortOpen", description: "Open CELL audio port", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "audio", name: "cellAudioPortStart", description: "Start CELL audio port", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "audio", name: "cellAudioPortStop", description: "Stop CELL audio port", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "audio", name: "cellAudioPortClose", description: "Close CELL audio port", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "rsx", name: "cellGcmSetVertexDataArray", description: "Set RSX vertex array", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "rsx", name: "cellGcmSetVertexArrayPointer", description: "Set RSX vertex pointer", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "rsx", name: "cellGcmSetDrawIndexArray", description: "Draw RSX indexed array", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "rsx", name: "cellGcmSetDrawArray", description: "Draw RSX array", platform: Platform::Ps3, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libc", name: "memcpy", description: "Copy memory", platform: Platform::Ps3, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memset", description: "Set memory", platform: Platform::Ps3, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "strlen", description: "String length", platform: Platform::Ps3, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "printf", description: "Formatted print", platform: Platform::Ps3, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "malloc", description: "Allocate memory", platform: Platform::Ps3, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "free", description: "Free memory", platform: Platform::Ps3, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libkernel", name: "sceKernelLoadDirectModule", description: "Load a direct module", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "sceKernelDlsym", description: "Resolve dynamic symbol", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "sceKernelMapDirectMemory", description: "Map direct memory", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "sceKernelMmap", description: "Map memory", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "sceKernelMunmap", description: "Unmap memory", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "sceKernelMprotect", description: "Protect memory region", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "sceKernelCreateThread", description: "Create a thread", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "sceKernelWaitThreadEnd", description: "Wait for thread end", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libkernel", name: "sceKernelExitThread", description: "Exit current thread", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceLibc", name: "printf", description: "Formatted print", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceLibc", name: "memcpy", description: "Copy memory", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceLibc", name: "memset", description: "Set memory", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceLibc", name: "strlen", description: "String length", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceLibc", name: "malloc", description: "Allocate memory", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceLibc", name: "free", description: "Free allocated memory", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceLibc", name: "strcmp", description: "Compare strings", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceLibc", name: "strcpy", description: "Copy string", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceLibc", name: "sprintf", description: "Formatted print to string", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceGnmDriver", name: "sceGnmSubmitCommandBuffer", description: "Submit GNM command buffer (GPU)", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceGnmDriver", name: "sceGnmSubmitCommandBuffers", description: "Submit multiple GNM command buffers", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceGnmDriver", name: "sceGnmDrawInitDefaultHardContext", description: "Init GNM default hardware context", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libScePad", name: "scePadInit", description: "Initialize controller", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libScePad", name: "scePadOpen", description: "Open controller", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libScePad", name: "scePadRead", description: "Read controller data", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libScePad", name: "scePadReadState", description: "Read controller state", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libScePad", name: "scePadClose", description: "Close controller", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceAudio", name: "sceAudioOutOpen", description: "Open audio output", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceAudio", name: "sceAudioOutOutput", description: "Output audio data", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceAudio", name: "sceAudioOutClose", description: "Close audio output", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceVideoOut", name: "sceVideoOutOpen", description: "Open video output", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceVideoOut", name: "sceVideoOutSetFlipRate", description: "Set video flip rate", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceVideoOut", name: "sceVideoOutSubmitFlip", description: "Submit video flip", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceVideoOut", name: "sceVideoOutRegisterBuffers", description: "Register video buffers", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceVideoOut", name: "sceVideoOutClose", description: "Close video output", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceSysmodule", name: "sceSysmoduleLoadModule", description: "Load a system module", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libSceSysmodule", name: "sceSysmoduleUnloadModule", description: "Unload a system module", platform: Platform::Ps4, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3d8", name: "Direct3D_CreateDevice", description: "Create D3D8 device", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3d8", name: "Direct3D_CheckDeviceFormat", description: "Check D3D device format", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3d8", name: "Direct3D_GetDeviceCaps", description: "Get D3D device caps", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3dx8", name: "D3DXCreateTextureFromFile", description: "Create texture from file", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3dx8", name: "D3DXCreateTextureFromFileEx", description: "Create texture from file (extended)", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3dx8", name: "D3DXCreateVertexBuffer", description: "Create vertex buffer", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3dx8", name: "D3DXMatrixLookAtLH", description: "D3DX look-at matrix (LH)", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3dx8", name: "D3DXMatrixPerspectiveFovLH", description: "D3DX perspective matrix (LH)", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3dx8", name: "D3DXMatrixRotationY", description: "D3DX rotation Y matrix", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3dx8", name: "D3DXMatrixScaling", description: "D3DX scaling matrix", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3dx8", name: "D3DXMatrixTranslation", description: "D3DX translation matrix", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "NtCreateFile", description: "Create/open a file (NT)", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "NtClose", description: "Close a handle (NT)", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "NtReadFile", description: "Read from a file (NT)", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "NtWriteFile", description: "Write to a file (NT)", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "NtDeviceIoControlFile", description: "Device I/O control (NT)", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "MmAllocateContiguousMemory", description: "Allocate contiguous physical memory", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "MmFreeContiguousMemory", description: "Free contiguous physical memory", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeCreateThread", description: "Create a kernel thread", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeTerminateThread", description: "Terminate a thread", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeDelayExecutionThread", description: "Delay thread execution", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeWaitForSingleObject", description: "Wait for a single object", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeWaitForMultipleObjects", description: "Wait for multiple objects", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeInitializeEvent", description: "Initialize a kernel event", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeSetEvent", description: "Set a kernel event", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeInitializeSemaphore", description: "Initialize a semaphore", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeReleaseSemaphore", description: "Release a semaphore", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeInitializeMutant", description: "Initialize a mutant (mutex)", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeReleaseMutant", description: "Release a mutant (mutex)", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "XAudioCreateSoundBank", description: "Create XAudio sound bank", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "XAudioPlaySoundBank", description: "Play XAudio sound bank", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "XInputGetState", description: "Get controller input state", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "XInputSetState", description: "Set controller output state", platform: Platform::Xbox, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xam", name: "XamAlloc", description: "Allocate XAM memory", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xam", name: "XamFree", description: "Free XAM memory", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xam", name: "XamInputGetState", description: "Get XAM input state", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xam", name: "XamInputGetCapabilities", description: "Get XAM input capabilities", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xam", name: "XamInputSetState", description: "Set XAM input state", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xam", name: "XamShowMessageBoxUI", description: "Show message box UI", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "NtCreateFile", description: "Create/open file (X360)", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "NtClose", description: "Close handle (X360)", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "NtReadFile", description: "Read file (X360)", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "NtWriteFile", description: "Write file (X360)", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeCreateThread", description: "Create kernel thread (X360)", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeTerminateThread", description: "Terminate thread (X360)", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeWaitForSingleObject", description: "Wait for object (X360)", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeSetEvent", description: "Set event (X360)", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xboxkrnl", name: "KeInitializeEvent", description: "Initialize event (X360)", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3d9", name: "Direct3DCreate9", description: "Create D3D9 device (X360)", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "d3d9", name: "Direct3D9CreateDevice", description: "Create D3D9 device object", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xgraphics", name: "XTL_CreateTextureFromDDS", description: "Create texture from DDS", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "xaudiodll", name: "XAudioCreateEngine", description: "Create XAudio2 engine", platform: Platform::Xbox360, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSDynExport", description: "Dynamically export a function", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSDynLoad_Acquire", description: "Acquire a dynamic library", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSDynLoad_Release", description: "Release a dynamic library", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSDynLoad_FindExport", description: "Find an exported function", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSCreateThread", description: "Create a Cafe OS thread", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSResumeThread", description: "Resume a Cafe OS thread", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSSuspendThread", description: "Suspend a Cafe OS thread", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSJoinThread", description: "Join a Cafe OS thread", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSExitThread", description: "Exit current Cafe OS thread", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSYieldThread", description: "Yield current Cafe OS thread", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSGetCurrentThread", description: "Get current thread", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSSetThreadPriority", description: "Set thread priority", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSGetThreadPriority", description: "Get thread priority", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSInitMutex", description: "Initialize a mutex", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSLockMutex", description: "Lock a mutex", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSUnlockMutex", description: "Unlock a mutex", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSInitSemaphore", description: "Initialize a semaphore", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSSignalSemaphore", description: "Signal a semaphore", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSWaitSemaphore", description: "Wait on a semaphore", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSInitEvent", description: "Initialize an event", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSSetEvent", description: "Set an event", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSWaitEvent", description: "Wait on an event", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSAllocFromSystem", description: "Allocate from system heap", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSFreeToSystem", description: "Free to system heap", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "DCFlushRange", description: "Flush data cache range", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "ICInvalidateRange", description: "Invalidate instruction cache range", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSSleepTicks", description: "Sleep for N ticks", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "coreinit", name: "OSGetTime", description: "Get system time (ticks)", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "vpad", name: "VPADRead", description: "Read Wii U GamePad input", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "vpad", name: "VPADInit", description: "Initialize GamePad", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "vpad", name: "VPADGetTPCalibratedPoint", description: "Get calibrated touch point", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "padscore", name: "KPADRead", description: "Read Wii Remote/Pro Controller", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "padscore", name: "WPADRead", description: "Read Wii Remote input", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "gx2", name: "GX2Init", description: "Initialize GX2 graphics", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "gx2", name: "GX2DrawDone", description: "Wait for GX2 drawing completion", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "gx2", name: "GX2SetColorBuffer", description: "Set GX2 color buffer", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "gx2", name: "GX2SetViewport", description: "Set GX2 viewport", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "gx2", name: "GX2SetScissor", description: "Set GX2 scissor region", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "gx2", name: "GX2DrawEx2", description: "Draw GX2 indexed (extended)", platform: Platform::WiiU, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "DCFlushRange", description: "Flush data cache range", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "ICInvalidateRange", description: "Invalidate instruction cache", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSCreateThread", description: "Create an OS thread", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSResumeThread", description: "Resume an OS thread", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSSuspendThread", description: "Suspend an OS thread", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSJoinThread", description: "Join an OS thread", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSGetCurrentThread", description: "Get current thread", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSInitMutex", description: "Initialize a mutex", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSLockMutex", description: "Lock a mutex", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSUnlockMutex", description: "Unlock a mutex", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSInitSemaphore", description: "Initialize a semaphore", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSSignalSemaphore", description: "Signal a semaphore", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSWaitSemaphore", description: "Wait on a semaphore", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSAllocFromSystem", description: "Allocate from system heap", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSFreeToSystem", description: "Free to system heap", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "DolphinOS", name: "OSGetTime", description: "Get system time", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "GX", name: "GXInit", description: "Initialize GX graphics", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "GX", name: "GXDrawDone", description: "Wait for GX drawing completion", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "GX", name: "GXSetViewport", description: "Set GX viewport", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "GX", name: "GXSetScissor", description: "Set GX scissor", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "GX", name: "GXSetCullMode", description: "Set GX cull mode", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "GX", name: "GXDrawBegin", description: "Begin GX draw", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "GX", name: "GXDrawEnd", description: "End GX draw", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "GX", name: "GXSetArray", description: "Set GX vertex array", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "PAD", name: "PADInit", description: "Initialize controller pads", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "PAD", name: "PADRead", description: "Read controller data", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "PAD", name: "PADControlMotor", description: "Control controller motor", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "VI", name: "VIConfigure", description: "Configure video interface", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "VI", name: "VIFlush", description: "Flush video interface", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "VI", name: "VIWaitForRetrace", description: "Wait for video retrace", platform: Platform::GameCube, match_method: MatchMethod::Name },
    SdkSymbolEntry { library: "libc", name: "memcpy", description: "Copy memory block", platform: Platform::Ps3, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memset", description: "Set memory block", platform: Platform::Ps3, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "strlen", description: "String length", platform: Platform::Ps3, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memcpy", description: "Copy memory block", platform: Platform::Xbox360, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memset", description: "Set memory block", platform: Platform::Xbox360, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "strlen", description: "String length", platform: Platform::Xbox360, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memcpy", description: "Copy memory block", platform: Platform::WiiU, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memset", description: "Set memory block", platform: Platform::WiiU, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "strlen", description: "String length", platform: Platform::WiiU, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memcpy", description: "Copy memory block", platform: Platform::GameCube, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "memset", description: "Set memory block", platform: Platform::GameCube, match_method: MatchMethod::Signature },
    SdkSymbolEntry { library: "libc", name: "strlen", description: "String length", platform: Platform::GameCube, match_method: MatchMethod::Signature },
];

pub fn build_name_index(platform: Platform) -> HashMap<&'static str, &'static SdkSymbolEntry> {
    let mut map = HashMap::new();
    for entry in SDK_DATABASE {
        if entry.platform == platform && matches!(entry.match_method, MatchMethod::Name) {
            map.insert(entry.name, entry);
        }
    }
    map
}

pub fn build_ordinal_index(platform: Platform) -> HashMap<u32, &'static SdkSymbolEntry> {
    let mut map = HashMap::new();
    for entry in SDK_DATABASE {
        if entry.platform == platform {
            if let MatchMethod::Ordinal(ord) = entry.match_method {
                map.insert(ord, entry);
            }
        }
    }
    map
}

pub fn match_by_names(names: &[(String, u64)], platform: Platform) -> SdkScanResult {
    let db = build_name_index(platform);
    let mut matches = Vec::new();
    let mut detected_libs = Vec::new();
    for (name, address) in names {
        if let Some(entry) = db.get(name.as_str()) {
            matches.push(SdkSymbolMatch {
                address: *address, name: entry.name.to_string(),
                library: entry.library.to_string(), description: entry.description.to_string(),
                platform: platform.as_str().to_string(), match_method: "Name".to_string(),
            });
            if !detected_libs.contains(&entry.library.to_string()) {
                detected_libs.push(entry.library.to_string());
            }
        }
    }
    SdkScanResult { platform: platform.as_str().to_string(), total_functions_scanned: names.len(),
        matched_count: matches.len(), matches, detected_libraries: detected_libs }
}

pub fn match_by_ordinals(ordinals: &[(u32, u64)], platform: Platform) -> SdkScanResult {
    let db = build_ordinal_index(platform);
    let mut matches = Vec::new();
    let mut detected_libs = Vec::new();
    for (ord, address) in ordinals {
        if let Some(entry) = db.get(ord) {
            matches.push(SdkSymbolMatch {
                address: *address, name: entry.name.to_string(),
                library: entry.library.to_string(), description: entry.description.to_string(),
                platform: platform.as_str().to_string(), match_method: "Ordinal".to_string(),
            });
            if !detected_libs.contains(&entry.library.to_string()) {
                detected_libs.push(entry.library.to_string());
            }
        }
    }
    SdkScanResult { platform: platform.as_str().to_string(), total_functions_scanned: ordinals.len(),
        matched_count: matches.len(), matches, detected_libraries: detected_libs }
}

pub fn db_count_for_platform(platform: Platform) -> usize {
    SDK_DATABASE.iter().filter(|e| e.platform == platform).count()
}

pub fn db_count_total() -> usize { SDK_DATABASE.len() }

pub fn libraries_for_platform(platform: Platform) -> Vec<&'static str> {
    let mut libs = Vec::new();
    for entry in SDK_DATABASE {
        if entry.platform == platform && !libs.contains(&entry.library) { libs.push(entry.library); }
    }
    libs
}
