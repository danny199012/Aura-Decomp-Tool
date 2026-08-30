// Sega Genesis / Master System ROM parser and M68K disassembler
// Provides alternative-to-Ghidra decompilation support for Sega platforms

use serde::{Deserialize, Serialize};
use std::fs;

// ===================== Sega Genesis/Master System ROM Header =====================

/// Sega Genesis/Mega Drive ROM header (Cartridge Header)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisHeader {
    pub title: String,
    pub company_code: String,
    pub region: String,
    pub rom_size: usize,
    pub ram_size: Option<usize>,
    pub header_checksum: u8,
    pub game_id: String,
    pub platform: String, // "genesis", "sms", "gamegear"
}

/// Identification result for Sega ROM files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegaRomIdentification {
    pub is_sega_rom: bool,
    pub header: Option<GenesisHeader>,
    pub rom_data: Vec<u8>,
    pub platform: String, // "genesis", "sms", "gamegear"
}

/// M68K instruction disassembly result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M68kInstruction {
    pub address: u32,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub size: usize, // instruction length in bytes
}

/// Disassembly output for Sega ROM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegaDisassembly {
    pub platform: String,
    pub title: String,
    pub instructions: Vec<M68kInstruction>,
    pub entry_point: u32,
}

// ===================== M68K Disassembler =====================

/// M68K register names for data registers
const DATA_REG_NAMES: [&str; 8] = ["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"];

/// M68K register names for address registers
const ADDR_REG_NAMES: [&str; 8] = [
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "sp",
];

/// M68K condition codes for CC conditions
const CC_NAMES: [&str; 16] = [
    "f",   // $0 - False
    "hi",  // $1 - Higher (unsigned >)
    "hs",  // $2 - Higher or same / Carry clear (unsigned >=)
    "eq",  // $3 - Equal / Zero set
    "vc",  // $4 - Overflow clear
    "vs",  // $5 - Overflow set
    "pl",  // $6 - Plus / Signed >= 0
    "mi",  // $7 - Minus / Signed < 0
    "ge",  // $8 - Greater than or equal (signed)
    "lt",  // $9 - Less than (signed)
    "gt",  // $A - Greater than (signed)
    "le",  // $B - Less than or equal (signed)
    "ne",  // $C - Not equal
    "geu", // $D - Greater than or equal unsigned (same as hs)
    "cs",  // $E - Carry set (same as hs)
    "true",$F - True (always)
];

/// Parse a data register (D0-D7) from bits [2:0]
fn parse_data_reg(bits: u8) -> &'static str {
    DATA_REG_NAMES[(bits & 0x07) as usize]
}

/// Parse an address register (A0-A7) from bits [2:0]
fn parse_addr_reg(bits: u8) -> &'static str {
    ADDR_REG_NAMES[(bits & 0x07) as usize]
}

/// Read a 16-bit value from the ROM at given offset (big-endian)
#[inline]
fn read_be_u16(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    ((data[offset] as u16) << 8) | (data[offset + 1] as u16)
}

/// Read a 32-bit value from the ROM at given offset (big-endian)
#[inline]
fn read_be_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    ((data[offset] as u32) << 24)
        | ((data[offset + 1] as u32) << 16)
        | ((data[offset + 2] as u32) << 8)
        | (data[offset + 3] as u32)
}

/// Sign-extend an 8-bit value to i16
fn sign_extend_i8(val: i8) -> i16 {
    val as i16
}

/// Sign-extend a 16-bit value to i32 for address calculations
fn sign_extend_i16(val: i16) -> i32 {
    val as i32
}

/// Format an effective address mode for M68K (post-increment, pre-decrement, etc.)
enum EaFormat {
    DirectDataRegister(&'static str),
    DirectAddressRegister(&'static str),
    AddressRegisterIndirect(&'static str),
    AddressRegisterIndirectWithPostIncrement(&'static str),
    AddressRegisterIndirectWithPreDecrement(&'static str),
    AddressRegisterIndirectWithDisplacement(u16, &'static str),
    AddressRegisterIndirectWithIndex(u8, &'static str, &'static str), // index, base, displacement info
    AbsoluteShort(u32),
    AbsoluteLong(u32),
    ProgramCounterWithDisplacement(u16, u32), // displacement, pc_base
    ProgramCounterWithIndex(u8, u32),        // index, pc_base
    Immediate(u32, usize),                    // value, byte_size (1=byte, 2=word, 4=long)
    ConditionCode(u16),                       // CC value
}

/// Format M68K effective address for display
fn format_ea(ea: &EaFormat) -> String {
    match ea {
        EaFormat::DirectDataRegister(r) => format!("{}", r),
        EaFormat::DirectAddressRegister(r) => format!("{}", r),
        EaFormat::AddressRegisterIndirect(r) => format!("({})", r),
        EaFormat::AddressRegisterIndirectWithPostIncrement(r) => format!("({})+", r),
        EaFormat::AddressRegisterIndirectWithPreDecrement(r) => format!("-({})", r),
        EaFormat::AddressRegisterIndirectWithDisplacement(off, r) => {
            format!("{:x}({})", off, r)
        }
        EaFormat::AddressRegisterIndirectWithIndex(idx, base, disp) => {
            if *disp == "a0" || *disp == "a1" {
                // Indexed with displacement
                format!("({}{}, {}{})", idx, base, disp, *idx)
            } else {
                format!("({}, {})", idx, base)
            }
        }
        EaFormat::AbsoluteShort(addr) => format!("0x{:04X}", addr),
        EaFormat::AbsoluteLong(addr) => format!("0x{:08X}", addr),
        EaFormat::ProgramCounterWithDisplacement(off, pc_base) => {
            format!("0x{:06X} (PC offset 0x{:04X})", *pc_base as i32 + (*off as i16 as i32), off)
        }
        EaFormat::ProgramCounterWithIndex(idx, _pc_base) => {
            format!("(PC, {})", idx)
        }
        EaFormat::Immediate(val, size) => match size {
            1 => format!("#${:02X}.B", val),
            2 => format!("#${:04X}.W", val),
            4 => format!("#${:08X}.L", val),
            _ => format!("#{}", val),
        },
        EaFormat::ConditionCode(cc) => {
            let idx = (*cc & 0x0F) as usize;
            if idx < CC_NAMES.len() {
                CC_NAMES[idx].to_string()
            } else {
                format!("0x{:X}", cc)
            }
        }
    }
}

/// Parse M68K effective address mode from bits in instruction word 1
fn parse_ea_mode(data: &[u8], offset: usize, mode_bits: u8, is_register: bool, base_pc: u32) -> (EaFormat, usize) {
    let ea_reg = if is_register {
        parse_data_reg(mode_bits & 0x07)
    } else {
        parse_addr_reg(mode_bits & 0x07)
    };

    // EA mode field is bits [5:3] of word1
    let mode = (mode_bits >> 3) & 0x07;

    match mode {
        0 => {
            // Direct address modes
            if is_register {
                (EaFormat::DirectDataRegister(ea_reg), 2)
            } else {
                (EaFormat::DirectAddressRegister(ea_reg), 2)
            }
        }
        1 => {
            // Address register indirect
            if is_register {
                (EaFormat::AddressRegisterIndirect(ea_reg), 2)
            } else {
                (EaFormat::AddressRegisterIndirect(ea_reg), 2)
            }
        }
        2 => {
            // Address register indirect with post-increment
            if mode_bits & 0x08 == 0 {
                // No X register - simple post-increment
                (EaFormat::AddressRegisterIndirectWithPostIncrement(ea_reg), 2)
            } else {
                // With X register - read word2 for displacement
                let disp = read_be_u16(data, offset + 2);
                (EaFormat::AddressRegisterIndirectWithDisplacement(disp, ea_reg), 4)
            }
        }
        3 => {
            // Pre-decrement
            (EaFormat::AddressRegisterIndirectWithPreDecrement(ea_reg), 2)
        }
        4 => {
            // Displaced - 8-bit signed displacement
            let disp = data[offset + 2] as i8;
            let disp_val = if is_register {
                format!("{:+d}({})", disp, ea_reg)
            } else {
                format!("{:+d}({})", disp, ea_reg)
            };
            (EaFormat::AddressRegisterIndirectWithDisplacement(disp as u16, ea_reg), 4)
        }
        5 => {
            // Indexed - read index byte from word2
            let index_byte = data[offset + 2];
            let base_reg = parse_ea_mode(data, offset + 2, index_byte & 0xE0, false, base_pc);
            let idx_size = (index_byte >> 3) & 0x07;
            let disp_size = index_byte & 0x07;
            
            if disp_size == 0 {
                // No displacement
                (EaFormat::AddressRegisterIndirectWithIndex(idx_size, ea_reg, "none"), 4)
            } else if disp_size == 5 || disp_size == 6 {
                // 8-bit or 16-bit signed displacement
                let disp = data[offset + 3] as i8;
                (EaFormat::AddressRegisterIndirectWithIndex(idx_size, ea_reg, &format!("{:+d}", disp)), 4)
            } else {
                (EaFormat::AddressRegisterIndirectWithIndex(idx_size, ea_reg, "none"), 6)
            }
        }
        6 => {
            // Absolute short addressing
            let addr = read_be_u16(data, offset + 2) as u32;
            (EaFormat::AbsoluteShort(addr), 4)
        }
        7 => {
            // Absolute long addressing or immediate
            if is_register {
                // Immediate data
                let val = read_be_u32(data, offset + 2);
                (EaFormat::Immediate(val, 4), 6)
            } else {
                (EaFormat::AbsoluteLong(read_be_u32(data, offset + 2)), 6)
            }
        }
        _ => (EaFormat::DirectDataRegister(ea_reg), 2)
    }
}

/// Parse program counter-based addressing
fn parse_pc_ea_mode(data: &[u8], offset: usize, mode_bits: u8, base_pc: u32) -> (EaFormat, usize) {
    let mode = (mode_bits >> 3) & 0x07;
    
    match mode {
        0..=5 => {
            // Address register indirect with displacement or indexed
            let disp_or_idx = read_be_u16(data, offset + 2);
            if mode <= 4 {
                (EaFormat::ProgramCounterWithDisplacement(disp_or_idx, base_pc), 4)
            } else {
                // Indexed PC addressing
                (EaFormat::ProgramCounterWithIndex((disp_or_idx >> 8) as u8, base_pc), 6)
            }
        }
        6 => {
            // Absolute short PC-relative
            let addr = ((base_pc as u16 & 0xFFFE) as u32) + (read_be_u16(data, offset + 2) as i16 as i32 as u16) as u32;
            (EaFormat::AbsoluteShort(addr), 4)
        }
        7 => {
            // Absolute long PC-relative
            let disp = read_be_u32(data, offset + 2);
            let addr = base_pc + disp;
            (EaFormat::AbsoluteLong(addr), 6)
        }
    }
}

/// Disassemble a single M68K instruction from ROM data at given address
fn disassemble_m68k_instruction(data: &[u8], address: u32, max_instructions: usize) -> Vec<M68kInstruction> {
    let mut instructions = Vec::new();
    let mut offset = (address as usize).min(data.len());
    
    while offset < data.len() && instructions.len() < max_instructions {
        if offset + 2 > data.len() {
            break;
        }

        let opcode = read_be_u16(data, offset);
        let instr_addr = address + (offset as u32 - address as u32);
        
        // Decode based on opcode category
        let (mnemonic, operands, instr_size) = decode_m68k_opcode(opcode, data, offset, instr_addr);
        
        if instr_size > 0 {
            let bytes: Vec<u8> = data[offset..offset + instr_size].to_vec();
            instructions.push(M68kInstruction {
                address: instr_addr,
                bytes,
                mnemonic: mnemonic.to_string(),
                operands: operands.to_string(),
                size: instr_size,
            });
            offset += instr_size;
        } else {
            // Unknown instruction
            instructions.push(M68kInstruction {
                address: instr_addr,
                bytes: vec![0xFF, 0x00],
                mnemonic: ".word".to_string(),
                operands: format!("0x{:04X}", opcode),
                size: 2,
            });
            offset += 2;
        }
    }
    
    instructions
}

/// Decode M68K opcode and return (mnemonic, operands, instruction_size)
fn decode_m68k_opcode(opcode: u16, data: &[u8], offset: usize, pc: u32) -> (&'static str, String, usize) {
    let op_class = (opcode >> 12) & 0x0F;
    
    match op_class {
        // Move instructions (0xxx)
        0 => decode_move_instruction(opcode, data, offset, pc),
        
        // Move condition code / SR (10xx)
        1 => decode_move_sr_instruction(opcode, data, offset, pc),
        
        // Extend/NEGX/CLR/MOVEP (1100)
        2 => decode_misc_alu_instruction(opcode, data, offset, pc),
        
        // ALU operations (1101)
        3 => decode_alu_instruction(opcode, data, offset, pc),
        
        // Move to/from SR (1110)
        4 => decode_move_to_sr_instruction(opcode, data, offset, pc),
        
        // Logical/shift/rotate (1111xxxx xxxx xxxx) - high nibble of first byte
        5..=7 => decode_shift_rotate_instruction(opcode, data, offset, pc),
        
        // Jump/Branch/JSR (01xx or 4xxx)
        _ => decode_jump_branch_instruction(opcode, data, offset, pc),
    }
}

/// Decode MOVE instructions (op class 0)
fn decode_move_instruction(opcode: u16, data: &[u8], offset: usize, _pc: u32) -> (&'static str, String, usize) {
    // Bit 15 = 0 for MOVE family
    // Size field is bits [7:6] of word1
    let size = (opcode >> 6) & 0x03;
    let src_ea_mode = (opcode >> 9) & 0x07;
    let dst_ea_mode = opcode & 0x07;
    
    // Determine MOVE variant based on size and EA modes
    match size {
        0 => { // Byte move (.B - 8 bits)
            if (dst_ea_mode == 7 && src_ea_mode <= 1) || (src_ea_mode == 7 && dst_ea_mode <= 5) {
                // MOVEQ - Move Quick (8-bit signed immediate)
                let val = data[offset + 2] as i8;
                ("moveq", format!("#${:02X}, d{}", val & 0xFF, dst_ea_mode), 2)
            } else {
                // MOVE.B src, dst
                let src_fmt = parse_ea_mode(data, offset, (src_ea_mode << 3) as u8, src_ea_mode <= 1, _pc);
                let dst_fmt = parse_ea_mode(data, offset + 2, (dst_ea_mode << 3) as u8, true, _pc);
                ("move.b", format!("{}, {}", format_ea(&src_fmt.0), format_ea(&dst_fmt.0)), src_fmt.1 + dst_fmt.1)
            }
        }
        1 => { // Word move (.W - 16 bits)
            if (dst_ea_mode == 7 && src_ea_mode <= 1) || (src_ea_mode == 7 && dst_ea_mode <= 5) {
                let val = read_be_u16(data, offset + 2);
                ("move.w", format!("#${:04X}, d{}", val, dst_ea_mode), 4)
            } else {
                let src_fmt = parse_ea_mode(data, offset, (src_ea_mode << 3) as u8, src_ea_mode <= 1, _pc);
                let dst_fmt = parse_ea_mode(data, offset + 2, (dst_ea_mode << 3) as u8, true, _pc);
                ("move.w", format!("{}, {}", format_ea(&src_fmt.0), format_ea(&dst_fmt.0)), src_fmt.1 + dst_fmt.1)
            }
        }
        2 => { // Long move (.L - 32 bits)
            if (dst_ea_mode == 7 && src_ea_mode <= 1) || (src_ea_mode == 7 && dst_ea_mode <= 5) {
                let val = read_be_u32(data, offset + 2);
                ("move.l", format!("#${:08X}, d{}", val, dst_ea_mode), 6)
            } else {
                let src_fmt = parse_ea_mode(data, offset, (src_ea_mode << 3) as u8, src_ea_mode <= 1, _pc);
                let dst_fmt = parse_ea_mode(data, offset + 2, (dst_ea_mode << 3) as u8, true, _pc);
                ("move.l", format!("{}, {}", format_ea(&src_fmt.0), format_ea(&dst_fmt.0)), src_fmt.1 + dst_fmt.1)
            }
        }
        _ => {
            // Unusual size - treat as MOVE.W
            let src_fmt = parse_ea_mode(data, offset, (src_ea_mode << 3) as u8, src_ea_mode <= 1, _pc);
            let dst_fmt = parse_ea_mode(data, offset + 2, (dst_ea_mode << 3) as u8, true, _pc);
            ("move.w", format!("{}, {}", format_ea(&src_fmt.0), format_ea(&dst_fmt.0)), src_fmt.1 + dst_fmt.1)
        }
    }
}

/// Decode MOVE SR/CCR/DFF instructions (op class 1)
fn decode_move_sr_instruction(opcode: u16, data: &[u8], offset: usize, _pc: u32) -> (&'static str, String, usize) {
    // Bit 14 = 1 indicates MOVE SR family
    let op = (opcode >> 9) & 0x07;
    let ea_reg = opcode & 0x07;
    
    match op {
        0 => ("move.sr", format!("d{}", ea_reg), 2), // Move SR to register
        1 => ("move.ccr", format!(""), 2),           // Move CCR (bits [5:4] = 01)
        2 => ("move.sr", format!("(sp)+"), 2),       // Move SR to (sp)+
        3 => ("move.dff", format!(""), 2),           // Move DFF
        4 => ("move.t", format!("d{}", ea_reg), 2),  // Move T flag to register
        5 => ("move.ccr", format!(""), 2),           // Move CCR with T flag
        _ => {
            let dst_fmt = parse_ea_mode(data, offset, (ea_reg << 3) as u8, false, _pc);
            ("move.sr", format_ea(&dst_fmt.0), dst_fmt.1)
        }
    }
}

/// Decode ALU instructions (op class 3 = 110x)
fn decode_alu_instruction(opcode: u16, data: &[u8], offset: usize, _pc: u32) -> (&'static str, String, usize) {
    // Bits [14:12] = operation code
    let op_code = (opcode >> 12) & 0x07;
    
    match op_code {
        // ADD instructions (00x)
        0 => {
            let size = (opcode >> 6) & 0x03;
            let src_mode = (opcode >> 9) & 0x07;
            let dst_reg = opcode & 0x07;
            
            let mnemonic = match size {
                0 => "add.b",
                1 => "add.w",
                2 => "add.l",
                _ => "add.w",
            };
            
            let src_fmt = parse_ea_mode(data, offset, (src_mode << 3) as u8, false, _pc);
            (mnemonic, format!("{}, d{}", format_ea(&src_fmt.0), dst_reg), src_fmt.1 + 2)
        }
        
        // SUB instructions (01x)
        1 => {
            let size = (opcode >> 6) & 0x03;
            let src_mode = (opcode >> 9) & 0x07;
            let dst_reg = opcode & 0x07;
            
            let mnemonic = match size {
                0 => "sub.b",
                1 => "sub.w",
                2 => "sub.l",
                _ => "sub.w",
            };
            
            let src_fmt = parse_ea_mode(data, offset, (src_mode << 3) as u8, false, _pc);
            (mnemonic, format!("{}, d{}", format_ea(&src_fmt.0), dst_reg), src_fmt.1 + 2)
        }
        
        // AND instructions (100)
        2 => {
            let size = (opcode >> 6) & 0x03;
            let src_mode = (opcode >> 9) & 0x07;
            let dst_reg = opcode & 0x07;
            
            let mnemonic = match size {
                0 => "and.b",
                1 => "and.w",
                2 => "and.l",
                _ => "and.w",
            };
            
            let src_fmt = parse_ea_mode(data, offset, (src_mode << 3) as u8, false, _pc);
            ("and.w", format!("{}, d{}", format_ea(&src_fmt.0), dst_reg), src_fmt.1 + 2)
        }
        
        // OR instructions (101)
        3 => {
            let size = (opcode >> 6) & 0x03;
            let src_mode = (opcode >> 9) & 0x07;
            let dst_reg = opcode & 0x07;
            
            let mnemonic = match size {
                0 => "or.b",
                1 => "or.w",
                2 => "or.l",
                _ => "or.w",
            };
            
            let src_fmt = parse_ea_mode(data, offset, (src_mode << 3) as u8, false, _pc);
            ("or.w", format!("{}, d{}", format_ea(&src_fmt.0), dst_reg), src_fmt.1 + 2)
        }
        
        // CMP instructions (11x)
        4 => {
            let size = (opcode >> 6) & 0x03;
            let src_mode = (opcode >> 9) & 0x07;
            let dst_reg = opcode & 0x07;
            
            let mnemonic = match size {
                0 => "cmp.b",
                1 => "cmp.w",
                2 => "cmp.l",
                _ => "cmp.w",
            };
            
            let src_fmt = parse_ea_mode(data, offset, (src_mode << 3) as u8, false, _pc);
            ("cmp.w", format!("{}, d{}", format_ea(&src_fmt.0), dst_reg), src_fmt.1 + 2)
        }
        
        // BIT instructions (AND/BIC/BIS) - bits [14:13] = 10 or 11
        5 | 6 | 7 => {
            let bit_op = (opcode >> 13) & 0x03;
            match bit_op {
                2 => ("bic", String::new(), 2), // Bit clear
                3 => ("bis", String::new(), 2), // Bit set
                _ => ("alu", String::new(), 2),
            }
        }
    }
}

/// Decode miscellaneous ALU instructions (op class 2 = 1100)
fn decode_misc_alu_instruction(opcode: u16, data: &[u8], offset: usize, _pc: u32) -> (&'static str, String, usize) {
    // Bits [14:12] = operation
    let op_code = (opcode >> 12) & 0x07;
    
    match op_code {
        0 => {
            // ADDA instructions
            let size = if opcode & 0x80 == 0 { ".W" } else { ".L" };
            let src_mode = (opcode >> 9) & 0x07;
            let dst_reg = opcode & 0x07;
            
            let src_fmt = parse_ea_mode(data, offset, (src_mode << 3) as u8, false, _pc);
            ("adda".to_string(), format!("{}, a{}", format_ea(&src_fmt.0), dst_reg), src_fmt.1 + 2)
        }
        1 => {
            // SUBA instructions  
            let size = if opcode & 0x80 == 0 { ".W" } else { ".L" };
            let src_mode = (opcode >> 9) & 0x07;
            let dst_reg = opcode & 0x07;
            
            let src_fmt = parse_ea_mode(data, offset, (src_mode << 3) as u8, false, _pc);
            ("suba".to_string(), format!("{}, a{}", format_ea(&src_fmt.0), dst_reg), src_fmt.1 + 2)
        }
        2 => {
            // LINK instruction
            let reg = opcode & 0x07;
            if opcode & 0xFF00 == 0 {
                ("link", format!("a{}", reg), 4)
            } else {
                ("link", format!("a{}, 0x{:04X}", reg, read_be_u16(data, offset + 2)), 4)
            }
        }
        3 => {
            // UNLINK instruction
            let reg = opcode & 0x07;
            ("unlink", format!("a{}", reg), 2)
        }
        _ => {
            // NOP, CLR, NEG, etc. based on lower bits
            let low_nibble = opcode & 0x0F;
            match low_nibble {
                0x0 => ("nop", String::new(), 2),
                0x4 | 0x5 | 0x6 | 0x7 => ("clr.w", String::new(), 2),
                _ => ("misc", format!("0x{:04X}", opcode), 2),
            }
        }
    }
}

/// Decode shift/rotate instructions (op class 5-7)
fn decode_shift_rotate_instruction(opcode: u16, data: &[u8], offset: usize, _pc: u32) -> (&'static str, String, usize) {
    let op_class = ((opcode >> 12) & 0x0F) as usize;
    
    // Bit pattern for shift/rotate: 01xx xxxx xxxx xxxx or 1xxx xxxx xxxx xxxx
    if op_class >= 5 && op_class <= 7 {
        let op_code = (opcode >> 8) & 0xF0;
        
        match op_code {
            0x40 => ("lsl.w", String::new(), 2), // Logical shift left
            0x50 => ("lsr.w", String::new(), 2), // Logical shift right
            0x60 => ("asr.w", String::new(), 2), // Arithmetic shift right
            0x70 => ("rol.w", String::new(), 2), // Rotate left
            0x80 => ("ror.w", String::new(), 2), // Rotate right
            0x90 => ("roxl.w", String::new(), 2),// Rotate left through X
            0xA0 => ("asl.w", String::new(), 2), // Arithmetic shift left
            0xB0 => ("asr.w", String::new(), 2), // Arithmetic shift right
            _ => ("shift", format!("0x{:04X}", opcode), 2),
        }
    } else {
        ("unknown", format!("0x{:04X}", opcode), 2)
    }
}

/// Decode jump/branch/JSR instructions (op class 4 or variable)
fn decode_jump_branch_instruction(opcode: u16, data: &[u8], offset: usize, pc: u32) -> (&'static str, String, usize) {
    // Check for BCC/BRA/BSR (0x6xxx family)
    if (opcode >> 12) == 0x6 {
        let cc = opcode & 0x0F;
        
        if opcode & 0xF000 == 0x6000 {
            // BCC (Branch on Condition Code)
            let cond_name = if cc < CC_NAMES.len() { CC_NAMES[cc] } else { "unknown" };
            
            // Read displacement from word2
            let disp = read_be_u16(data, offset + 2) as i16;
            let target = pc as i32 + 4 + (disp as i32);
            
            ("bcc", format!("0x{:08X}", target), 4)
        } else if opcode & 0xF000 == 0x6A00 {
            // BRA (Branch Always - BCC with condition 'true')
            let disp = read_be_u16(data, offset + 2) as i16;
            let target = pc as i32 + 4 + (disp as i32);
            
            ("bra", format!("0x{:08X}", target), 4)
        } else if opcode & 0xF000 == 0x6700 {
            // BSR (Branch to Subroutine)
            let disp = read_be_u16(data, offset + 2) as i16;
            let target = pc as i32 + 4 + (disp as i32);
            
            ("bsr", format!("0x{:08X}", target), 4)
        } else {
            ("bcc", format!("{}", CC_NAMES[cc as usize]), 2)
        }
    } else if (opcode >> 12) == 0x4 {
        // JSR/JMP (4xxx family)
        let base_reg = opcode & 0x07;
        
        if opcode & 0x00FF == 0x00C7 {
            // JMP (indirect jump via register)
            ("jmp", format!("({})", ADDR_REG_NAMES[base_reg]), 2)
        } else if opcode & 0x00FF == 0x0087 || opcode & 0x00FF == 0x00C6 {
            // JSR (jump to subroutine via register)
            ("jsr", format!("({})", ADDR_REG_NAMES[base_reg]), 2)
        } else {
            // Check for PC-relative JSR (40xx or 44xx with specific patterns)
            if opcode & 0x00FF == 0x00C7 {
                ("jsr", format!("({})", ADDR_REG_NAMES[base_reg]), 2)
            } else {
                ("jmp", format!("0x{:04X}", opcode), 2)
            }
        }
    } else if (opcode >> 12) == 0xD {
        // RTS/RTI family (Dxxx)
        match opcode & 0xF00F {
            0xD002 => ("rts", String::new(), 2),      // Return from subroutine
            0xD003 => ("rti", String::new(), 2),      // Return from interrupt
            0xD04E => ("rte", String::new(), 2),      // Return from exception (68000+)
            _ => ("unknown", format!("0x{:04X}", opcode), 2),
        }
    } else if (opcode >> 12) == 0xE {
        // TRAP instructions (Exxx)
        let vec_num = opcode & 0x0F;
        ("trap", format!("#{}", vec_num), 2)
    } else {
        // Default: unknown instruction
        ("unknown", format!("0x{:04X}", opcode), 2)
    }
}

// ===================== ROM Header Parsing =====================

/// Identify Sega Genesis/Master System ROM from file data
pub fn identify_sega_rom(data: &[u8]) -> SegaRomIdentification {
    if data.len() < 128 {
        return SegaRomIdentification {
            is_sega_rom: false,
            header: None,
            rom_data: Vec::new(),
            platform: "unknown".to_string(),
        };
    }

    // Check for Genesis/Mega Drive signature at offset 0x0100
    let is_genesis = check_genesis_signature(data);
    
    // Check for Master System signature
    let is_sms = check_sms_signature(data);
    
    if is_genesis {
        let header = parse_genesis_header(data);
        SegaRomIdentification {
            is_sega_rom: true,
            header,
            rom_data: data.to_vec(),
            platform: "genesis".to_string(),
        }
    } else if is_sms {
        let header = parse_sms_header(data);
        SegaRomIdentification {
            is_sega_rom: true,
            header,
            rom_data: data.to_vec(),
            platform: "sms".to_string(),
        }
    } else {
        // Try to detect by ROM size patterns
        let platform = detect_platform_by_size(data.len());
        SegaRomIdentification {
            is_sega_rom: true,
            header: None,
            rom_data: data.to_vec(),
            platform,
        }
    }
}

/// Check for Genesis/Mega Drive signature at offset 0x0100
fn check_genesis_signature(data: &[u8]) -> bool {
    if data.len() < 0x100 + 48 {
        return false;
    }
    
    // Genesis header typically starts with "SEGA" or "SEGA MEGA DRIVE" at offset 0x0100
    let title_start = 0x100;
    if data[title_start] == b'S' && data[title_start + 1] == b'E' && data[title_start + 2] == b'G' && data[title_start + 3] == b'A' {
        return true;
    }
    
    // Check for known Genesis game signatures
    if data.len() >= 0x100 + 0x60 {
        let region = String::from_utf8_lossy(&data[0x12A..=0x12D]);
        if region == "USA" || region == "EUR" || region == "JAP" {
            return true;
        }
    }
    
    false
}

/// Check for Master System signature
fn check_sms_signature(data: &[u8]) -> bool {
    // SMS ROMs often have specific markers or are multiples of standard sizes
    if data.len() < 0x4000 {
        return false;
    }
    
    // SMS header is typically at offset 0x0000 with specific byte patterns
    // The SMS uses a different cartridge format
    
    // Check for SMS-specific title location (offset 0x0135 in some formats)
    if data.len() >= 0x200 {
        let maker_code = String::from_utf8_lossy(&data[0x013F..=0x0142]);
        if !maker_code.is_empty() && (maker_code.chars().all(|c| c.is_ascii_alphabetic()) || maker_code == "SEGA") {
            return true;
        }
    }
    
    false
}

/// Parse Genesis/Mega Drive ROM header
fn parse_genesis_header(data: &[u8]) -> Option<GenesisHeader> {
    if data.len() < 0x100 + 0x60 {
        return None;
    }
    
    let title_start = 0x100;
    let title_end = data[title_start..].iter().position(|&b| b == b'\0' || b == b' ').unwrap_or(data.len() - title_start);
    let title = String::from_utf8_lossy(&data[title_start..title_start + title_end]).to_string();
    
    // Company code at offset 0x013A
    let company_code = if data.len() >= 0x13B {
        String::from_utf8_lossy(&data[0x13A..=0x13D]).trim_matches('\0').to_string()
    } else {
        "Unknown".to_string()
    };
    
    // Region at offset 0x012A (relative to header start)
    let region = if data.len() >= 0x130 {
        String::from_utf8_lossy(&data[0x12A..=0x12C]).trim_matches('\0').to_string()
    } else {
        "Unknown".to_string()
    };
    
    // Game ID at offset 0x0134
    let game_id = if data.len() >= 0x13E {
        String::from_utf8_lossy(&data[0x134..=0x13D]).trim_matches('\0').to_string()
    } else {
        "Unknown".to_string()
    };
    
    // ROM size detection
    let rom_size = data.len();
    let ram_size = detect_ram_size(data);
    
    Some(GenesisHeader {
        title,
        company_code,
        region,
        rom_size,
        ram_size,
        header_checksum: 0,
        game_id,
        platform: "genesis".to_string(),
    })
}

/// Parse Master System ROM header
fn parse_sms_header(data: &[u8]) -> Option<GenesisHeader> {
    let title = if data.len() >= 0x144 {
        String::from_utf8_lossy(&data[0x134..=0x143]).trim_matches('\0').to_string()
    } else {
        "SMS Game".to_string()
    };
    
    let company_code = if data.len() >= 0x143 {
        String::from_utf8_lossy(&data[0x13F..=0x142]).trim_matches('\0').to_string()
    } else {
        "Unknown".to_string()
    };
    
    Some(GenesisHeader {
        title,
        company_code,
        region: "SMS".to_string(),
        rom_size: data.len(),
        ram_size: Some(0x0080), // Default SMS RAM
        header_checksum: 0,
        game_id: String::new(),
        platform: "sms".to_string(),
    })
}

/// Detect ROM size based on file size and common patterns
fn detect_rom_size(file_size: usize) -> usize {
    // Common Genesis ROM sizes (power of 2, minimum 512KB)
    if file_size >= 0x80000 {
        ((file_size + 0xFFFF) & !0xFFFF) // Round up to nearest 64KB
    } else {
        file_size
    }
}

/// Detect RAM size from ROM header or default
fn detect_ram_size(data: &[u8]) -> Option<usize> {
    // Genesis RAM is typically at offset 0x01F0 in header
    if data.len() >= 0x1F4 {
        let ram_bytes = data[0x1F0..=0x1F3];
        if ram_bytes[0] != 0 || ram_bytes[1] != 0 {
            // RAM size encoded as bits
            let ram_size_code = (ram_bytes[0] << 8) | ram_bytes[1];
            match ram_size_code {
                0x0000 => Some(0x0000), // No RAM
                0x0001 => Some(0x0080), // 128 bytes (SMS)
                0x0100 => Some(0x2000), // 8KB
                0x0400 => Some(0x8000), // 32KB
                _ => None,
            }
        } else {
            None
        }
    } else {
        None
    }
}

/// Detect platform type based on ROM size patterns
fn detect_platform_size_patterns(file_size: usize) -> String {
    match file_size {
        0x4000..=0x10000 => "sms".to_string(), // SMS typically smaller
        0x20000..=0x200000 => "genesis".to_string(), // Genesis typically larger
        _ => "unknown".to_string(),
    }
}

/// Detect platform type based on ROM size patterns  
fn detect_platform_by_size(file_size: usize) -> String {
    if file_size <= 0x10000 {
        "sms".to_string()
    } else if file_size >= 0x20000 && file_size <= 0x200000 {
        "genesis".to_string()
    } else {
        "gamegear".to_string() // GameGear ROMs are intermediate size
    }
}

/// Disassemble Genesis/Master System ROM starting from entry point
#[tauri::command]
fn disassemble_sega_rom(rom_data: Vec<u8>, base_addr: u32, max_instructions: Option<usize>) -> Result<SegaDisassembly, String> {
    let identification = identify_sega_rom(&rom_data);
    
    if !identification.is_sega_rom {
        return Err("File does not appear to be a Sega Genesis/Master System ROM".to_string());
    }
    
    let max_instr = max_instructions.unwrap_or(4096);
    let entry_point = identification.header.as_ref().map(|h| 0x00000100).unwrap_or(0x00000000);
    
    // Disassemble from reset vector (usually 0x00000100 for Genesis)
    let instructions = disassemble_m68k_instruction(&rom_data, entry_point.max(base_addr), max_instr);
    
    Ok(SegaDisassembly {
        platform: identification.platform.clone(),
        title: identification.header.as_ref().map(|h| h.title.clone()).unwrap_or_else(|| "Unknown".to_string()),
        instructions,
        entry_point,
    })
}

/// Get Sega ROM identification info
#[tauri::command]
fn identify_sega_rom_cmd(path: String) -> Result<serde_json::Value, String> {
    let data = std::fs::read(&path).map_err(|e| format!("Failed to read file: {}", e))?;
    let identification = identify_sega_rom(&data);
    
    if !identification.is_sega_rom {
        return Err("File does not appear to be a Sega Genesis/Master System ROM".to_string());
    }
    
    Ok(serde_json::json!({
        "platform": identification.platform,
        "header": identification.header.map(|h| serde_json::json!({
            "title": h.title,
            "company_code": h.company_code,
            "region": h.region,
            "rom_size": h.rom_size,
            "ram_size": h.ram_size,
            "game_id": h.game_id,
        })),
    }))
}

// ===================== Export Functions =====================

/// Export disassembly as CSV (compatible with Ghidra import)
#[tauri::command]
fn export_sega_disasm_csv(disasm: &SegaDisassembly) -> Result<String, String> {
    let mut csv = String::from("Address,Mnemonic,Operands,Size\n");
    
    for instr in &disasm.instructions {
        // Escape operands for CSV
        let operands_escaped = disasm.operands.replace('"', "\"\"");
        csv.push_str(&format!(
            "0x{:08X},{},{},{}\n",
            instr.address, instr.mnemonic, operands_escaped, instr.size
        ));
    }
    
    Ok(csv)
}

/// Export disassembly as assembly source file (.asm format)
#[tauri::command]
fn export_sega_disasm_asm(disasm: &SegaDisassembly) -> Result<String, String> {
    let mut asm = String::new();
    
    asm.push_str("; Sega ");
    asm.push_str(&disasm.platform);
    asm.push_str(" Disassembly\n");
    asm.push_str("; Title: ");
    asm.push_str(&disasm.title);
    asm.push_str("\n; Entry Point: 0x");
    write!(asm, "{:08X}", disasm.entry_point).unwrap();
    asm.push_str("\n\n");
    
    for instr in &disasm.instructions {
        write!(asm, "0x{:08X}: ", instr.address).unwrap();
        write!(asm, "{:<16}", instr.mnemonic).unwrap();
        if !instr.operands.is_empty() {
            write!(asm, "{:<30}", instr.operands).unwrap();
        }
        writeln!(asm).unwrap();
    }
    
    Ok(asm)
}

/// Export function list as JSON (for ps2recomp-style config)
#[tauri::command]
fn export_sega_functions_json(disasm: &SegaDisassembly) -> Result<String, String> {
    // Detect potential functions by analyzing BSR/JMP/JSR targets
    let mut functions = Vec::new();
    
    for instr in &disasm.instructions {
        if instr.mnemonic == "bsr" || instr.mnemonic.starts_with("jsr") || instr.mnemonic == "bra" {
            // Extract target address from operands
            if let Some(addr_str) = extract_target_address(&instr.operands) {
                if let Ok(target_addr) = u32::from_str_radix(&addr_str[2..], 16) {
                    functions.push(serde_json::json!({
                        "name": format!("sub_{:08X}", target_addr),
                        "start": format!("0x{:08X}", target_addr),
                        "end": format!("0x{:08X}", target_addr + 0x100), // Estimated
                        "size": 0x100,
                    }));
                }
            }
        }
    }
    
    Ok(serde_json::json!({
        "platform": disasm.platform,
        "title": disasm.title,
        "entry_point": format!("0x{:08X}", disasm.entry_point),
        "functions": functions,
    }).to_string())
}

/// Extract target address from M68K instruction operands
fn extract_target_address(operands: &str) -> Option<String> {
    // Look for hex patterns like 0xXXXXXXXX
    let trimmed = operands.trim();
    if let Some(pos) = trimmed.find("0x") {
        let rest = &trimmed[pos..];
        let end = rest.find(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X').unwrap_or(rest.len());
        Some(rest[..end].to_string())
    } else {
        None
    }
}