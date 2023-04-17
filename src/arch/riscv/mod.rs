//! RISCV relocation types
//!

#[cfg(test)]
mod test;

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum RelocationTypes {
    /// No relocation.
    R_RISCV_NONE,
    /// Add 32 bit zero extended symbol value
    R_RISCV_32,
    /// Add 64 bit symbol value.            
    R_RISCV_64,
    /// Add load address of shared object.    
    R_RISCV_RELATIVE,
    /// Copy data from shared object.        
    R_RISCV_COPY,
    /// Set GOT entry to code address.
    R_RISCV_JUMP_SLOT,
    /// 32 bit ID of module containing symbol
    R_RISCV_TLS_DTPMOD32,
    /// ID of module containing symbol
    R_RISCV_TLS_DTPMOD64,
    /// 32 bit relative offset in TLS block
    R_RISCV_TLS_DTPREL32,
    /// Relative offset in TLS block
    R_RISCV_TLS_DTPREL64,
    /// 32 bit relative offset in static TLS block
    R_RISCV_TLS_TPREL32,
    /// Relative offset in static TLS block
    R_RISCV_TLS_TPREL64,
    /// PC-relative branch
    R_RISCV_BRANCH,
    /// PC-relative jump
    R_RISCV_JAL,
    /// PC-relative call
    R_RISCV_CALL,
    /// PC-relative call (PLT)
    R_RISCV_CALL_PLT,
    /// PC-relative GOT reference
    R_RISCV_GOT_HI20,
    /// PC-relative TLS IE GOT offset
    R_RISCV_TLS_GOT_HI20,
    /// PC-relative TLS GD reference
    R_RISCV_TLS_GD_HI20,
    /// PC-relative reference
    R_RISCV_PCREL_HI20,
    /// PC-relative reference
    R_RISCV_PCREL_LO12_I,
    /// PC-relative reference
    R_RISCV_PCREL_LO12_S,
    /// Absolute address
    R_RISCV_HI20,
    /// Absolute address
    R_RISCV_LO12_I,
    /// Absolute address  
    R_RISCV_LO12_S,
    /// TLS LE thread offset
    R_RISCV_TPREL_HI20,
    /// TLS LE thread offset
    R_RISCV_TPREL_LO12_I,
    /// TLS LE thread offset
    R_RISCV_TPREL_LO12_S,
    /// TLS LE thread usage
    R_RISCV_TPREL_ADD,
    /// 8-bit label addition
    R_RISCV_ADD8,
    /// 16-bit label addition
    R_RISCV_ADD16,
    /// 32-bit label addition
    R_RISCV_ADD32,
    /// 64-bit label addition
    R_RISCV_ADD64,
    /// 8-bit label subtraction
    R_RISCV_SUB8,
    /// 16-bit label subtraction
    R_RISCV_SUB16,
    /// 32-bit label subtraction
    R_RISCV_SUB32,
    /// 64-bit label subtraction
    R_RISCV_SUB64,
    /// GNU C++ vtable hierarchy
    R_RISCV_GNU_VTINHERIT,
    /// GNU C++ vtable member usage
    R_RISCV_GNU_VTENTRY,
    /// Alignment statement
    R_RISCV_ALIGN,
    /// PC-relative branch offset
    R_RISCV_RVC_BRANCH,
    /// PC-relative jump offset
    R_RISCV_RVC_JUMP,
    /// Absolute address
    R_RISCV_RVC_LUI,
    /// GP-relative reference
    R_RISCV_GPREL_I,
    /// GP-relative reference
    R_RISCV_GPREL_S,
    /// TP-relative TLS LE load
    R_RISCV_TPREL_I,
    /// TP-relative TLS LE store
    R_RISCV_TPREL_S,
    /// Instruction pair can be relaxed
    R_RISCV_RELAX,
    /// Local label subtraction
    R_RISCV_SUB6,
    /// Local label subtraction        
    R_RISCV_SET6,
    /// Local label subtraction
    R_RISCV_SET8,
    /// Local label subtraction
    R_RISCV_SET16,
    /// Local label subtraction
    R_RISCV_SET32,

    /// Unknown
    Unknown(u32),
}

impl RelocationTypes {
    /// Construct new riscv::RelocationTypes
    pub fn from(typ: u32) -> RelocationTypes {
        use RelocationTypes::*;
        match typ {
            0 => R_RISCV_NONE,
            1 => R_RISCV_32,
            2 => R_RISCV_64,
            3 => R_RISCV_RELATIVE,
            4 => R_RISCV_COPY,
            5 => R_RISCV_JUMP_SLOT,
            6 => R_RISCV_TLS_DTPMOD32,
            7 => R_RISCV_TLS_DTPMOD64,
            8 => R_RISCV_TLS_DTPREL32,
            9 => R_RISCV_TLS_DTPREL64,
            10 => R_RISCV_TLS_TPREL32,
            11 => R_RISCV_TLS_TPREL64,
            16 => R_RISCV_BRANCH,
            17 => R_RISCV_JAL,
            18 => R_RISCV_CALL,
            19 => R_RISCV_CALL_PLT,
            20 => R_RISCV_GOT_HI20,
            21 => R_RISCV_TLS_GOT_HI20,
            22 => R_RISCV_TLS_GD_HI20,
            23 => R_RISCV_PCREL_HI20,
            24 => R_RISCV_PCREL_LO12_I,
            25 => R_RISCV_PCREL_LO12_S,
            26 => R_RISCV_HI20,
            27 => R_RISCV_LO12_I,
            28 => R_RISCV_LO12_S,
            29 => R_RISCV_TPREL_HI20,
            30 => R_RISCV_TPREL_LO12_I,
            31 => R_RISCV_TPREL_LO12_S,
            32 => R_RISCV_TPREL_ADD,
            33 => R_RISCV_ADD8,
            34 => R_RISCV_ADD16,
            35 => R_RISCV_ADD32,
            36 => R_RISCV_ADD64,
            37 => R_RISCV_SUB8,
            38 => R_RISCV_SUB16,
            39 => R_RISCV_SUB32,
            40 => R_RISCV_SUB64,
            41 => R_RISCV_GNU_VTINHERIT,
            42 => R_RISCV_GNU_VTENTRY,
            43 => R_RISCV_ALIGN,
            44 => R_RISCV_RVC_BRANCH,
            45 => R_RISCV_RVC_JUMP,
            46 => R_RISCV_RVC_LUI,
            47 => R_RISCV_GPREL_I,
            48 => R_RISCV_GPREL_S,
            49 => R_RISCV_TPREL_I,
            50 => R_RISCV_TPREL_S,
            51 => R_RISCV_RELAX,
            52 => R_RISCV_SUB6,
            53 => R_RISCV_SET6,
            54 => R_RISCV_SET8,
            55 => R_RISCV_SET16,
            56 => R_RISCV_SET32,
            x => Unknown(x),
        }
    }
}
