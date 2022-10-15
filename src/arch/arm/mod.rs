// Should be in xmas-elf see: https://github.com/nrc/xmas-elf/issues/54
/// Relocation types for ARM 32-bit.
///
/// Based on "ELF for the ARM® Architecture" pdf.
/// Document number: ARM IHI 0044F, current through ABI release 2.10.
/// Date of issue: 24th November 2015.
///
/// The following nomenclature is used for the operation:
/// - S (when used on its own) is the address of the symbol.
/// - A is the addend for the relocation.
/// - P is the address of the place being relocated (derived from r_offset).
/// - Pa is the adjusted address of the place being relocated, defined as (P & 0xFFFFFFFC).
/// - T is 1 if the target symbol S has type STT_FUNC and the symbol addresses a Thumb instruction;
///   it is 0 otherwise.
/// - B(S) is the addressing origin of the output segment defining the symbol S. The origin is
///   not required to be the base address of the segment. This value must always be word-aligned.
/// - GOT_ORG is the addressing origin of the Global Offset Table (the indirection table for imported
///   data addresses). This value must always be word-aligned. See §4.6.1.8, Proxy generating
///   relocations.
/// - GOT(S) is the address of the GOT entry for the symbol S.
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum RelocationTypes {
    /// Static, Miscellaneous.
    R_ARM_NONE,
    /// Deprecated, ARM, ((S + A) | T) – P.
    R_ARM_PC24,
    /// Static, Data, (S + A) | T.
    R_ARM_ABS32,
    /// Static, Data, ((S + A) | T) – P.
    R_ARM_REL32,
    /// Static, ARM, S + A – P.
    R_ARM_LDR_PC_G0,
    /// Static, Data, S + A.
    R_ARM_ABS16,
    /// Static, ARM, S + A.
    R_ARM_ABS12,
    /// Static, Thumb16, S + A.
    R_ARM_THM_ABS5,
    /// Static, Data, S + A.
    R_ARM_ABS8,
    /// Static, Data, ((S + A) | T) – B(S).
    R_ARM_SBREL32,
    /// Static, Thumb32, ((S + A) | T) – P.
    R_ARM_THM_CALL,
    /// Static, Thumb16, S + A – Pa.
    R_ARM_THM_PC8,
    /// Dynamic, Data, ΔB(S) + A.
    R_ARM_BREL_ADJ,
    /// Dynamic, Data.
    R_ARM_TLS_DESC,
    /// Obsolete, Encoding reserved for future Dynamic relocations.
    R_ARM_THM_SWI8,
    /// Obsolete, Encoding reserved for future Dynamic relocations.
    R_ARM_XPC25,
    /// Obsolete, Encoding reserved for future Dynamic relocations.
    R_ARM_THM_XPC22,
    /// Dynamic, Data, Module[S].
    R_ARM_TLS_DTPMOD32,
    /// Dynamic, Data, S + A – TLS.
    R_ARM_TLS_DTPOFF32,
    /// Dynamic, Data, S + A – tp.
    R_ARM_TLS_TPOFF32,
    /// Dynamic, Miscellaneous.
    R_ARM_COPY,
    /// Dynamic, Data, (S + A) | T.
    R_ARM_GLOB_DAT,
    /// Dynamic, Data, (S + A) | T.
    R_ARM_JUMP_SLOT,
    /// Dynamic, Data, B(S) + A [Note: see Table 4-18].
    R_ARM_RELATIVE,
    /// Static, Data, ((S + A) | T) – GOT_ORG.
    R_ARM_GOTOFF32,
    /// Static, Data, B(S) + A – P.
    R_ARM_BASE_PREL,
    /// Static, Data, GOT(S) + A – GOT_ORG.
    R_ARM_GOT_BREL,
    /// Deprecated, ARM, ((S + A) | T) – P.
    R_ARM_PLT32,
    /// Static, ARM, ((S + A) | T) – P.
    R_ARM_CALL,
    /// Static, ARM, ((S + A) | T) – P.
    R_ARM_JUMP24,
    /// Static, Thumb32, ((S + A) | T) – P.
    R_ARM_THM_JUMP24,
    /// Static, Data, B(S) + A.
    R_ARM_BASE_ABS,
    /// Obsolete, Note, – Legacy (ARM ELF B02) names have been retained for these obsolete relocations.
    R_ARM_ALU_PCREL_7_0,
    /// Obsolete, Note, – Legacy (ARM ELF B02) names have been retained for these obsolete relocations.
    R_ARM_ALU_PCREL_15_8,
    /// Obsolete, Note, – Legacy (ARM ELF B02) names have been retained for these obsolete relocations.
    R_ARM_ALU_PCREL_23_15,
    /// Deprecated, ARM, S + A – B(S).
    R_ARM_LDR_SBREL_11_0_NC,
    /// Deprecated, ARM, S + A – B(S).
    R_ARM_ALU_SBREL_19_12_NC,
    /// Deprecated, ARM, S + A – B(S).
    R_ARM_ALU_SBREL_27_20_CK,
    /// Static, Miscellaneous, (S + A) | T or ((S + A) | T) – P.
    R_ARM_TARGET1,
    /// Deprecated, Data, ((S + A) | T) – B(S).
    R_ARM_SBREL31,
    /// Static, Miscellaneous.
    R_ARM_V4BX,
    /// Static, Miscellaneous.
    R_ARM_TARGET2,
    /// Static, Data, ((S + A) | T) – P.
    R_ARM_PREL31,
    /// Static, ARM, (S + A) | T.
    R_ARM_MOVW_ABS_NC,
    /// Static, ARM, S + A.
    R_ARM_MOVT_ABS,
    /// Static, ARM, ((S + A) | T) – P.
    R_ARM_MOVW_PREL_NC,
    /// Static, ARM, S + A – P.
    R_ARM_MOVT_PREL,
    /// Static, Thumb32, (S + A) | T.
    R_ARM_THM_MOVW_ABS_NC,
    /// Static, Thumb32, S + A.
    R_ARM_THM_MOVT_ABS,
    /// Static, Thumb32, ((S + A) | T) – P.
    R_ARM_THM_MOVW_PREL_NC,
    /// Static, Thumb32, S + A – P.
    R_ARM_THM_MOVT_PREL,
    /// Static, Thumb32, ((S + A) | T) – P.
    R_ARM_THM_JUMP19,
    /// Static, Thumb16, S + A – P.
    R_ARM_THM_JUMP6,
    /// Static, Thumb32, ((S + A) | T) – Pa.
    R_ARM_THM_ALU_PREL_11_0,
    /// Static, Thumb32, S + A – Pa.
    R_ARM_THM_PC12,
    /// Static, Data, S + A.
    R_ARM_ABS32_NOI,
    /// Static, Data, S + A – P.
    R_ARM_REL32_NOI,
    /// Static, ARM, ((S + A) | T) – P.
    R_ARM_ALU_PC_G0_NC,
    /// Static, ARM, ((S + A) | T) – P.
    R_ARM_ALU_PC_G0,
    /// Static, ARM, ((S + A) | T) – P.
    R_ARM_ALU_PC_G1_NC,
    /// Static, ARM, ((S + A) | T) – P.
    R_ARM_ALU_PC_G1,
    /// Static, ARM, ((S + A) | T) – P.
    R_ARM_ALU_PC_G2,
    /// Static, ARM, S + A – P.
    R_ARM_LDR_PC_G1,
    /// Static, ARM, S + A – P.
    R_ARM_LDR_PC_G2,
    /// Static, ARM, S + A – P.
    R_ARM_LDRS_PC_G0,
    /// Static, ARM, S + A – P.
    R_ARM_LDRS_PC_G1,
    /// Static, ARM, S + A – P.
    R_ARM_LDRS_PC_G2,
    /// Static, ARM, S + A – P.
    R_ARM_LDC_PC_G0,
    /// Static, ARM, S + A – P.
    R_ARM_LDC_PC_G1,
    /// Static, ARM, S + A – P.
    R_ARM_LDC_PC_G2,
    /// Static, ARM, ((S + A) | T) – B(S).
    R_ARM_ALU_SB_G0_NC,
    /// Static, ARM, ((S + A) | T) – B(S).
    R_ARM_ALU_SB_G0,
    /// Static, ARM, ((S + A) | T) – B(S).
    R_ARM_ALU_SB_G1_NC,
    /// Static, ARM, ((S + A) | T) – B(S).
    R_ARM_ALU_SB_G1,
    /// Static, ARM, ((S + A) | T) – B(S).
    R_ARM_ALU_SB_G2,
    /// Static, ARM, S + A – B(S).
    R_ARM_LDR_SB_G0,
    /// Static, ARM, S + A – B(S).
    R_ARM_LDR_SB_G1,
    /// Static, ARM, S + A – B(S).
    R_ARM_LDR_SB_G2,
    /// Static, ARM, S + A – B(S).
    R_ARM_LDRS_SB_G0,
    /// Static, ARM, S + A – B(S).
    R_ARM_LDRS_SB_G1,
    /// Static, ARM, S + A – B(S).
    R_ARM_LDRS_SB_G2,
    /// Static, ARM, S + A – B(S).
    R_ARM_LDC_SB_G0,
    /// Static, ARM, S + A – B(S).
    R_ARM_LDC_SB_G1,
    /// Static, ARM, S + A – B(S).
    R_ARM_LDC_SB_G2,
    /// Static, ARM, ((S + A) | T) – B(S).
    R_ARM_MOVW_BREL_NC,
    /// Static, ARM, S + A – B(S).
    R_ARM_MOVT_BREL,
    /// Static, ARM, ((S + A) | T) – B(S).
    R_ARM_MOVW_BREL,
    /// Static, Thumb32, ((S + A) | T) – B(S).
    R_ARM_THM_MOVW_BREL_NC,
    /// Static, Thumb32, S + A – B(S).
    R_ARM_THM_MOVT_BREL,
    /// Static, Thumb32, ((S + A) | T) – B(S).
    R_ARM_THM_MOVW_BREL,
    /// Static, Data.
    R_ARM_TLS_GOTDESC,
    /// Static, ARM,
    R_ARM_TLS_CALL,
    /// Static, ARM, TLS relaxation.
    R_ARM_TLS_DESCSEQ,
    /// Static, Thumb32.
    R_ARM_THM_TLS_CALL,
    /// Static, Data, PLT(S) + A.
    R_ARM_PLT32_ABS,
    /// Static, Data, GOT(S) + A.
    R_ARM_GOT_ABS,
    /// Static, Data, GOT(S) + A – P.
    R_ARM_GOT_PREL,
    /// Static, ARM, GOT(S) + A – GOT_ORG.
    R_ARM_GOT_BREL12,
    /// Static, ARM, S + A – GOT_ORG.
    R_ARM_GOTOFF12,
    /// Static, Miscellaneous.
    R_ARM_GOTRELAX,
    /// Deprecated, Data, ???.
    R_ARM_GNU_VTENTRY,
    /// Deprecated, Data, ???.
    R_ARM_GNU_VTINHERIT,
    /// Static, Thumb16, S + A – P.
    R_ARM_THM_JUMP11,
    /// Static, Thumb16, S + A – P.
    R_ARM_THM_JUMP8,
    /// Static, Data, GOT(S) + A – P.
    R_ARM_TLS_GD32,
    /// Static, Data, GOT(S) + A – P.
    R_ARM_TLS_LDM32,
    /// Static, Data, S + A – TLS.
    R_ARM_TLS_LDO32,
    /// Static, Data, GOT(S) + A – P.
    R_ARM_TLS_IE32,
    /// Static, Data, S + A – tp.
    R_ARM_TLS_LE32,
    /// Static, ARM, S + A – TLS.
    R_ARM_TLS_LDO12,
    /// Static, ARM, S + A – tp.
    R_ARM_TLS_LE12,
    /// Static, ARM, GOT(S) + A – GOT_ORG.
    R_ARM_TLS_IE12GP,
    /// Private 0.
    R_ARM_PRIVATE_0,
    /// Private 1.
    R_ARM_PRIVATE_1,
    /// Private 2.
    R_ARM_PRIVATE_2,
    /// Private 3.
    R_ARM_PRIVATE_3,
    /// Private 4.
    R_ARM_PRIVATE_4,
    /// Private 5.
    R_ARM_PRIVATE_5,
    /// Private 6.
    R_ARM_PRIVATE_6,
    /// Private 7.
    R_ARM_PRIVATE_7,
    /// Private 8.
    R_ARM_PRIVATE_8,
    /// Private 9.
    R_ARM_PRIVATE_9,
    /// Private 10.
    R_ARM_PRIVATE_10,
    /// Private 11.
    R_ARM_PRIVATE_11,
    /// Private 12.
    R_ARM_PRIVATE_12,
    /// Private 13.
    R_ARM_PRIVATE_13,
    /// Private 14.
    R_ARM_PRIVATE_14,
    /// Private 15.
    R_ARM_PRIVATE_15,
    /// Obsolete.
    R_ARM_ME_TOO,
    /// Static, Thumb16.
    R_ARM_THM_TLS_DESCSEQ16,
    /// Static, Thumb32.
    R_ARM_THM_TLS_DESCSEQ32,
    /// Static, Thumb32, GOT(S) + A – GOT_ORG.
    R_ARM_THM_GOT_BREL12,
    /// Static, Thumb16, (S + A) | T.
    R_ARM_THM_ALU_ABS_G0_NC,
    /// Static, Thumb16, S + A.
    R_ARM_THM_ALU_ABS_G1_NC,
    /// Static, Thumb16, S + A.
    R_ARM_THM_ALU_ABS_G2_NC,
    /// Static, Thumb16, S + A.
    R_ARM_THM_ALU_ABS_G3,
    /// Unknown
    Unknown(u32),
}

impl RelocationTypes {
    /// Construct new arm::RelocationTypes
    pub fn from(typ: u32) -> RelocationTypes {
        use RelocationTypes::*;
        // The weird ordering comes by copying directly from the manual which is
        // not consecutive either...
        match typ {
            0 => R_ARM_NONE,
            1 => R_ARM_PC24,
            2 => R_ARM_ABS32,
            3 => R_ARM_REL32,
            4 => R_ARM_LDR_PC_G0,
            5 => R_ARM_ABS16,
            6 => R_ARM_ABS12,
            7 => R_ARM_THM_ABS5,
            8 => R_ARM_ABS8,
            9 => R_ARM_SBREL32,
            10 => R_ARM_THM_CALL,
            11 => R_ARM_THM_PC8,
            12 => R_ARM_BREL_ADJ,
            13 => R_ARM_TLS_DESC,
            14 => R_ARM_THM_SWI8,
            15 => R_ARM_XPC25,
            16 => R_ARM_THM_XPC22,
            17 => R_ARM_TLS_DTPMOD32,
            18 => R_ARM_TLS_DTPOFF32,
            19 => R_ARM_TLS_TPOFF32,
            20 => R_ARM_COPY,
            21 => R_ARM_GLOB_DAT,
            22 => R_ARM_JUMP_SLOT,
            23 => R_ARM_RELATIVE,
            24 => R_ARM_GOTOFF32,
            25 => R_ARM_BASE_PREL,
            26 => R_ARM_GOT_BREL,
            27 => R_ARM_PLT32,
            28 => R_ARM_CALL,
            29 => R_ARM_JUMP24,
            30 => R_ARM_THM_JUMP24,
            31 => R_ARM_BASE_ABS,
            32 => R_ARM_ALU_PCREL_7_0,
            33 => R_ARM_ALU_PCREL_15_8,
            34 => R_ARM_ALU_PCREL_23_15,
            35 => R_ARM_LDR_SBREL_11_0_NC,
            36 => R_ARM_ALU_SBREL_19_12_NC,
            37 => R_ARM_ALU_SBREL_27_20_CK,
            38 => R_ARM_TARGET1,
            39 => R_ARM_SBREL31,
            40 => R_ARM_V4BX,
            41 => R_ARM_TARGET2,
            42 => R_ARM_PREL31,
            43 => R_ARM_MOVW_ABS_NC,
            44 => R_ARM_MOVT_ABS,
            45 => R_ARM_MOVW_PREL_NC,
            46 => R_ARM_MOVT_PREL,
            47 => R_ARM_THM_MOVW_ABS_NC,
            48 => R_ARM_THM_MOVT_ABS,
            49 => R_ARM_THM_MOVW_PREL_NC,
            50 => R_ARM_THM_MOVT_PREL,
            51 => R_ARM_THM_JUMP19,
            52 => R_ARM_THM_JUMP6,
            53 => R_ARM_THM_ALU_PREL_11_0,
            54 => R_ARM_THM_PC12,
            55 => R_ARM_ABS32_NOI,
            56 => R_ARM_REL32_NOI,
            57 => R_ARM_ALU_PC_G0_NC,
            58 => R_ARM_ALU_PC_G0,
            59 => R_ARM_ALU_PC_G1_NC,
            60 => R_ARM_ALU_PC_G1,
            61 => R_ARM_ALU_PC_G2,
            62 => R_ARM_LDR_PC_G1,
            63 => R_ARM_LDR_PC_G2,
            64 => R_ARM_LDRS_PC_G0,
            65 => R_ARM_LDRS_PC_G1,
            66 => R_ARM_LDRS_PC_G2,
            67 => R_ARM_LDC_PC_G0,
            68 => R_ARM_LDC_PC_G1,
            69 => R_ARM_LDC_PC_G2,
            70 => R_ARM_ALU_SB_G0_NC,
            71 => R_ARM_ALU_SB_G0,
            72 => R_ARM_ALU_SB_G1_NC,
            73 => R_ARM_ALU_SB_G1,
            74 => R_ARM_ALU_SB_G2,
            75 => R_ARM_LDR_SB_G0,
            76 => R_ARM_LDR_SB_G1,
            77 => R_ARM_LDR_SB_G2,
            78 => R_ARM_LDRS_SB_G0,
            79 => R_ARM_LDRS_SB_G1,
            80 => R_ARM_LDRS_SB_G2,
            81 => R_ARM_LDC_SB_G0,
            82 => R_ARM_LDC_SB_G1,
            83 => R_ARM_LDC_SB_G2,
            84 => R_ARM_MOVW_BREL_NC,
            85 => R_ARM_MOVT_BREL,
            86 => R_ARM_MOVW_BREL,
            87 => R_ARM_THM_MOVW_BREL_NC,
            88 => R_ARM_THM_MOVT_BREL,
            89 => R_ARM_THM_MOVW_BREL,
            90 => R_ARM_TLS_GOTDESC,
            91 => R_ARM_TLS_CALL,
            92 => R_ARM_TLS_DESCSEQ,
            93 => R_ARM_THM_TLS_CALL,
            94 => R_ARM_PLT32_ABS,
            95 => R_ARM_GOT_ABS,
            96 => R_ARM_GOT_PREL,
            97 => R_ARM_GOT_BREL12,
            98 => R_ARM_GOTOFF12,
            99 => R_ARM_GOTRELAX,
            100 => R_ARM_GNU_VTENTRY,
            101 => R_ARM_GNU_VTINHERIT,
            102 => R_ARM_THM_JUMP11,
            103 => R_ARM_THM_JUMP8,
            104 => R_ARM_TLS_GD32,
            105 => R_ARM_TLS_LDM32,
            106 => R_ARM_TLS_LDO32,
            107 => R_ARM_TLS_IE32,
            108 => R_ARM_TLS_LE32,
            109 => R_ARM_TLS_LDO12,
            110 => R_ARM_TLS_LE12,
            111 => R_ARM_TLS_IE12GP,
            112 => R_ARM_PRIVATE_0,
            113 => R_ARM_PRIVATE_1,
            114 => R_ARM_PRIVATE_2,
            115 => R_ARM_PRIVATE_3,
            116 => R_ARM_PRIVATE_4,
            117 => R_ARM_PRIVATE_5,
            118 => R_ARM_PRIVATE_6,
            119 => R_ARM_PRIVATE_7,
            120 => R_ARM_PRIVATE_8,
            121 => R_ARM_PRIVATE_9,
            122 => R_ARM_PRIVATE_10,
            123 => R_ARM_PRIVATE_11,
            124 => R_ARM_PRIVATE_12,
            125 => R_ARM_PRIVATE_13,
            126 => R_ARM_PRIVATE_14,
            127 => R_ARM_PRIVATE_15,
            128 => R_ARM_ME_TOO,
            129 => R_ARM_THM_TLS_DESCSEQ16,
            130 => R_ARM_THM_TLS_DESCSEQ32,
            131 => R_ARM_THM_GOT_BREL12,
            132 => R_ARM_THM_ALU_ABS_G0_NC,
            133 => R_ARM_THM_ALU_ABS_G1_NC,
            134 => R_ARM_THM_ALU_ABS_G2_NC,
            135 => R_ARM_THM_ALU_ABS_G3,
            x => Unknown(x),
        }
    }
}
