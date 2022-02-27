#![no_std]
#![crate_name = "elfloader"]
#![crate_type = "lib"]

#[cfg(test)]
#[macro_use]
extern crate std;
#[cfg(test)]
extern crate env_logger;

mod binary;
pub use binary::ElfBinary;

#[cfg(test)]
mod test;

use core::fmt;
use core::iter::Filter;

use bitflags::bitflags;
use xmas_elf::dynamic::*;
use xmas_elf::program::ProgramIter;

pub use xmas_elf::program::{Flags, ProgramHeader, ProgramHeader64};
pub use xmas_elf::sections::{Rel, Rela};
pub use xmas_elf::symbol_table::{Entry, Entry64};
pub use xmas_elf::{P32, P64};

/// An iterator over [`ProgramHeader`] whose type is `LOAD`.
pub type LoadableHeaders<'a, 'b> = Filter<ProgramIter<'a, 'b>, fn(&ProgramHeader) -> bool>;
pub type PAddr = u64;
pub type VAddr = u64;

// Abstract relocation entries to be passed to the
// trait's relocate method. Library user can decide
// how to handle each relocation
pub enum RelaEntry<'a> {
    Rel32(&'a Rel<P32>),
    Rel64(&'a Rel<P64>),
    Rela32(&'a Rela<P32>),
    Rela64(&'a Rela<P64>),
}

#[derive(PartialEq, Clone, Debug)]
pub enum ElfLoaderErr {
    ElfParser { source: &'static str },
    SymbolTableNotFound,
    UnsupportedElfFormat,
    UnsupportedElfVersion,
    UnsupportedEndianness,
    UnsupportedAbi,
    UnsupportedElfType,
    UnsupportedSectionData,
    UnsupportedRelocationEntry,
}

impl From<&'static str> for ElfLoaderErr {
    fn from(source: &'static str) -> Self {
        ElfLoaderErr::ElfParser { source }
    }
}

impl fmt::Display for ElfLoaderErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfLoaderErr::ElfParser { source } => write!(f, "Error in ELF parser: {}", source),
            ElfLoaderErr::SymbolTableNotFound => write!(f, "No symbol table in the ELF file"),
            ElfLoaderErr::UnsupportedElfFormat => write!(f, "ELF format not supported"),
            ElfLoaderErr::UnsupportedElfVersion => write!(f, "ELF version not supported"),
            ElfLoaderErr::UnsupportedEndianness => write!(f, "ELF endianness not supported"),
            ElfLoaderErr::UnsupportedAbi => write!(f, "ELF ABI not supported"),
            ElfLoaderErr::UnsupportedElfType => write!(f, "ELF type not supported"),
            ElfLoaderErr::UnsupportedSectionData => write!(f, "Can't handle this section data"),
            ElfLoaderErr::UnsupportedRelocationEntry => {
                write!(f, "Can't handle relocation entry")
            }
        }
    }
}

// Should be in xmas-elf see: https://github.com/nrc/xmas-elf/issues/54
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum TypeRela32 {
    /// No relocation.
    R_NONE,
    /// Add 32 bit dword symbol value.
    R_32,
    /// PC-relative 32 bit signed sym value.
    R_PC32,
    /// PC-relative 32 bit GOT offset.
    R_GOT32,
    /// PC-relative 32 bit PLT offset.
    R_PLT32,
    /// Copy data from shared object.
    R_COPY,
    /// Set GOT entry to data address.
    R_GLOB_DAT,
    /// Set GOT entry to code address.
    R_JMP_SLOT,
    /// Add load address of shared object.
    R_RELATIVE,
    /// PC relative offset to GOT entry
    R_GOTOFF,
    R_GOTPC,
    R_32PLT,
    R_16,
    R_PC16,
    R_8,
    R_PC8,
    R_SIZE32,
    /// Unknown
    Unknown(u8),
}

impl TypeRela32 {
    // Construt a new TypeRela32
    pub fn from(typ: u8) -> TypeRela32 {
        use TypeRela32::*;
        match typ {
            0 => R_NONE,
            1 => R_PC32,
            2 => R_32,
            3 => R_GOT32,
            4 => R_PLT32,
            5 => R_COPY,
            6 => R_GLOB_DAT,
            7 => R_JMP_SLOT,
            8 => R_RELATIVE,
            9 => R_GOTOFF,
            10 => R_GOTPC,
            11 => R_32PLT,
            20 => R_16,
            21 => R_PC16,
            22 => R_8,
            23 => R_PC8,
            38 => R_SIZE32,
            x => Unknown(x),
        }
    }
}

// Should be in xmas-elf see: https://github.com/nrc/xmas-elf/issues/54
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum TypeRela64 {
    /// No relocation.
    R_NONE,
    /// Add 64 bit symbol value.
    R_64,
    /// PC-relative 32 bit signed sym value.
    R_PC32,
    /// PC-relative 32 bit GOT offset.
    R_GOT32,
    /// PC-relative 32 bit PLT offset.
    R_PLT32,
    /// Copy data from shared object.
    R_COPY,
    /// Set GOT entry to data address.
    R_GLOB_DAT,
    /// Set GOT entry to code address.
    R_JMP_SLOT,
    /// Add load address of shared object.
    R_RELATIVE,
    /// Add 32 bit signed pcrel offset to GOT.
    R_GOTPCREL,
    /// Add 32 bit zero extended symbol value
    R_32,
    /// Add 32 bit sign extended symbol value
    R_32S,
    /// Add 16 bit zero extended symbol value
    R_16,
    /// Add 16 bit signed extended pc relative symbol value
    R_PC16,
    /// Add 8 bit zero extended symbol value
    R_8,
    /// Add 8 bit signed extended pc relative symbol value
    R_PC8,
    /// ID of module containing symbol
    R_DTPMOD64,
    /// Offset in TLS block
    R_DTPOFF64,
    /// Offset in static TLS block
    R_TPOFF64,
    /// PC relative offset to GD GOT entry
    R_TLSGD,
    /// PC relative offset to LD GOT entry
    R_TLSLD,
    /// Offset in TLS block
    R_DTPOFF32,
    /// PC relative offset to IE GOT entry
    R_GOTTPOFF,
    /// Offset in static TLS block
    R_TPOFF32,
    /// Unknown
    Unknown(u32),
}

impl TypeRela64 {
    // Construt a new TypeRela64
    pub fn from(typ: u32) -> TypeRela64 {
        use TypeRela64::*;
        match typ {
            0 => R_NONE,
            1 => R_64,
            2 => R_PC32,
            3 => R_GOT32,
            4 => R_PLT32,
            5 => R_COPY,
            6 => R_GLOB_DAT,
            7 => R_JMP_SLOT,
            8 => R_RELATIVE,
            9 => R_GOTPCREL,
            10 => R_32,
            11 => R_32S,
            12 => R_16,
            13 => R_PC16,
            14 => R_8,
            15 => R_PC8,
            16 => R_DTPMOD64,
            17 => R_DTPOFF64,
            18 => R_TPOFF64,
            19 => R_TLSGD,
            20 => R_TLSLD,
            21 => R_DTPOFF32,
            22 => R_GOTTPOFF,
            23 => R_TPOFF32,
            x => Unknown(x),
        }
    }
}

bitflags! {
    #[derive(Default)]
    pub struct DynamicFlags1: u64 {
        const NOW = FLAG_1_NOW;
        const GLOBAL = FLAG_1_GLOBAL;
        const GROUP = FLAG_1_GROUP;
        const NODELETE = FLAG_1_NODELETE;
        const LOADFLTR = FLAG_1_LOADFLTR;
        const INITFIRST = FLAG_1_INITFIRST;
        const NOOPEN = FLAG_1_NOOPEN;
        const ORIGIN = FLAG_1_ORIGIN;
        const DIRECT = FLAG_1_DIRECT;
        const TRANS = FLAG_1_TRANS;
        const INTERPOSE = FLAG_1_INTERPOSE;
        const NODEFLIB = FLAG_1_NODEFLIB;
        const NODUMP = FLAG_1_NODUMP;
        const CONFALT = FLAG_1_CONFALT;
        const ENDFILTEE = FLAG_1_ENDFILTEE;
        const DISPRELDNE = FLAG_1_DISPRELDNE;
        const DISPRELPND = FLAG_1_DISPRELPND;
        const NODIRECT = FLAG_1_NODIRECT;
        const IGNMULDEF = FLAG_1_IGNMULDEF;
        const NOKSYMS = FLAG_1_NOKSYMS;
        const NOHDR = FLAG_1_NOHDR;
        const EDITED = FLAG_1_EDITED;
        const NORELOC = FLAG_1_NORELOC;
        const SYMINTPOSE = FLAG_1_SYMINTPOSE;
        const GLOBAUDIT = FLAG_1_GLOBAUDIT;
        const SINGLETON = FLAG_1_SINGLETON;
        const STUB = FLAG_1_STUB;
        const PIE = FLAG_1_PIE;
    }
}

/// Information parse from the .dynamic section
pub struct DynamicInfo {
    pub flags1: DynamicFlags1,
    pub rela: u64,
    pub rela_size: u64,
}

/// Implement this trait for customized ELF loading.
///
/// The flow of ElfBinary is that it first calls `allocate` for all regions
/// that need to be allocated (i.e., the LOAD program headers of the ELF binary),
/// then `load` will be called to fill the allocated regions, and finally
/// `relocate` is called for every entry in the RELA table.
pub trait ElfLoader {
    /// Allocates a virtual region specified by `load_headers`.
    fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr>;

    /// Copies `region` into memory starting at `base`.
    /// The caller makes sure that there was an `allocate` call previously
    /// to initialize the region.
    fn load(&mut self, flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr>;

    /// Request for the client to relocate the given `entry`
    /// within the loaded ELF file.
    fn relocate(&mut self, entry: RelaEntry) -> Result<(), ElfLoaderErr>;

    /// Inform client about where the initial TLS data is located.
    fn tls(
        &mut self,
        _tdata_start: VAddr,
        _tdata_length: u64,
        _total_size: u64,
        _align: u64,
    ) -> Result<(), ElfLoaderErr> {
        Ok(())
    }

    /// In case there is a `.data.rel.ro` section we instruct the loader
    /// to change the passed offset to read-only (this is called after
    /// the relocate calls are completed).
    ///
    /// Note: The default implementation is a no-op since this is
    /// not strictly necessary to implement.
    fn make_readonly(&mut self, _base: VAddr, _size: usize) -> Result<(), ElfLoaderErr> {
        Ok(())
    }
}
