#![no_std]
#![crate_name = "elfloader"]
#![crate_type = "lib"]

#[cfg(test)]
#[macro_use]
extern crate std;
#[cfg(test)]
extern crate env_logger;

use core::fmt;
use core::iter::Filter;

use bitflags::bitflags;
use log::*;
use xmas_elf::dynamic::*;
use xmas_elf::header;
use xmas_elf::program::ProgramHeader::Ph64;
use xmas_elf::program::{ProgramIter, SegmentData, Type};
use xmas_elf::sections::SectionData;
use xmas_elf::*;

pub use xmas_elf::program::{Flags, ProgramHeader, ProgramHeader64};
pub use xmas_elf::sections::Rela;
pub use xmas_elf::symbol_table::{Entry, Entry64};
pub use xmas_elf::{P32, P64};

/// An iterator over [`ProgramHeader`] whose type is `LOAD`.
pub type LoadableHeaders<'a, 'b> = Filter<ProgramIter<'a, 'b>, fn(&ProgramHeader) -> bool>;
pub type PAddr = u64;
pub type VAddr = u64;

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
    /// Unkown
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

/// Abstract representation of a loadable ELF binary.
pub struct ElfBinary<'s> {
    /// The ELF file in question.
    pub file: ElfFile<'s>,
    /// Parsed information from the .dynamic section (if the binary has it).
    pub dynamic: Option<DynamicInfo>,
}

impl<'s> fmt::Debug for ElfBinary<'s> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ElfBinary{{ [")?;
        for p in self.program_headers() {
            write!(f, " pheader = {}", p)?;
        }
        write!(f, "] }}")
    }
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
    ///
    /// # Safety
    ///
    /// The caller must ensure that there was an `allocate` call previously
    /// to initialize the region.
    unsafe fn load(&mut self, flags: Flags, base: VAddr, region: &[u8])
        -> Result<(), ElfLoaderErr>;

    /// Request for the client to relocate the given `entry`
    /// within the loaded ELF file.
    fn relocate(&mut self, entry: &Rela<P64>) -> Result<(), ElfLoaderErr>;

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

impl<'s> ElfBinary<'s> {
    /// Create a new ElfBinary.
    pub fn new(region: &'s [u8]) -> Result<ElfBinary<'s>, ElfLoaderErr> {
        let file = ElfFile::new(region)?;

        // Parse relevant parts out of the the .dynamic section
        let mut dynamic = None;
        for p in file.program_iter() {
            if let Ph64(header) = p {
                let typ = header.get_type()?;
                if typ == Type::Dynamic {
                    dynamic = ElfBinary::parse_dynamic(&file, header)?;
                    break;
                }
            }
        }

        Ok(ElfBinary { file, dynamic })
    }

    /// Returns true if the binary is compiled as position independent code or false otherwise.
    ///
    /// For the binary to be PIE it needs to have a .dynamic section with PIE set in the flags1
    /// field.
    pub fn is_pie(&self) -> bool {
        self.dynamic.as_ref().map_or(false, |d: &DynamicInfo| {
            d.flags1.contains(DynamicFlags1::PIE)
        })
    }

    /// Return the entry point of the ELF file.
    ///
    /// Note this may be zero in case of position independent executables.
    pub fn entry_point(&self) -> u64 {
        self.file.header.pt2.entry_point()
    }

    /// Create a slice of the program headers.
    pub fn program_headers(&self) -> ProgramIter {
        self.file.program_iter()
    }

    /// Get the name of the sectione
    pub fn symbol_name(&self, symbol: &'s dyn Entry) -> &'s str {
        symbol.get_name(&self.file).unwrap_or("unknown")
    }

    /// Enumerate all the symbols in the file
    pub fn for_each_symbol<F: FnMut(&'s dyn Entry)>(
        &self,
        mut func: F,
    ) -> Result<(), ElfLoaderErr> {
        let symbol_section = self
            .file
            .find_section_by_name(".symtab")
            .ok_or(ElfLoaderErr::SymbolTableNotFound)?;
        let symbol_table = symbol_section.get_data(&self.file)?;
        if let SectionData::SymbolTable64(entries) = symbol_table {
            for entry in entries {
                //trace!("entry {:?}", entry);
                func(entry);
            }
            Ok(())
        } else if let SectionData::SymbolTable32(entries) = symbol_table {
            for entry in entries {
                //trace!("entry {:?}", entry);
                func(entry);
            }
            Ok(())
        } else {
            Err(ElfLoaderErr::SymbolTableNotFound)
        }
    }

    /// Can we load this binary on our platform?
    fn is_loadable(&self) -> Result<(), ElfLoaderErr> {
        let header = self.file.header;
        let typ = header.pt2.type_().as_type();

        if header.pt1.class() != header::Class::SixtyFour {
            Err(ElfLoaderErr::UnsupportedElfFormat)
        } else if header.pt1.version() != header::Version::Current {
            Err(ElfLoaderErr::UnsupportedElfVersion)
        } else if header.pt1.data() != header::Data::LittleEndian {
            Err(ElfLoaderErr::UnsupportedEndianness)
        } else if !(header.pt1.os_abi() == header::OsAbi::SystemV
            || header.pt1.os_abi() == header::OsAbi::Linux)
        {
            Err(ElfLoaderErr::UnsupportedAbi)
        } else if !(typ == header::Type::Executable || typ == header::Type::SharedObject) {
            error!("Invalid ELF type {:?}", typ);
            Err(ElfLoaderErr::UnsupportedElfType)
        } else {
            Ok(())
        }
    }

    /// Process the relocation entries for the ELF file.
    ///
    /// Issues call to `loader.relocate` and passes the relocation entry.
    fn maybe_relocate(&self, loader: &mut dyn ElfLoader) -> Result<(), ElfLoaderErr> {
        // It's easier to just locate the section by name:
        self.file.find_section_by_name(".rela.dyn").map_or(
            Ok(()), // .rela.dyn section found
            |rela_section_dyn| {
                let data = rela_section_dyn.get_data(&self.file)?;
                if let SectionData::Rela64(rela_entries) = data {
                    // Now we finally have a list of relocation we're supposed to perform:
                    for entry in rela_entries {
                        let _typ = TypeRela64::from(entry.get_type());
                        // Does the entry blong to the current header?
                        loader.relocate(entry)?;
                    }

                    Ok(())
                } else {
                    Err(ElfLoaderErr::UnsupportedSectionData)
                }
            },
        )
    }

    /// Processes a dynamic header section.
    ///
    /// This section contains mostly entry points to other section headers (like relocation).
    /// At the moment this just does sanity checking for relocation later.
    ///
    /// A human readable version of the dynamic section is best obtained with `readelf -d <binary>`.
    fn parse_dynamic(
        file: &ElfFile,
        dynamic_header: &ProgramHeader64,
    ) -> Result<Option<DynamicInfo>, ElfLoaderErr> {
        trace!("load dynamic segement {:?}", dynamic_header);

        // Walk through the dynamic program header and find the rela and sym_tab section offsets:
        let segment = dynamic_header.get_data(file)?;
        let mut flags1 = Default::default();
        let mut rela: u64 = 0;
        let mut rela_size: u64 = 0;

        match segment {
            SegmentData::Dynamic64(dyn_entries) => {
                for dyn_entry in dyn_entries {
                    let tag = dyn_entry.get_tag()?;
                    match tag {
                        Tag::Rela => rela = dyn_entry.get_ptr()?,
                        Tag::RelaSize => rela_size = dyn_entry.get_val()?,
                        Tag::Flags1 => {
                            flags1 =
                                unsafe { DynamicFlags1::from_bits_unchecked(dyn_entry.get_val()?) };
                        }
                        _ => trace!("unsupported {:?}", dyn_entry),
                    }
                }
            }
            _ => {
                return Err(ElfLoaderErr::UnsupportedSectionData);
            }
        };

        trace!(
            "rela size {:?} rela off {:?} flags1 {:?}",
            rela_size,
            rela,
            flags1
        );

        Ok(Some(DynamicInfo {
            flags1,
            rela,
            rela_size,
        }))
    }

    /// Processing the program headers and issue commands to loader.
    ///
    /// Will tell loader to create space in the address space / region where the
    /// header is supposed to go, then copy it there, and finally relocate it.
    pub fn load(&self, loader: &mut dyn ElfLoader) -> Result<(), ElfLoaderErr> {
        self.is_loadable()?;

        loader.allocate(self.iter_loadable_headers())?;

        // Load all headers
        for p in self.file.program_iter() {
            if let Ph64(header) = p {
                let typ = header.get_type()?;
                if typ == Type::Load {
                    // SAFETY: Yes, `loader.allocate(load_iter)?;` allocates memory.
                    unsafe {
                        loader.load(
                            header.flags,
                            header.virtual_addr,
                            header.raw_data(&self.file),
                        )?;
                    }
                } else if typ == Type::Tls {
                    loader.tls(
                        header.virtual_addr,
                        header.file_size,
                        header.mem_size,
                        header.align,
                    )?;
                }
            }
        }

        // Relocate headers
        self.maybe_relocate(loader)?;

        // Process .data.rel.ro
        for p in self.file.program_iter() {
            if let Ph64(header) = p {
                let typ = header.get_type()?;
                if typ == Type::GnuRelro {
                    loader.make_readonly(header.virtual_addr, header.mem_size as usize)?;
                }
            }
        }

        Ok(())
    }

    fn iter_loadable_headers(&self) -> LoadableHeaders {
        // Trying to determine loadeable headers
        fn select_load(pheader: &ProgramHeader) -> bool {
            if let Ph64(header) = pheader {
                header
                    .get_type()
                    .map(|typ| typ == Type::Load)
                    .unwrap_or(false)
            } else {
                false
            }
        }

        // Create an iterator (well filter really) that has all loadeable
        // headers and pass it to the loader
        // TODO: This is pretty ugly, maybe we can do something with impl Trait?
        // https://stackoverflow.com/questions/27535289/what-is-the-correct-way-to-return-an-iterator-or-any-other-trait
        self.file.program_iter().filter(select_load)
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    use std::fs;
    use std::vec::Vec;

    #[derive(Eq, Clone, PartialEq, Copy, Debug)]
    enum LoaderAction {
        Allocate(VAddr, usize, Flags),
        Load(VAddr, usize),
        Relocate(VAddr, u64),
        Tls(VAddr, u64, u64, u64),
    }
    struct TestLoader {
        vbase: VAddr,
        actions: Vec<LoaderAction>,
    }

    impl TestLoader {
        fn new(offset: VAddr) -> TestLoader {
            TestLoader {
                vbase: offset,
                actions: Vec::with_capacity(12),
            }
        }
    }

    impl ElfLoader for TestLoader {
        fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr> {
            for header in load_headers {
                info!(
                    "allocate base = {:#x} size = {:#x} flags = {}",
                    header.virtual_addr(),
                    header.mem_size(),
                    header.flags()
                );

                self.actions.push(LoaderAction::Allocate(
                    header.virtual_addr(),
                    header.mem_size() as usize,
                    header.flags(),
                ));
            }
            Ok(())
        }

        fn relocate(&mut self, entry: &Rela<P64>) -> Result<(), ElfLoaderErr> {
            let typ = TypeRela64::from(entry.get_type());

            // Get the pointer to where the relocation happens in the
            // memory where we loaded the headers
            //
            // vbase is the new base where we locate the binary
            //
            // get_offset(): For an executable or shared object, the value indicates
            // the virtual address of the storage unit affected by the relocation.
            // This information makes the relocation entries more useful for the runtime linker.
            let addr: *mut u64 = (self.vbase + entry.get_offset()) as *mut u64;

            match typ {
                TypeRela64::R_64 => {
                    trace!("R_64");
                    Ok(())
                }
                TypeRela64::R_RELATIVE => {
                    // This is a relative relocation, add the offset (where we put our
                    // binary in the vspace) to the addend and we're done.
                    self.actions.push(LoaderAction::Relocate(
                        addr as u64,
                        self.vbase + entry.get_addend(),
                    ));
                    trace!(
                        "R_RELATIVE *{:p} = {:#x}",
                        addr,
                        self.vbase + entry.get_addend()
                    );
                    Ok(())
                }
                TypeRela64::R_GLOB_DAT => {
                    trace!("TypeRela64::R_GLOB_DAT: Can't handle that.");
                    Ok(())
                }
                TypeRela64::R_NONE => Ok(()),
                _ => Err(ElfLoaderErr::UnsupportedRelocationEntry),
            }
        }

        unsafe fn load(
            &mut self,
            _flags: Flags,
            base: VAddr,
            region: &[u8],
        ) -> Result<(), ElfLoaderErr> {
            info!("load base = {:#x} size = {:#x} region", base, region.len());
            self.actions.push(LoaderAction::Load(base, region.len()));
            Ok(())
        }

        fn tls(
            &mut self,
            tdata_start: VAddr,
            tdata_length: u64,
            total_size: u64,
            alignment: u64,
        ) -> Result<(), ElfLoaderErr> {
            info!(
                "tdata_start = {:#x} tdata_length = {:#x} total_size = {:#x} alignment = {:#}",
                tdata_start, tdata_length, total_size, alignment
            );
            self.actions.push(LoaderAction::Tls(
                tdata_start,
                tdata_length,
                total_size,
                alignment,
            ));
            Ok(())
        }
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn load_pie_elf() {
        init();
        let binary_blob = fs::read("test/test").expect("Can't read binary");
        let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

        assert!(binary.is_pie());

        let mut loader = TestLoader::new(0x1000_0000);
        binary.load(&mut loader).expect("Can't load?");

        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Allocate(VAddr::from(0x0u64), 0x888, Flags(1 | 4)))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Allocate(VAddr::from(0x200db8u64), 0x260, Flags(2 | 4)))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Load(VAddr::from(0x0u64), 0x888))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Load(VAddr::from(0x200db8u64), 0x258))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Relocate(0x1000_0000 + 0x200db8, 0x1000_0000 + 0x000640))
            .is_some());
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Relocate(0x1000_0000 + 0x200dc0, 0x1000_0000 + 0x000600))
            .is_some());

        //info!("test {:#?}", loader.actions);
    }

    #[test]
    fn check_nopie() {
        init();
        let binary_blob = fs::read("test/test_nopie").expect("Can't read binary");
        let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

        assert!(!binary.is_pie());
    }

    #[test]
    fn check_tls() {
        init();

        let binary_blob = fs::read("test/tls").expect("Can't read binary");
        let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");
        let mut loader = TestLoader::new(0x1000_0000);
        binary.load(&mut loader).expect("Can't load?");
        /*
        TLS produces entries of this form:
        pheader = Program header:
        type:             Ok(Tls)
        flags:              R
        offset:           0xdb4
        virtual address:  0x200db4
        physical address: 0x200db4
        file size:        0x4
        memory size:      0x8
        align:            0x4

        File size is 0x4 because we have one tdata entry; memory size
        is 8 because we also have one bss entry that needs to be written with zeroes.
        So to initialize TLS: we allocate zeroed memory of size `memory size`, then copy
        file size starting at virtual address in the beginning.
        */
        assert!(loader
            .actions
            .iter()
            .find(|&&x| x == LoaderAction::Tls(VAddr::from(0x200db4u64), 0x4, 0x8, 0x4))
            .is_some());
    }
}

#[cfg(doctest)]
mod test_readme {
    macro_rules! external_doc_test {
        ($x:expr) => {
            #[doc = $x]
            extern "C" {}
        };
    }

    external_doc_test!(include_str!("../README.md"));
}
