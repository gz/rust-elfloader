use crate::{
    DynamicFlags1, DynamicInfo, ElfLoader, ElfLoaderErr, LoadableHeaders, RelaEntry, TypeRela64,
};
use core::fmt;
use log::*;
use xmas_elf::dynamic::Tag;
use xmas_elf::program::ProgramHeader::{self, Ph32, Ph64};
use xmas_elf::program::{ProgramIter, SegmentData, Type};
use xmas_elf::sections::SectionData;
pub use xmas_elf::symbol_table::{Entry, Entry64};
use xmas_elf::ElfFile;
use xmas_elf::*;

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

impl<'s> ElfBinary<'s> {
    /// Create a new ElfBinary.
    pub fn new(region: &'s [u8]) -> Result<ElfBinary<'s>, ElfLoaderErr> {
        let file = ElfFile::new(region)?;

        // Parse relevant parts out of the the .dynamic section
        let mut dynamic = None;
        for p in file.program_iter() {
            let typ = match p {
                Ph64(header) => header.get_type()?,
                Ph32(header) => header.get_type()?,
            };

            if typ == Type::Dynamic {
                dynamic = ElfBinary::parse_dynamic(&file, &p)?;
                break;
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

    /// Returns the dynamic loader if present.
    ///
    /// readelf -x .interp <binary>
    ///
    /// For a statically compiled binary this will return None
    pub fn interpreter(&'s self) -> Option<&'s str> {
        self.file
            .find_section_by_name(".interp")
            .and_then(|interp_section| {
                let data = interp_section.get_data(&self.file).ok()?;
                match data {
                    SectionData::Undefined(val) => {
                        if val.len() < 2 {
                            return None;
                        }
                        Some(core::str::from_utf8(&val[..val.len() - 1]).ok()?)
                    }
                    _ => None,
                }
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

        if header.pt1.version() != header::Version::Current {
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
        // It's easier to just locate the section by name, either:
        // - .rela.dyn
        // - .rel.dyn
        let relocation_section = self
            .file
            .find_section_by_name(".rela.dyn")
            .or_else(|| self.file.find_section_by_name(".rel.dyn"));

        relocation_section.map_or(
            Ok(()), // neither section found
            |rela_section_dyn| {
                let data = rela_section_dyn.get_data(&self.file)?;
                match data {
                    SectionData::Rela64(rela_entries) => {
                        // Now we finally have a list of relocation we're supposed to perform:
                        for entry in rela_entries {
                            let _typ = TypeRela64::from(entry.get_type());
                            // Does the entry blong to the current header?
                            loader.relocate(RelaEntry::Rela64(entry))?;
                        }

                        Ok(())
                    }
                    SectionData::Rela32(rela_entries) => {
                        trace!("Relocation entries: {:?}", rela_entries);

                        // Now we finally have a list of relocation we're supposed to perform:
                        for entry in rela_entries {
                            //let _typ = TypeRela32::from(entry.get_type());
                            // Does the entry blong to the current header?
                            loader.relocate(RelaEntry::Rela32(entry))?;
                        }
                        Ok(())
                    }
                    SectionData::Rel32(rela_entries) => {
                        trace!("Relocation entries: {:?}", rela_entries);

                        // Now we finally have a list of relocation we're supposed to perform:
                        for entry in rela_entries {
                            //let _typ = TypeRela32::from(entry.get_type());
                            // Does the entry blong to the current header?
                            loader.relocate(RelaEntry::Rel32(entry))?;
                        }
                        Ok(())
                    }
                    _ => Err(ElfLoaderErr::UnsupportedSectionData),
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
    fn parse_dynamic<'a>(
        file: &ElfFile,
        dynamic_header: &'a ProgramHeader<'a>,
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
                        Tag::Needed => {
                            trace!(
                                "Required library {:?}",
                                file.get_dyn_string(dyn_entry.get_val()? as u32)
                            )
                        }
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
            SegmentData::Dynamic32(dyn_entries) => {
                for dyn_entry in dyn_entries {
                    let tag = dyn_entry.get_tag()?;
                    match tag {
                        Tag::Needed => {
                            trace!(
                                "Required library {:?}",
                                file.get_dyn_string(dyn_entry.get_val()?)
                            )
                        }
                        Tag::Rela => rela = dyn_entry.get_ptr()?.into(),
                        Tag::RelaSize => rela_size = dyn_entry.get_val()?.into(),
                        Tag::Flags => {
                            flags1 = unsafe {
                                DynamicFlags1::from_bits_unchecked(dyn_entry.get_val()? as u64)
                            };
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
        for header in self.file.program_iter() {
            let raw = match header {
                Ph32(inner) => inner.raw_data(&self.file),
                Ph64(inner) => inner.raw_data(&self.file),
            };
            let typ = header.get_type()?;
            match typ {
                Type::Load => {
                    loader.load(header.flags(), header.virtual_addr(), raw)?;
                }
                Type::Tls => {
                    loader.tls(
                        header.virtual_addr(),
                        header.file_size(),
                        header.mem_size(),
                        header.align(),
                    )?;
                }
                _ => {} // skip for now
            }
        }

        // Relocate headers
        self.maybe_relocate(loader)?;

        // Process .data.rel.ro
        for header in self.file.program_iter() {
            if header.get_type()? == Type::GnuRelro {
                loader.make_readonly(header.virtual_addr(), header.mem_size() as usize)?
            }
        }

        Ok(())
    }

    fn iter_loadable_headers(&self) -> LoadableHeaders {
        // Trying to determine loadeable headers
        fn select_load(pheader: &ProgramHeader) -> bool {
            match pheader {
                Ph32(header) => header
                    .get_type()
                    .map(|typ| typ == Type::Load)
                    .unwrap_or(false),
                Ph64(header) => header
                    .get_type()
                    .map(|typ| typ == Type::Load)
                    .unwrap_or(false),
            }
        }

        // Create an iterator (well filter really) that has all loadeable
        // headers and pass it to the loader
        // TODO: This is pretty ugly, maybe we can do something with impl Trait?
        // https://stackoverflow.com/questions/27535289/what-is-the-correct-way-to-return-an-iterator-or-any-other-trait
        self.file.program_iter().filter(select_load)
    }
}
