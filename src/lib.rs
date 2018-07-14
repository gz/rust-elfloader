#![feature(core, core_prelude, core_slice_ext, custom_derive)]
#![no_std]
#![crate_name = "elfloader"]
#![crate_type = "lib"]
#![deny(warnings)]

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod elf;
use core::fmt;
use core::mem::{size_of, transmute};

pub type PAddr = u64;
pub type VAddr = usize;

/// Abstract representation of a loadable ELF binary.
pub struct ElfBinary<'s> {
    name: &'s str,
    region: &'s [u8],
    header: &'s elf::FileHeader,
}

impl<'s> fmt::Debug for ElfBinary<'s> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ElfBinary{{ {} {} [", self.name, self.header)?;
        for p in self.program_headers() {
            write!(f, " pheader = {}", p)?;
        }
        write!(f, "] }}")
    }
}

/// Implement this for ELF loading.
pub trait ElfLoader {
    /// Allocates a virtual region of size amount of bytes.
    fn allocate(&mut self, base: VAddr, size: usize, flags: elf::ProgFlag);

    /// Copies the region into the base.
    fn load(&mut self, base: VAddr, region: &'static [u8]);
}

// T must be a POD for this to be safe
unsafe fn slice_pod<T>(region: &[u8], offset: usize, count: usize) -> &[T] {
    assert!(region.len() - offset >= count * size_of::<T>());
    core::slice::from_raw_parts(region[offset..].as_ptr() as *const T, count)
}

impl<'s> ElfBinary<'s> {
    /// Create a new ElfBinary.
    /// Makes sure that the provided region has valid ELF magic byte sequence
    /// and is big enough to contain at least the ELF file header
    /// otherwise it will return None.
    pub fn new(name: &'s str, region: &'s [u8]) -> Option<ElfBinary<'s>> {
        if region.len() >= size_of::<elf::FileHeader>() && region.starts_with(elf::ELF_MAGIC) {
            let header: &elf::FileHeader = unsafe { &slice_pod(region, 0, 1)[0] };
            return Some(ElfBinary {
                name: name,
                region: region,
                header: header,
            });
        }

        None
    }

    /// Create a slice of the program headers.
    pub fn program_headers(&self) -> &'s [elf::ProgramHeader] {
        let correct_header_size = self.header.phentsize as usize == size_of::<elf::ProgramHeader>();
        let pheader_region_size = self.header.phoff as usize
            + self.header.phnum as usize * self.header.phentsize as usize;
        let big_enough_region = self.region.len() >= pheader_region_size;

        if self.header.phoff == 0 || !correct_header_size || !big_enough_region {
            return &[];
        }

        unsafe {
            slice_pod(
                self.region,
                self.header.phoff as usize,
                self.header.phnum as usize,
            )
        }
    }

    // Get the string at offset str_offset in the string table strtab
    fn strtab_str(&self, strtab: &'s elf::SectionHeader, str_offset: elf::StrOffset) -> &'s str {
        assert!(strtab.shtype == elf::SHT_STRTAB);
        let data = self.section_data(strtab);
        let offset = str_offset.0 as usize;
        let mut end = offset;
        while data[end] != 0 {
            end += 1;
        }
        core::str::from_utf8(&data[offset..end]).unwrap()
    }

    // Get the name of the section
    pub fn symbol_name(&self, symbol: &'s elf::Symbol) -> &'s str {
        let strtab = self
            .section_headers()
            .iter()
            .find(|s| s.shtype == elf::SHT_STRTAB && self.section_name(s) == ".strtab")
            .unwrap();
        self.strtab_str(strtab, symbol.name)
    }

    // Get the data of the section
    pub fn section_data(&self, section: &'s elf::SectionHeader) -> &'s [u8] {
        &self.region[(section.offset as usize)..(section.offset as usize + section.size as usize)]
    }

    // Get the name of the section
    pub fn section_name(&self, section: &'s elf::SectionHeader) -> &'s str {
        self.strtab_str(
            &self.section_headers()[self.header.shstrndx as usize],
            section.name,
        )
    }

    // Get the symbols of the section
    fn section_symbols(&self, section: &'s elf::SectionHeader) -> &'s [elf::Symbol] {
        assert!(section.shtype == elf::SHT_SYMTAB);
        unsafe {
            slice_pod(
                self.section_data(section),
                0,
                section.size as usize / size_of::<elf::Symbol>(),
            )
        }
    }

    // Enumerate all the symbols in the file
    pub fn for_each_symbol<F: FnMut(&'s elf::Symbol)>(&self, mut func: F) {
        for sym in self
            .section_headers()
            .iter()
            .filter(|s| s.shtype == elf::SHT_SYMTAB)
            .flat_map(|s| self.section_symbols(s).iter())
        {
            func(sym);
        }
    }

    /// Create a slice of the section headers.
    pub fn section_headers(&self) -> &'s [elf::SectionHeader] {
        let correct_header_size = self.header.shentsize as usize == size_of::<elf::SectionHeader>();
        let sheader_region_size = self.header.shoff as usize
            + self.header.shnum as usize * self.header.shentsize as usize;
        let big_enough_region = self.region.len() >= sheader_region_size;

        if self.header.shoff == 0 || !correct_header_size || !big_enough_region {
            return &[];
        }

        unsafe {
            slice_pod(
                self.region,
                self.header.shoff as usize,
                self.header.shnum as usize,
            )
        }
    }

    /// Can we load the binary on our platform?
    fn _can_load(&self) -> bool {
        let correct_class = self.header.ident.class == elf::ELFCLASS64;
        let correct_elfversion = self.header.ident.version == elf::EV_CURRENT;
        let correct_data = self.header.ident.data == elf::ELFDATA2LSB;
        let correct_osabi = self.header.ident.osabi == elf::ELFOSABI_SYSV
            || self.header.ident.osabi == elf::ELFOSABI_LINUX;
        let correct_type =
            unsafe { self.header.elftype == elf::ET_EXEC || self.header.elftype == elf::ET_DYN };
        let correct_machine = unsafe { self.header.machine == elf::EM_X86_64 };

        correct_class
            && correct_data
            && correct_elfversion
            && correct_machine
            && correct_osabi
            && correct_type
    }

    fn load_header(&self, p: &elf::ProgramHeader, loader: &mut ElfLoader) {
        let big_enough_region = self.region.len() >= (p.offset + p.filesz) as usize;
        if !big_enough_region {
            //log!("Unable to load {}", p);
            return;
        }

        loader.allocate(p.vaddr, p.memsz as usize, p.flags);
        let segment: &'static [u8] = unsafe {
            core::slice::from_raw_parts(
                transmute(&self.region[p.offset as usize]),
                p.filesz as usize,
            )
        };
        loader.load(p.vaddr, segment);
    }

    pub fn load(&self, loader: &mut ElfLoader) {
        for p in self.program_headers() {
            let _ = match p.progtype {
                elf::PT_LOAD => self.load_header(p, loader),
                _ => (),
            };
        }
    }
}
