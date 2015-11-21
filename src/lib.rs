#![feature(no_std, core, core_prelude, core_slice_ext, custom_derive)]
#![no_std]

#![crate_name = "elfloader"]
#![crate_type = "lib"]

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod elf;
use core::fmt;
use core::mem::{transmute, size_of};

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
        write!(f, "{} {}", self.name, self.header)
    }
}

/// Verify that memory region starts with a correct ELF magic.
fn valid_elf_magic(region: &[u8]) -> bool {
    region[0] == elf::ELFMAG0 &&
    region[1] == elf::ELFMAG1 &&
    region[2] == elf::ELFMAG2 &&
    region[3] == elf::ELFMAG3
}

/// Implement this for ELF loading.
pub trait ElfLoader {
    /// Allocates a virtual region of size amount of bytes.
    fn allocate(&mut self, base: VAddr, size: usize, flags: elf::ProgFlag);

    /// Copies the region into the base.
    fn load(&mut self, base: VAddr, region: &'static [u8]);
}

impl<'s> ElfBinary<'s> {

    /// Create a new ElfBinary.
    /// Makes sure that the provided region has valid ELF magic byte sequence
    /// and is big enough to contain at least the ELF file header
    /// otherwise it will return None.
    pub fn new(name: &'s str, region: &'s [u8]) -> Option<ElfBinary<'s>> {
        if region.len() >= size_of::<elf::FileHeader>() && valid_elf_magic(region) {
            let header: &elf::FileHeader = unsafe { transmute(&region[0]) };
            return Some(ElfBinary { name: name, region: region, header: header });
        }

        None
    }

    /// Print the program headers.
    pub fn print_program_headers(&self) {
        for p in self.program_headers() {
            //log!("pheader = {}", p);
        }
    }

    /// Create a slice of the program headers.
    fn program_headers(&self) -> &[elf::ProgramHeader] {
        let correct_header_size = self.header.phentsize as usize == size_of::<elf::ProgramHeader>();
        let pheader_region_size = self.header.phoff as usize + self.header.phnum as usize * self.header.phentsize as usize;
        let big_enough_region = self.region.len() >= pheader_region_size;

        if !correct_header_size || !big_enough_region {
            return &[];
        }

        let pheaders: &[elf::ProgramHeader] = unsafe {
            core::slice::from_raw_parts(
                transmute(&self.region[self.header.phoff as usize]),
                self.header.phnum as usize)
        };
        return pheaders;
    }

    /// Can we load the binary on our platform?
    fn can_load(&self) -> bool {
        let correct_class = self.header.ident.class == elf::ELFCLASS64;
        let correct_elfversion = self.header.ident.version == elf::EV_CURRENT;
        let correct_data = self.header.ident.data == elf::ELFDATA2LSB;
        let correct_osabi = self.header.ident.osabi == elf::ELFOSABI_SYSV || self.header.ident.osabi == elf::ELFOSABI_LINUX;
        let correct_type = self.header.elftype == elf::ET_EXEC || self.header.elftype == elf::ET_DYN;
        let correct_machine = self.header.machine == elf::EM_X86_64;

        correct_class && correct_data && correct_elfversion && correct_machine && correct_osabi && correct_type
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
                transmute(&self.region[p.offset as usize]), p.filesz as usize)
        };
        loader.load(p.vaddr, segment);
    }

    pub fn load(&self, loader: &mut ElfLoader) {
        for p in self.program_headers() {
            let x = match p.progtype {
                elf::PT_LOAD => self.load_header(p, loader),
                _ => ()
            };
        }
    }

}
