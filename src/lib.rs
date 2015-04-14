#![feature(custom_derive)]
#![feature(no_std)]
#![feature(core)]
#![no_std]

#![crate_name = "elfloader"]
#![crate_type = "lib"]

#[macro_use]
extern crate core;
#[macro_use]
extern crate klogger;

#[cfg(test)]
#[macro_use]
extern crate std;

mod elf;
use core::prelude::*;
use core::mem::{transmute, size_of};
use core::slice;

/// Abstract representation of a loadable ELF binary.
pub struct ElfBinary {
    name: &'static str,
    region: &'static [u8],
    header: &'static elf::FileHeader,
}

/// Verify that memory region starts with a correct ELF magic.
fn valid_elf_magic(region: &'static [u8]) -> bool {
    region[0] == elf::ELFMAG0 &&
    region[1] == elf::ELFMAG1 &&
    region[2] == elf::ELFMAG2 &&
    region[3] == elf::ELFMAG3
}

impl ElfBinary {

    /// Create a new ElfBinary.
    /// Makes sure that the provided region has valid ELF magic byte sequence
    /// and is big enough to contain at least the ELF file header
    /// otherwise it will return None.
    pub fn new(name: &'static str, region: &'static [u8]) -> Option<ElfBinary> {
        if region.len() >= size_of::<elf::FileHeader>() && valid_elf_magic(region) {
            let header: &elf::FileHeader = unsafe { transmute(&region[0]) };
            return Some(ElfBinary { name: name, region: region, header: header });
        }

        None
    }

    /// Print the program header.
    pub fn print_headers(&self) {
        for p in self.program_headers() {
            log!("pheader = {}", p);
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

}
