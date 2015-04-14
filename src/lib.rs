#![feature(no_std)]
#![feature(core)]
#![no_std]

#![crate_name = "elfloader"]
#![crate_type = "lib"]

#[macro_use]
extern crate core;
#[macro_use]
extern crate x86;
#[macro_use]
extern crate klogger;

mod types;
use core::mem::{transmute, size_of};

pub struct ElfBinary {
    pub start: u64,
    pub size: usize,
}

pub fn parse_elf(binary: &'static [u8]) {

    // Verify the magic number
    if binary[0] != types::ELFMAG0 ||
       binary[1] != types::ELFMAG1 ||
       binary[2] != types::ELFMAG2 ||
       binary[3] != types::ELFMAG3 {
        return
    }

    //log!("header size = {}", size_of::<types::FileHeader>() );
    let header: &types::FileHeader = unsafe { transmute(&binary[0]) };
    log!("header = {}", header);
    log!("Start of program header: {}", header.phoff);
    log!("Start of section header: {}", header.shoff);

    let correct_class = header.ident.class == types::ELFCLASS64;
    let correct_elfversion = header.ident.version == types::EV_CURRENT;
    let correct_data = header.ident.data == types::ELFDATA2LSB;
    let correct_osabi = header.ident.osabi == types::ELFOSABI_SYSV || header.ident.osabi == types::ELFOSABI_LINUX;
    let correct_type = header.elftype == types::ET_EXEC || header.elftype == types::ET_DYN;
    let correct_machine = header.machine == types::EM_X86_64;

    if !correct_class ||
       !correct_data ||
       !correct_elfversion ||
       !correct_machine ||
       !correct_osabi ||
       !correct_type {
        log!("Unable to load this ELF file.");
        return
       }


    log!("sizeof(ProgramHeader) = {}", size_of::<types::ProgramHeader>());
    let pheader: &types::ProgramHeader = unsafe { transmute(&binary[header.phoff as usize]) };

    log!("pheader = {}", pheader);

}
