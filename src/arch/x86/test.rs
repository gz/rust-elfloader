use std::fs;

use crate::arch::test::*;
use crate::*;

#[test]
fn load_pie_elf() {
    init();
    let binary_blob = fs::read("test/test.x86").expect("Can't read binary");
    let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

    assert!(binary.is_pie());

    let mut loader = TestLoader::new(0x1000_0000);
    binary.load(&mut loader).expect("Can't load?");

    for action in loader.actions.iter() {
        println!("{:?}", action);
    }

    // View allocate/load actions with readelf -l [binary]
    // Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
    // LOAD           0x000000 0x00000000 0x00000000 0x003bc 0x003bc R   0x1000
    // LOAD           0x001000 0x00001000 0x00001000 0x00288 0x00288 R E 0x1000
    // LOAD           0x002000 0x00002000 0x00002000 0x0016c 0x0016c R   0x1000
    // LOAD           0x002ef4 0x00003ef4 0x00003ef4 0x00128 0x0012c RW  0x1000
    assert!(loader
        .actions
        .iter()
        .find(|&&x| x == LoaderAction::Allocate(VAddr::from(0x0u64), 0x003bc, Flags(4)))
        .is_some());
    assert!(loader
        .actions
        .iter()
        .find(|&&x| x == LoaderAction::Allocate(VAddr::from(0x1000u64), 0x288, Flags(1 | 4)))
        .is_some());
    assert!(loader
        .actions
        .iter()
        .find(|&&x| x == LoaderAction::Allocate(VAddr::from(0x002000u64), 0x0016c, Flags(4)))
        .is_some());
    assert!(loader
        .actions
        .iter()
        .find(|&&x| x == LoaderAction::Allocate(VAddr::from(0x3ef4u64), 0x12c, Flags(2 | 4)))
        .is_some());
    assert!(loader
        .actions
        .iter()
        .find(|&&x| x == LoaderAction::Load(VAddr::from(0x0u64), 0x003bc))
        .is_some());
    assert!(loader
        .actions
        .iter()
        .find(|&&x| x == LoaderAction::Load(VAddr::from(0x001000u64), 0x00288))
        .is_some());
    assert!(loader
        .actions
        .iter()
        .find(|&&x| x == LoaderAction::Load(VAddr::from(0x002000u64), 0x0016c))
        .is_some());
    assert!(loader
        .actions
        .iter()
        .find(|&&x| x == LoaderAction::Load(VAddr::from(0x00003ef4u64), 0x00128))
        .is_some());

    // View relocation actions with readelf -r [binary]
    // Offset     Info    Type            Sym.Value  Sym. Name
    // 00003ef4  00000008 R_386_RELATIVE
    // 00003ef8  00000008 R_386_RELATIVE
    // 00003ff8  00000008 R_386_RELATIVE
    // 00004018  00000008 R_386_RELATIVE
    assert!(loader
        .actions
        .iter()
        .find(|&&x| x == LoaderAction::Relocate(0x1000_0000 + 0x00003ef4, 0x1000_0000))
        .is_some());
    assert!(loader
        .actions
        .iter()
        .find(|&&x| x == LoaderAction::Relocate(0x1000_0000 + 0x00003ef8, 0x1000_0000))
        .is_some());
}

#[test]
fn check_nopie() {
    init();
    let binary_blob = fs::read("test/test_nopie.x86").expect("Can't read binary");
    let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

    assert!(!binary.is_pie());
}

#[test]
fn check_tls() {
    init();

    let binary_blob = fs::read("test/tls.x86").expect("Can't read binary");
    let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");
    let mut loader = TestLoader::new(0x1000_0000);
    binary.load(&mut loader).expect("Can't load?");
    /*
    TLS produces entries of this form:
    pheader = Program header:
    type:             Ok(Tls)
    flags:              R
    offset:           0x2ef0
    virtual address:  0x3ef0
    physical address: 0x3ef0
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
        .find(|&&x| x == LoaderAction::Tls(VAddr::from(0x3ef0u64), 0x4, 0x8, 0x4))
        .is_some());
}
