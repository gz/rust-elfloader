use std::fs;

use crate::arch::test::*;
use crate::*;

#[test]
fn load_pie_elf() {
    init();
    let binary_blob = fs::read("test/test.x86_64").expect("Can't read binary");
    let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

    assert!(binary.is_pie());

    let mut loader = TestLoader::new(0x1000_0000);
    binary.load(&mut loader).expect("Can't load?");

    for action in loader.actions.iter() {
        println!("{:?}", action);
    }

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
}

#[test]
fn check_nopie() {
    init();
    let binary_blob = fs::read("test/test_nopie.x86_64").expect("Can't read binary");
    let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

    assert!(!binary.is_pie());
}

#[test]
fn check_tls() {
    init();

    let binary_blob = fs::read("test/tls.x86_64").expect("Can't read binary");
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
