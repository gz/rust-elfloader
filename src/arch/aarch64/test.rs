use std::fs;

use crate::arch::test::*;
use crate::*;

#[test]
fn load_pie_elf() {
    init();
    let binary_blob = fs::read("test/test.aarch64").expect("Can't read binary");
    let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

    assert!(binary.is_pie());

    let mut loader = TestLoader::new(0x1000_0000);
    binary.load(&mut loader).expect("Can't load?");

    for action in loader.actions.iter() {
        println!("{:?}", action);
    }

    // View allocate/load actions with readelf -l [binary]
    // Program Headers:
    // Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
    // PHDR           0x000040 0x0000000000000040 0x0000000000000040 0x0001f8 0x0001f8 R   0x8
    // INTERP         0x000238 0x0000000000000238 0x0000000000000238 0x00001b 0x00001b R   0x1
    // [Requesting program interpreter: /lib/ld-linux-aarch64.so.1]
    // LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x0008cc 0x0008cc R E 0x10000
    // LOAD           0x000d90 0x0000000000010d90 0x0000000000010d90 0x000280 0x000288 RW  0x10000
    // DYNAMIC        0x000da0 0x0000000000010da0 0x0000000000010da0 0x0001f0 0x0001f0 RW  0x8
    // NOTE           0x000254 0x0000000000000254 0x0000000000000254 0x000044 0x000044 R   0x4
    // GNU_EH_FRAME   0x0007e4 0x00000000000007e4 0x00000000000007e4 0x00003c 0x00003c R   0x4
    // GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
    // GNU_RELRO      0x000d90 0x0000000000010d90 0x0000000000010d90 0x000270 0x000270 R   0x1
    assert_eq!(
        loader.actions[0],
        LoaderAction::Allocate(VAddr::from(0x0u64), 0x8cc, Flags(1 | 4))
    );
    assert_eq!(
        loader.actions[1],
        LoaderAction::Allocate(VAddr::from(0x10d90u64), 0x288, Flags(0b110))
    );
    assert_eq!(
        loader.actions[2],
        LoaderAction::Load(VAddr::from(0x0u64), 0x8cc)
    );
    assert_eq!(
        loader.actions[3],
        LoaderAction::Load(VAddr::from(0x10d90u64), 0x280)
    );

    // View relocation actions with readelf -r [binary]
    // Relocation section '.rela.dyn' at offset 0x480 contains 8 entries:
    //     Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
    // 0000000000010d90  0000000000000403 R_AARCH64_RELATIVE                        750
    // 0000000000010d98  0000000000000403 R_AARCH64_RELATIVE                        700
    // 0000000000010ff0  0000000000000403 R_AARCH64_RELATIVE                        754
    // 0000000000011008  0000000000000403 R_AARCH64_RELATIVE                        11008
    // 0000000000010fd8  0000000400000401 R_AARCH64_GLOB_DAT     0000000000000000 _ITM_deregisterTMCloneTable + 0
    // 0000000000010fe0  0000000500000401 R_AARCH64_GLOB_DAT     0000000000000000 __cxa_finalize@GLIBC_2.17 + 0
    // 0000000000010fe8  0000000600000401 R_AARCH64_GLOB_DAT     0000000000000000 __gmon_start__ + 0
    // 0000000000010ff8  0000000800000401 R_AARCH64_GLOB_DAT     0000000000000000 _ITM_registerTMCloneTable + 0
    //
    // Relocation section '.rela.plt' at offset 0x540 contains 5 entries:
    //     Offset             Info             Type               Symbol's Value  Symbol's Name + Addend
    // 0000000000010fa8  0000000300000402 R_AARCH64_JUMP_SLOT    0000000000000000 __libc_start_main@GLIBC_2.34 + 0
    // 0000000000010fb0  0000000500000402 R_AARCH64_JUMP_SLOT    0000000000000000 __cxa_finalize@GLIBC_2.17 + 0
    // 0000000000010fb8  0000000600000402 R_AARCH64_JUMP_SLOT    0000000000000000 __gmon_start__ + 0
    // 0000000000010fc0  0000000700000402 R_AARCH64_JUMP_SLOT    0000000000000000 abort@GLIBC_2.17 + 0
    // 0000000000010fc8  0000000900000402 R_AARCH64_JUMP_SLOT    0000000000000000 printf@GLIBC_2.17 + 0
    assert_eq!(
        loader.actions[4],
        LoaderAction::Relocate(0x1000_0000 + 0x10d90, 0x1000_0750)
    );
    assert_eq!(
        loader.actions[5],
        LoaderAction::Relocate(0x1000_0000 + 0x10d98, 0x1000_0700)
    );
    assert_eq!(
        loader.actions[6],
        LoaderAction::Relocate(0x1000_0000 + 0x10ff0, 0x1000_0754)
    );
    assert_eq!(
        loader.actions[7],
        LoaderAction::Relocate(0x1000_0000 + 0x11008, 0x1001_1008)
    );

    // R_AARCH64_GLOB_DAT entries next, but we ignore them in the test loader:
    /*assert_eq!(
        loader.actions[8],
        LoaderAction::Relocate(0x1000_0000 + 0x10fd8, 0x1000_0000)
    );

    assert_eq!(
        loader.actions[9],
        LoaderAction::Relocate(0x1000_0000 + 0x10fe0, 0x1000_0000)
    );

    assert_eq!(
        loader.actions[10],
        LoaderAction::Relocate(0x1000_0000 + 0x10fe8, 0x1000_0000)
    );
    assert_eq!(
        loader.actions[11],
        LoaderAction::Relocate(0x1000_0000 + 0x10ff8, 0x1000_0000)
    );*/

    assert_eq!(loader.actions.len(), 8);
}

#[test]
fn check_nopie() {
    init();
    let binary_blob = fs::read("test/test_nopie.aarch64").expect("Can't read binary");
    let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

    assert!(!binary.is_pie());
}

#[test]
fn check_tls() {
    init();

    let binary_blob = fs::read("test/tls.aarch64").expect("Can't read binary");
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
        .find(|&&x| x == LoaderAction::Tls(VAddr::from(0x10d8cu64), 0x4, 0x8, 0x4))
        .is_some());
}
