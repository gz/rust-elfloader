use std::fs;

use crate::arch::test::*;
use crate::*;

#[test]
fn load_pie_elf() {
    init();
    let binary_blob = fs::read("test/test.riscv64").expect("Can't read binary");
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
    // PHDR           0x000040 0x0000000000000040 0x0000000000000040 0x000188 0x000188 R   0x8
    // INTERP         0x0001c8 0x00000000000001c8 0x00000000000001c8 0x00001a 0x00001a R   0x1
    // [Requesting program interpreter: /lib/ld-linux-aarch64.so.1]
    // LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x000780 0x000780 R E 0x10000
    // LOAD           0x000e20 0x0000000000001e20 0x0000000000001e20 0x000250 0x000288 RW  0x10000
    // DYNAMIC        0x000e30 0x0000000000001e30 0x0000000000001e30 0x0001d0 0x0001d0 RW  0x8
    assert_eq!(
        loader.actions[0],
        LoaderAction::Allocate(VAddr::from(0x0u64), 0x780, Flags(1 | 4))
    );
    assert_eq!(
        loader.actions[1],
        LoaderAction::Allocate(VAddr::from(0x1e20u64), 0x288, Flags(0b110))
    );
    assert_eq!(
        loader.actions[2],
        LoaderAction::Load(VAddr::from(0x0u64), 0x780)
    );
    assert_eq!(
        loader.actions[3],
        LoaderAction::Load(VAddr::from(0x1e20u64), 0x250)
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
    //
    // Relocation section '.rela.dyn' at offset 0x420 contains 11 entries:
    //   Offset          Info           Type           Sym. Value    Sym. Name + Addend
    // 000000001e20  000000000003 R_RISCV_RELATIVE                     6ac
    // 000000001e28  000000000003 R_RISCV_RELATIVE                     644
    // 000000002000  000000000003 R_RISCV_RELATIVE                     2000
    // 000000002058  000000000003 R_RISCV_RELATIVE                     6e0
    // 000000002030  000300000002 R_RISCV_64        0000000000000000 __cxa_finalize + 0
    // 000000002038  000400000002 R_RISCV_64        0000000000000000 _init + 0
    // 000000002040  000500000002 R_RISCV_64        0000000000000000 __deregister_fram[...] + 0
    // 000000002048  000600000002 R_RISCV_64        0000000000000000 _ITM_registerTMCl[...] + 0
    // 000000002050  000700000002 R_RISCV_64        0000000000000000 _ITM_deregisterTM[...] + 0
    // 000000002060  000800000002 R_RISCV_64        0000000000000000 _fini + 0
    // 000000002068  000a00000002 R_RISCV_64        0000000000000000 __register_frame_info + 0
    //
    // Relocation section '.rela.plt' at offset 0x528 contains 2 entries:
    //   Offset          Info           Type           Sym. Value    Sym. Name + Addend
    // 000000002018  000200000005 R_RISCV_JUMP_SLOT 0000000000000000 printf + 0
    // 000000002020  000900000005 R_RISCV_JUMP_SLOT 0000000000000000 __libc_start_main + 0
    assert_eq!(
        loader.actions[4],
        LoaderAction::Relocate(0x1000_0000 + 0x1e20, 0x1000_06ac)
    );
    assert_eq!(
        loader.actions[5],
        LoaderAction::Relocate(0x1000_0000 + 0x1e28, 0x1000_0644)
    );
    assert_eq!(
        loader.actions[6],
        LoaderAction::Relocate(0x1000_0000 + 0x2000, 0x1000_2000)
    );
    assert_eq!(
        loader.actions[7],
        LoaderAction::Relocate(0x1000_0000 + 0x2058, 0x1000_06e0)
    );

    assert_eq!(loader.actions.len(), 8);
}

#[test]
fn check_nopie() {
    init();
    let binary_blob = fs::read("test/test_nopie.riscv64").expect("Can't read binary");
    let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");

    assert!(!binary.is_pie());
}

#[test]
fn check_tls() {
    init();

    let binary_blob = fs::read("test/tls.riscv64").expect("Can't read binary");
    let binary = ElfBinary::new(binary_blob.as_slice()).expect("Got proper ELF file");
    let mut loader = TestLoader::new(0x1000_0000);
    binary.load(&mut loader).expect("Can't load?");
    /*
    readelf -l test/tls.riscv64
    TLS produces entries of this form:
    pheader = Program header:
    type:             Ok(Tls)
    flags:              R
    offset:           0xe20
    virtual address:  0x1e0c
    physical address: 0x1e0c
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
        .find(|&&x| x == LoaderAction::Tls(VAddr::from(0x1e0cu64), 0x4, 0x8, 0x4))
        .is_some());
}
