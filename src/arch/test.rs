use crate::*;
use log::{info, trace};
use std::vec::Vec;

#[derive(Eq, Clone, PartialEq, Copy, Debug)]
pub(crate) enum LoaderAction {
    Allocate(VAddr, usize, Flags),
    Load(VAddr, usize),
    Relocate(VAddr, u64),
    Tls(VAddr, u64, u64, u64),
}
pub(crate) struct TestLoader {
    pub(crate) vbase: VAddr,
    pub(crate) actions: Vec<LoaderAction>,
}

impl TestLoader {
    pub(crate) fn new(offset: VAddr) -> TestLoader {
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

    fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        use crate::arch::aarch64::RelocationTypes::*;
        use crate::arch::riscv::RelocationTypes::*;
        use crate::arch::x86::RelocationTypes::*;
        use crate::arch::x86_64::RelocationTypes::*;
        use RelocationType::{x86, x86_64, AArch64, RiscV};

        // Get the pointer to where the relocation happens in the
        // memory where we loaded the headers
        //
        // vbase is the new base where we locate the binary
        //
        // get_offset(): For an executable or shared object, the value indicates
        // the virtual address of the storage unit affected by the relocation.
        // This information makes the relocation entries more useful for the runtime linker.
        let addr: *mut u64 = (self.vbase + entry.offset) as *mut u64;

        match entry.rtype {
            // x86
            x86(R_386_32) => Ok(()),
            x86(R_386_RELATIVE) => {
                info!("R_RELATIVE {:p} ", addr);
                self.actions
                    .push(LoaderAction::Relocate(addr as u64, self.vbase));
                Ok(())
            }
            x86(R_386_GLOB_DAT) => {
                trace!("R_386_GLOB_DAT: Can't handle that.");
                Ok(())
            }
            x86(R_386_NONE) => Ok(()),
            // RISCV
            RiscV(R_RISCV_64) => Ok(()),
            RiscV(R_RISCV_NONE) => Ok(()),
            RiscV(R_RISCV_RELATIVE) => {
                // This type requires addend to be present
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

                // This is a relative relocation, add the offset (where we put our
                // binary in the vspace) to the addend and we're done.
                self.actions
                    .push(LoaderAction::Relocate(addr as u64, self.vbase + addend));
                trace!("R_RELATIVE *{:p} = {:#x}", addr, self.vbase + addend);
                Ok(())
            }

            // x86_64
            x86_64(R_AMD64_64) => {
                trace!("R_64");
                Ok(())
            }
            x86_64(R_AMD64_RELATIVE) => {
                // This type requires addend to be present
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

                // This is a relative relocation, add the offset (where we put our
                // binary in the vspace) to the addend and we're done.
                self.actions
                    .push(LoaderAction::Relocate(addr as u64, self.vbase + addend));
                trace!("R_RELATIVE *{:p} = {:#x}", addr, self.vbase + addend);
                Ok(())
            }
            AArch64(R_AARCH64_RELATIVE) => {
                // This type requires addend to be present
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

                // This is a relative relocation, add the offset (where we put our
                // binary in the vspace) to the addend and we're done.
                self.actions
                    .push(LoaderAction::Relocate(addr as u64, self.vbase + addend));
                trace!("R_RELATIVE *{:p} = {:#x}", addr, self.vbase + addend);
                Ok(())
            }
            AArch64(R_AARCH64_GLOB_DAT) => {
                trace!("R_AARCH64_GLOB_DAT: Can't handle that.");
                Ok(())
            }
            x86_64(R_AMD64_GLOB_DAT) => {
                trace!("R_AMD64_GLOB_DAT: Can't handle that.");
                Ok(())
            }
            x86_64(R_AMD64_NONE) => Ok(()),
            e => {
                log::error!("Unsupported relocation type: {:?}", e);
                Err(ElfLoaderErr::UnsupportedRelocationEntry)
            }
        }
    }

    fn load(&mut self, _flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
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

pub(crate) fn init() {
    let _ = env_logger::builder().is_test(true).try_init();
}
