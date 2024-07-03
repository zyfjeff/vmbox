use std::sync::MutexGuard;

use arch::BOOT_STACK_POINTER;
use arch::HIGH_RAM_START;
use arch::ZERO_PAGE_START;
use base::Error;
use base::Result;
use kvm_bindings::{kvm_msr_entry, CpuId, MsrList, Msrs};
use kvm_ioctls::{IoEventAddress, VcpuExit, VcpuFd};
use vm_memory::{GuestAddress, GuestMemory};
use vmm_sys_util::eventfd::EventFd;

/* This CPUID returns the signature 'KVMKVMKVM' in ebx, ecx, and edx.  It
 * should be used to determine that a VM is running under KVM.
 */
const KVM_CPUID_SIGNATURE: u32 = 0x40000000;

/* This CPUID returns two feature bitmaps in eax, edx. Before enabling
 * a particular paravirtualization, the appropriate feature bit should
 * be checked in eax. The performance hint feature bit should be checked
 * in edx.
 */
const KVM_CPUID_FEATURES: u32 = 0x40000001;

const MSR_IA32_MISC_ENABLE: u32 = 0x000001a0;
const MSR_IA32_MISC_ENABLE_FAST_STRING_BIT: u64 = 0;
const MSR_IA32_MISC_ENABLE_FAST_STRING: u64 = 1u64 << MSR_IA32_MISC_ENABLE_FAST_STRING_BIT;

macro_rules! SETUP_SEGMENT_REGS {
    ($registers:ident, $segment_name:ident) => {
        $registers.$segment_name.base = 0;
        $registers.$segment_name.limit = u32::MAX;
        $registers.$segment_name.g = 1;
    };
}

/// A single route for an IRQ.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqRoute {
    pub gsi: u32,
    pub source: IrqSource,
}

// Convenience constructors for IrqRoutes
impl IrqRoute {
    pub fn ioapic_irq_route(irq_num: u32) -> IrqRoute {
        IrqRoute {
            gsi: irq_num,
            source: IrqSource::Irqchip {
                chip: IrqSourceChip::Ioapic,
                pin: irq_num,
            },
        }
    }

    pub fn pic_irq_route(id: IrqSourceChip, irq_num: u32) -> IrqRoute {
        IrqRoute {
            gsi: irq_num,
            source: IrqSource::Irqchip {
                chip: id,
                pin: irq_num % 8,
            },
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqSource {
    Irqchip { chip: IrqSourceChip, pin: u32 },
    Msi { address: u64, data: u32 },
}

/// The source chip of an `IrqSource`
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqSourceChip {
    PicPrimary,
    PicSecondary,
    Ioapic,
}

pub mod kvm;
pub use kvm::KvmVm;

pub struct Vcpu<'a, T: GuestMemory + Send> {
    vm: &'a KvmVm<T>,
    fd: VcpuFd,
}

impl<'a, T: GuestMemory + Send> Vcpu<'a, T> {
    pub fn new(fd: VcpuFd, vm: &'a KvmVm<T>) -> Result<Self> {
        Self::init_cpu_regs(&fd)?;
        let mut cpuid = vm.get_hypervisor().get_supported_cpuid()?;
        Self::init_cpu_id(&fd, &mut cpuid)?;
        Self::init_cpu_msrs(&fd)?;

        Ok(Vcpu { fd, vm })
    }

    pub fn init_cpu_id(fd: &VcpuFd, support_cpuid: &mut CpuId) -> Result<()> {
        for id in support_cpuid.as_mut_slice() {
            if id.function == KVM_CPUID_SIGNATURE {
                id.eax = KVM_CPUID_FEATURES;
                id.ebx = 0x4b4d564b; /* KVMK */
                id.ecx = 0x564b4d56; /* VMKV */
                id.edx = 0x4d; /* M */
            }
        }
        fd.set_cpuid2(support_cpuid)
            .map_err(|e| Error::new(e.errno()))?;
        Ok(())
    }

    pub fn init_cpu_msrs(fd: &VcpuFd) -> Result<()> {
        let kvm_msrs_entry = vec![kvm_msr_entry {
            index: MSR_IA32_MISC_ENABLE,
            data: MSR_IA32_MISC_ENABLE_FAST_STRING,
            ..Default::default()
        }];
        let kvm_msrs_wrapper = Msrs::from_entries(&kvm_msrs_entry).unwrap();
        fd.set_msrs(&kvm_msrs_wrapper)
            .map_err(|e| Error::new(e.errno()))?;
        Ok(())
    }

    pub fn init_cpu_regs(fd: &VcpuFd) -> Result<()> {
        let mut sregs = fd.get_sregs().map_err(|e| Error::new(e.errno()))?;
        SETUP_SEGMENT_REGS!(sregs, cs);
        SETUP_SEGMENT_REGS!(sregs, ds);
        SETUP_SEGMENT_REGS!(sregs, fs);
        SETUP_SEGMENT_REGS!(sregs, gs);
        SETUP_SEGMENT_REGS!(sregs, es);
        SETUP_SEGMENT_REGS!(sregs, ss);

        sregs.cs.db = 1;
        sregs.ss.db = 1;
        sregs.cr0 |= 1; // enable protected mode

        fd.set_sregs(&sregs).map_err(|e| Error::new(e.errno()))?;

        let mut regs = fd.get_regs().map_err(|e| Error::new(e.errno()))?;
        regs.rflags = 2;
        regs.rsp = BOOT_STACK_POINTER;
        regs.rip = HIGH_RAM_START.0;
        regs.rsi = ZERO_PAGE_START.0;

        fd.set_regs(&regs).map_err(|e| Error::new(e.errno()))?;

        Ok(())
    }

    pub fn run(&mut self) -> Result<VcpuExit> {
        let res = self.fd.run().map_err(|e| Error::new(e.errno()))?;
        Ok(res)
    }

    pub fn set_immediate_exit(&mut self, exit: bool) {
        self.fd.set_kvm_immediate_exit(exit.into());
    }
}

/// A trait for checking hypervisor capabilities.
pub trait Hypervisor: Send {
    /// Makes a shallow clone of this `Hypervisor`.
    fn try_clone(&self) -> Result<Self>
    where
        Self: Sized;
    /// Get the system supported CPUID values.
    fn get_supported_cpuid(&self) -> Result<CpuId>;

    /// Get the system emulated CPUID values.
    fn get_emulated_cpuid(&self) -> Result<CpuId>;

    /// Gets the list of supported MSRs.
    fn get_msr_index_list(&self) -> Result<MsrList>;
}

/// A wrapper for using a VM and getting/setting its state.
pub trait Vm: Send {
    type G: GuestMemory + Send;
    /// Makes a shallow clone of this `Vm`.
    fn try_clone(&self) -> Result<Self>
    where
        Self: Sized;

    /// Get the guest physical address size in bits.
    fn get_guest_phys_addr_bits(&self) -> u8;

    /// Gets the guest-mapped memory for the Vm.
    fn get_memory_lock(&self) -> MutexGuard<Self::G>;

    /// Registers an event to be signaled whenever a certain address is written to.
    ///
    /// The `datamatch` parameter can be used to limit signaling `evt` to only the cases where the
    /// value being written is equal to `datamatch`. Note that the size of `datamatch` is important
    /// and must match the expected size of the guest's write.
    ///
    /// In all cases where `evt` is signaled, the ordinary vmexit to userspace that would be
    /// triggered is prevented.
    fn register_ioevent<D: Into<u64>>(
        &mut self,
        evt: &EventFd,
        addr: IoEventAddress,
        datamatch: D,
    ) -> Result<()>;

    /// Unregisters an event previously registered with `register_ioevent`.
    ///
    /// The `evt`, `addr`, and `datamatch` set must be the same as the ones passed into
    /// `register_ioevent`.
    fn unregister_ioevent<D: Into<u64>>(
        &mut self,
        evt: &EventFd,
        addr: IoEventAddress,
        datamatch: D,
    ) -> Result<()>;

    fn get_hypervisor(&self) -> &dyn Hypervisor;

    /// Create a Vcpu with the specified Vcpu ID.
    fn create_vcpu(&self, id: u64) -> Result<Vcpu<Self::G>>;

    /// Sets the address of the three-page region in the VM's address space.
    fn set_tss_addr(&self, addr: GuestAddress) -> Result<()>;

    /// Sets the address of a one-page region in the VM's address space.
    fn set_identity_map_addr(&self, addr: GuestAddress) -> Result<()>;
}
