use base::errno_result;
use base::vec_with_array_field;
use base::Error;
use base::Result;
use kvm_bindings::kvm_irq_routing;
use kvm_bindings::kvm_irq_routing_entry;
use kvm_bindings::kvm_irq_routing_irqchip;
use kvm_bindings::kvm_pit_config;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_bindings::MsrList;
use kvm_bindings::KVM_IRQCHIP_IOAPIC;
use kvm_bindings::KVM_IRQCHIP_PIC_MASTER;
use kvm_bindings::KVM_IRQCHIP_PIC_SLAVE;
use kvm_bindings::{
    kvm_irq_routing_entry__bindgen_ty_1, kvm_irq_routing_msi, KVM_IRQ_ROUTING_IRQCHIP,
    KVM_IRQ_ROUTING_MSI,
};
use kvm_ioctls::IoEventAddress;
use kvm_ioctls::{Kvm, VmFd};
use std::arch::x86_64::__cpuid;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::sync::Arc;
use std::sync::MutexGuard;
use sync::Mutex;
use vm_memory::GuestAddress;
use vm_memory::GuestMemory;
use vm_memory::GuestMemoryRegion;
use vmm_sys_util::eventfd::EventFd;

use super::IrqRoute;
use super::IrqSource;
use super::IrqSourceChip;
use crate::Hypervisor;
use crate::Vcpu;
use crate::Vm;

const KVM_MAX_CPUID_ENTRIES: usize = 80;
/// Number of pins on the standard KVM/IOAPIC.
pub const NUM_IOAPIC_PINS: usize = 24;

/// Gets host cpu max physical address bits.
pub(crate) fn host_phys_addr_bits() -> u8 {
    // SAFETY: trivially safe
    let highest_ext_function = unsafe { __cpuid(0x80000000) };
    if highest_ext_function.eax >= 0x80000008 {
        // SAFETY: trivially safe
        let addr_size = unsafe { __cpuid(0x80000008) };
        // Low 8 bits of 0x80000008 leaf: host physical address size in bits.
        addr_size.eax as u8
    } else {
        36
    }
}

// This function translates an IrqSrouceChip to the kvm u32 equivalent. It has a different
// implementation between x86_64 and aarch64 because the irqchip KVM constants are not defined on
// all architectures.
pub(super) fn chip_to_kvm_chip(chip: IrqSourceChip) -> u32 {
    match chip {
        IrqSourceChip::PicPrimary => KVM_IRQCHIP_PIC_MASTER,
        IrqSourceChip::PicSecondary => KVM_IRQCHIP_PIC_SLAVE,
        IrqSourceChip::Ioapic => KVM_IRQCHIP_IOAPIC,
    }
}

impl From<&IrqRoute> for kvm_irq_routing_entry {
    fn from(item: &IrqRoute) -> Self {
        match &item.source {
            IrqSource::Irqchip { chip, pin } => kvm_irq_routing_entry {
                gsi: item.gsi,
                type_: KVM_IRQ_ROUTING_IRQCHIP,
                u: kvm_irq_routing_entry__bindgen_ty_1 {
                    irqchip: kvm_irq_routing_irqchip {
                        irqchip: chip_to_kvm_chip(*chip),
                        pin: *pin,
                    },
                },
                ..Default::default()
            },
            IrqSource::Msi { address, data } => kvm_irq_routing_entry {
                gsi: item.gsi,
                type_: KVM_IRQ_ROUTING_MSI,
                u: kvm_irq_routing_entry__bindgen_ty_1 {
                    msi: kvm_irq_routing_msi {
                        address_lo: *address as u32,
                        address_hi: (*address >> 32) as u32,
                        data: *data,
                        ..Default::default()
                    },
                },
                ..Default::default()
            },
        }
    }
}

pub struct KvmVm<T: GuestMemory + Send> {
    kvm: Kvm,
    vm_fd: VmFd,
    memory: Arc<Mutex<T>>,
}

impl Hypervisor for Kvm {
    fn try_clone(&self) -> Result<Self>
    where
        Self: Sized,
    {
        let kvm_clone_fd = unsafe { libc::fcntl(self.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if kvm_clone_fd < 0 {
            return errno_result();
        }

        let kvm_clone = unsafe { Kvm::from_raw_fd(kvm_clone_fd) };
        Ok(kvm_clone)
    }

    fn get_supported_cpuid(&self) -> Result<kvm_bindings::CpuId> {
        self.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| Error::new(e.errno()))
    }

    fn get_emulated_cpuid(&self) -> Result<kvm_bindings::CpuId> {
        self.get_emulated_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| Error::new(e.errno()))
    }

    fn get_msr_index_list(&self) -> Result<MsrList> {
        self.get_msr_index_list().map_err(|e| Error::new(e.errno()))
    }
}

impl<T: GuestMemory + Send> KvmVm<T> {
    pub fn new(mem: T) -> Result<KvmVm<T>> {
        let kvm = Kvm::new().map_err(|e| Error::new(e.errno()))?;
        let vm_fd = kvm.create_vm().map_err(|e| Error::new(e.errno()))?;

        for m in mem.iter().enumerate() {
            let host_addr = mem.get_host_address(m.1.start_addr()).unwrap() as u64;
            let user_memory_region = kvm_userspace_memory_region {
                slot: m.0 as u32,
                flags: 0,
                guest_phys_addr: m.1.start_addr().0,
                memory_size: m.1.len(),
                userspace_addr: host_addr,
            };
            unsafe {
                vm_fd
                    .set_user_memory_region(user_memory_region)
                    .map_err(|e| Error::new(e.errno()))?;
            }
        }

        let vm = Self {
            kvm,
            vm_fd,
            memory: Arc::new(Mutex::new(mem)),
        };

        vm.init_arch()?;
        Ok(vm)
    }

    /// Does platform specific initialization for the KvmVm.
    pub fn init_arch(&self) -> Result<()> {
        Ok(())
    }

    /// Retrieves the number of pins for emulated IO-APIC.
    pub fn get_ioapic_num_pins(&self) -> Result<usize> {
        Ok(NUM_IOAPIC_PINS)
    }

    /// Creates an in kernel interrupt controller.
    ///
    /// See the documentation on the KVM_CREATE_IRQCHIP ioctl.
    pub fn create_irq_chip(&self) -> Result<()> {
        self.vm_fd
            .create_irq_chip()
            .map_err(|e| Error::new(e.errno()))
    }

    /// Creates a PIT as per the KVM_CREATE_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    pub fn create_pit(&self) -> Result<()> {
        let pit_config = kvm_pit_config::default();
        self.vm_fd
            .create_pit2(pit_config)
            .map_err(|e| Error::new(e.errno()))
    }

    /// Sets the level on the given irq to 1 if `active` is true, and 0 otherwise.
    pub fn set_irq_line(&self, irq: u32, active: bool) -> Result<()> {
        self.vm_fd
            .set_irq_line(irq, active)
            .map_err(|e| Error::new(e.errno()))
    }

    /// Registers an event that will, when signalled, trigger the `gsi` irq, and `resample_evt`
    /// ( when not None ) will be triggered when the irqchip is resampled.
    pub fn register_irqfd(
        &self,
        gsi: u32,
        evt: &EventFd,
        resample_evt: Option<&EventFd>,
    ) -> Result<()> {
        if let Some(resample) = resample_evt {
            self.vm_fd
                .register_irqfd_with_resample(evt, resample, gsi)
                .map_err(|e| Error::new(e.errno()))
        } else {
            self.vm_fd
                .register_irqfd(evt, gsi)
                .map_err(|e| Error::new(e.errno()))
        }
    }

    /// Unregisters an event that was previously registered with
    /// `register_irqfd`.
    ///
    /// The `evt` and `gsi` pair must be the same as the ones passed into
    /// `register_irqfd`.
    pub fn unregister_irqfd(&self, gsi: u32, evt: &EventFd) -> Result<()> {
        self.vm_fd
            .unregister_irqfd(evt, gsi)
            .map_err(|e| Error::new(e.errno()))
    }

    /// Sets the GSI routing table, replacing any table set with previous calls to
    /// `set_gsi_routing`.
    pub fn set_gsi_routing(&self, routes: &[IrqRoute]) -> Result<()> {
        let mut irq_routing =
            vec_with_array_field::<kvm_irq_routing, kvm_irq_routing_entry>(routes.len());
        irq_routing[0].nr = routes.len() as u32;

        // SAFETY:
        // Safe because we ensured there is enough space in irq_routing to hold the number of
        // route entries.
        let irq_routes = unsafe { irq_routing[0].entries.as_mut_slice(routes.len()) };
        for (route, irq_route) in routes.iter().zip(irq_routes.iter_mut()) {
            *irq_route = kvm_irq_routing_entry::from(route);
        }

        self.vm_fd
            .set_gsi_routing(&irq_routing[0])
            .map_err(|e| Error::new(e.errno()))
    }

    pub fn register_ioeventfd<D: Into<u64>>(
        &self,
        evt: &EventFd,
        addr: IoEventAddress,
        datamatch: D,
    ) -> Result<()> {
        self.vm_fd
            .register_ioevent(evt, &addr, datamatch)
            .map_err(|e| Error::new(e.errno()))
    }

    pub fn unregister_ioeventfd<D: Into<u64>>(
        &self,
        evt: &EventFd,
        addr: IoEventAddress,
        datamatch: D,
    ) -> Result<()> {
        self.vm_fd
            .unregister_ioevent(evt, &addr, datamatch)
            .map_err(|e| Error::new(e.errno()))
    }
}

impl<T: GuestMemory + Send> Vm for KvmVm<T> {
    type G = T;
    fn try_clone(&self) -> Result<Self>
    where
        Self: Sized,
    {
        let kvm_clone = self.kvm.try_clone()?;

        let vm_clone_fd = unsafe { libc::fcntl(self.vm_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if vm_clone_fd < 0 {
            return errno_result();
        }

        let vm_clone = unsafe {
            kvm_clone
                .create_vmfd_from_rawfd(vm_clone_fd)
                .map_err(|e| Error::new(e.errno()))?
        };

        Ok(Self {
            kvm: kvm_clone,
            vm_fd: vm_clone,
            memory: Arc::clone(&self.memory),
        })
    }

    fn get_guest_phys_addr_bits(&self) -> u8 {
        host_phys_addr_bits()
    }

    /// Gets the guest-mapped memory for the Vm.
    fn get_memory_lock(&self) -> MutexGuard<'_, T> {
        self.memory.lock()
    }

    fn register_ioevent<D: Into<u64>>(
        &mut self,
        evt: &EventFd,
        addr: IoEventAddress,
        datamatch: D,
    ) -> Result<()> {
        self.register_ioeventfd(evt, addr, datamatch)
    }

    fn unregister_ioevent<D: Into<u64>>(
        &mut self,
        evt: &EventFd,
        addr: IoEventAddress,
        datamatch: D,
    ) -> Result<()> {
        self.unregister_ioeventfd(evt, addr, datamatch)
    }

    fn get_hypervisor(&self) -> &dyn Hypervisor {
        &self.kvm
    }

    /// Create a Vcpu with the specified Vcpu ID.
    fn create_vcpu(&self, id: u64) -> Result<Vcpu<T>> {
        let vcpu_fd = self
            .vm_fd
            .create_vcpu(id)
            .map_err(|e| Error::new(e.errno()))?;
        let kvm_cloned = self.try_clone()?;
        Vcpu::new(vcpu_fd, kvm_cloned, id as u32)
    }

    fn set_tss_addr(&self, addr: GuestAddress) -> Result<()> {
        self.vm_fd
            .set_tss_address(addr.0 as usize)
            .map_err(|e| Error::new(e.errno()))
    }

    fn set_identity_map_addr(&self, addr: GuestAddress) -> Result<()> {
        self.vm_fd
            .set_identity_map_address(addr.0)
            .map_err(|e| Error::new(e.errno()))
    }
}
