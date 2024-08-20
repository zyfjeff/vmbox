use base::Result;
use devices::Bus;
use hypervisor::Vcpu;
use kvm_bindings::{KVM_SYSTEM_EVENT_CRASH, KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN};
use kvm_ioctls::VcpuExit;
use log::{error, info, warn};
use std::{
    sync::Arc,
    thread::{self, JoinHandle},
};
use vm_memory::GuestMemory;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ExitState {
    Reset,
    Stop,
    Crash,
}

pub fn run_vcpu<T: GuestMemory + Send + 'static>(
    vcpu: Vcpu<T>,
    io_bus: Arc<Bus>,
) -> Result<JoinHandle<()>> {
    let apic_id = vcpu.get_apic_id().clone();
    let res = thread::Builder::new()
        .name(format!("vmbox_vcpu_{}", apic_id))
        .spawn(move || {
            let exit_state = vcpu_loop(vcpu, io_bus);
            error!("unexpect vcpu exit: {:?}", exit_state);
        })?;
    Ok(res)
}

pub fn vcpu_loop<T: GuestMemory + Send>(vcpu: Vcpu<T>, io_bus: Arc<Bus>) -> ExitState {
    let mut interrupted_by_signal = false;
    let mut vcpu = vcpu;
    loop {
        if !interrupted_by_signal {
            match vcpu.run() {
                Ok(VcpuExit::IoIn(addr, data)) => {
                    if !io_bus.read(addr as u64, data) {
                        //error!("failed to handle read io: {:?}, data: {:?}", addr, data);
                    }
                }
                Ok(VcpuExit::IoOut(addr, data)) => {
                    if !io_bus.write(addr as u64, data) {
                        //error!("failed to handle write io: {:?}", addr);
                    }
                }
                Ok(VcpuExit::MmioRead(addr, data)) => {
                    if !io_bus.read(addr, data) {
                        error!("failed to handle mmio read: {:?}", addr);
                    }
                }
                Ok(VcpuExit::MmioWrite(addr, data)) => {
                    if !io_bus.write(addr, data) {
                        error!("failed to handle mmio write: {:?}", addr);
                    }
                }
                Ok(VcpuExit::Shutdown) => {
                    return ExitState::Stop;
                }
                Ok(VcpuExit::FailEntry(harde_reason, cpu)) => {
                    error!("vcpu hw run failure: {:#x}, cpu: {}", harde_reason, cpu);
                    return ExitState::Crash;
                }
                Ok(VcpuExit::SystemEvent(ty, data)) => {
                    info!("system event type: {} data: {:?}", ty, data);
                    match ty {
                        KVM_SYSTEM_EVENT_CRASH => return ExitState::Crash,
                        KVM_SYSTEM_EVENT_RESET => return ExitState::Reset,
                        KVM_SYSTEM_EVENT_SHUTDOWN => return ExitState::Stop,
                        _ => {
                            warn!("unknow system event");
                        }
                    }
                }
                Ok(exit_state) => {
                    info!("unhanle exit_state: {:?}", exit_state);
                }
                Err(e) => match e.errno() {
                    libc::EINTR => interrupted_by_signal = true,
                    libc::EAGAIN => {}
                    _ => {
                        error!("vcpu hit unknown error: {}", e);
                        return ExitState::Crash;
                    }
                },
            }
        }

        if interrupted_by_signal {
            vcpu.set_immediate_exit(false);
        }
    }
}
