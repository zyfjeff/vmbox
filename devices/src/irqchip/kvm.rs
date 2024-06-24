use std::sync::Arc;

use base::Result;
use hypervisor::{KvmVm, Vm};
use sync::Mutex;
use vm_memory::GuestMemory;

use super::IrqChip;
use hypervisor::IrqRoute;
use hypervisor::IrqSourceChip;

/// Default x86 routing table.  Pins 0-7 go to primary pic and ioapic, pins 8-15 go to secondary
/// pic and ioapic, and pins 16-23 go only to the ioapic.
fn kvm_default_irq_routing_table(ioapic_pins: usize) -> Vec<IrqRoute> {
    let mut routes: Vec<IrqRoute> = Vec::new();

    for i in 0..8 {
        routes.push(IrqRoute::pic_irq_route(IrqSourceChip::PicPrimary, i));
        routes.push(IrqRoute::ioapic_irq_route(i));
    }
    for i in 8..16 {
        routes.push(IrqRoute::pic_irq_route(IrqSourceChip::PicSecondary, i));
        routes.push(IrqRoute::ioapic_irq_route(i));
    }
    for i in 16..ioapic_pins as u32 {
        routes.push(IrqRoute::ioapic_irq_route(i));
    }

    routes
}

pub struct KvmKernelIrqChip<T: GuestMemory + Send> {
    pub(super) vm: KvmVm<T>,
    pub(super) routes: Arc<Mutex<Vec<IrqRoute>>>,
}

impl<T: GuestMemory + Send> KvmKernelIrqChip<T> {
    /// Construct a new KvmKernelIrqchip.
    pub fn new(vm: KvmVm<T>) -> Result<KvmKernelIrqChip<T>> {
        vm.create_irq_chip()?;
        vm.create_pit()?;
        let ioapic_pins = vm.get_ioapic_num_pins()?;

        Ok(KvmKernelIrqChip {
            vm,
            routes: Arc::new(Mutex::new(kvm_default_irq_routing_table(ioapic_pins))),
        })
    }
}

impl<T: GuestMemory + Send> IrqChip for KvmKernelIrqChip<T> {
    fn register_edge_irq_event(
        &mut self,
        irq: u32,
        irq_event: &crate::irq_event::IrqEdgeEvent,
        _source: super::IrqEventSource,
    ) -> base::Result<Option<super::IrqEventIndex>> {
        self.vm.register_irqfd(irq, irq_event.get_trigger(), None)?;
        Ok(None)
    }

    fn unregister_edge_irq_event(
        &mut self,
        irq: u32,
        irq_event: &crate::irq_event::IrqEdgeEvent,
    ) -> base::Result<()> {
        self.vm.unregister_irqfd(irq, irq_event.get_trigger())
    }

    fn register_level_irq_event(
        &mut self,
        irq: u32,
        irq_event: &crate::irq_event::IrqLevelEvent,
        _source: super::IrqEventSource,
    ) -> base::Result<Option<super::IrqEventIndex>> {
        self.vm
            .register_irqfd(irq, irq_event.get_trigger(), Some(irq_event.get_resample()))?;
        Ok(None)
    }

    fn unregister_level_irq_event(
        &mut self,
        irq: u32,
        irq_event: &crate::irq_event::IrqLevelEvent,
    ) -> base::Result<()> {
        self.vm.unregister_irqfd(irq, irq_event.get_trigger())
    }

    fn try_clone(&self) -> base::Result<Self>
    where
        Self: Sized,
    {
        let vm = self.vm.try_clone()?;
        let routes = Arc::clone(&self.routes);

        Ok(Self { vm, routes })
    }

    fn service_irq(&mut self, irq: u32, level: bool) -> Result<()> {
        self.vm.set_irq_line(irq, level)
    }

    fn route_irq(&mut self, route: IrqRoute) -> Result<()> {
        let mut routes = self.routes.lock();
        routes.retain(|r| r.gsi != route.gsi);

        routes.push(route);

        self.vm.set_gsi_routing(&routes)
    }
}
