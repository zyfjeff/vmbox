use base::Result;
use hypervisor::IrqRoute;

use crate::irq_event::IrqLevelEvent;
use crate::{irq_event::IrqEdgeEvent, BusDevice, DeviceId};

mod kvm;

pub use kvm::KvmKernelIrqChip;

pub type IrqEventIndex = usize;

/// Identification information about the source of an IrqEvent
#[derive(Clone, Debug)]
pub struct IrqEventSource {
    pub device_id: DeviceId,
    pub queue_id: usize,
    pub device_name: String,
}

impl IrqEventSource {
    pub fn from_device(device: &dyn BusDevice) -> Self {
        Self {
            device_id: device.device_id(),
            queue_id: 0,
            device_name: device.debug_label(),
        }
    }
}

/// Trait that abstracts interactions with interrupt controllers.
///
/// Each VM will have one IrqChip instance which is responsible for routing IRQ lines and
/// registering IRQ events. Depending on the implementation, the IrqChip may interact with an
/// underlying hypervisor API or emulate devices in userspace.
///
/// This trait is generic over a Vcpu type because some IrqChip implementations can support
/// multiple hypervisors with a single implementation.
pub trait IrqChip: Send {
    /// Register an event with edge-trigger semantic that can trigger an interrupt for a particular
    /// GSI.
    fn register_edge_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqEdgeEvent,
        source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>>;

    /// Unregister an event with edge-trigger semantic for a particular GSI.
    fn unregister_edge_irq_event(&mut self, irq: u32, irq_event: &IrqEdgeEvent) -> Result<()>;

    /// Register an event with level-trigger semantic that can trigger an interrupt for a particular
    /// GSI.
    fn register_level_irq_event(
        &mut self,
        irq: u32,
        irq_event: &IrqLevelEvent,
        source: IrqEventSource,
    ) -> Result<Option<IrqEventIndex>>;

    /// Unregister an event with level-trigger semantic for a particular GSI.
    fn unregister_level_irq_event(&mut self, irq: u32, irq_event: &IrqLevelEvent) -> Result<()>;

    /// Either assert or deassert an IRQ line.  Sends to either an interrupt controller, or does
    /// a send_msi if the irq is associated with an MSI.
    fn service_irq(&mut self, irq: u32, level: bool) -> Result<()>;

    /// Route an IRQ line to an interrupt controller, or to a particular MSI vector.
    fn route_irq(&mut self, route: IrqRoute) -> Result<()>;

    /// Attempt to create a shallow clone of this IrqChip instance.
    fn try_clone(&self) -> Result<Self>
    where
        Self: Sized;
}
