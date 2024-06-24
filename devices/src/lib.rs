mod bus;
pub use bus::Bus;
pub use bus::BusAccessInfo;
pub use bus::BusDevice;
pub use bus::BusRange;
pub use bus::BusType;
pub use bus::DeviceId;
pub use bus::Error as BusError;

pub mod irqchip;

mod irq_event;

mod serial;
pub mod serial_device;
pub mod virtio;
pub use irq_event::*;

pub use serial::Serial;
pub use serial_device::Error as SerialError;
pub use serial_device::SerialHardware;
pub use serial_device::SerialType;

/// Address for Serial ports in x86
pub const SERIAL_ADDR: [u64; 4] = [0x3f8, 0x2f8, 0x3e8, 0x2e8];
