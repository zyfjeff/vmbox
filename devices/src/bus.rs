use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt, result,
    sync::Arc,
};

use sync::Mutex;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Bus Range not found")]
    Empty,
    /// The insertion failed because the new device overlapped with an old device.
    #[error("new device {base},{len} overlaps with an old device {other_base},{other_len}")]
    Overlap {
        base: u64,
        len: u64,
        other_base: u64,
        other_len: u64,
    },
}

pub type Result<T> = result::Result<T, Error>;

/// Information about how a device was accessed.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct BusAccessInfo {
    /// Offset from base address that the device was accessed at.
    pub offset: u64,
    /// Absolute address of the device's access in its address space.
    pub address: u64,
    /// ID of the entity requesting a device access, usually the VCPU id.
    pub id: usize,
}

// Implement `Display` for `MinMax`.
impl std::fmt::Display for BusAccessInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BusType {
    Mmio,
    Io,
}

/// Holds a base and length representing the address space occupied by a `BusDevice`.
///
/// * base - The address at which the range start.
/// * len - The length of the range in bytes.
#[derive(Copy, Clone)]
pub struct BusRange {
    pub base: u64,
    pub len: u64,
}

impl BusRange {
    /// Returns true if `addr` is within the range.
    pub fn contains(&self, addr: u64) -> bool {
        self.base <= addr && addr < self.base.saturating_add(self.len)
    }

    /// Returns true if there is overlap with the given range.
    pub fn overlaps(&self, base: u64, len: u64) -> bool {
        self.base < base.saturating_add(len) && base < self.base.saturating_add(self.len)
    }
}

impl Eq for BusRange {}

impl PartialEq for BusRange {
    fn eq(&self, other: &BusRange) -> bool {
        self.base == other.base
    }
}

impl Ord for BusRange {
    fn cmp(&self, other: &BusRange) -> Ordering {
        self.base.cmp(&other.base)
    }
}

impl PartialOrd for BusRange {
    fn partial_cmp(&self, other: &BusRange) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Debug for BusRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}..+{:#x}", self.base, self.len)
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PlatformDeviceId {
    Pit = 1,
    Pic = 2,
    Ioapic = 3,
    Serial = 4,
    Cmos = 5,
    I8042 = 6,
    Pl030 = 7,
}

/// A wrapper structure for pci device and vendor id.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PciId {
    vendor_id: u16,
    device_id: u16,
}

impl PciId {
    pub fn new(vendor_id: u16, device_id: u16) -> Self {
        Self {
            vendor_id,
            device_id,
        }
    }
}

impl From<PciId> for u32 {
    fn from(pci_id: PciId) -> Self {
        // vendor ID is the lower 16 bits and device id is the upper 16 bits
        pci_id.vendor_id as u32 | (pci_id.device_id as u32) << 16
    }
}

impl From<u32> for PciId {
    fn from(value: u32) -> Self {
        let vendor_id = (value & 0xFFFF) as u16;
        let device_id = (value >> 16) as u16;
        Self::new(vendor_id, device_id)
    }
}

impl From<PlatformDeviceId> for DeviceId {
    fn from(v: PlatformDeviceId) -> Self {
        Self::PlatformDeviceId(v)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DeviceId {
    /// PCI Device, use its PciId directly.
    PciDeviceId(PciId),
    /// Platform device, use a unique Id.
    PlatformDeviceId(PlatformDeviceId),
}

impl TryFrom<u16> for PlatformDeviceId {
    type Error = base::Error;

    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            1 => Ok(PlatformDeviceId::Pit),
            2 => Ok(PlatformDeviceId::Pic),
            3 => Ok(PlatformDeviceId::Ioapic),
            4 => Ok(PlatformDeviceId::Serial),
            5 => Ok(PlatformDeviceId::Cmos),
            6 => Ok(PlatformDeviceId::I8042),
            7 => Ok(PlatformDeviceId::Pl030),
            _ => Err(base::Error::new(libc::EINVAL)),
        }
    }
}

impl TryFrom<u32> for DeviceId {
    type Error = base::Error;

    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        let device_id = (value & 0xFFFF) as u16;
        let vendor_id = ((value & 0xFFFF_0000) >> 16) as u16;
        if vendor_id == 0xFFFF {
            Ok(DeviceId::PlatformDeviceId(PlatformDeviceId::try_from(
                device_id,
            )?))
        } else {
            Ok(DeviceId::PciDeviceId(PciId::new(vendor_id, device_id)))
        }
    }
}

impl From<DeviceId> for u32 {
    fn from(id: DeviceId) -> Self {
        match id {
            DeviceId::PciDeviceId(pci_id) => pci_id.into(),
            DeviceId::PlatformDeviceId(id) => 0xFFFF0000 | id as u32,
        }
    }
}

/// Trait for devices that respond to reads or writes in an arbitrary address space.
///
/// The device does not care where it exists in address space as each method is only given an offset
/// into its allocated portion of address space.
#[allow(unused_variables)]
pub trait BusDevice: Send {
    /// Returns a label suitable for debug output.
    fn debug_label(&self) -> String;
    /// Returns a unique id per device type suitable for metrics gathering.
    fn device_id(&self) -> DeviceId;
    /// Reads at `offset` from this device
    fn read(&mut self, offset: BusAccessInfo, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&mut self, offset: BusAccessInfo, data: &[u8]) {}

    /// Gets a list of all ranges registered by this BusDevice.
    fn get_ranges(&self) -> Vec<(BusRange, BusType)> {
        Vec::new()
    }
    /// Invoked when the device is destroyed
    fn destroy_device(&mut self) {}
}

#[derive(Clone)]
struct BusEntry {
    device: BusDeviceEntry,
}

#[derive(Clone)]
enum BusDeviceEntry {
    OuterSync(Arc<Mutex<dyn BusDevice>>),
}

/// A device container for routing reads and writes over some address space.
///
/// This doesn't have any restrictions on what kind of device or address space this applies to. The
/// only restriction is that no two devices can overlap in this address space.
#[derive(Clone)]
pub struct Bus {
    devices: Arc<Mutex<BTreeMap<BusRange, BusEntry>>>,
    access_id: usize,
    bus_type: BusType,
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new(bus_type: BusType) -> Bus {
        Bus {
            devices: Arc::new(Mutex::new(BTreeMap::new())),
            access_id: 0,
            bus_type,
        }
    }

    /// Gets the bus type
    pub fn get_bus_type(&self) -> BusType {
        self.bus_type
    }

    /// Sets the id that will be used for BusAccessInfo.
    pub fn set_access_id(&mut self, id: usize) {
        self.access_id = id;
    }

    fn first_before(&self, addr: u64) -> Option<(BusRange, BusEntry)> {
        let devices = self.devices.lock();
        let (range, entry) = devices
            .range(..=BusRange { base: addr, len: 1 })
            .next_back()?;
        Some((*range, entry.clone()))
    }

    fn get_device(&self, addr: u64) -> Option<(u64, u64, BusEntry)> {
        if let Some((range, entry)) = self.first_before(addr) {
            let offset = addr - range.base;
            if offset < range.len {
                return Some((offset, addr, entry));
            }
        }
        None
    }

    /// There is no unique ID for device instances. For now we use the Arc pointers to dedup them.
    ///
    /// See virtio-gpu for an example of a single device instance with multiple bus entries.
    ///
    /// TODO: Add a unique ID to BusDevice and use that instead of pointers.
    fn unique_devices(&self) -> Vec<BusDeviceEntry> {
        let mut seen_ptrs = BTreeSet::new();
        self.devices
            .lock()
            .iter()
            .map(|(_, bus_entry)| bus_entry.device.clone())
            .filter(|dev| match dev {
                BusDeviceEntry::OuterSync(dev) => seen_ptrs.insert(Arc::as_ptr(dev) as *const u8),
            })
            .collect()
    }

    /// Puts the given device at the given address space.
    pub fn insert(&self, device: Arc<Mutex<dyn BusDevice>>, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::Overlap {
                base,
                len,
                other_base: 0,
                other_len: 0,
            });
        }

        // Reject all cases where the new device's range overlaps with an existing device.
        let mut devices = self.devices.lock();
        devices.iter().try_for_each(|(range, _dev)| {
            if range.overlaps(base, len) {
                Err(Error::Overlap {
                    base,
                    len,
                    other_base: range.base,
                    other_len: range.len,
                })
            } else {
                Ok(())
            }
        })?;

        if devices
            .insert(
                BusRange { base, len },
                BusEntry {
                    device: BusDeviceEntry::OuterSync(device),
                },
            )
            .is_some()
        {
            return Err(Error::Overlap {
                base,
                len,
                other_base: base,
                other_len: len,
            });
        }

        Ok(())
    }

    /// Remove the given device at the given address space.
    pub fn remove(&self, base: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::Overlap {
                base,
                len,
                other_base: 0,
                other_len: 0,
            });
        }

        let mut devices = self.devices.lock();
        if devices
            .iter()
            .any(|(range, _dev)| range.base == base && range.len == len)
        {
            let ret = devices.remove(&BusRange { base, len });
            if ret.is_some() {
                Ok(())
            } else {
                Err(Error::Empty)
            }
        } else {
            Err(Error::Empty)
        }
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> bool {
        if let Some((offset, address, entry)) = self.get_device(addr) {
            let io = BusAccessInfo {
                address,
                offset,
                id: self.access_id,
            };

            match &entry.device {
                BusDeviceEntry::OuterSync(dev) => dev.lock().read(io, data),
            }
            true
        } else {
            false
        }
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, addr: u64, data: &[u8]) -> bool {
        if let Some((offset, address, entry)) = self.get_device(addr) {
            let io = BusAccessInfo {
                address,
                offset,
                id: self.access_id,
            };

            match &entry.device {
                BusDeviceEntry::OuterSync(dev) => dev.lock().write(io, data),
            }
            true
        } else {
            false
        }
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new(BusType::Io)
    }
}
