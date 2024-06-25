mod layout;

pub use layout::*;
use vm_memory::{Address, GuestAddress};

/// Type for memory region types.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegionType {
    /// RAM type
    Ram,

    /// SubRegion memory region.
    /// A SubRegion is a memory region sub-region, allowing for a region
    /// to be split into sub regions managed separately.
    /// For example, the x86 32-bit memory hole is a SubRegion.
    SubRegion,

    /// Reserved type.
    /// A Reserved memory region is one that should not be used for memory
    /// allocation. This type can be used to prevent the VMM from allocating
    /// memory ranges in a specific address range.
    Reserved,
}

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemory structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions() -> Vec<(GuestAddress, usize, RegionType)> {
    vec![
        // 0 GiB ~ 3GiB: memory before the gap
        (
            GuestAddress(0),
            layout::MEM_32BIT_RESERVED_START.0 as usize,
            RegionType::Ram,
        ),
        // 4 GiB ~ inf: memory after the gap
        (layout::RAM_64BIT_START, usize::MAX, RegionType::Ram),
        // 3 GiB ~ 3712 MiB: 32-bit device memory hole
        (
            layout::MEM_32BIT_RESERVED_START,
            layout::MEM_32BIT_DEVICES_SIZE as usize,
            RegionType::SubRegion,
        ),
        // 3712 MiB ~ 3968 MiB: 32-bit reserved memory hole
        (
            layout::MEM_32BIT_RESERVED_START.unchecked_add(layout::MEM_32BIT_DEVICES_SIZE),
            (layout::MEM_32BIT_RESERVED_SIZE - layout::MEM_32BIT_DEVICES_SIZE) as usize,
            RegionType::Reserved,
        ),
    ]
}