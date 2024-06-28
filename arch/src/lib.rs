mod layout;

pub use layout::*;
use vm_memory::GuestAddress;

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemory structure for the platform.
/// For x86_64 all addresses are valid from the start of the kernel except a
/// carve out at the end of 32bit address space.
pub fn arch_memory_regions(size: u64) -> Vec<(GuestAddress, usize)> {
    let mem_start = START_OF_RAM_32BITS;
    let mem_end = GuestAddress(size + mem_start);

    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(PCI_MMIO_START);

    let mut regions = Vec::new();
    if mem_end <= end_32bit_gap_start {
        regions.push((GuestAddress(mem_start), size as usize));
    } else {
        regions.push((
            GuestAddress(mem_start),
            (end_32bit_gap_start.0 - mem_start) as usize,
        ));
        regions.push((
            first_addr_past_32bits,
            (mem_end.0 - end_32bit_gap_start.0) as usize,
        ));
    }

    regions
}
