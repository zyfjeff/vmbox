use vm_memory::GuestAddress;

// TODO(tinqian.zyf): 为啥是这两个地址
// TSS后面跟着Identify map、TSS的大小是 3 * 4KB
// Identify map 的大小是4K
pub const TSS_ADDRESS: GuestAddress = GuestAddress(0xfffbd000);
pub const TSS_ADDRESS_END: GuestAddress = GuestAddress(0xfffbd000 + 0x3000);
pub const IDENTIFY_MAP_ADDR: GuestAddress = GuestAddress(0xffffc000);

// MPTABLE, describing VCPUS.
pub const MPTABLE_START: GuestAddress = GuestAddress(0x9fc00);

/// The 'zero page', a.k.a linux kernel bootparams.
pub const ZERO_PAGE_START: GuestAddress = GuestAddress(0x7000);

pub const CMDLINE_START: GuestAddress = GuestAddress(0x20000);

/// Kernel command line start address maximum size.
pub const CMDLINE_MAX_SIZE: usize = 0x10000;

pub const BOOT_STACK_POINTER: u64 = 0x8000;

// ** High RAM (start: 1MiB, length: 3071MiB) **
pub const HIGH_RAM_START: GuestAddress = GuestAddress(0x100000);

pub const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;

// ** 32-bit reserved area (start: 3GiB, length: 896MiB) **
pub const MEM_32BIT_RESERVED_START: GuestAddress = GuestAddress(0xc000_0000);
pub const MEM_32BIT_RESERVED_SIZE: u64 = PCI_MMCONFIG_SIZE + MEM_32BIT_DEVICES_SIZE;
pub const PCI_MMCONFIG_SIZE: u64 = 256 << 20;
pub const MEM_32BIT_DEVICES_SIZE: u64 = 640 << 20;



// ** 64-bit RAM start (start: 4GiB, length: varies) **
pub const RAM_64BIT_START: GuestAddress = GuestAddress(0x1_0000_0000);