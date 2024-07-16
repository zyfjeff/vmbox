mod acpi;
mod layout;

use std::{fs, io, os::linux::fs::MetadataExt, path::Path, result};

pub use layout::*;
use linux_loader::loader::bootparam::{boot_params, CAN_USE_HEAP, KEEP_SEGMENTS};
use resources::AddressRange;
use thiserror::Error;
use vm_memory::{FileOffset, GuestAddress, GuestMemory, MmapRegion};

const KERNEL_OPTS: &'static str = "console=ttyS0 pci=conf1";

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to open the kernel image: {0}")]
    LoadKernel(io::Error),
    #[error("failed to open the initrd image: {0}")]
    LoadInitrd(io::Error),
    #[error("invalid e820 configuration")]
    InvalidE820Config,
    #[error("failed to mmap file region: {0}")]
    FaildedMmapRegion(vm_memory::mmap::MmapRegionError),
    #[error("invalid address: {0}")]
    InvalidAddress(vm_memory::GuestMemoryError),
    #[error("not enough memory")]
    NotEnoughMemory,
}

pub type Result<T> = result::Result<T, Error>;

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

enum E820Type {
    Ram = 0x01,
    Reserved = 0x2,
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(params: &mut boot_params, range: AddressRange, mem_type: E820Type) -> Result<()> {
    if params.e820_entries >= params.e820_table.len() as u8 {
        return Err(Error::InvalidE820Config);
    }

    let size = range.len().ok_or(Error::InvalidE820Config)?;

    params.e820_table[params.e820_entries as usize].addr = range.start;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type as u32;
    params.e820_entries += 1;

    Ok(())
}

pub fn vm_load_image<T: GuestMemory + Send, P: AsRef<Path>>(mem: &T, kernel_path: P) -> Result<()> {
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(kernel_path)
        .map_err(|e| Error::LoadKernel(e))?;
    let kernel_size = f.metadata().map_err(|e| Error::LoadKernel(e))?.st_size();
    let kernel_file = FileOffset::new(f, 0);

    let region = MmapRegion::<()>::from_file(kernel_file, kernel_size as usize)
        .map_err(|e| Error::FaildedMmapRegion(e))?;
    let raw_boot = mem
        .get_host_address(ZERO_PAGE_START)
        .map_err(|e| Error::InvalidAddress(e))?;

    unsafe { raw_boot.copy_from(region.as_ptr(), std::mem::size_of::<boot_params>()) };

    let boot = unsafe { &mut *(raw_boot as *const boot_params as *mut boot_params) };

    boot.hdr.vid_mode = 0xffff; // VGA
    boot.hdr.type_of_loader = 0xFF;
    boot.hdr.loadflags = boot.hdr.loadflags | CAN_USE_HEAP as u8 | 0x01 | KEEP_SEGMENTS as u8;
    boot.hdr.heap_end_ptr = 0xFE00;
    boot.hdr.ext_loader_ver = 0x0;
    boot.hdr.cmd_line_ptr = 0x20000;

    let cmdline = mem
        .get_host_address(CMDLINE_START)
        .map_err(|e| Error::InvalidAddress(e))?;
    unsafe {
        cmdline.copy_from(KERNEL_OPTS.as_ptr(), KERNEL_OPTS.len());
    }

    let kernel = mem
        .get_host_address(HIGH_RAM_START)
        .map_err(|e| Error::InvalidAddress(e))?;
    let setupsz = (boot.hdr.setup_sects + 1) as usize * 512;
    let kernel_data_addr = region.as_ptr().wrapping_add(setupsz);
    unsafe {
        kernel.copy_from(kernel_data_addr, region.size() - setupsz);
    }
    boot.e820_entries = 0;
    add_e820_entry(
        boot,
        AddressRange {
            start: 0,
            end: 0xa0000 - 1,
        },
        E820Type::Ram,
    )?;

    let guest_mem_end = mem.last_addr().0 - 1;

    add_e820_entry(
        boot,
        AddressRange {
            start: HIGH_RAM_START.0,
            end: guest_mem_end.min(PCI_MMIO_START - 1),
        },
        E820Type::Ram,
    )?;

    let above_4g = AddressRange {
        start: FIRST_ADDR_PAST_32BITS,
        end: guest_mem_end,
    };

    if !above_4g.is_empty() {
        add_e820_entry(boot, above_4g, E820Type::Ram)?;
    }

    add_e820_entry(
        boot,
        AddressRange {
            start: DEFAULT_PCIE_CFG_MMIO_START,
            end: DEFAULT_PCIE_CFG_MMIO_END,
        },
        E820Type::Reserved,
    )?;

    // Reserve memory section for Identity map and TSS
    add_e820_entry(
        boot,
        AddressRange {
            start: IDENTIFY_MAP_ADDR.0,
            end: TSS_ADDRESS_END.0 - 1,
        },
        E820Type::Reserved,
    )?;
    Ok(())
}

pub fn vm_load_initrd<T: GuestMemory + Send, P: AsRef<Path>>(
    mem: &T,
    initrd_path: P,
    mem_size: usize,
) -> Result<()> {
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(initrd_path)
        .map_err(|e| Error::LoadInitrd(e))?;
    let initrd_size = f.metadata().map_err(|e| Error::LoadKernel(e))?.st_size();
    let initrd_file = FileOffset::new(f, 0);
    let region = MmapRegion::<()>::from_file(initrd_file, initrd_size as usize)
        .map_err(|e| Error::FaildedMmapRegion(e))?;

    let raw_boot = mem
        .get_host_address(ZERO_PAGE_START)
        .map_err(|e| Error::InvalidAddress(e))?;
    let boot = unsafe { &mut *(raw_boot as *const boot_params as *mut boot_params) };

    let mut initrd_addr_max = u64::from(boot.hdr.initrd_addr_max);
    // Default initrd_addr_max for old kernels (see Documentation/x86/boot.txt).
    if boot.hdr.initrd_addr_max == 0 {
        initrd_addr_max = 0x37FFFFFF;
    }

    let mut initrd_addr = boot.hdr.initrd_addr_max & !0xfffff;

    let mem_max = mem.last_addr().0 - 1;
    if initrd_addr_max > mem_max {
        initrd_addr_max = mem_max;
    }

    loop {
        if initrd_addr < HIGH_RAM_START.0 as u32 {
            return Err(Error::NotEnoughMemory);
        }
        if (initrd_addr as usize) < (mem_size - region.size()) {
            break;
        }

        initrd_addr = initrd_addr - HIGH_RAM_START.0 as u32;
    }

    let kernel_initrd_addr = mem
        .get_host_address(GuestAddress(initrd_addr as u64))
        .map_err(|e| Error::InvalidAddress(e))?;
    unsafe {
        kernel_initrd_addr.copy_from(region.as_ptr(), initrd_size as usize);
    }

    boot.hdr.ramdisk_image = initrd_addr;
    boot.hdr.ramdisk_size = initrd_size as u32;

    Ok(())
}
