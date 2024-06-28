use std::fs;
use std::io::stdout;
use std::os::linux::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::{mem::MaybeUninit, path::PathBuf};

use anyhow::{anyhow, Context};
use arch::{
    arch_memory_regions, CMDLINE_START, DEFAULT_PCIE_CFG_MMIO_END, DEFAULT_PCIE_CFG_MMIO_START,
    FIRST_ADDR_PAST_32BITS, HIGH_RAM_START, IDENTIFY_MAP_ADDR, PCI_MMIO_START, TSS_ADDRESS,
    TSS_ADDRESS_END, ZERO_PAGE_START,
};
use clap::Parser;
use devices::irqchip::{IrqChip, IrqEventSource, KvmKernelIrqChip};
use devices::serial_device::ConsoleInput;
use devices::{Bus, BusDevice, BusType, Serial, SERIAL_ADDR};
use kvm_ioctls::VcpuExit;
use log::info;
use resources::AddressRange;
use sync::Mutex;
use vm_memory::{FileOffset, GuestAddress, GuestMemory, GuestMemoryMmap, MmapRegion};

use hypervisor::{KvmVm, Vm};
use linux_loader::loader::bootparam::{boot_params, CAN_USE_HEAP, KEEP_SEGMENTS};

mod mmap;

const RAM_SIZE: usize = 1 << 32;
const X86_64_SERIAL_1_3_IRQ: u32 = 4;
const X86_64_SERIAL_2_4_IRQ: u32 = 3;

const KERNEL_OPTS: &'static str = "console=ttyS0 pci=conf1";

static SAVED_TERMIOS: OnceLock<nix::libc::termios> = OnceLock::new();

pub fn errno_result<T>() -> anyhow::Result<T> {
    Err(std::io::Error::last_os_error().into())
}

macro_rules! syscall {
    ($e:expr) => {{
        let res = $e;
        if res < 0 {
            $crate::errno_result()
        } else {
            Ok(res)
        }
    }};
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, value_name = "KERNEL_FILE_PATH")]
    kernel: PathBuf,
    #[arg(short, long, value_name = "INITRD_FILE_PATH")]
    initrd: PathBuf,
    #[arg(short, long, value_name = "DISK_IMAGE_FILE_PATH")]
    disk: Option<PathBuf>,
}

extern "C" fn restore_termios() {
    SAVED_TERMIOS.get().map(|tattr| unsafe {
        nix::libc::tcsetattr(nix::libc::STDIN_FILENO, nix::libc::TCSANOW, tattr)
    });
}

fn set_input_mode() -> anyhow::Result<()> {
    unsafe {
        if nix::libc::isatty(nix::libc::STDIN_FILENO) == 0 {
            return Err(anyhow::anyhow!("Not a terminal"));
        }
    }

    let mut tattr: MaybeUninit<nix::libc::termios> = MaybeUninit::zeroed();
    syscall!(unsafe { nix::libc::tcgetattr(nix::libc::STDIN_FILENO, tattr.as_mut_ptr()) })?;

    let mut tattr: nix::libc::termios = unsafe { tattr.assume_init() };

    SAVED_TERMIOS.get_or_init(|| tattr.clone());
    tattr.c_cflag &= !(nix::libc::ICANON | nix::libc::ECHO | nix::libc::ISIG);
    syscall!(unsafe { nix::libc::tcsetattr(nix::libc::STDIN_FILENO, nix::libc::TCSANOW, &tattr) })?;

    syscall!(unsafe { nix::libc::atexit(restore_termios) })?;
    Ok(())
}

fn vm_load_initrd<T: GuestMemory + Send, P: AsRef<Path>>(
    vm: &mut KvmVm<T>,
    initrd_path: P,
) -> anyhow::Result<()> {
    let mem = vm.get_memory_lock();
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(initrd_path)
        .context("failed to open the initrd")?;
    let initrd_size = f.metadata()?.st_size();
    let initrd_file = FileOffset::new(f, 0);
    let region = MmapRegion::<()>::from_file(initrd_file, initrd_size as usize)
        .context("failed to mmap the initrd")?;

    let raw_boot = mem.get_host_address(ZERO_PAGE_START)?;
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
            return Err(anyhow!("Not enough memory for initrd"));
        }
        if (initrd_addr as usize) < (RAM_SIZE - region.size()) {
            break;
        }

        initrd_addr = initrd_addr - HIGH_RAM_START.0 as u32;
    }

    let kernel_initrd_addr = mem.get_host_address(GuestAddress(initrd_addr as u64))?;
    unsafe {
        kernel_initrd_addr.copy_from(region.as_ptr(), initrd_size as usize);
    }

    boot.hdr.ramdisk_image = initrd_addr;
    boot.hdr.ramdisk_size = initrd_size as u32;

    Ok(())
}

enum E820Type {
    Ram = 0x01,
    Reserved = 0x2,
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(
    params: &mut boot_params,
    range: AddressRange,
    mem_type: E820Type,
) -> anyhow::Result<()> {
    if params.e820_entries >= params.e820_table.len() as u8 {
        return Err(anyhow!(format!("invalid e820 configuration")));
    }

    let size = range
        .len()
        .ok_or(anyhow!(format!("invalid e820 configuration")))?;

    params.e820_table[params.e820_entries as usize].addr = range.start;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type as u32;
    params.e820_entries += 1;

    Ok(())
}

fn vm_load_image<T: GuestMemory + Send, P: AsRef<Path>>(
    vm: &mut KvmVm<T>,
    kernel_path: P,
) -> anyhow::Result<()> {
    let mem = vm.get_memory_lock();
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(kernel_path)
        .context("failed to read kernel image")?;
    let kernel_size = f.metadata()?.st_size();
    let kernel_file = FileOffset::new(f, 0);

    let region = MmapRegion::<()>::from_file(kernel_file, kernel_size as usize)
        .context("failed to mmap the kernel image")?;
    let raw_boot = mem.get_host_address(ZERO_PAGE_START)?;

    unsafe { raw_boot.copy_from(region.as_ptr(), std::mem::size_of::<boot_params>()) };

    let boot = unsafe { &mut *(raw_boot as *const boot_params as *mut boot_params) };

    boot.hdr.vid_mode = 0xffff; // VGA
    boot.hdr.type_of_loader = 0xFF;
    boot.hdr.loadflags = boot.hdr.loadflags | CAN_USE_HEAP as u8 | 0x01 | KEEP_SEGMENTS as u8;
    boot.hdr.heap_end_ptr = 0xFE00;
    boot.hdr.ext_loader_ver = 0x0;
    boot.hdr.cmd_line_ptr = 0x20000;

    let cmdline = mem.get_host_address(CMDLINE_START)?;
    unsafe {
        cmdline.copy_from(KERNEL_OPTS.as_ptr(), KERNEL_OPTS.len());
    }

    let kernel = mem.get_host_address(HIGH_RAM_START)?;
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

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    set_input_mode()?;

    info!("start to load kernel");

    if !cli.kernel.exists() {
        return Err(anyhow!(format!("kernel {:?} not exists", cli.kernel)));
    }

    let ranges = arch_memory_regions(RAM_SIZE as u64);
    let mem = GuestMemoryMmap::<()>::from_ranges(&ranges)?;
    let mut vmm = KvmVm::new(mem)?;
    vmm.set_tss_addr(GuestAddress(TSS_ADDRESS.0))?;
    vmm.set_identity_map_addr(GuestAddress(IDENTIFY_MAP_ADDR.0))?;
    let mut irq_chip: KvmKernelIrqChip<GuestMemoryMmap> = KvmKernelIrqChip::new(vmm.try_clone()?)?;

    let com_evt_1_3 = devices::IrqEdgeEvent::new()?;

    let clone_fd = com_evt_1_3.get_trigger().try_clone()?;

    let serial = Serial::new(
        clone_fd,
        Some(Box::new(ConsoleInput::new())),
        Some(Box::new(stdout())),
        true,
    );

    let source = IrqEventSource {
        device_id: serial.device_id(),
        queue_id: 0,
        device_name: serial.debug_label(),
    };

    let io_bus = Arc::new(Bus::new(BusType::Io));
    io_bus
        .insert(Arc::new(Mutex::new(serial)), SERIAL_ADDR[0], 0x8)
        .unwrap();

    vm_load_image(&mut vmm, cli.kernel)?;
    vm_load_initrd(&mut vmm, cli.initrd)?;

    let mut vcpu = vmm.create_vcpu(0)?;
    irq_chip.register_edge_irq_event(X86_64_SERIAL_1_3_IRQ, &com_evt_1_3, source)?;
    loop {
        let res = vcpu.run()?;
        match res {
            VcpuExit::IoIn(address, data) => {
                io_bus.read(address as u64, data);
            }
            VcpuExit::IoOut(address, data) => {
                io_bus.write(address as u64, data);
            }

            _ => {
                print!("unhanle vcpu exit event : {:?}", res)
            }
        }
    }
}
