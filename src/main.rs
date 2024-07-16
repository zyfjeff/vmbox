use std::io::stdout;
use std::sync::{Arc, OnceLock};
use std::{mem::MaybeUninit, path::PathBuf};

use anyhow::anyhow;
use arch::{arch_memory_regions, vm_load_image, vm_load_initrd, IDENTIFY_MAP_ADDR, TSS_ADDRESS};
use base::syscall;
use clap::Parser;
use devices::irqchip::{IrqChip, IrqEventSource, KvmKernelIrqChip};
use devices::serial_device::ConsoleInput;
use devices::{Bus, BusDevice, BusType, Serial, SERIAL_ADDR};
use hypervisor::{KvmVm, Vm};
use log::info;
use sync::Mutex;
use vcpu::run_vcpu;
use vm_memory::{GuestAddress, GuestMemoryMmap};

mod vcpu;

const RAM_SIZE: usize = 1 << 34;
const X86_64_SERIAL_1_3_IRQ: u32 = 4;
#[allow(dead_code)]
const X86_64_SERIAL_2_4_IRQ: u32 = 3;

static SAVED_TERMIOS: OnceLock<nix::libc::termios> = OnceLock::new();

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

    SAVED_TERMIOS.get_or_init(|| tattr);
    tattr.c_cflag &= !(nix::libc::ICANON | nix::libc::ECHO | nix::libc::ISIG);
    syscall!(unsafe { nix::libc::tcsetattr(nix::libc::STDIN_FILENO, nix::libc::TCSANOW, &tattr) })?;

    syscall!(unsafe { nix::libc::atexit(restore_termios) })?;
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
    let vmm = KvmVm::new(mem)?;
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

    let mem = vmm.get_memory_lock();
    vm_load_image(&*mem, cli.kernel)?;
    vm_load_initrd(&*mem, cli.initrd, RAM_SIZE)?;
    irq_chip.register_edge_irq_event(X86_64_SERIAL_1_3_IRQ, &com_evt_1_3, source)?;
    let mut all_vcpu_join = Vec::new();

    for i in 0..8 {
        let vcpu = vmm.create_vcpu(i)?;
        let vcpu_join = run_vcpu(vcpu, Arc::clone(&io_bus))?;
        all_vcpu_join.push(vcpu_join);
    }

    all_vcpu_join.into_iter().for_each(|j| {
        j.join().unwrap();
    });

    Ok(())
}
