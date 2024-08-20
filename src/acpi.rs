use acpi_tables::{
    aml,
    madt::{EnabledStatus, IoApic, ProcessorLocalApic},
    rsdp::Rsdp,
    sdt::Sdt,
    Aml,
};
use arch::{APIC_DEFAULT_PHYS_BASE, DEFAULT_PCIE_CFG_MMIO_START, IO_APIC_DEFAULT_PHYS_BASE};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};
use zerocopy::AsBytes;

const MADT_CPU_ENABLE_FLAG: usize = 0;
const MADT_CPU_ONLINE_CAPABLE_FLAG: usize = 1;
const OEM_REVISION: u32 = 1;

/* Values for Type in APIC sub-headers */
pub const ACPI_X2APIC_PROCESSOR: u8 = 9;
pub const ACPI_APIC_IO: u8 = 1;
pub const ACPI_APIC_XRUPT_OVERRIDE: u8 = 2;

fn next_offset(offset: GuestAddress, len: u64) -> Option<GuestAddress> {
    // Enforce 64-byte allocation alignment.
    match len % 64 {
        0 => offset.checked_add(len),
        x => offset.checked_add(len.checked_add(64 - x)?),
    }
}

pub fn create_acpi_tables<T: GuestMemory>(
    guest_mem: &T,
    cpu_ids: &Vec<u8>,
) -> Option<GuestAddress> {
    let rsdp_offset = arch::RSDP_POINTER;
    let facs_offset = next_offset(rsdp_offset, Rsdp::len() as u64)?;
    let mut offset = next_offset(facs_offset, acpi_tables::facs::FACS::len() as u64)?;
    let mut tables: Vec<u64> = Vec::new();

    // SSDT
    // User supplied System Description Tables, e.g. SSDT.

    // FACS
    let facs = acpi_tables::facs::FACS::new();
    guest_mem.write(facs.as_bytes(), facs_offset).ok()?;

    // DSDT

    // FACP aka FADT

    // MADT

    let mut madt = acpi_tables::madt::MADT::new(
        *b"VMBOX ",
        *b"VMBOXID ",
        OEM_REVISION,
        acpi_tables::madt::LocalInterruptController::Address(APIC_DEFAULT_PHYS_BASE),
    );
    for id in cpu_ids {
        let processor = ProcessorLocalApic::new(*id, *id, EnabledStatus::Enabled);
        madt.add_structure(processor);
    }

    let ioapic = IoApic::new(0, IO_APIC_DEFAULT_PHYS_BASE, 0);
    madt.add_structure(ioapic);

    let mut madt_data = Vec::new();
    madt.to_aml_bytes(&mut madt_data);
    guest_mem.write(madt_data.as_bytes(), offset).ok()?;

    tables.push(offset.0);
    offset = next_offset(offset, madt_data.len() as u64)?;

    // MCFG

    let mut mcfg = acpi_tables::mcfg::MCFG::new(*b"VMBOX ", *b"VMBOXID ", OEM_REVISION);
    mcfg.add_ecam(DEFAULT_PCIE_CFG_MMIO_START, 0, 0, 2);
    let mut mcfg_data = Vec::new();
    mcfg.to_aml_bytes(&mut mcfg_data);
    guest_mem.write(mcfg_data.as_bytes(), offset).ok()?;
    tables.push(offset.0);
    offset = next_offset(offset, madt_data.len() as u64)?;

    // XSDT
    let mut xsdt = acpi_tables::xsdt::XSDT::new(*b"VMBOX ", *b"VMBOXID ", OEM_REVISION);
    for table in tables {
        xsdt.add_entry(table);
    }
    let mut xsdt_data = Vec::new();
    xsdt.to_aml_bytes(&mut xsdt_data);
    guest_mem.write(xsdt_data.as_bytes(), offset).ok()?;

    // RSDP
    let rsdp = acpi_tables::rsdp::Rsdp::new(*b"VMBOX ", offset.0);
    guest_mem.write(rsdp.as_bytes(), rsdp_offset).ok()?;

    Some(rsdp_offset)
}
