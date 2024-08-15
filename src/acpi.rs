use acpi_tables::{aml, rsdp::Rsdp, sdt::Sdt, Aml};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};
use zerocopy::AsBytes;


const MADT_CPU_ENABLE_FLAG: usize = 0;
const MADT_CPU_ONLINE_CAPABLE_FLAG: usize = 1;

/* Values for Type in APIC sub-headers */
pub const ACPI_X2APIC_PROCESSOR: u8 = 9;
pub const ACPI_APIC_IO: u8 = 1;
pub const ACPI_APIC_XRUPT_OVERRIDE: u8 = 2;

#[allow(dead_code)]
#[repr(packed)]
#[derive(AsBytes)]
struct LocalX2Apic {
    pub r#type: u8,
    pub length: u8,
    pub _reserved: u16,
    pub apic_id: u32,
    pub flags: u32,
    pub processor_id: u32,
}

struct Cpu {
    cpu_id: u16,
    proximity_domain: u32,
    dynamic: bool,
    topology: Option<(u16, u16, u16)>,
}

impl Cpu {
    fn generate_mat(&self) -> Vec<u8> {
        let x2apic_id = arch::get_x2apic_id(self.cpu_id.into(), self.topology);

        let lapic = LocalX2Apic {
            r#type: ACPI_X2APIC_PROCESSOR,
            length: 16,
            processor_id: self.cpu_id.into(),
            apic_id: x2apic_id,
            flags: 1 << MADT_CPU_ENABLE_FLAG,
            _reserved: 0,
        };

        let mut mat_data: Vec<u8> = vec![0; std::mem::size_of_val(&lapic)];
        // SAFETY: mat_data is large enough to hold lapic
        unsafe { *(mat_data.as_mut_ptr() as *mut LocalX2Apic) = lapic };

        mat_data
    }
}

impl Aml for Cpu {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        let mat_data: Vec<u8> = self.generate_mat();
        aml::Device::new(
            format!("C{:03X}", self.cpu_id).as_str().into(),
            vec![
                &aml::Name::new("_HID".into(), &"ACPI0007"),
                &aml::Name::new("_UID".into(), &self.cpu_id),
                #[cfg(target_arch = "x86_64")]
                &aml::Method::new(
                    "_STA".into(),
                    0,
                    false,
                    // Mark CPU present see CSTA implementation
                    vec![&aml::Return::new(&0xfu8)],
                ),
                &aml::Method::new(
                    "_PXM".into(),
                    0,
                    false,
                    vec![&aml::Return::new(&self.proximity_domain)],
                ),
                // The Linux kernel expects every CPU device to have a _MAT entry
                // containing the LAPIC for this processor with the enabled bit set
                // even it if is disabled in the MADT (non-boot CPU)
                #[cfg(target_arch = "x86_64")]
                &aml::Name::new("_MAT".into(), &aml::BufferData::new(mat_data)),
            ],
        )
        .to_aml_bytes(sink);
    }
}


struct CpuNotify {
    cpu_id: u16,
}

impl Aml for CpuNotify {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        let object = aml::Path::new(&format!("C{:03X}", self.cpu_id));
        aml::If::new(
            &aml::Equal::new(&aml::Arg(0), &self.cpu_id),
            vec![&aml::Notify::new(&object, &aml::Arg(1))],
        )
        .to_aml_bytes(sink)
    }
}

struct CpuMethods {
    max_vcpus: u8,
    dynamic: bool,
}

impl Aml for CpuMethods {
    fn to_aml_bytes(&self, sink: &mut dyn acpi_tables::AmlSink) {
        aml::Method::new("CSCN".into(), 0, true, vec![]).to_aml_bytes(sink)
    }
}

pub fn create_dsdt_table(
) -> Sdt {

    // DSDT
    let mut dsdt = Sdt::new(*b"DSDT", 36, 6, *b"VMBOX ", *b"VBOXDSDT", 1);
    let mut bytes = Vec::new();


    // memory
    aml::Device::new(
        "_SB_.MHPC".into(),
        vec![
            &aml::Name::new("_HID".into(), &aml::EISAName::new("PNP0A06")),
            &aml::Name::new("_UID".into(), &"Memory Hotplug Controller"),
            // Empty MSCN for GED
            &aml::Method::new("MSCN".into(), 0, true, vec![]),
        ],
    ).to_aml_bytes(&mut bytes);


    // CPU devices
    let hid = aml::Name::new("_HID".into(), &"ACPI0010");
    let uid = aml::Name::new("_CID".into(), &aml::EISAName::new("PNP0A05"));
    // Bundle methods together under a common object
    let methods = CpuMethods {
        max_vcpus: 8,
        dynamic: false,
    };
    let mut cpu_data_inner: Vec<&dyn Aml> = vec![&hid, &uid, &methods];
    let topology = Some((1, 8, 1));

    let mut cpu_devices = Vec::new();
    for cpu_id in 0..8 {
        let cpu_device = Cpu {
            cpu_id,
            proximity_domain: 0,
            dynamic: false,
            topology,
        };

        cpu_devices.push(cpu_device);
    }

    for cpu_device in cpu_devices.iter() {
        cpu_data_inner.push(cpu_device);
    }

    aml::Device::new("_SB_.CPUS".into(), cpu_data_inner).to_aml_bytes(&mut bytes);

    dsdt.append_slice(&bytes);

    dsdt
}


pub fn create_acpi_tables<T: GuestMemory>(guest_mem: &T) -> GuestAddress {
    let rsdp_offset = arch::RSDP_POINTER;
    let mut tables: Vec<u64> = Vec::new();
    let dsdt = create_dsdt_table();

    let dsdt_offset = rsdp_offset.checked_add(Rsdp::len() as u64).unwrap();
    let slice = guest_mem.get_slice(dsdt_offset, dsdt.len()).unwrap();
    slice.write_slice(dsdt.as_slice(), dsdt.len()).unwrap();
    rsdp_offset
}
