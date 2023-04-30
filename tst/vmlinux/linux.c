/**
 * @file vmlinux/linux.c
 *
 * @copyright 2022 Bill Zissimopoulos
 */
/*
 * This file is part of VirtualMetal.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * Affero General Public License version 3 as published by the Free
 * Software Foundation.
 */

#include <vmlinux/plugin.h>

/*
 * Memory Layout for Linux guest
 *
 * 0000     NULL page
 * 1000     ACPI tables
 *          ...
 *          ^^^
 *          |||
 * 4000     VCPU data: GDT, TSS, initial stack (grows towards lower addresses)
 * 5000     ACPI wakeup mailbox
 * 6000     hyper page (currently unused)
 * 7000     root page: PML4
 * 8000     PDPT page table (identity mapped, maps 512G, upto 3T, grows towards higher addresses)
 *          |||
 *          vvv
 *          ...
 * e000     Linux boot_params
 * f000     Linux command line
 */
#define VM_PLUGIN_LINUX_MEMORY_SIZEMIN  (16 * 1024 * 1024)
#define VM_PLUGIN_LINUX_ACPI_TABLE      (0x1000)
#define VM_PLUGIN_LINUX_VCPU_TABLE      (0x4000)
#define VM_PLUGIN_LINUX_MAILBOX         (0x5000)
#define VM_PLUGIN_LINUX_PAGE_TABLE      (0x7000)
#define VM_PLUGIN_LINUX_BOOT_PARAMS     (0xe000)
#define VM_PLUGIN_LINUX_CMD_LINE        (0xf000)

/* ACPI 6.4 */
ARCH_PACK(struct acpi_rsdp
{
    uint8_t signature[8];
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t revision;
    uint32_t rsdt_address;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t extended_checksum;
    uint8_t reserved[3];
});
ARCH_STATIC_ASSERT(36 == sizeof(struct acpi_rsdp));
ARCH_PACK(struct acpi_header
{
    uint8_t signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
});
ARCH_STATIC_ASSERT(36 == sizeof(struct acpi_header));
ARCH_PACK(struct acpi_gas
{
    uint8_t address_space_id;
    uint8_t register_bit_width;
    uint8_t register_bit_offset;
    uint8_t access_size;
    uint64_t address;
});
ARCH_STATIC_ASSERT(12 == sizeof(struct acpi_gas));
ARCH_PACK(struct acpi_xsdt
{
    struct acpi_header header;
});
ARCH_STATIC_ASSERT(36 == sizeof(struct acpi_xsdt));
ARCH_PACK(struct acpi_fadt
{
    struct acpi_header header;
    uint32_t firmware_control;
    uint32_t dsdt;
    uint8_t reserved0;
    uint8_t preferred_pm_profile;
    uint16_t sci_int;
    uint32_t smi_cmd;
    uint8_t acpi_enable;
    uint8_t acpi_disable;
    uint8_t s4bios_req;
    uint8_t pstate_cnt;
    uint32_t pm1a_evt_blk;
    uint32_t pm1b_evt_blk;
    uint32_t pm1a_cnt_blk;
    uint32_t pm1b_cnt_blk;
    uint32_t pm2_cnt_blk;
    uint32_t pm_tmr_blk;
    uint32_t gpe0_blk;
    uint32_t gpe1_blk;
    uint8_t pm1_evt_len;
    uint8_t pm1_cnt_len;
    uint8_t pm2_cnt_len;
    uint8_t pm_tmr_len;
    uint8_t gpe0_blk_len;
    uint8_t gpe1_blk_len;
    uint8_t gpe1_base;
    uint8_t cst_cnt;
    uint16_t p_lvl2_lat;
    uint16_t p_lvl3_lat;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t duty_offset;
    uint8_t duty_width;
    uint8_t day_alrm;
    uint8_t mon_alrm;
    uint8_t century;
    uint16_t iapc_boot_arch;
    uint8_t reserved1;
    uint32_t flags;
    struct acpi_gas reset_reg;
    uint8_t reset_value;
    uint16_t arm_boot_arch;
    uint8_t fadt_minor_version;
    uint64_t x_firmware_ctrl;
    uint64_t x_dsdt;
    struct acpi_gas x_pm1a_evt_blk;
    struct acpi_gas x_pm1b_evt_blk;
    struct acpi_gas x_pm1a_cnt_blk;
    struct acpi_gas x_pm1b_cnt_blk;
    struct acpi_gas x_pm2_cnt_blk;
    struct acpi_gas x_pm_tmr_blk;
    struct acpi_gas x_gpe0_blk;
    struct acpi_gas x_gpe1_blk;
    struct acpi_gas sleep_control_reg;
    struct acpi_gas sleep_status_reg;
    uint8_t hypervisor_vendor_identity[8];
});
ARCH_STATIC_ASSERT(140 == (uint64_t)&((struct acpi_fadt *)0)->x_dsdt);
ARCH_STATIC_ASSERT(276 == sizeof(struct acpi_fadt));
ARCH_PACK(struct acpi_dsdt
{
    struct acpi_header header;
});
ARCH_STATIC_ASSERT(36 == sizeof(struct acpi_dsdt));
ARCH_PACK(struct acpi_madt
{
    struct acpi_header header;
    uint32_t lapic_address;
    uint32_t flags;
});
ARCH_STATIC_ASSERT(44 == sizeof(struct acpi_madt));
ARCH_PACK(struct acpi_lapic
{
    uint8_t type;
    uint8_t length;
    uint8_t acpi_processor_id;
    uint8_t lapic_id;
    uint32_t flags;
});
ARCH_STATIC_ASSERT(8 == sizeof(struct acpi_lapic));
ARCH_PACK(struct acpi_ioapic
{
    uint8_t type;
    uint8_t length;
    uint8_t ioapic_id;
    uint8_t reserved;
    uint32_t ioapic_address;
    uint32_t gsi_base;
});
ARCH_STATIC_ASSERT(12 == sizeof(struct acpi_ioapic));
ARCH_PACK(struct acpi_wakeup
{
    uint8_t type;
    uint8_t length;
    uint16_t mailbox_version;
    uint32_t reserved;
    uint64_t mailbox_address;
});
ARCH_STATIC_ASSERT(16 == sizeof(struct acpi_wakeup));
#define acpi_store_checksum(p0, skip0)\
    acpi_store_checksum_ex(p0, skip0, (uint8_t *)(p0) + sizeof *(p0))
static inline
void acpi_store_checksum_ex(void *p0, void *skip0, void *endp0)
{
    uint8_t s = 0, *p = p0, *skip = skip0, *endp = endp0;
    for (; skip != p; p++)
        s += *p;
    for (p++; endp != p; p++)
        s += *p;
    *skip = -s;
}

/* linux boot params */
#define bp_acpi_rsdp_addr               0x070
#define bp_e820_entries                 0x1e8
#define bp_setup_header                 0x1f1
#define bp_e820_table                   0x2d0   /* 128 entries */
ARCH_PACK(struct setup_header
{
    uint8_t setup_sects;
    uint16_t root_flags;
    uint32_t syssize;
    uint16_t ram_size;
    uint16_t vid_mode;
    uint16_t root_dev;
    uint16_t boot_flag;
    uint16_t jump;
    uint32_t header;
    uint16_t version;
    uint32_t realmode_swtch;
    uint16_t start_sys_seg;
    uint16_t kernel_version;
    uint8_t type_of_loader;
    uint8_t loadflags;
    uint16_t setup_move_size;
    uint32_t code32_start;
    uint32_t ramdisk_image;
    uint32_t ramdisk_size;
    uint32_t bootsect_kludge;
    uint16_t heap_end_ptr;
    uint8_t ext_loader_ver;
    uint8_t ext_loader_type;
    uint32_t cmd_line_ptr;
    uint32_t initrd_addr_max;
    uint32_t kernel_alignment;
    uint8_t relocatable_kernel;
    uint8_t min_alignment;
    uint16_t xloadflags;
    uint32_t cmdline_size;
    uint32_t hardware_subarch;
    uint64_t hardware_subarch_data;
    uint32_t payload_offset;
    uint32_t payload_length;
    uint64_t setup_data;
    uint64_t pref_address;
    uint32_t init_size;
    uint32_t handover_offset;
    uint32_t kernel_info_offset;
});
ARCH_PACK(struct e820_entry
{
    uint64_t addr;
    uint64_t size;
    uint32_t type;
});

static vm_result_t vm_plugin_linux_runcmd_c(vm_config_t *config,
    vm_runcmd_t *runcmd, char phase, const char *value);
static vm_result_t vm_plugin_linux_runcmd_m(vm_t *instance,
    vm_runcmd_t *runcmd, char phase, const char *value);
static vm_result_t vm_plugin_linux_setup_acpi_table(vm_t *instance);
static vm_result_t vm_plugin_linux_setup_page_table(vm_t *instance);
static vm_result_t vm_plugin_linux_setup_boot_params(vm_t *instance, vm_count_t memory_size);
static vm_result_t vm_plugin_linux_setup_command_line(vm_t *instance, const char *cmd_line);
static vm_result_t vm_plugin_linux_infi(vm_t *instance, vm_count_t vcpu_index,
    int dir, vm_result_t result);
static vm_result_t vm_plugin_linux_mmio(vm_t *instance, vm_count_t vcpu_index,
    vm_count_t flags, vm_count_t address, vm_count_t length, void *buffer);
static vm_result_t vm_plugin_linux_pmio(vm_t *instance, vm_count_t vcpu_index,
    vm_count_t flags, vm_count_t address, vm_count_t length, void *buffer);

/* adapted from vm_run: check macro */
#define CHK(C)  do \
    if (C) ; else { result = vm_result(VM_ERROR_CONFIG, 0); goto exit; } \
    while (0)

vm_result_t vm_plugin_linux_runcmd(void *context,
    vm_runcmd_t *runcmd, char phase, const char *value)
{
    switch (phase)
    {
    case VM_RUNCMD_PHASE_CREATE:
        return vm_plugin_linux_runcmd_c(context, runcmd, phase, value);
    case VM_RUNCMD_PHASE_MEMORY:
        return vm_plugin_linux_runcmd_m(context, runcmd, phase, value);
    default:
        return VM_RESULT_SUCCESS;
    }
}

static vm_result_t vm_plugin_linux_runcmd_c(vm_config_t *config,
    vm_runcmd_t *runcmd, char phase, const char *value)
{
    config->infi = vm_plugin_linux_infi;
    config->mmio = vm_plugin_linux_mmio;
    config->pmio = vm_plugin_linux_pmio;
    config->passthrough = 1;
    return VM_RESULT_SUCCESS;
}

static vm_result_t vm_plugin_linux_runcmd_m(vm_t *instance,
    vm_runcmd_t *runcmd, char phase, const char *value)
{
    vm_result_t result;
    vm_count_t length;
    int file;
    char *p;

    length = strtoullint(value, &p, +1);
    CHK(',' == *p);
    if (length < VM_PLUGIN_LINUX_MEMORY_SIZEMIN)
        length = VM_PLUGIN_LINUX_MEMORY_SIZEMIN;

    /* load ELF linux kernel for execution */
    file = open(p + 1, O_RDONLY);
    if (-1 == file)
    {
        result = vm_result(VM_ERROR_FILE, errno);
        goto exit;
    }
    result = vm_load(instance, 0, length, file,
        VM_LOAD_EXEC | VM_LOAD_EXEC_REPORT);
    close(file);
    if (!vm_result_check(result))
        goto exit;

    /* setup ACPI */
    result = vm_plugin_linux_setup_acpi_table(instance);
    if (!vm_result_check(result))
        goto exit;

    /* setup identity mapped page table */
    result = vm_plugin_linux_setup_page_table(instance);
    if (!vm_result_check(result))
        goto exit;

    /* setup boot_params */
    result = vm_plugin_linux_setup_boot_params(instance, length);
    if (!vm_result_check(result))
        goto exit;

    /* setup command line */
    result = vm_plugin_linux_setup_command_line(instance, "console=ttyS0");
    if (!vm_result_check(result))
        goto exit;

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

static vm_result_t vm_plugin_linux_setup_acpi_table(vm_t *instance)
{
    ARCH_PACK(struct acpi_table
    {
        ARCH_ALIGN(64) struct acpi_rsdp rsdp;
        ARCH_ALIGN(64) struct acpi_xsdt xsdt;
        ARCH_ALIGN( 1) uint64_t xsdt_entries[3];
        ARCH_ALIGN(64) struct acpi_fadt fadt;
        ARCH_ALIGN(64) struct acpi_dsdt dsdt;
        ARCH_ALIGN(64) uint8_t madt[];
    });
    ARCH_STATIC_ASSERT(36 ==
        (uint64_t)&((struct acpi_table *)0)->xsdt_entries - (uint64_t)&((struct acpi_table *)0)->xsdt);
    static struct acpi_table acpi_table =
    {
        /* RSDP */
        .rsdp.signature = "RSD PTR ",
        .rsdp.revision = 2,
        .rsdp.length = sizeof(struct acpi_rsdp),
        .rsdp.xsdt_address = VM_PLUGIN_LINUX_ACPI_TABLE + (uint64_t)&((struct acpi_table *)0)->xsdt,
        /* XSDT */
        .xsdt.header.signature = "XSDT",
        .xsdt.header.length = sizeof(struct acpi_xsdt) + sizeof ((struct acpi_table *)0)->xsdt_entries,
        .xsdt.header.revision = 1,
        .xsdt_entries[0] = VM_PLUGIN_LINUX_ACPI_TABLE + (uint64_t)&((struct acpi_table *)0)->fadt,
        .xsdt_entries[1] = VM_PLUGIN_LINUX_ACPI_TABLE + (uint64_t)&((struct acpi_table *)0)->dsdt,
        .xsdt_entries[2] = VM_PLUGIN_LINUX_ACPI_TABLE + (uint64_t)&((struct acpi_table *)0)->madt,
        /* FADT */
        .fadt.header.signature = "FACP",
        .fadt.header.length = sizeof(struct acpi_fadt),
        .fadt.header.revision = 6,
        .fadt.fadt_minor_version = 4,
        .fadt.iapc_boot_arch = 0x3c,    /* no legacy devs, no 8042, no VGA, no MSI, no ASPM, no CMOS */
        .fadt.flags = 0,
        .fadt.x_dsdt = VM_PLUGIN_LINUX_ACPI_TABLE + (uint64_t)&((struct acpi_table *)0)->dsdt,
        .fadt.hypervisor_vendor_identity = "VrtMetal",
        /* DSDT */
        .dsdt.header.signature = "DSDT",
        .dsdt.header.length = sizeof(struct acpi_dsdt),
        .dsdt.header.revision = 2,
    };
    vm_result_t result;
    vm_config_t config;
    vm_count_t guest_address, length;
    ARCH_PACK(struct
    {
        struct acpi_madt base;
        struct acpi_wakeup wakeup;
        struct acpi_ioapic ioapic;
        struct acpi_lapic lapic[VM_CONFIG_VCPU_COUNT_MAX];
    }) madt;

    vm_getconfig(instance, &config, ~0ULL);

    /*
     * Setup fixed length tables in acpi_table.
     *
     * The acpi_table also contains the DSDT which is variable length, but contains no entries in
     * this implementation.
     *
     * It is safe to compute checksums for the static tables in acpi_table with multiple threads,
     * because given a static table we always compute the same value.
     */
    acpi_store_checksum_ex(&acpi_table.rsdp, &acpi_table.rsdp.checksum, &acpi_table.rsdp.length);
    acpi_store_checksum(&acpi_table.rsdp, &acpi_table.rsdp.extended_checksum);
    acpi_store_checksum_ex(&acpi_table.xsdt, &acpi_table.xsdt.header.checksum,
        (uint8_t *)&acpi_table.xsdt + acpi_table.xsdt.header.length);
    acpi_store_checksum(&acpi_table.fadt, &acpi_table.fadt.header.checksum);
    acpi_store_checksum(&acpi_table.dsdt, &acpi_table.dsdt.header.checksum);

    guest_address = VM_PLUGIN_LINUX_ACPI_TABLE;
    length = sizeof acpi_table;
    vm_mwrite(instance,
        &acpi_table,
        guest_address,
        &length);
    CHK(sizeof acpi_table == length);

    /*
     * Setup variable length MADT.
     */
    memset(&madt, 0, sizeof madt);
    madt.base.header.signature[0] = 'A';
    madt.base.header.signature[1] = 'P';
    madt.base.header.signature[2] = 'I';
    madt.base.header.signature[3] = 'C';
    madt.base.header.length = (uint32_t)(
        (uint8_t *)&madt.lapic[config.vcpu_count] - (uint8_t *)&madt.base);
    madt.base.header.revision = 5;
    madt.base.lapic_address = 0xFEE00000;
    madt.wakeup.type = 0x10;            /* multiprocessor wakeup */
    madt.wakeup.length = sizeof madt.wakeup;
    madt.wakeup.mailbox_version = 0;
    madt.wakeup.mailbox_address = VM_PLUGIN_LINUX_MAILBOX;
    madt.ioapic.type = 1;               /* I/O APIC */
    madt.ioapic.length = sizeof madt.ioapic;
    madt.ioapic.ioapic_id = (uint8_t)config.vcpu_count;
    madt.ioapic.ioapic_address = 0xFEC00000;
    madt.ioapic.gsi_base = 0;
    for (vm_count_t index = 0; config.vcpu_count > index; index++)
    {
        madt.lapic[index].type = 0;     /* processor local apic */
        madt.lapic[index].length = sizeof madt.lapic[index];
        madt.lapic[index].acpi_processor_id = (uint8_t)index;
        madt.lapic[index].lapic_id = (uint8_t)index;
        madt.lapic[index].flags = 1;    /* processor enabled */
    }
    acpi_store_checksum_ex(
        &madt.base, &madt.base.header.checksum, &madt.lapic[config.vcpu_count]);

    guest_address = VM_PLUGIN_LINUX_ACPI_TABLE + (uint64_t)&((struct acpi_table *)0)->madt;
    length = madt.base.header.length;
    vm_mwrite(instance,
        &madt.base,
        guest_address,
        &length);
    CHK(madt.base.header.length == length);

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

static vm_result_t vm_plugin_linux_setup_page_table(vm_t *instance)
{
    vm_result_t result;
    vm_config_t config;
    vm_count_t pg0_address, pg1_address, pg1_count, guest_address, length;

    pg0_address = VM_PLUGIN_LINUX_PAGE_TABLE;
    pg1_address = pg0_address + 4096;
    pg1_count = 1;  /* 512G of identity mapped memory */

    guest_address = pg1_address | 0x03/* Present | ReadWrite */;
    for (vm_count_t index = 0; pg1_count > index; index++)
    {
        length = sizeof guest_address;
        vm_mwrite(instance,
            &guest_address,
            pg0_address,
            &length);
        CHK(sizeof guest_address == length);
        pg0_address += 8;
        guest_address += 4096;
    }

    guest_address = 0 | 0x83/* Present | ReadWrite | PageSize */;
    for (vm_count_t index = 0; pg1_count * 512 > index; index++)
    {
        length = sizeof guest_address;
        vm_mwrite(instance,
            &guest_address,
            pg1_address,
            &length);
        CHK(sizeof guest_address == length);
        pg1_address += 8;
        guest_address += 0x8000000000ULL;
    }

    memset(&config, 0, sizeof config);
    config.page_table = VM_PLUGIN_LINUX_PAGE_TABLE;
    vm_setconfig(instance, &config, VM_CONFIG_BIT(page_table));

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

static vm_result_t vm_plugin_linux_setup_boot_params(vm_t *instance, vm_count_t memory_size)
{
    vm_result_t result;
    vm_config_t config;
    vm_count_t guest_address, length;
    uint64_t acpi_rsdp_addr;
    uint8_t e820_entries;
    struct e820_entry e820_table[] =
    {
        { 0x00000000, 0x00010000, 2/* reserved */},
        { 0x00010000, memory_size - 0x00010000, 1/* usable */},
    };
    struct setup_header setup_header;

    guest_address = VM_PLUGIN_LINUX_BOOT_PARAMS + bp_acpi_rsdp_addr;
    acpi_rsdp_addr = VM_PLUGIN_LINUX_ACPI_TABLE;
    length = sizeof acpi_rsdp_addr;
    vm_mwrite(instance,
        &acpi_rsdp_addr,
        guest_address,
        &length);
    CHK(sizeof acpi_rsdp_addr == length);

    guest_address = VM_PLUGIN_LINUX_BOOT_PARAMS + bp_e820_entries;
    e820_entries = sizeof e820_table / sizeof e820_table[0];
    length = sizeof e820_entries;
    vm_mwrite(instance,
        &e820_entries,
        guest_address,
        &length);
    CHK(sizeof e820_entries == length);
    guest_address = VM_PLUGIN_LINUX_BOOT_PARAMS + bp_e820_table;
    length = sizeof e820_table;
    vm_mwrite(instance,
        &e820_table,
        guest_address,
        &length);
    CHK(sizeof e820_table == length);

    memset(&setup_header, 0, sizeof setup_header);
    //setup_header.vid_mode = 0;
    setup_header.type_of_loader = 0xff;
    setup_header.cmd_line_ptr = VM_PLUGIN_LINUX_CMD_LINE;
    guest_address = VM_PLUGIN_LINUX_BOOT_PARAMS + bp_setup_header;
    length = sizeof setup_header;
    vm_mwrite(instance,
        &setup_header,
        guest_address,
        &length);
    CHK(sizeof setup_header == length);

    memset(&config, 0, sizeof config);
    config.vcpu_args[1] = VM_PLUGIN_LINUX_BOOT_PARAMS;
    config.vcpu_table = VM_PLUGIN_LINUX_VCPU_TABLE;
    config.vcpu_mailbox = VM_PLUGIN_LINUX_MAILBOX;
    vm_setconfig(instance, &config,
        VM_CONFIG_BIT(vcpu_args[1]) | VM_CONFIG_BIT(vcpu_table) | VM_CONFIG_BIT(vcpu_mailbox));

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

static vm_result_t vm_plugin_linux_setup_command_line(vm_t *instance, const char *cmd_line)
{
    vm_result_t result;
    vm_count_t guest_address, length, cmd_line_size;

    cmd_line_size = strlen(cmd_line) + 1;

    guest_address = VM_PLUGIN_LINUX_CMD_LINE;
    length = cmd_line_size;
    vm_mwrite(instance,
        (void *)cmd_line,
        guest_address,
        &length);
    CHK(cmd_line_size == length);

    result = VM_RESULT_SUCCESS;

exit:
    return result;
}

#undef CHK

struct vm_plugin_linux_data
{
    ioapic_t *apic;
    serial_t *port;
};

static vm_result_t vm_plugin_linux_infi(vm_t *instance, vm_count_t vcpu_index,
    int dir, vm_result_t result)
{
    if (~0ULL != vcpu_index)
        return VM_RESULT_SUCCESS;

    struct vm_plugin_linux_data *data = 0;

    if (+1 == dir)
    {
        data = malloc(sizeof *data);
        if (0 == data)
        {
            result = vm_result(VM_ERROR_RESOURCES, 0);
            goto exit;
        }

        result = ioapic_create(instance, &data->apic);
        if (!vm_result_check(result))
            goto exit;

        int fd[2] = { STDIN_FILENO, STDOUT_FILENO };
        result = serial_create(fd, data->apic, 4, &data->port);
        if (!vm_result_check(result))
            goto exit;

        *vm_context(instance) = data;
        data = 0;
    }
    else
    if (-1 == dir)
        data = *vm_context(instance);

    result = VM_RESULT_SUCCESS;

exit:
    if (0 != data)
    {
        if (0 != data->port)
            serial_delete(data->port);

        if (0 != data->apic)
            ioapic_delete(data->apic);

        free(data);
    }

    return result;
}

static vm_result_t vm_plugin_linux_mmio(vm_t *instance, vm_count_t vcpu_index,
    vm_count_t flags, vm_count_t address, vm_count_t length, void *buffer)
{
    if (VM_XMIO_RD == VM_XMIO_DIR(flags))
        memset(buffer, 0, length);

    struct vm_plugin_linux_data *data = *vm_context(instance);

    if (0xff >= address - 0xFEC00000)
        ioapic_io(data->apic, flags, address, buffer);

    return VM_RESULT_SUCCESS;
}

static vm_result_t vm_plugin_linux_pmio(vm_t *instance, vm_count_t vcpu_index,
    vm_count_t flags, vm_count_t address, vm_count_t length, void *buffer)
{
    if (VM_XMIO_RD == VM_XMIO_DIR(flags))
        memset(buffer, 0, length);

    struct vm_plugin_linux_data *data = *vm_context(instance);

    if (7 >= address - 0x3f8 && 1 == length)
        serial_io(data->port, flags, address, buffer);

    return VM_RESULT_SUCCESS;
}
