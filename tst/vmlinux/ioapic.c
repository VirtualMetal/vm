/**
 * @file vmlinux/ioapic.c
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

#define IOREGSEL                        0x00
#define IOWIN                           0x10
#define IOAPICID                        0x00
#define IOAPICVER                       0x01
#define IOAPICARB                       0x02
#define IOREDTBL                        0x10

struct ioapic
{
    vm_t *instance;
    pthread_mutex_t mutex;
    uint8_t ioregsel;
    uint32_t regs[64];
    unsigned
        has_mutex:1;
};

vm_result_t ioapic_create(vm_t *instance, ioapic_t **papic)
{
    vm_result_t result;
    ioapic_t *apic = 0;
    int error;

    *papic = 0;

    apic = malloc(sizeof *apic);
    if (0 == apic)
    {
        result = vm_result(VM_ERROR_RESOURCES, 0);
        goto exit;
    }

    memset(apic, 0, sizeof *apic);
    apic->instance = instance;
    apic->regs[IOAPICVER] = 0x00170011;

    error = pthread_mutex_init(&apic->mutex, 0);
    if (0 != error)
    {
        result = vm_result(VM_ERROR_RESOURCES, error);
        goto exit;
    }
    apic->has_mutex = 1;

    *papic = apic;
    result = VM_RESULT_SUCCESS;

exit:
    if (!vm_result_check(result) && 0 != apic)
        ioapic_delete(apic);

    return result;
}

vm_result_t ioapic_delete(ioapic_t *apic)
{
    if (apic->has_mutex)
        pthread_mutex_destroy(&apic->mutex);

    free(apic);

    return VM_RESULT_SUCCESS;
}

vm_result_t ioapic_io(ioapic_t *apic, vm_count_t flags, vm_count_t address, void *buffer)
{
    address &= 0xff;

    pthread_mutex_lock(&apic->mutex);

    switch (address)
    {
    case IOREGSEL:
        if (VM_XMIO_RD == VM_XMIO_DIR(flags))
            *(uint8_t *)buffer = apic->ioregsel;
        else
            apic->ioregsel = *(uint8_t *)buffer;
        break;
    case IOWIN:
        switch (apic->ioregsel)
        {
        case IOAPICVER: case IOAPICARB:
            if (VM_XMIO_RD == VM_XMIO_DIR(flags))
                *(uint32_t *)buffer = apic->regs[apic->ioregsel & 0x3f];
            break;
        default:
            if (VM_XMIO_RD == VM_XMIO_DIR(flags))
                *(uint32_t *)buffer = apic->regs[apic->ioregsel & 0x3f];
            else
            {
                apic->regs[apic->ioregsel & 0x3f] = *(uint32_t *)buffer;
                /* DELIVS and RemoteIRR are R/O; bits are reserved in high 32 bits; so all OK */
                apic->regs[apic->ioregsel & 0x3f] &= ~(0x5000);
            }
            break;
        }
        break;
    }

    pthread_mutex_unlock(&apic->mutex);

    return VM_RESULT_SUCCESS;
}

vm_result_t ioapic_irq(ioapic_t *apic, vm_count_t irq)
{
    vm_result_t result;
    vm_count_t vector;

    pthread_mutex_lock(&apic->mutex);

    vector = apic->regs[IOREDTBL + irq * 2] & 0xff;
    result = vm_interrupt(apic->instance, 0, vector);

    pthread_mutex_unlock(&apic->mutex);

    return result;
}
