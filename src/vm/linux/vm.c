/**
 * @file vm/linux/vm.c
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

#include <vm/vm.h>
#include <vm/internal.h>
#include <linux/kvm.h>

struct Vm
{
    VmConfig Config;
    int Hvfd;
    int Vmfd;
};

VmResult VmCreate(const VmConfig *Config, Vm **PInstance)
{
    VmResult Result;
    Vm *Instance = 0;

    *PInstance = 0;

    Instance = malloc(sizeof *Instance);
    if (0 == Instance)
    {
        Result = VmErrorMemory;
        goto exit;
    }

    memset(Instance, 0, sizeof *Instance);
    Instance->Hvfd = -1;
    Instance->Vmfd = -1;
    Instance->Config = *Config;

    if (0 == Instance->Config.CpuCount)
    {
        cpu_set_t Affinity;

        CPU_ZERO(&Affinity);
        if (-1 == sched_getaffinity(0, sizeof Affinity, &Affinity))
        {
            Result = VmMakeResult(VmErrorInstance, errno);
            goto exit;
        }

        Instance->Config.CpuCount = (VmCount)CPU_COUNT(&Affinity);
    }
    if (0 == Instance->Config.CpuCount)
        Instance->Config.CpuCount = 1;

    Instance->Hvfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (-1 == Instance->Hvfd)
    {
        Result = VmMakeResult(VmErrorHypervisor, errno);
        goto exit;
    }

    if (12 != ioctl(Instance->Hvfd, KVM_GET_API_VERSION, NULL))
    {
        Result = VmErrorHypervisor;
        goto exit;
    }

    Instance->Vmfd = ioctl(Instance->Hvfd, KVM_CREATE_VM, NULL);
    if (-1 != Instance->Vmfd)
    {
        Result = VmMakeResult(VmErrorInstance, errno);
        goto exit;
    }

    *PInstance = Instance;
    Result = VmResultSuccess;

exit:
    if (VmResultSuccess != Result && 0 != Instance)
        VmDelete(Instance);

    return Result;
}

VmResult VmDelete(Vm *Instance)
{
    if (-1 != Instance->Vmfd)
        close(Instance->Vmfd);

    if (-1 != Instance->Hvfd)
        close(Instance->Hvfd);

    free(Instance);

    return VmResultSuccess;
}

VmResult VmSetDebugLog(Vm *Instance, unsigned Flags)
{
    return VmErrorNotImpl;
}

VmResult VmStartDispatcher(Vm *Instance)
{
    return VmErrorNotImpl;
}

VmResult VmWaitDispatcher(Vm *Instance)
{
    return VmErrorNotImpl;
}

VmResult VmStopDispatcher(Vm *Instance)
{
    return VmErrorNotImpl;
}
