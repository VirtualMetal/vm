/**
 * @file vm/macos/vm.c
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

struct Vm
{
};

struct VmCpu
{
};

VmResult VmCreate(const VmConfig *Config, Vm **PInstance)
{
}

VmResult VmDestroy(Vm *Instance)
{
}

VmResult VmCpuCreate(Vm *Instance, VmCpu **PCpu)
{
}

VmResult VmCpuDestroy(VmCpu *Cpu)
{
}

VmResult VmCpuRun(VmCpu *Cpu, const VmCpuEvents *Events)
{
}

VmResult VmCpuStop(VmCpu *Cpu)
{
}
