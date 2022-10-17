/**
 * @file vm/program.c
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

static int vmrun(int argc, char **argv)
{
	VmResult Result;
	VmConfig Config;
	Vm *Instance = 0;

	memset(&Config, 0, sizeof Config);
	Config.CpuCount = 1;
	Config.MemorySize = 4096;

	Result = VmCreate(&Config, &Instance);
	if (VmResultSuccess != Result)
		goto exit;

	VmSetDebugLog(Instance, (unsigned)-1);

	Result = VmStartDispatcher(Instance);
	if (VmResultSuccess != Result)
		goto exit;

	VmWaitDispatcher(Instance);

	VmStopDispatcher(Instance);

exit:
	if (0 != Instance)
		VmDelete(Instance);

	return VmResultSuccess == Result ? 0 : 1;
}

int main(int argc, char **argv)
{
	return vmrun(argc, argv);
}

EXEMAIN;
