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
#include <lib/hv/minimal.h>

static const char *basename(const char *path)
{
	for (const char *p = path; *p; p++)
		switch (*p)
		{
		case '/':
#if defined(_WIN64) || defined(_WIN32)
		case '\\':
#endif
			path = p + 1;
			break;
		}
	return path;
}

static const char *baseext(const char *path)
{
	for (const char *p = path; *p; p++)
		switch (*p)
		{
		case '.':
			path = p;
			break;
		}
	return path;
}

int vmrun(int argc, char **argv)
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

	VmSetDebugLog(Instance, -1);

	Result = VmStartDispatcher(Instance);
	if (VmResultSuccess != Result)
		goto exit;

	VmWaitDispatcher(Instance);

	VmStopDispatcher(Instance);

exit:
	if (0 == Instance)
		VmDelete(Instance);

	return VmResultSuccess == Result ? 0 : 1;
}

int main(int argc, char **argv)
{
	const char *progname, *command;

	progname = basename(argv[0]);
	*(char *)baseext(progname) = '\0';
	if ('v' == progname[0] && 'm' == progname[1] && '\0' != progname[2])
		command = progname + 2;
	else if (2 <= argc)
		command = argv[1];
	else
		goto usage;

	if (0 == strcmp("run", command))
		return vmrun(argc - 1, argv + 1);
	else
		goto usage;

	return 0;

usage:
	return 2;
}

EXEMAIN;
