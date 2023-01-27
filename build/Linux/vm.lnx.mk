Include = \
	../../inc/vm/vm.h \
	../../src/arch/arch.h \
	../../src/arch/x64.h \
	../../src/vm/internal.h
Compile = \
	../../src/vm/gdb.c \
	../../src/vm/lnxvm.c \
	../../src/vm/load.c \
	../../src/vm/program.c \
	../../src/vm/result.c \
	../../src/vm/run.c \
	../../src/vm/textconf.c

include common.mk
