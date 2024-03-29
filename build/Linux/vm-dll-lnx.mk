Include = \
	../../inc/vm/vm.h \
	../../src/arch/arch.h \
	../../src/arch/x64.h \
	../../src/vm/internal.h
Compile = \
	../../src/vm/gdb.c \
	../../src/vm/library.c \
	../../src/vm/load.c \
	../../src/vm/result.c \
	../../src/vm/run.c \
	../../src/vm/textconf.c \
	../../src/vm/vm-lnx.c
Incdirs = ../../src ../../inc

CPPFLAGS = -DVM_API_INTERNAL
CFLAGS = -fpic
LDFLAGS = -shared
LDLIBS = -lpthread -ldl
include common.inc
