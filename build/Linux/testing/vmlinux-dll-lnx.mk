Include = \
	../../../inc/vm/vm.h \
	../../../inc/xp/platform.h \
	../../../inc/xp/utility.h \
	../../../inc/xp/xp.h \
	../../../tst/vmlinux/plugin.h
Compile = \
	../../../tst/vmlinux/ioapic.c \
	../../../tst/vmlinux/linux.c \
	../../../tst/vmlinux/plugin.c \
	../../../tst/vmlinux/serial.c
Incdirs = ../../../tst ../../../src ../../../inc

CFLAGS = -fpic
LDFLAGS = -shared -L$(OutDir)
LDLIBS = -l:vm.so -lpthread
include ../common.inc
