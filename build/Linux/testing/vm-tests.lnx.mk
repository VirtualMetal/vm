Include = \
	../../../inc/vm/vm.h \
	../../../src/arch/arch.h \
	../../../src/arch/x64.h \
	../../../src/tlib/testsuite.h \
	../../../src/vm/internal.h \
	../../../tst/vm-tests/vm-tests.h
Compile = \
	../../../src/tlib/testsuite.c \
	../../../src/vm/gdb.c \
	../../../src/vm/load.c \
	../../../src/vm/result.c \
	../../../src/vm/run.c \
	../../../src/vm/textconf.c \
	../../../src/vm/vm-lnx.c \
	../../../tst/vm-tests/debug-test.c \
	../../../tst/vm-tests/run-test.c \
	../../../tst/vm-tests/textconf-test.c \
	../../../tst/vm-tests/vm-tests.c
Incdirs = ../../../tst ../../../src ../../../inc

include ../common.inc
