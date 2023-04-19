Include = \
	../../../inc/vm/vm.h \
	../../../inc/xp/platform.h \
	../../../inc/xp/utility.h \
	../../../inc/xp/xp.h \
	../../../tst/tlib/testsuite.h \
	../../../tst/vm-tests/vm-tests.h
Compile = \
	../../../tst/tlib/testsuite.c \
	../../../tst/vm-tests/debug-test.c \
	../../../tst/vm-tests/run-test.c \
	../../../tst/vm-tests/textconf-test.c \
	../../../tst/vm-tests/vm-tests.c
Incdirs = ../../../tst ../../../src ../../../inc

LDFLAGS = -Wl,-rpath,'$$ORIGIN' -L$(OutDir)
LDLIBS = -l:vm.so
include ../common.inc
