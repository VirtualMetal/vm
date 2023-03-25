Include = \
	../../../inc/vm/vm.h \
	../../../src/tlib/testsuite.h \
	../../../tst/vm-tests/vm-tests.h
Compile = \
	../../../src/tlib/testsuite.c \
	../../../tst/vm-tests/debug-test.c \
	../../../tst/vm-tests/run-test.c \
	../../../tst/vm-tests/textconf-test.c \
	../../../tst/vm-tests/vm-tests.c
Incdirs = ../../../tst ../../../src ../../../inc

LDFLAGS = -Wl,-rpath,'$$ORIGIN' -L$(OutDir)
LDLIBS = -l:vm.so
include ../common.inc
