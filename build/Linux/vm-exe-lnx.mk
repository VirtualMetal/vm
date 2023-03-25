Include = \
	../../inc/vm/vm.h \
	../../src/vm/internal.h
Compile = \
	../../src/vm/program.c
Incdirs = ../../src ../../inc

LDFLAGS = -Wl,-rpath,'$$ORIGIN' -L$(OutDir)
LDLIBS = -l:vm.so
include common.inc
