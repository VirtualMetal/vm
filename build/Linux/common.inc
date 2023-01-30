topdir := $(abspath $(strip $(foreach _,. .. ../.. ../../.. ../../../.. ../../../../.. ../../../../../..,\
	$(if $(wildcard $(_)/.git),$(_)/.git,)))/..)
makdir := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
comma := ,

Include := $(abspath $(Include))
Compile := $(abspath $(Compile))
Incdirs := $(abspath $(Incdirs))

ProjectName ?= $(basename $(notdir $(firstword $(MAKEFILE_LIST))))
TargetName ?= $(basename $(ProjectName))
Configuration ?= Debug
PlatformTarget ?= x64
OutDir ?= $(makdir)/build/$(Configuration)
IntDir ?= $(makdir)/build/$(ProjectName).build/$(Configuration)/$(PlatformTarget)

CC := /opt/x86_64-linux-musl-native/bin/g++
CC := $(if $(wildcard $(CC)),$(CC),g++)
CPPFLAGS ?=
CPPFLAGS += $(foreach _,$(Incdirs),-I$(abspath $(_)))
CPPFLAGS += $(if $(findstring Debug,$(Configuration)),,)
CPPFLAGS += $(if $(findstring Release,$(Configuration)),-DNDEBUG,)
CFLAGS ?=
CFLAGS += -xc -std=c11 -fno-strict-aliasing -fno-exceptions -fmacro-prefix-map=$(topdir)/= \
	-Wall -Wconversion -Wno-sign-conversion -Wno-pointer-sign
CFLAGS += $(if $(findstring Debug,$(Configuration)),-O0 -fno-omit-frame-pointer -g2 -gdwarf-2,)
CFLAGS += $(if $(findstring Release,$(Configuration)),-O3 -fomit-frame-pointer -g0,)
LDFLAGS ?= -static
LDFLAGS += -Wl,--no-undefined -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
LDFLAGS += $(if $(findstring Release,$(Configuration)),-Wl$(comma)--strip-all,)
LDLIBS ?= -lpthread

objmap = $(addprefix $(IntDir)/,$(notdir $(1:.c=.o)))
ccrule = $(call objmap,$(1)): $(1) $(Include) | $(IntDir); $(CC) $(CPPFLAGS) $(CFLAGS) -c -o $$@ $$<
Objects = $(call objmap,$(Compile))

$(ProjectName): $(OutDir)/$(TargetName)
$(OutDir)/$(TargetName): $(Objects) | $(OutDir); $(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
$(foreach _,$(Compile),$(eval $(call ccrule,$(_))))
$(OutDir) $(IntDir):; mkdir -p $@
