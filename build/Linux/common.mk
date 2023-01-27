commondir := $(dir $(lastword $(MAKEFILE_LIST)))
comma := ,

ProjectName ?= $(basename $(notdir $(firstword $(MAKEFILE_LIST))))
TargetName ?= $(basename $(ProjectName))
Configuration ?= Debug
PlatformTarget ?= x64
OutDir ?= $(commondir)build/$(Configuration)
IntDir ?= $(commondir)build/$(ProjectName).build/$(Configuration)/$(PlatformTarget)

CC := /opt/x86_64-linux-musl-native/bin/g++
CC := $(if $(wildcard $(CC)),$(CC),g++)
CPPFLAGS ?= -I$(commondir)../../src -I$(commondir)../../inc
CFLAGS ?= -xc -std=c11 -Wall
CFLAGS += $(if $(findstring Debug,$(Configuration)),-g,)
CFLAGS += $(if $(findstring Release,$(Configuration)),-O3,)
LDFLAGS ?= -static
LDFLAGS += $(if $(findstring Release,$(Configuration)),-Wl$(comma)--strip-all,)
LDLIBS ?= -lpthread

objmap = $(addprefix $(IntDir)/,$(notdir $(1:.c=.o)))
ccrule = $(call objmap,$(1)): $(1) $(Include) | $(IntDir); $(CC) $(CPPFLAGS) $(CFLAGS) -c -o $$@ $$<
Objects = $(call objmap,$(Compile))

$(ProjectName): $(OutDir)/$(TargetName)
$(OutDir)/$(TargetName): $(Objects) | $(OutDir); $(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
$(foreach _,$(Compile),$(eval $(call ccrule,$(_))))
$(OutDir) $(IntDir):; mkdir -p $@
