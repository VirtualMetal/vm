goal: dll exe tst

dll:
	$(MAKE) -f vm-dll-lnx.mk

exe: dll
	$(MAKE) -f vm-exe-lnx.mk

tst: dll
	$(MAKE) -C testing -f vm-tests-lnx.mk
	$(MAKE) -C testing -f vmlinux-dll-lnx.mk
