goal: dll exe

dll:
	$(MAKE) -f vm-dll-lnx.mk

exe: dll
	$(MAKE) -f vm-exe-lnx.mk
	$(MAKE) -C testing -f vm-tests-lnx.mk
