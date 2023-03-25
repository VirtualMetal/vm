goal: so lnx

so:
	$(MAKE) -f vm.so.mk

lnx: so
	$(MAKE) -f vm.lnx.mk
	$(MAKE) -C testing -f vm-tests.lnx.mk
