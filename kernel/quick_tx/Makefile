BUILD_KERNEL?=$(shell uname -r)
KSRC  ?= /lib/modules/$(BUILD_KERNEL)/build
PWD=$(shell pwd)

ifneq (,$(TCPR_DEBUG))
EXTRA_CFLAGS += -g -DHAVE_TCPR_DEBUG 
endif

ifneq ($(KERNELRELEASE),)
# kbuild part of makefile

obj-m += quick_tx.o
quick_tx-objs := quick_tx_main.o quick_tx_mmap.o quick_tx_worker.o

else
# normal makefile
modules:
	$(MAKE) -C $(KSRC) M=$(PWD) -I../include modules
endif
ifeq (.depend,$(wildcard .depend))
include .depend
endif
clean:
	@rm -rf *.o Module.symvers *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions modules.order Module.markers
