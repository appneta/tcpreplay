BUILD_KERNEL?=$(shell uname -r)
KSRC  ?= /lib/modules/$(BUILD_KERNEL)/build
PWD?=$(shell pwd)

# The following commands are needed to build the modules as out-of-tree
M:=$(PWD)

# Additional compile flags (e.g. header location)
EXTRA_CFLAGS := -I$(M) -I$(M)/../include 
EXTRA_CFLAGS += -Wno-unused-but-set-variable

ifneq (,$(QUICK_TX_DEBUG))
EXTRA_CFLAGS += "-DQUICK_TX_DEBUG -g"
endif

ifneq ($(KERNELRELEASE),)
# kbuild part of makefile

obj-m += quick_tx.o
quick_tx-objs := quick_tx_main.o quick_tx_mmap.o quick_tx_worker.o

else
# normal makefile
modules:
	$(MAKE) -C $(KSRC) M=$(PWD) modules
endif
ifeq (.depend,$(wildcard .depend))
include .depend
endif
clean:
	@rm -rf *.o Module.symvers *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions modules.order Module.markers
