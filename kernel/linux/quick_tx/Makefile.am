# kernel/linux/quick_tx/Makefile.am

EXTRA_DIST = kcompat.h Makefile.kernel Makefile.common

EXTRA_PROGRAMS = automake_dummy 
automake_dummy_SOURCES = quick_tx_main.c \
						quick_tx_mmap.c \
						quick_tx_worker.c \
						quick_tx_worker_e1000.c \
						quick_tx_worker_virtio_net.c
					 
module_DATA = quick_tx.o 
module_OBJECTS = quick_tx_main.o \
				quick_tx_mmap.o \
				quick_tx_worker.o \
				quick_tx_worker_e1000.o \
				quick_tx_worker_virtio_net.o
				
include Makefile.common
