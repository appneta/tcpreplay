# kernel/linux/quick_tx/Makefile.am

EXTRA_DIST = kcompat.h Makefile.kernel Makefile.common

EXTRA_PROGRAMS = automake_dummy 
automake_dummy_SOURCES = quick_tx_main.c \
						quick_tx_mmap.c \
						quick_tx_worker.c
					 
module_DATA = quick_tx.o 
module_OBJECTS = quick_tx_main.o \
				quick_tx_mmap.o \
				quick_tx_worker.o
include Makefile.common
