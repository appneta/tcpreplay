noinst_LIBRARIES = libcommon.a

libcommon_a_SOURCES = cidr.c err.c list.c cache.c services.c \
		      fakepcap.c fakepcapnav.c fakepoll.c xX.c utils.c \
		      tcpdump.c

AM_CFLAGS = -I.. -I../..

libcommon_a_LIBADD = ../../lib/libstrl.a

noinst_HEADERS = cidr.h err.h list.h cache.h services.h \
		 fakepcap.h fakepcapnav.h fakepoll.h xX.h utils.h \
		 tcpdump.h

MOSTLYCLEANFILES = *~

MAINTAINERCLEANFILES = Makefile.in
