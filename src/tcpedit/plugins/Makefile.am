# $Id: $
noinst_LIBRARIES = libdltplugin.a

libdltplugin_a_SOURCES = dlt_plugins.c

noinst_HEADERS = dlt_plugins.h dlt_stub.h

dlt_plugins.c: dlt_stub.h

dlt_stub.h: dlt_opts.def dlt_stub.def
	@AUTOGEN@ dlt_stub.def

AM_CFLAGS = -I.. -I../.. -I../../.. -I../../common $(LIBOPTS_CFLAGS) 

EXTRA_DIST =

MOSTLYCLEANFILES = *~

MAINTAINERCLEANFILES = Makefile.in 

include $(srcdir)/dlt_en10mb/Makefile.am

