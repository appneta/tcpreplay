# $Id: Makefile.am 1472 2006-06-11 23:14:48Z aturner $
noinst_LIBRARIES = libflow.a

libflow_a_SOURCES = flownode.c flowstate.c flowbuff.c flowkey.c

AM_CFLAGS = -I.. -I../.. $(LNAV_CFLAGS)

libflow_a_LIBADD = ../../lib/libstrl.a

noinst_HEADERS = flownode.h flowstate.h flowbuff.h flowkey.h

MOSTLYCLEANFILES = *~

MAINTAINERCLEANFILES = Makefile.in 
