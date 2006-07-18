# $Id$
noinst_LIBRARIES = libtcpedit.a

libtcpedit_a_SOURCES = tcpedit.c parse_args.c edit_packet.c \
	rewrite_l2.c portmap.c ../mac.c dlt.c

manpages: tcpedit.1

tcpedit.1: tcpedit_stub.def
	@AUTOGEN@  -T agman1.tpl --base-name tcpedit tcpedit_stub.def

tcpedit_stub.h: tcpedit_opts.def
	@AUTOGEN@ tcpedit_stub.def

AM_CFLAGS = -I.. -I../common -I../.. $(LIBOPTS_CFLAGS)

noinst_HEADERS = tcpedit.h edit_packet.h rewrite_l2.h portmap.h \
	tcpedit_stub.h parse_args.h dlt.h

MOSTLYCLEANFILES = *~

MAINTAINERCLEANFILES = Makefile.in tcpedit_stub.h tcpedit.1

EXTRA_DIST = tcpedit_stub.def tcpedit_opts.def
