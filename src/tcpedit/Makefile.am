noinst_LIBRARIES = libtcpedit.a

libtcpedit_a_SOURCES = tcpedit.c tcpedit_opts.c parse_args.c edit_packet.c \
					   rewrite_l2.c portmap.c 

tcpedit_stub.h: tcpedit_stub.def
	@AUTOGEN@ tcpedit_stub.def

tcpedit_opts.h: tcpedit_stub.h tcpedit_opts.c
tcpedit_opts.c: tcpedit_opts.def
	@AUTOGEN@ tcpedit_opts.def

AM_CFLAGS = -I.. -I../common -I../.. 

noinst_HEADERS = tcpedit.h edit_packet.h rewrite_l2.h portmap.h \
				 tcpedit_stub.h tcpedit_opts.h parse_args.h

MOSTLYCLEANFILES = *~

MAINTAINERCLEANFILES = Makefile.in
