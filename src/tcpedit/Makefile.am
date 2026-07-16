# $Id: Makefile.am 1630 2007-02-03 04:23:14Z aturner $
#SUBDIRS = plugins

noinst_LIBRARIES = libtcpedit.a

libtcpedit_a_SOURCES = tcpedit.c tcpedit_args.c parse_args.c edit_packet.c \
	portmap.c dlt.c checksum.c incremental_checksum.c \
	tcpedit_api.c fuzzing.c rewrite_sequence.c

# tcpedit_stub.h is a hand-maintained source (src/tcpedit/tcpedit_stub.h)
# providing the AutoOpts-compatible accessor macros backed by the getopt_long
# parser in tcpedit_args.c.  There is no generated tcpedit.1 man page: the
# tcpedit options are documented in docs/tcpedit_options.adoc, included by the
# tcprewrite/tcpbridge/tcpreplay-edit AsciiDoc man pages.

AM_CFLAGS = -I$(srcdir). -I$(srcdir)/.. -I$(srcdir)/../common -I$(srcdir)/../.. @LDNETINC@ $(LNAV_CFLAGS)

noinst_HEADERS = tcpedit.h edit_packet.h portmap.h \
	tcpedit_stub.h tcpedit_args.h parse_args.h dlt.h checksum.h \
	incremental_checksum.h tcpedit_api.h \
	tcpedit_types.h plugins.h plugins_api.h \
	plugins_types.h fuzzing.h rewrite_sequence.h

MOSTLYCLEANFILES = *~

MAINTAINERCLEANFILES = Makefile.in

include plugins/Makefile.am

