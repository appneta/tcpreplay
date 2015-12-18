# $Id: Makefile.am 1630 2007-02-03 04:23:14Z aturner $
#SUBDIRS = plugins

noinst_LIBRARIES = libtcpedit.a

BUILT_SOURCES = tcpedit_stub.h

libtcpedit_a_SOURCES = tcpedit.c parse_args.c edit_packet.c \
	portmap.c dlt.c checksum.c incremental_checksum.c \
	tcpedit_api.c

manpages: tcpedit.1

tcpedit.1: tcpedit_stub.def
	@AUTOGEN@  -T agman1.tpl --base-name tcpedit tcpedit_stub.def

tcpedit.c: tcpedit_stub.h

# Get AutoOpts search path
#opts_list=`find plugins -type d -not -regex ".*\.svn.*" -not -regex ".*\.deps.*" -exec echo -n "-L {} " \;`

tcpedit_stub.h: tcpedit_opts.def tcpedit_stub.def $(srcdir)/plugins/dlt_stub.def
	@AUTOGEN@ $(opts_list) tcpedit_stub.def

AM_CFLAGS = -I.. -I../common -I../.. @LDNETINC@ $(LIBOPTS_CFLAGS) $(LNAV_CFLAGS)

noinst_HEADERS = tcpedit.h edit_packet.h portmap.h \
	tcpedit_stub.h parse_args.h dlt.h checksum.h \
	incremental_checksum.h tcpedit_api.h \
	tcpedit_types.h plugins.h plugins_api.h plugins_types.h

MOSTLYCLEANFILES = *~

MAINTAINERCLEANFILES = Makefile.in tcpedit_stub.h tcpedit.1

EXTRA_DIST = tcpedit_stub.def tcpedit_opts.def

include $(srcdir)/plugins/Makefile.am

