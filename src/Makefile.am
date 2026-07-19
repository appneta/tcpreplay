# $Id: Makefile.am 1632 2007-02-03 18:46:16Z aturner $
if COMPILE_FRAGROUTE
    LIBFRAGROUTE = ./fragroute/libfragroute.a @LDNETLIB@
    FRAGROUTE_DIR = fragroute
else
    LIBFRAGROUTE = 
    FRAGROUTE_DIR = 
endif

SUBDIRS = common tcpedit $(FRAGROUTE_DIR)

if SYSTEM_STRLCPY
LIBSTRL =
else
LIBSTRL = ../lib/libstrl.a
endif

BUILT_SOURCES = defines.h

manpages: tcpprep.1 tcprewrite.1 tcpreplay.1 tcpbridge.1 tcpreplay-edit.1 tcpliveplay.1 tcpcapinfo.1

autoopts: tcpreplay_opts.c tcprewrite_opts.c tcpbridge_opts.c tcpliveplay_opts.c tcpcapinfo_opts.c \
	manpages tcpreplay_edit_opts.c


# Get AutoOpts search path (still used by tcpedit_stub.h's autogen rule)
opts_list=-L tcpedit

# man-page source (AsciiDoc, generated from the .def like *_opts.c/h - see
# scripts/autoopts/README.md) and the rendered pages.  #895 phase 2: GNU
# autogen's man pipeline is replaced entirely; asciidoctor is only needed to
# (re)render the committed .adoc after a .def doc/descrip/explain/detail edit.
autoopts_dir = $(abs_top_srcdir)/scripts/autoopts

tcpprep.adoc: tcpprep_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_adoc.py tcpprep tcpprep_opts.def > tcpprep.adoc

tcpprep.1: tcpprep.adoc
	cd $(srcdir) && @ASCIIDOCTOR@ -b manpage -o tcpprep.1 tcpprep.adoc

tcprewrite.adoc: tcprewrite_opts.def tcpedit/tcpedit_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_adoc.py tcprewrite tcprewrite_opts.def > tcprewrite.adoc

tcprewrite.1: tcprewrite.adoc
	cd $(srcdir) && @ASCIIDOCTOR@ -b manpage -o tcprewrite.1 tcprewrite.adoc

tcpreplay-edit.adoc: tcpreplay_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_adoc.py tcpreplay-edit tcpreplay_opts.def TCPREPLAY_EDIT > tcpreplay-edit.adoc

tcpreplay-edit.1: tcpreplay-edit.adoc
	cd $(srcdir) && @ASCIIDOCTOR@ -b manpage -o tcpreplay-edit.1 tcpreplay-edit.adoc

tcpreplay.adoc: tcpreplay_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_adoc.py tcpreplay tcpreplay_opts.def > tcpreplay.adoc

tcpreplay.1: tcpreplay.adoc
	cd $(srcdir) && @ASCIIDOCTOR@ -b manpage -o tcpreplay.1 tcpreplay.adoc

tcpbridge.adoc: tcpbridge_opts.def tcpedit/tcpedit_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_adoc.py tcpbridge tcpbridge_opts.def > tcpbridge.adoc

tcpbridge.1: tcpbridge.adoc
	cd $(srcdir) && @ASCIIDOCTOR@ -b manpage -o tcpbridge.1 tcpbridge.adoc

tcpliveplay.adoc: tcpliveplay_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_adoc.py tcpliveplay tcpliveplay_opts.def > tcpliveplay.adoc

tcpliveplay.1: tcpliveplay.adoc
	cd $(srcdir) && @ASCIIDOCTOR@ -b manpage -o tcpliveplay.1 tcpliveplay.adoc

tcpcapinfo.adoc: tcpcapinfo_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_adoc.py tcpcapinfo tcpcapinfo_opts.def > tcpcapinfo.adoc

tcpcapinfo.1: tcpcapinfo.adoc
	cd $(srcdir) && @ASCIIDOCTOR@ -b manpage -o tcpcapinfo.1 tcpcapinfo.adoc

man_MANS = tcpreplay.1 tcpprep.1 tcprewrite.1 tcpreplay-edit.1 tcpcapinfo.1
EXTRA_DIST = tcpreplay.1 tcpprep.1 tcprewrite.1 tcpbridge.1 tcpreplay-edit.1 \
	tcpliveplay.1 tcpcapinfo.1 \
	tcpreplay.adoc tcpprep.adoc tcprewrite.adoc tcpbridge.adoc \
	tcpreplay-edit.adoc tcpliveplay.adoc tcpcapinfo.adoc
bin_PROGRAMS = tcpreplay tcpprep tcprewrite tcpreplay-edit tcpcapinfo

if COMPILE_TCPBRIDGE
bin_PROGRAMS += tcpbridge 
man_MANS += tcpbridge.1
endif

if COMPILE_TCPLIVEPLAY
bin_PROGRAMS += tcpliveplay
man_MANS += tcpliveplay.1
endif

tcpreplay_edit_CFLAGS = $(LIBOPTS_CFLAGS) -I$(srcdir)/.. -I$(srcdir)/tcpedit $(LNAV_CFLAGS) @LDNETINC@ -DTCPREPLAY -DTCPREPLAY_EDIT -DHAVE_CACHEFILE_SUPPORT
tcpreplay_edit_LDADD = ./tcpedit/libtcpedit.a ./common/libcommon.a $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@ $(LIBOPTS_LDADD)
tcpreplay_edit_SOURCES = tcpreplay_edit_opts.c send_packets.c signal_handler.c tcpreplay.c tcpreplay_api.c sleep.c replay.c
tcpreplay_edit_OBJECTS: tcpreplay_edit_opts.h

BUILT_SOURCES += tcpreplay_edit_opts.h
tcpreplay_edit_opts.h: tcpreplay_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_h.py tcpreplay_edit_opts tcpreplay_opts.def TCPREPLAY_EDIT > tcpreplay_edit_opts.h

tcpreplay_edit_opts.c: tcpreplay_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_c.py tcpreplay_edit_opts tcpreplay_opts.def TCPREPLAY_EDIT > tcpreplay_edit_opts.c

tcpreplay_CFLAGS = $(LIBOPTS_CFLAGS) -I$(srcdir)/.. $(LNAV_CFLAGS) @LDNETINC@ -DTCPREPLAY
tcpreplay_SOURCES = tcpreplay_opts.c send_packets.c signal_handler.c tcpreplay.c tcpreplay_api.c sleep.c replay.c
tcpreplay_LDADD = ./common/libcommon.a $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@ $(LIBOPTS_LDADD)
tcpreplay_OBJECTS: tcpreplay_opts.h

BUILT_SOURCES += tcpreplay_opts.h
tcpreplay_opts.h: tcpreplay_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_h.py tcpreplay_opts tcpreplay_opts.def > tcpreplay_opts.h

tcpreplay_opts.c: tcpreplay_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_c.py tcpreplay_opts tcpreplay_opts.def > tcpreplay_opts.c

if ENABLE_OSX_FRAMEWORKS
tcpreplay_LDFLAGS = -framework CoreServices -framework Carbon
tcpreplay_edit_LDFLAGS = -framework CoreServices -framework Carbon
endif

######################################################################
# libtcpreplay - installable static library exposing tcpreplay_api.h (#133)
#
# Additive: the tcpreplay binary keeps building from its own objects; the
# library recompiles the same engine sources (per-target flags give the
# objects unique names) plus everything from common/ so a single archive
# is self-contained apart from libpcap and (system) libopts.
######################################################################
lib_LIBRARIES = libtcpreplay.a
libtcpreplay_a_CFLAGS = $(LIBOPTS_CFLAGS) -I$(srcdir)/.. $(LNAV_CFLAGS) @LDNETINC@ -DTCPREPLAY
libtcpreplay_a_SOURCES = send_packets.c signal_handler.c tcpreplay_api.c sleep.c replay.c \
	libtcpreplay_globals.c \
	common/cidr.c common/err.c common/list.c common/cache.c common/services.c common/get.c \
	common/fakepcap.c common/fakepcapnav.c common/fakepoll.c common/xX.c common/utils.c \
	common/timer.c common/sendpacket.c common/dlt_names.c common/mac.c common/interface.c \
	common/flows.c common/txring.c
nodist_libtcpreplay_a_SOURCES = tcpreplay_opts.c common/git_version.c
if ENABLE_TCPDUMP
libtcpreplay_a_SOURCES += common/tcpdump.c
endif
if COMPILE_NETMAP
libtcpreplay_a_SOURCES += common/netmap.c
endif
if !SYSTEM_STRLCPY
libtcpreplay_a_SOURCES += ../lib/strlcpy.c ../lib/strlcat.c
endif
if NEED_LIBOPTS
# libopts tearoff builds aren't installed, so fold the tearoff into the
# archive to keep the installed library self-contained
nodist_libtcpreplay_a_SOURCES += ../libopts/libopts.c
endif

# public headers, installed under $(includedir)/tcpreplay preserving layout
# so the internal '#include <common/...>' / '#include "config.h"' includes
# resolve with the single -I from libtcpreplay.pc's Cflags
tcpreplayincludedir = $(includedir)/tcpreplay
nobase_tcpreplayinclude_HEADERS = tcpreplay_api.h tcpreplay.h tcpr.h common.h \
	common/cache.h common/cidr.h common/dlt_names.h common/err.h common/fakepcap.h \
	common/fakepcapnav.h common/fakepoll.h common/flows.h common/get.h common/interface.h \
	common/list.h common/mac.h common/netmap.h common/pcap_dlt.h common/sendpacket.h \
	common/services.h common/tcpdump.h common/timer.h common/txring.h common/utils.h \
	common/xX.h
nodist_tcpreplayinclude_HEADERS = defines.h config.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libtcpreplay.pc

tcpliveplay_CFLAGS = $(LIBOPTS_CFLAGS) -I$(srcdir)/.. $(LNAV_CFLAGS) -DTCPREPLAY -DTCPLIVEPLAY
tcpliveplay_SOURCES = tcpliveplay_opts.c tcpliveplay.c
tcpliveplay_LDADD = ./common/libcommon.a $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@ $(LIBOPTS_LDADD)
tcpliveplay_OBJECTS: tcpliveplay_opts.h

BUILT_SOURCES += tcpliveplay_opts.h
tcpliveplay_opts.h: tcpliveplay_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_h.py tcpliveplay_opts tcpliveplay_opts.def > tcpliveplay_opts.h

tcpliveplay_opts.c: tcpliveplay_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_c.py tcpliveplay_opts tcpliveplay_opts.def > tcpliveplay_opts.c


tcprewrite_CFLAGS = $(LIBOPTS_CFLAGS) -I$(srcdir)/.. -I$(srcdir)/tcpedit @LDNETINC@ $(LNAV_CFLAGS) -DTCPREWRITE -DHAVE_CACHEFILE_SUPPORT
tcprewrite_LDADD = ./tcpedit/libtcpedit.a ./common/libcommon.a \
	$(LIBSTRL) @LPCAPLIB@ $(LIBOPTS_LDADD) @DMALLOC_LIB@ \
	$(LIBFRAGROUTE)
tcprewrite_SOURCES = tcprewrite_opts.c tcprewrite.c 
tcprewrite_OBJECTS: tcprewrite_opts.h

BUILT_SOURCES += tcprewrite_opts.h
tcprewrite_opts.h: tcprewrite_opts.def tcpedit/tcpedit_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_h.py tcprewrite_opts tcprewrite_opts.def > tcprewrite_opts.h

tcprewrite_opts.c: tcprewrite_opts.def tcpedit/tcpedit_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_c.py tcprewrite_opts tcprewrite_opts.def > tcprewrite_opts.c

tcpcapinfo_CFLAGS = $(LIBOPTS_CFLAGS) -I$(srcdir)/.. $(LNAV_CFLAGS) @LDNETINC@ -DTCPCAPINFO
tcpcapinfo_LDADD = ./common/libcommon.a \
    $(LIBSTRL) @LPCAPLIB@ $(LIBOPTS_LDADD) @DMALLOC_LIB@
tcpcapinfo_SOURCES = tcpcapinfo_opts.c tcpcapinfo.c
tcpcapinfo_OBJECTS: tcpcapinfo_opts.h

BUILT_SOURCES += tcpcapinfo_opts.h
tcpcapinfo_opts.h: tcpcapinfo_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_h.py tcpcapinfo_opts tcpcapinfo_opts.def > tcpcapinfo_opts.h

tcpcapinfo_opts.c: tcpcapinfo_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_c.py tcpcapinfo_opts tcpcapinfo_opts.def > tcpcapinfo_opts.c

tcpprep_CFLAGS = $(LIBOPTS_CFLAGS) -I$(srcdir)/.. $(LNAV_CFLAGS) @LDNETINC@ -DTCPPREP
tcpprep_LDADD = ./common/libcommon.a \
    $(LIBSTRL) @LPCAPLIB@ $(LIBOPTS_LDADD) @DMALLOC_LIB@
tcpprep_SOURCES = tcpprep_opts.c tcpprep.c tree.c tcpprep_api.c
tcpprep_OBJECTS: tcpprep_opts.h

BUILT_SOURCES += tcpprep_opts.h
tcpprep_opts.h: tcpprep_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_h.py tcpprep_opts tcpprep_opts.def > tcpprep_opts.h

tcpprep_opts.c: tcpprep_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_c.py tcpprep_opts tcpprep_opts.def > tcpprep_opts.c

tcpbridge_CFLAGS = $(LIBOPTS_CFLAGS) -I$(srcdir)/.. -I$(srcdir)/tcpedit $(LNAV_CFLAGS) @LDNETINC@ -DTCPBRIDGE
tcpbridge_LDADD = ./tcpedit/libtcpedit.a ./common/libcommon.a \
    $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@ $(LIBOPTS_LDADD) @DMALLOC_LIB@
if ENABLE_OSX_FRAMEWORKS
tcpbridge_LDFLAGS = -framework CoreServices -framework Carbon
endif
tcpbridge_SOURCES = tcpbridge_opts.c tcpbridge.c bridge.c
tcpbridge_OBJECTS: tcpbridge_opts.h

BUILT_SOURCES += tcpbridge_opts.h
tcpbridge_opts.h: tcpbridge_opts.def tcpedit/tcpedit_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_h.py tcpbridge_opts tcpbridge_opts.def > tcpbridge_opts.h

tcpbridge_opts.c: tcpbridge_opts.def tcpedit/tcpedit_opts.def
	cd $(srcdir) && @PYTHON3@ $(autoopts_dir)/emit_c.py tcpbridge_opts tcpbridge_opts.def > tcpbridge_opts.c

noinst_HEADERS = tcpreplay.h tcpprep.h bridge.h defines.h tree.h tcpliveplay.h \
		 send_packets.h signal_handler.h common.h tcpreplay_opts.h tcpliveplay_opts.h \
		 tcpreplay_edit_opts.h tcprewrite.h tcprewrite_opts.h tcpprep_opts.h \
		 tcpprep_opts.def tcprewrite_opts.def tcpreplay_opts.def tcpliveplay_opts.def \
		 tcpbridge_opts.def tcpbridge.h tcpbridge_opts.h tcpr.h sleep.h tcpcapinfo_opts.h \
		 tcpcapinfo_opts.def replay.h tcpreplay_api.h tcpprep_api.h timestamp_trace.h \
		 msvc_inttypes.h msvc_stdint.h

MOSTLYCLEANFILES = *~ *.o

MAINTAINERCLEANFILES = Makefile.in tcpreplay_opts.h tcpreplay_opts.c tcpliveplay_opts.c \
		       tcprewrite_opts.c tcprewrite_opts.h tcpprep_opts.c tcpliveplay_opts.h tcpcapinfo_opts.h \
		       tcpcapinfo_opts.c tcpprep_opts.h tcpprep.1 tcpreplay.1 tcprewrite.1 tcpliveplay.1 tcpcapinfo.1 \
		       tcpbridge.1 tcpbridge_opts.h tcpbridge_opts.c \
			   tcpreplay_edit_opts.c tcpreplay_edit_opts.h \
			   tcpreplay-edit.1 \
			   tcpreplay.adoc tcpprep.adoc tcprewrite.adoc tcpliveplay.adoc \
			   tcpcapinfo.adoc tcpbridge.adoc tcpreplay-edit.adoc
