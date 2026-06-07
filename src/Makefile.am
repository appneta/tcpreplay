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

# tcpcapinfo, tcpliveplay, tcpprep, tcprewrite and tcpbridge have been migrated
# off AutoOpts: their man pages are rendered from hand-maintained AsciiDoc
# sources with asciidoctor instead of from the .def files.  The generated pages
# are shipped via EXTRA_DIST, so asciidoctor is only needed by maintainers
# (re)building them from source.
if HAVE_ASCIIDOCTOR
manpages: tcpprep.1 tcprewrite.1 tcpreplay.1 tcpbridge.1 tcpreplay-edit.1 tcpliveplay.1 tcpcapinfo.1

tcpcapinfo.1: $(top_srcdir)/docs/tcpcapinfo.1.adoc
	@ASCIIDOCTOR@ -b manpage -o $@ $<

tcpliveplay.1: $(top_srcdir)/docs/tcpliveplay.1.adoc
	@ASCIIDOCTOR@ -b manpage -o $@ $<

tcpprep.1: $(top_srcdir)/docs/tcpprep.1.adoc
	@ASCIIDOCTOR@ -b manpage -o $@ $<

tcprewrite.1: $(top_srcdir)/docs/tcprewrite.1.adoc $(top_srcdir)/docs/tcpedit_options.adoc
	@ASCIIDOCTOR@ -b manpage -o $@ $<

tcpbridge.1: $(top_srcdir)/docs/tcpbridge.1.adoc $(top_srcdir)/docs/tcpedit_options.adoc
	@ASCIIDOCTOR@ -b manpage -o $@ $<

tcpreplay.1: $(top_srcdir)/docs/tcpreplay.1.adoc
	@ASCIIDOCTOR@ -b manpage -o $@ $<

tcpreplay-edit.1: $(top_srcdir)/docs/tcpreplay-edit.1.adoc $(top_srcdir)/docs/tcpedit_options.adoc
	@ASCIIDOCTOR@ -b manpage -o $@ $<
else
manpages:
	@echo "asciidoctor not found: install it to (re)generate the man pages" >&2
endif

# Only install and distribute the man pages when they can actually be made
# available,
if BUILD_MANPAGES
man_MANS = tcpreplay.1 tcpprep.1 tcprewrite.1 tcpreplay-edit.1 tcpcapinfo.1
EXTRA_DIST = tcpreplay.1 tcpprep.1 tcprewrite.1 tcpbridge.1 tcpreplay-edit.1 \
	tcpliveplay.1 tcpcapinfo.1
endif
bin_PROGRAMS = tcpreplay tcpprep tcprewrite tcpreplay-edit tcpcapinfo

if COMPILE_TCPBRIDGE
bin_PROGRAMS += tcpbridge 
if BUILD_MANPAGES
man_MANS += tcpbridge.1
endif
endif

if COMPILE_TCPLIVEPLAY
bin_PROGRAMS += tcpliveplay
if BUILD_MANPAGES
man_MANS += tcpliveplay.1
endif
endif

# tcpreplay-edit shares tcpreplay's sources, compiled with -DTCPREPLAY_EDIT so
# the shared tcpedit options are pulled in (via tcpedit/tcpedit_args.c).
tcpreplay_edit_CFLAGS = -I$(srcdir)/.. -I$(srcdir)/tcpedit $(LNAV_CFLAGS) @LDNETINC@ -DTCPREPLAY -DTCPREPLAY_EDIT -DHAVE_CACHEFILE_SUPPORT
tcpreplay_edit_LDADD = ./tcpedit/libtcpedit.a ./common/libcommon.a $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@
tcpreplay_edit_SOURCES = tcpreplay_args.c send_packets.c signal_handler.c tcpreplay.c tcpreplay_api.c sleep.c replay.c

tcpreplay_CFLAGS = -I$(srcdir)/.. $(LNAV_CFLAGS) @LDNETINC@ -DTCPREPLAY
tcpreplay_SOURCES = tcpreplay_args.c send_packets.c signal_handler.c tcpreplay.c tcpreplay_api.c sleep.c replay.c
tcpreplay_LDADD = ./common/libcommon.a $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@

if ENABLE_OSX_FRAMEWORKS
tcpreplay_LDFLAGS = -framework CoreServices -framework Carbon
tcpreplay_edit_LDFLAGS = -framework CoreServices -framework Carbon
endif

tcpliveplay_CFLAGS = -I$(srcdir)/.. $(LNAV_CFLAGS) -DTCPREPLAY -DTCPLIVEPLAY
tcpliveplay_SOURCES = tcpliveplay_args.c tcpliveplay.c
tcpliveplay_LDADD = ./common/libcommon.a $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@


tcprewrite_CFLAGS = -I$(srcdir)/.. -I$(srcdir)/tcpedit @LDNETINC@ $(LNAV_CFLAGS) -DTCPREWRITE -DHAVE_CACHEFILE_SUPPORT
tcprewrite_LDADD = ./tcpedit/libtcpedit.a ./common/libcommon.a \
	$(LIBSTRL) @LPCAPLIB@ @DMALLOC_LIB@ \
	$(LIBFRAGROUTE)
tcprewrite_SOURCES = tcprewrite_args.c tcprewrite.c

tcpcapinfo_CFLAGS = -I$(srcdir)/.. $(LNAV_CFLAGS) @LDNETINC@ -DTCPCAPINFO
tcpcapinfo_LDADD = ./common/libcommon.a \
    $(LIBSTRL) @LPCAPLIB@ @DMALLOC_LIB@
tcpcapinfo_SOURCES = tcpcapinfo_args.c tcpcapinfo.c

tcpprep_CFLAGS = -I$(srcdir)/.. $(LNAV_CFLAGS) @LDNETINC@ -DTCPPREP
tcpprep_LDADD = ./common/libcommon.a \
    $(LIBSTRL) @LPCAPLIB@ @DMALLOC_LIB@
tcpprep_SOURCES = tcpprep_args.c tcpprep.c tree.c tcpprep_api.c

tcpbridge_CFLAGS = -I$(srcdir)/.. -I$(srcdir)/tcpedit $(LNAV_CFLAGS) @LDNETINC@ -DTCPBRIDGE
tcpbridge_LDADD = ./tcpedit/libtcpedit.a ./common/libcommon.a \
    $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@ @DMALLOC_LIB@
if ENABLE_OSX_FRAMEWORKS
tcpbridge_LDFLAGS = -framework CoreServices -framework Carbon
endif
tcpbridge_SOURCES = tcpbridge_args.c tcpbridge.c bridge.c

noinst_HEADERS = tcpreplay.h tcpprep.h bridge.h defines.h tree.h tcpliveplay.h \
		 send_packets.h signal_handler.h common.h tcprewrite.h \
		 tcpbridge.h tcpr.h sleep.h \
		 tcpcapinfo_args.h tcpliveplay_args.h tcpprep_args.h \
		 tcprewrite_args.h tcpbridge_args.h tcpreplay_args.h \
		 replay.h tcpreplay_api.h tcpprep_api.h timestamp_trace.h \
		 msvc_inttypes.h msvc_stdint.h

MOSTLYCLEANFILES = *~ *.o

MAINTAINERCLEANFILES = Makefile.in \
		       tcpprep.1 tcpreplay.1 tcprewrite.1 tcpliveplay.1 tcpcapinfo.1 \
		       tcpbridge.1 tcpreplay-edit.1
