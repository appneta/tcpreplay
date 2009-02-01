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

manpages: tcpprep.1 tcprewrite.1 tcpreplay.1 tcpbridge.1 tcpreplay-edit.1

autoopts: tcpreplay_opts.c tcprewrite_opts.c tcpbridge_opts.c manpages \
	tcpreplay_edit_opts.c


# Get AutoOpts search path
opts_list=-L tcpedit

tcpprep.1: tcpprep_opts.def
	@AUTOGEN@ -T agman1.tpl $(opts_list) --base-name tcpprep tcpprep_opts.def

tcprewrite.1: tcprewrite_opts.def tcpedit/tcpedit_opts.def
	@AUTOGEN@ -T agman1.tpl $(opts_list) --base-name tcprewrite tcprewrite_opts.def

tcpreplay-edit.1: tcpreplay_opts.def
	@AUTOGEN@ -T agman1.tpl $(opts_list) -DTCPREPLAY_EDIT --base-name tcpreplay-edit tcpreplay_opts.def

tcpreplay.1: tcpreplay_opts.def
	@AUTOGEN@ -T agman1.tpl $(opts_list) --base-name tcpreplay tcpreplay_opts.def

tcpbridge.1: tcpbridge_opts.def tcpedit/tcpedit_opts.def
	@AUTOGEN@ -T agman1.tpl $(opts_list) --base-name tcpbridge tcpbridge_opts.def

man_MANS = tcpreplay.1 tcpprep.1 tcprewrite.1 tcpreplay-edit.1
EXTRA_DIST = tcpreplay.1 tcpprep.1 tcprewrite.1 tcpbridge.1 tcpreplay-edit.1
bin_PROGRAMS = tcpreplay tcpprep tcprewrite tcpreplay-edit

if COMPILE_TCPBRIDGE
bin_PROGRAMS += tcpbridge
man_MANS += tcpbridge.1
endif

tcpreplay_edit_CFLAGS = $(LIBOPTS_CFLAGS) -I.. $(LNAV_CFLAGS) @LDNETINC@ -DTCPREPLAY -DTCPREPLAY_EDIT
tcpreplay_edit_LDADD = ./tcpedit/libtcpedit.a ./common/libcommon.a $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@ $(LIBOPTS_LDADD)
tcpreplay_edit_SOURCES = tcpreplay_edit_opts.c send_packets.c signal_handler.c tcpreplay.c sleep.c
tcpreplay_edit_OBJECTS: tcpreplay_opts.h
tcpreplay_edit_opts.h: tcpreplay_edit_opts.c

tcpreplay_edit_opts.c: tcpreplay_opts.def
	@AUTOGEN@ $(opts_list) -DTCPREPLAY_EDIT -b tcpreplay_edit_opts \
		tcpreplay_opts.def

tcpreplay_CFLAGS = $(LIBOPTS_CFLAGS) -I.. $(LNAV_CFLAGS) @LDNETINC@ -DTCPREPLAY
tcpreplay_SOURCES = tcpreplay_opts.c send_packets.c signal_handler.c tcpreplay.c sleep.c
tcpreplay_LDADD = ./common/libcommon.a $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@ $(LIBOPTS_LDADD)
tcpreplay_OBJECTS: tcpreplay_opts.h
tcpreplay_opts.h: tcpreplay_opts.c

tcpreplay_opts.c: tcpreplay_opts.def
	@AUTOGEN@ $(opts_list) tcpreplay_opts.def

if ENABLE_OSX_FRAMEWORKS
tcpreplay_LDFLAGS = -framework CoreServices -framework Carbon
tcpreplay_edit_LDFLAGS = -framework CoreServices -framework Carbon
endif


tcprewrite_CFLAGS = $(LIBOPTS_CFLAGS) -I.. @LDNETINC@ $(LNAV_CFLAGS) -DTCPREWRITE -DHAVE_CACHEFILE_SUPPORT
tcprewrite_LDADD = ./tcpedit/libtcpedit.a ./common/libcommon.a \
	$(LIBSTRL) @LPCAPLIB@ $(LIBOPTS_LDADD) @DMALLOC_LIB@ \
	$(LIBFRAGROUTE)
tcprewrite_SOURCES = tcprewrite_opts.c tcprewrite.c 
tcprewrite_OBJECTS: tcprewrite_opts.h
tcprewrite_opts.h: tcprewrite_opts.c
tcprewrite_opts.c: tcprewrite_opts.def tcpedit/tcpedit_opts.def
	@AUTOGEN@ $(opts_list) tcprewrite_opts.def


tcpprep_CFLAGS = $(LIBOPTS_CFLAGS) -I.. $(LNAV_CFLAGS) @LDNETINC@ -DTCPPREP
tcpprep_LDADD = ./common/libcommon.a \
    $(LIBSTRL) @LPCAPLIB@ $(LIBOPTS_LDADD) @DMALLOC_LIB@
tcpprep_SOURCES = tcpprep_opts.c tcpprep.c tree.c 
tcpprep_OBJECTS: tcpprep_opts.h
tcpprep_opts.h: tcpprep_opts.c
tcpprep_opts.c: tcpprep_opts.def
	@AUTOGEN@ tcpprep_opts.def

tcpbridge_CFLAGS = $(LIBOPTS_CFLAGS) -I.. $(LNAV_CFLAGS) @LDNETINC@ -DTCPBRIDGE
tcpbridge_LDADD = ./tcpedit/libtcpedit.a ./common/libcommon.a \
    $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@ $(LIBOPTS_LDADD) @DMALLOC_LIB@
if ENABLE_OSX_FRAMEWORKS
tcpbridge_LDFLAGS = -framework CoreServices -framework Carbon
endif
tcpbridge_SOURCES = tcpbridge_opts.c tcpbridge.c bridge.c send_packets.c sleep.c
tcpbridge_OBJECTS: tcpbridge_opts.h
tcpbridge_opts.h: tcpbridge_opts.c
tcpbridge_opts.c: tcpbridge_opts.def tcpedit/tcpedit_opts.def
	@AUTOGEN@ $(opts_list) tcpbridge_opts.def

noinst_HEADERS = tcpreplay.h tcpprep.h bridge.h defines.h tree.h \
		 send_packets.h signal_handler.h common.h tcpreplay_opts.h \
		 tcpreplay_edit_opts.h tcprewrite.h tcprewrite_opts.h tcpprep_opts.h \
		 tcpprep_opts.def tcprewrite_opts.def tcpreplay_opts.def \
		 tcpbridge_opts.def tcpbridge.h tcpbridge_opts.h tcpr.h sleep.h


MOSTLYCLEANFILES = *~ *.o

MAINTAINERCLEANFILES = Makefile.in tcpreplay_opts.h tcpreplay_opts.c \
		       tcprewrite_opts.c tcprewrite_opts.h tcpprep_opts.c \
		       tcpprep_opts.h tcpprep.1 tcpreplay.1 tcprewrite.1 \
		       tcpbridge.1 tcpbridge_opts.h tcpbridge_opts.c \
			   tcpreplay_edit_opts.c tcpreplay_edit_opts.h \
			   tcpreplay-edit.1
