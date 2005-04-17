SUBDIRS = common

if SYSTEM_STRLCPY
LIBSTRL =
else
LIBSTRL = ../lib/libstrl.a
endif

manpages: tcpprep.1 tcprewrite.1 tcpreplay.1 flowreplay.1 tcpbridge.1

tcpprep.1: tcpprep_opts.def
	@AUTOGEN@ -T agman1.tpl --base-name tcpprep tcpprep_opts.def

tcprewrite.1: tcprewrite_opts.def
	@AUTOGEN@ -T agman1.tpl --base-name tcprewrite tcprewrite_opts.def

tcpreplay.1: tcpreplay_opts.def
	@AUTOGEN@ -T agman1.tpl --base-name tcpreplay tcpreplay_opts.def

flowreplay.1: flowreplay_opts.def
	@AUTOGEN@ -T agman1.tpl --base-name flowreplay flowreplay_opts.def

tcpbridge.1: tcpbridge_opts.def
	@AUTOGEN@ -T agman1.tpl --base-name tcpbridge tcpbridge_opts.def

man_MANS = tcpreplay.1 tcpprep.1 tcprewrite.1 flowreplay.1 tcpbridge.1
EXTRA_DIST = tcpreplay.1 tcpprep.1 tcprewrite.1 flowreplay.1 tcpbridge.1

bin_PROGRAMS = tcpreplay tcpprep flowreplay tcprewrite tcpbridge

tcpreplay_CFLAGS = $(LIBOPTS_CFLAGS) -I.. -DTCPREPLAY
tcpreplay_LDADD = ./common/libcommon.a $(LIBSTRL) \
		  @LNETLIB@ @LPCAPLIB@ $(LIBOPTS_LDADD)
tcpreplay_SOURCES = tcpreplay_opts.c send_packets.c signal_handler.c tcpreplay.c
tcpreplay_OBJECTS: tcpreplay_opts.h
tcpreplay_opts.h: tcpreplay_opts.c
tcpreplay_opts.c: tcpreplay_opts.def
	@AUTOGEN@ tcpreplay_opts.def


tcprewrite_CFLAGS = $(LIBOPTS_CFLAGS) -I.. -DTCPREWRITE
tcprewrite_LDADD = ./common/libcommon.a $(LIBSTRL) \
		  @LNETLIB@ @LPCAPLIB@ $(LIBOPTS_LDADD)
tcprewrite_SOURCES = tcprewrite_opts.c tcprewrite.c mac.c portmap.c \
		     edit_packet.c rewrite_l2.c
tcprewrite_OBJECTS: tcprewrite_opts.h
tcprewrite_opts.h: tcprewrite_opts.c
tcprewrite_opts.c: tcprewrite_opts.def
	@AUTOGEN@ tcprewrite_opts.def


tcpprep_CFLAGS = $(LIBOPTS_CFLAGS) -I.. -DTCPPREP
tcpprep_LDADD = ./common/libcommon.a $(LIBSTRL) \
		  @LNETLIB@ @LPCAPLIB@ $(LIBOPTS_LDADD)
tcpprep_SOURCES = tcpprep_opts.c tcpprep.c tree.c
tcpprep_OBJECTS: tcpprep_opts.h
tcpprep_opts.h: tcpprep_opts.c
tcpprep_opts.c: tcpprep_opts.def
	@AUTOGEN@ tcpprep_opts.def

flowreplay_CFLAGS = $(LIBOPTS_CFLAGS) -I.. -DFLOWREPLAY
flowreplay_LDADD = ./common/libcommon.a $(LIBSTRL) \
		  @LNETLIB@ @LPCAPLIB@ $(LIBOPTS_LDADD)
flowreplay_SOURCES = flowreplay_opts.c flowreplay.c flowkey.c flownode.c \
		     flowbuff.c flowstate.c 
flowreplay_OBJECTS: flowreplay_opts.h
flowreplay_opts.h: flowreplay_opts.c
flowreplay_opts.c: flowreplay_opts.def
	@AUTOGEN@ flowreplay_opts.def

tcpbridge_CFLAGS = $(LIBOPTS_CFLAGS) -I.. -DTCPBRIDGE
tcpbridge_LDADD = ./common/libcommon.a $(LIBSTRL) \
		  @LNETLIB@ @LPCAPLIB@ $(LIBOPTS_LDADD)
tcpbridge_SOURCES = tcpbridge_opts.c tcpbridge.c bridge.c send_packets.c \
		edit_packet.c rewrite_l2.c mac.c
tcpbridge_OBJECTS: tcpbridge_opts.h
tcpbridge_opts.h: tcpbridge_opts.c
tcpbridge_opts.c: tcpbridge_opts.def
	@AUTOGEN@ tcpbridge_opts.def

noinst_HEADERS = tcpreplay.h tcpprep.h flowreplay.h bridge.h portmap.h \
		 defines.h dlt.h dlt_names.h edit_packet.h tree.h mac.h \
		 send_packets.h flowbuff.h flowkey.h flownode.h flowstate.h \
		 signal_handler.h common.h tcpreplay_opts.h rewrite_l2.h \
		 tcprewrite.h tcprewrite_opts.h tcpprep_opts.h portmap.h \
		 tcpprep_opts.def tcprewrite_opts.def tcpreplay_opts.def \
		 flowreplay_opts.def tcpbridge_opts.def tcpbridge.h


MOSTLYCLEANFILES = *~ *.o

MAINTAINERCLEANFILES = Makefile.in tcpreplay_opts.h tcpreplay_opts.c \
		       tcprewrite_opts.c tcprewrite_opts.h tcpprep_opts.c \
		       tcpprep_opts.h tcpprep.1 tcpreplay.1 tcprewrite.1 \
		       flowreplay.1 tcpbridge.1 tcpbridge_opts.h tcpbridge_opts.c
