SUBDIRS = common

if SYSTEM_STRLCPY
LIBSTRL =
else
LIBSTRL = ../lib/libstrl.a
endif

LDADD = ./common/libcommon.a $(LIBSTRL) \
		  @LNETLIB@ @LPCAPLIB@ $(LIBOPTS_LDADD)

tcprewrite_LDADD = ./common/libcommon.a $(LIBSTRL) \
		  @LNAVLIB@ @LNETLIB@ @LPCAPLIB@ $(LIBOPTS_LDADD)
bin_PROGRAMS = tcpreplay tcpprep flowreplay tcprewrite

tcpreplay_SOURCES = tcpreplay_opts.c send_packets.c signal_handler.c tcpreplay.c
tcpreplay_OBJECTS: tcpreplay_opts.h
tcpreplay_opts.h: tcpreplay_opts.c
tcpreplay_opts.c: tcpreplay_opts.def
	@AUTOGEN@ tcpreplay_opts.def


tcprewrite_SOURCES = tcprewrite_opts.c tcprewrite.c mac.c portmap.c edit_packet.c rewrite_l2.c
tcprewrite_OBJECTS: tcprewrite_opts.h
tcprewrite_opts.h: tcprewrite_opts.c
tcprewrite_opts.c: tcprewrite_opts.def
	@AUTOGEN@ tcprewrite_opts.def


tcpprep_SOURCES = tcpprep_opts.c tcpprep.c tree.c
tcpprep_OBJECTS: tcpprep_opts.h
tcpprep_opts.h: tcpprep_opts.c
tcpprep_opts.c: tcpprep_opts.def
	@AUTOGEN@ tcpprep_opts.def

flowreplay_SOURCES = flowreplay.c flowkey.c flownode.c flowbuff.c flowstate.c


AM_CFLAGS = -I.. $(LIBOPTS_CFLAGS)

noinst_HEADERS = tcpreplay.h tcpprep.h flowreplay.h netout.h portmap.h \
		 defines.h dlt.h dlt_names.h edit_packet.h tree.h mac.h \
		 send_packets.h flowbuff.h flowkey.h flownode.h flowstate.h \
		 signal_handler.h common.h tcpreplay_opts.h rewrite_l2.h \
		 tcprewrite.h tcprewrite_opts.h tcpprep_opts.h portmap.h \
		 tcpprep_opts.def tcprewrite_opts.def tcpreplay_opts.def 


MOSTLYCLEANFILES = *~ *.o

MAINTAINERCLEANFILES = Makefile.in tcpreplay_opts.h tcpreplay_opts.c \
		       tcprewrite_opts.c tcprewrite_opts.h tcpprep_opts.c \
		       tcpprep_opts.h
