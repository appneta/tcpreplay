SUBDIRS = common

tcpreplay_OBJECTS: tcpreplay_opts.h 

tcpreplay_opts.h: tcpreplay_opts.c

tcpreplay_opts.c:
	@AUTOGEN@ tcpreplay_opts.def

bin_PROGRAMS = tcpreplay tcpprep flowreplay tcprewrite

tcpreplay_SOURCES = tcpreplay.c send_packets.c timer.c \
		    signal_handler.c tcpreplay_opts.c
		    

tcprewrite_opts.c:
	@AUTOGEN@ tcprewrite_opts.def

tcprewrite_opts.h: tcprewrite_opts.c

tcpprep_opts.c:
	@AUTOGEN@ tcpprep_opts.def

tcpprep_opts.h: tcpprep_opts.c

tcprewrite_SOURCES = tcprewrite.c tcprewrite_opts.c mac.c portmap.c edit_packet.c

tcpprep_SOURCES = tcpprep.c tcpprep_opts.c tree.c

flowreplay_SOURCES = flowreplay.c flowkey.c flownode.c flowbuff.c flowstate.c

tcprewrite_LDADD = ./common/libcommon.a ../lib/libstrl.a \
		  @LNAVLIB@ @LNETLIB@ @LPCAPLIB@ $(LIBOPTS_LDADD)

tcpreplay_LDADD = ./common/libcommon.a ../lib/libstrl.a \
		  @LNAVLIB@ @LNETLIB@ @LPCAPLIB@ $(LIBOPTS_LDADD)

tcpprep_LDADD =  ./common/libcommon.a ../lib/libstrl.a \
		  @LNETLIB@ @LPCAPLIB@ $(LIBOPTS_LDADD)

flowreplay_LDADD = ./common/libcommon.a ../lib/libstrl.a \
		   @LNETLIB@ @LPCAPLIB@

noinst_HEADERS = tcpreplay.h tcpprep.h flowreplay.h netout.h timer.h \
		 defines.h dlt.h dlt_names.h edit_packet.h tree.h \
		 send_packets.h flowbuff.h flowkey.h flownode.h flowstate.h \
		 signal_handler.h common.h tcpreplay_opts.h \
		 tcprewrite.h tcprewrite_opts.h tcpprep_opts.h

tcpreplay_CFLAGS = -I.. $(LIBOPTS_CFLAGS)
tcpprep_CFLAGS = -I..
flowreplay_CFLAGS = -I..
tcprewrite_CFLAGS = -I..

MOSTLYCLEANFILES = *~ *.o

MAINTAINERCLEANFILES = Makefile.in tcpreplay_opts.h tcpreplay_opts.c \
		       tcprewrite_opts.c tcprewrite_opts.h tcpprep_opts.c \
		       tcpprep_opts.h
