SUBDIRS = common

bin_PROGRAMS = tcpreplay tcpprep flowreplay

tcpreplay_SOURCES = tcpreplay.c netout.c fileout.c mac.c \
		    signal_handler.c tcpdump.c edit_packet.c \
		    portmap.c
		    

tcpprep_SOURCES = tcpprep.c

flowreplay_SOURCES = flowreplay.c flowkey.c flownode.c flowbuff.c flowstate.c

tcpreplay_LDADD = ./common/libcommon.a ../lib/libstrl.a \
		  @LNAVLIB@ @LNETLIB@ @LPCAPLIB@

tcpprep_LDADD =  ./common/libcommon.a ../lib/libstrl.a \
		  @LNETLIB@ @LPCAPLIB@

flowreplay_LDADD = ./common/libcommon.a ../lib/libstrl.a \
		   @LNETLIB@ @LPCAPLIB@

noinst_HEADERS = tcpreplay.h tcpprep.h flowreplay.h netout.h \
		 defines.h dlt.h dlt_names.h edit_packet.h \
		 fileout.h flowbuff.h flowkey.h flownode.h flowstate.h \
		 signal_handler.h tcpdump.h

tcpreplay_CFLAGS = -I../lib
tcpprep_CFLAGS = -I../lib
flowreplay_CFLAGS = -I../lib

MOSTLYCLEANFILES = *~ *.o
