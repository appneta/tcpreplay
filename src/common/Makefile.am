# $Id: Makefile.am 1621 2006-11-09 07:01:37Z aturner $
noinst_LIBRARIES = libcommon.a

BUILT_SOURCES = svn_version.c

svn_version.c:
	$(ECHO) -n 'const char SVN_Version[] = "'   > svn_version.c
	svnversion -n ../..                     >> svn_version.c
	$(ECHO) '";'								>> svn_version.c
	$(ECHO) 'const char *svn_version(void) {'  >> svn_version.c
	$(ECHO) '	return SVN_Version;'			>> svn_version.c
	$(ECHO) '}' 			      				>> svn_version.c

libcommon_a_SOURCES = cidr.c err.c list.c cache.c services.c get.c \
		      fakepcap.c fakepcapnav.c fakepoll.c xX.c utils.c \
		      timer.c svn_version.c abort.c sendpacket.c \
			  dlt_names.c mac.c interface.c rdtsc.c

if ENABLE_TCPDUMP
libcommon_a_SOURCES += tcpdump.c
endif

AM_CFLAGS = -I.. -I../.. $(LNAV_CFLAGS) @LDNETINC@

libcommon_a_LIBADD = ../../lib/libstrl.a

noinst_HEADERS = cidr.h err.h list.h cache.h services.h get.h \
		 fakepcap.h fakepcapnav.h fakepoll.h xX.h utils.h \
		 tcpdump.h timer.h abort.h pcap_dlt.h sendpacket.h \
		 dlt_names.h mac.h interface.h rdtsc.h

MOSTLYCLEANFILES = *~

MAINTAINERCLEANFILES = Makefile.in svn_version.c
