# $Id$
noinst_LIBRARIES = libcommon.a

BUILT_SOURCES = svn_version.c

svn_version.c:
	echo -n 'const char SVN_Version[] = "'   > svn_version.c
	svnversion -n ../..                     >> svn_version.c
	echo '";'				>> svn_version.c
	echo 'const char *svn_version(void) {'  >> svn_version.c
	echo '	return SVN_Version;'		>> svn_version.c
	echo '}' 			        >> svn_version.c

libcommon_a_SOURCES = cidr.c err.c list.c cache.c services.c get.c \
		      fakepcap.c fakepcapnav.c fakepoll.c xX.c utils.c \
		      tcpdump.c timer.c svn_version.c abort.c

AM_CFLAGS = -I.. -I../.. $(LNAV_CFLAGS)

libcommon_a_LIBADD = ../../lib/libstrl.a

noinst_HEADERS = cidr.h err.h list.h cache.h services.h get.h \
		 fakepcap.h fakepcapnav.h fakepoll.h xX.h utils.h \
		 tcpdump.h timer.h abort.h pcap_dlt.h

MOSTLYCLEANFILES = *~

MAINTAINERCLEANFILES = Makefile.in svn_version.c
