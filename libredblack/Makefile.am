lib_LTLIBRARIES=libredblack.la
include_HEADERS=redblack.h
libredblack_la_SOURCES=redblack.c
libredblack_la_LDFLAGS= -version-info @REDBLACK_LIB_CURRENT@:@REDBLACK_LIB_REVISION@:@REDBLACK_LIB_AGE@
man_MANS=rbdelete.3 rbdestroy.3 rbfind.3 rbinit.3 rbsearch.3 rblookup.3 \
	rbwalk.3 rbopenlist.3 rbreadlist.3 rbcloselist.3
EXTRA_DIST=autogen.sh @PACKAGE@.spec @PACKAGE@.spec.in $(man_MANS) 
noinst_PROGRAMS=example example1 example2 example3
example_SOURCES=example.c
example_LDADD=libredblack.la
example1_SOURCES=example1.c
example1_LDADD=libredblack.la
example2_SOURCES=example2.c
example2_LDADD=libredblack.la
example3_SOURCES=example3.c
example3_LDADD=libredblack.la
CFLAGS=-Wall

rpms: distcheck rpms-nocheck

rpms-nocheck:
	rpm -ta @PACKAGE@-@VERSION@.tar.gz
	cp /usr/src/redhat/SRPMS/@PACKAGE@-@VERSION@-*.rpm .
	cp /usr/src/redhat/RPMS/*/@PACKAGE@-*@VERSION@-*.*.rpm .

release:
	man2html < rbinit.3 > rbinit.3.html
	man2html < rbopenlist.3 > rbopenlist.3.html
	ln redblack.html index.html
	scp @PACKAGE@-@VERSION@.tar.gz \
		@PACKAGE@-@VERSION@-*.src.rpm \
		@PACKAGE@-*@VERSION@-*.*.rpm \
		damo@shell1.sourceforge.net:/home/groups/ftp/pub/@PACKAGE@
	scp rbinit.3.html \
		rbopenlist.3.html \
		index.html \
		redblack.png \
		damo@shell1.sourceforge.net:/home/groups/@PACKAGE@/htdocs
	rm -f index.html

