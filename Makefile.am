AUTOMAKE_OPTIONS = foreign

include $(top_srcdir)/libopts/MakeDefs.inc

SUBDIRS = scripts lib src man docs $(LIBOPTS_DIR)
DIST_SUBDIRS = scripts lib src man docs libopts


docsdir = $(top_builddir)/docs

docs:
	echo Making docs in $(docsdir)
	cd $(docsdir) && make docs

testdir = $(top_buildir)/test

test:
	echo Making test in $(testdir)
	cd $(testdir) && make test

dlt_names:
	cat @SAVEFILE_C@ | $(top_builddir)/scripts/dlt2name.pl src/dlt_names.h

version:
	-rm -f src/common/svn_version.c
	cd src/common && make svn_version.c

MOSTLYCLEANFILES = tcpreplay.spec *~

DISTCLEANFILES = .tm_project.cache stamp-h1

MAINTAINERCLEANFILES = Makefile.in configure *.bak autom4te.cache
