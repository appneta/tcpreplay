AUTOMAKE_OPTIONS = foreign

include $(srcdir)/libopts/MakeDefs.inc

SUBDIRS = scripts lib src man docs $(LIBOPTS_DIR)
DIST_SUBDIRS = scripts lib src man docs


docsdir = $(top_buildir)/docs

docs:
	echo Making docs in $(docsdir)
	cd $(docsdir) && make docs

testdir = $(top_buildir)/test

test:
	echo Making test in $(testdir)
	cd $(testdir) && make test

dlt_names:
	cat @DLT_H@ | $(top_buildir)/scripts/dlt2name.pl src/dlt_names.h

MOSTLYCLEANFILES = tcpreplay.spec *~

MAINTAINERCLEANFILES = Makefile.in configure tcpreplay.prj.bak
