AUTOMAKE_OPTIONS = foreign

SUBDIRS = scripts lib src man docs
DIST_SUBDIRS = scripts lib src man docs


docsdir = $(top_buildir)/docs

docs:
	echo Making docs in $(docsdir)
	cd $(docsdir) && make docs

testdir = $(top_buildir)/test

test:
	echo Making test in $(testdir)
	cd $(testdir) && make test

MOSTLYCLEANFILES = tcpreplay.spec *~

MAINTAINERCLEANFILES = Makefile.in configure
