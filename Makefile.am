AUTOMAKE_OPTIONS = foreign

SUBDIRS = lib src man docs
DIST_SUBDIRS = scripts lib src man docs


testdir = $(top_buildir)/test

test:
	echo Making $ in $(testdir)
	cd $(testdir) && make $

MOSTLYCLEANFILES = tcpreplay.spec *~
