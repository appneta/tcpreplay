AUTOMAKE_OPTIONS = foreign

include $(top_srcdir)/libopts/MakeDefs.inc

SUBDIRS = scripts lib $(LIBOPTS_DIR) src
DIST_SUBDIRS = scripts lib src docs libopts
.PHONY: docs test

dist-hook: version manpages docs 

DOCS_DIR = $(top_builddir)/docs

docs:
	cd scripts && make
	echo Making docs in $(DOCS_DIR)
	cd $(DOCS_DIR) && make docs

clean-docs:
	cd $(DOCS_DIR) && make clean-docs

postweb:
	cd $(DOCS_DIR) && make postweb

manpages:
	cd src && make manpages

TEST_DIR = $(top_builddir)/test

test:
	echo Making test in $(TEST_DIR)
	cd $(TEST_DIR) && make test

dlt_names:
	cat @SAVEFILE_C@ | $(top_builddir)/scripts/dlt2name.pl src/dlt_names.h

version:
	-rm -f src/common/svn_version.c
	cd src/common && make svn_version.c

distclean-local:
	-rm -rf autom4te.cache

MOSTLYCLEANFILES = tcpreplay.spec *~

DISTCLEANFILES = .tm_project.cache stamp-h1 *.tar.*

MAINTAINERCLEANFILES = Makefile.in configure *.bak
