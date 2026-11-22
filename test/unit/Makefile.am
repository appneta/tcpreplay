# Unit tests for pure functions in the suite (see tap.h for why there is no
# test framework here).
#
# These are deliberately separate from the integration suite in test/, which
# needs a built binary, root, and a live NIC.  These need none of that, so
# they run under the standard `make check` on any developer machine and in
# every CI job - which is what makes them useful as regression tests.

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src -I$(top_builddir)/src \
	-I$(top_srcdir)/test/unit $(LIBOPTS_CFLAGS) @LDNETINC@ @PTHREAD_CFLAGS@

# libcommon.a carries txring.c and get.c; the strl* fallbacks come from
# lib/libstrl.a on systems without them in libc.
LDADD = $(top_builddir)/src/common/libcommon.a $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@

check_PROGRAMS = test_txring test_get_ipv6

# test_fragroute links libfragroute, so it only exists where libdnet does
if COMPILE_FRAGROUTE
check_PROGRAMS += test_fragroute
endif

TESTS = $(check_PROGRAMS)

# unit_globals.c supplies the globals libcommon.a references but does not
# define (debug), the same way each tool's main() file does
test_txring_SOURCES = test_txring.c unit_globals.c
test_get_ipv6_SOURCES = test_get_ipv6.c unit_globals.c

# libfragroute must come before libcommon: it calls into it, and a static
# archive only resolves backwards.
test_fragroute_SOURCES = test_fragroute.c unit_globals.c
test_fragroute_LDADD = $(top_builddir)/src/fragroute/libfragroute.a \
	$(top_builddir)/src/common/libcommon.a $(LIBSTRL) @LPCAPLIB@ @LDNETLIB@

noinst_HEADERS = tap.h

EXTRA_DIST = CMakeLists.txt
