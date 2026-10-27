# Fuzz targets (#1092).
#
# Two build modes, both driven from here:
#
#   default          Each target is built as a plain program that replays the
#                    checked-in corpus (see fuzz_common.h's FUZZ_STANDALONE
#                    driver) and is run by `make check`. This needs no clang
#                    and no libFuzzer, so the corpus - including any input
#                    OSS-Fuzz finds later - is a regression test everywhere
#                    the suite builds.
#
#   --enable-fuzzer  Targets are linked against libFuzzer instead, for actual
#                    fuzzing. Requires clang.
#
# The split matters: a crashing input is only useful as a regression test if
# people can run it without installing a fuzzing toolchain first.

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src -I$(top_builddir)/src \
	-I$(top_srcdir)/test/fuzz $(LIBOPTS_CFLAGS) @LDNETINC@ @PTHREAD_CFLAGS@

# libfragroute must come before libcommon: it calls into it, and a static
# archive only resolves backwards.
LDADD = $(FRAGROUTE_LIB) $(top_builddir)/src/common/libcommon.a \
	$(LIBSTRL) @LPCAPLIB@ @LDNETLIB@

if COMPILE_FRAGROUTE
FRAGROUTE_LIB = $(top_builddir)/src/fragroute/libfragroute.a
FRAGROUTE_TARGET = fuzz_fragroute
else
FRAGROUTE_LIB =
FRAGROUTE_TARGET =
endif

if ENABLE_FUZZER
# libFuzzer supplies main(); the targets are fuzzing binaries, not tests.
AM_CFLAGS = -fsanitize=fuzzer,address -g -O1
noinst_PROGRAMS = fuzz_services fuzz_pcap $(FRAGROUTE_TARGET) fuzz_tcpedit
TESTS =
else
# Standalone corpus replay: FUZZ_STANDALONE provides main().
AM_CFLAGS = -DFUZZ_STANDALONE
check_PROGRAMS = fuzz_services fuzz_pcap $(FRAGROUTE_TARGET) fuzz_tcpedit
TESTS = run-corpus.sh
endif

# fuzz_globals.c supplies the globals libcommon.a references but does not
# define (debug), as each tool's main() and src/libtcpreplay_globals.c do.
# Only needed in an --enable-debug build, where dbg()/dbgx() actually expand -
# which is why a plain ./configure links fine and CI does not.
fuzz_services_SOURCES = fuzz_services.c fuzz_globals.c
fuzz_pcap_SOURCES = fuzz_pcap.c fuzz_globals.c
fuzz_fragroute_SOURCES = fuzz_fragroute.c fuzz_globals.c
fuzz_tcpedit_SOURCES = fuzz_tcpedit.c fuzz_globals.c
fuzz_tcpedit_CPPFLAGS = $(AM_CPPFLAGS) $(LIBOPTS_CFLAGS)
# Mirror tcprewrite's link: the DLT plugins reference the
# tcpedit_tcpedit_optDesc_p descriptor defined by the generated
# tcprewrite_opts.c, and libcommon needs libstrl where the libc
# lacks strlcat/strlcpy.
fuzz_tcpedit_LDADD = $(top_builddir)/src/tcprewrite_opts.o \
	$(top_builddir)/src/tcpedit/libtcpedit.a $(LIBSTRL) $(LDADD) \
	$(LIBOPTS_LDADD)

noinst_HEADERS = fuzz_common.h

EXTRA_DIST = run-corpus.sh corpus CMakeLists.txt README.md
