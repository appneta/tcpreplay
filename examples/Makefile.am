# libtcpreplay usage examples (#133)
#
# Built as noinst so every build proves the library and its installed
# header layout keep working; see README.md for building against an
# installed libtcpreplay with pkg-config.

noinst_PROGRAMS = replay_stats

replay_stats_SOURCES = replay_stats.c
replay_stats_CFLAGS = -I$(top_srcdir)/src -I$(top_builddir)/src $(LIBOPTS_CFLAGS)
replay_stats_LDADD = $(top_builddir)/src/libtcpreplay.a @LPCAPLIB@ @LDNETLIB@ $(LIBOPTS_LDADD)

EXTRA_DIST = README.md
