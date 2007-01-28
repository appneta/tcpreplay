## LIBOPTS Makefile
MAINTAINERCLEANFILES    = Makefile.in
if INSTALL_LIBOPTS
lib_LTLIBRARIES         = libopts.la
else
noinst_LTLIBRARIES      = libopts.la
endif
libopts_la_SOURCES      = libopts.c
libopts_la_CPPFLAGS     = -I$(top_srcdir)
libopts_la_LDFLAGS      = -version-info  27:6:3
EXTRA_DIST              = \
    COPYING.lgpl            COPYING.mbsd            MakeDefs.inc  \
    README                  autoopts/options.h      autoopts/usage-txt.h  \
    autoopts.c              autoopts.h              boolean.c  \
    compat/compat.h         compat/pathfind.c       compat/snprintf.c  \
    compat/strchr.c         compat/strdup.c         compat/windows-config.h  \
    configfile.c            cook.c                  enumeration.c  \
    environment.c           genshell.c              genshell.h  \
    load.c                  m4/libopts.m4           m4/liboptschk.m4  \
    makeshell.c             nested.c                numeric.c  \
    pgusage.c               proto.h                 putshell.c  \
    restore.c               save.c                  sort.c  \
    stack.c                 streqvcmp.c             text_mmap.c  \
    tokenize.c              usage.c                 version.c
