## LIBOPTS Makefile
MAINTAINERCLEANFILES    = Makefile.in
if INSTALL_LIBOPTS
lib_LTLIBRARIES         = libopts.la
else
noinst_LTLIBRARIES      = libopts.la
endif
libopts_la_SOURCES      = libopts.c
libopts_la_CPPFLAGS     = -I$(top_srcdir)
libopts_la_LDFLAGS      = -version-info  36:5:11
EXTRA_DIST              = \
    COPYING.gplv3           COPYING.lgplv3          COPYING.mbsd  \
    MakeDefs.inc            README                  ag-char-map.h  \
    alias.c                 ao-strs.c               ao-strs.h  \
    autoopts/options.h      autoopts/project.h      autoopts/usage-txt.h  \
    autoopts.c              autoopts.h              boolean.c  \
    check.c                 compat/compat.h         compat/pathfind.c  \
    compat/snprintf.c       compat/strchr.c         compat/strdup.c  \
    compat/windows-config.h configfile.c            cook.c  \
    enum.c                  env.c                   file.c  \
    find.c                  genshell.c              genshell.h  \
    load.c                  m4/libopts.m4           m4/liboptschk.m4  \
    makeshell.c             nested.c                numeric.c  \
    parse-duration.c        parse-duration.h        pgusage.c  \
    proto.h                 putshell.c              reset.c  \
    restore.c               save.c                  sort.c  \
    stack.c                 streqvcmp.c             text_mmap.c  \
    time.c                  tokenize.c              usage.c  \
    value-type.c            value-type.h            version.c  \
    xat-attribute.c         xat-attribute.h
