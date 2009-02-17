
ADD_LIBRARY(opts STATIC libopts.c)
SET_TARGET_PROPERTIES(opts
    PROPERTIES LINK_FLAGS "-version-info  32:0:7 -DHAVE_CONFIG_H")

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/libopts)

CONFIGURE_FILE(config.h.cmake config.h @ONLY)


ADD_DEPENDENCIES(opts 
    config.h
    ag-char-map.h
    autoopts/options.h      autoopts/usage-txt.h    autoopts.c
    autoopts.h              boolean.c               compat/compat.h
    compat/pathfind.c       compat/snprintf.c       compat/strchr.c
    compat/strdup.c         compat/windows-config.h configfile.c
    cook.c                  enumeration.c           environment.c
    file.c                  genshell.c              genshell.c
    load.c                  makeshell.c             nested.c                
    numeric.c
    parse-duration.c        parse-duration.h        pgusage.c
    proto.h                 putshell.c              reset.c
    restore.c               save.c                  sort.c
    stack.c                 streqvcmp.c             text_mmap.c
    time.c                  tokenize.c              usage.c
    value-type.c            value-type.h            version.c
    xat-attribute.c         xat-attribute.h)