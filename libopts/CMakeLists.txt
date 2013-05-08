
ADD_LIBRARY(opts STATIC libopts.c)
SET_TARGET_PROPERTIES(opts
    PROPERTIES LINK_FLAGS "-version-info 36:5:11 -DHAVE_CONFIG_H")

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/libopts)

CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/libopts/config.h.cmake ${CMAKE_SOURCE_DIR}/libopts/config.h @ONLY)

ADD_DEPENDENCIES(opts 
autoopts/options.h	autoopts/roject.h	autoopts/usage-txt.h
compat/compat.h		compat/snprintf.c	compat/strdup.c
compat/pathfind.c	compat/strchr.c		compat/windows-config.h
ag-char-map.h		enum.c			parse-duration.c	text_mmap.c
alias.c			env.c			parse-duration.h	time.c
ao-strs.c		file.c			pgusage.c		tokenize.c
ao-strs.h		find.c			proto.h			usage.c
autoopts.c		genshell.c		putshell.c		value-type.c
autoopts.h		genshell.h		reset.c			value-type.h
boolean.c		libopts.c		restore.c		version.c
check.c			load.c			save.c			xat-attribute.c
config.h		makeshell.c		sort.c			xat-attribute.h
configfile.c		nested.c		stack.c
cook.c			numeric.c		streqvcmp.c)

