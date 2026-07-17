# $Id:$
# START OF: dlt_%{plugin}
# Note, if you add any files to your plugin, you will need to edit dlt_%{plugin}/Makefile.am
# add your .c files to libtcpedit_a_SOURCES
# add your .h files to noinst_HEADERS
# add any other files (like documentation, notes, etc) to EXTRA_DIST
# add your dependency information (see comment below)

eol =

libtcpedit_a_SOURCES += \
	%reldir%/%{plugin}.c \
	%reldir%/%{plugin}.h \
	%reldir%/%{plugin}_api.h \
	%reldir%/%{plugin}_types.h \
	$(eol)

noinst_HEADERS += \
	%reldir%/%{plugin}.h \
	%reldir%/%{plugin}_api.h \
	%reldir%/%{plugin}_types.h \
	$(eol)

EXTRA_DIST += %reldir%/%{plugin}_opts.def

# dependencies for your plugin source code.  Edit as necessary
%{plugin}.c: \
	$(TCPEDIT_PLUGINS_DEPS) \
	%reldir%/%{plugin}.h \
	%reldir%/%{plugin}_api.h \
	%reldir%/%{plugin}_types.h \
	$(eol)
	
# Note:
# You probably don't want to touch anything below this line until the end of the plugin

DLT_STUB_DEPS += %reldir%/%{plugin}_opts.def

MOSTLYCLEANFILES += *~

# END OF: dlt_%{plugin}
