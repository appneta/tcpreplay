# $Id:$
# START OF: dlt_raw
# Note, if you add any files to your plugin, you will need to edit dlt_<plugin>/Makefile.am
# add your .c files to libtcpedit_a_SOURCES
# add your .h files to noinst_HEADERS
# add any other files (like documentation, notes, etc) to EXTRA_DIST
# add your dependancy information (see comment below)

libtcpedit_a_SOURCES += %reldir%/raw.c

noinst_HEADERS += %reldir%/raw.h

EXTRA_DIST += %reldir%/raw_opts.def

# dependancies for your plugin source code.  Edit as necessary
raw.c: \
	%reldir%/../dlt_utils.h \
	%reldir%/../../tcpedit_stub.h \
	%reldir%/../../plugins/dlt_utils.h \
	%reldir%/../../plugins.h \
	%reldir%/../../plugins_api.h \
	%reldir%/../../plugins_types.h \
	%reldir%/../../tcpedit_api.h  \
	%reldir%/raw.h

# You probably don't want to touch anything below this line until the end of the plugin

DLT_STUB_DEPS += %reldir%/raw_opts.def

MOSTLYCLEANFILES += *~

# END OF: dlt_raw
