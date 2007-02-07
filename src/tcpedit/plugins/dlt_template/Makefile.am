# $Id:$
# START OF: dlt_%{plugin}
# Note, if you add any files to your plugin, you will need to edit dlt_%{plugin}/Makefile.am
# add your .c files to libtcpedit_a_SOURCES
# add your .h files to noinst_HEADERS
# add any other files (like documentation, notes, etc) to EXTRA_DIST
# add your dependancy information (see comment below)

libtcpedit_a_SOURCES += $(srcdir)/plugins/dlt_%{plugin}/%{plugin}.c

noinst_HEADERS += $(srcdir)/plugins/dlt_%{plugin}/%{plugin}.h

EXTRA_DIST += $(srcdir)/plugins/dlt_%{plugin}/%{plugin}_opts.def

# dependancies for your plugin source code.  Edit as necessary
$(srcdir)/plugins/dlt_%{plugin}/%{plugin}.c:  $(srcdir)/tcpedit_stub.h $(srcdir)/plugins/dlt_utils.h \
	$(srcdir)/plugins/dlt_%{plugin}/%{plugin}.h $(srcdir)/plugins/dlt_plugins.h $(srcdir)/plugins/dlt_plugins-int.h

# You probably don't want to touch anything below this line until the end of the plugin

DLT_STUB_DEPS += $(srcdir)/plugins/dlt_%{plugin}/%{plugin}_opts.def

MOSTLYCLEANFILES += $(srcdir)/plugins/dlt_%{plugin}/*~

# END OF: dlt_%{plugin}
