# $Id:$
# START OF: dlt_%{plugin}
# Note, if you add any files to your plugin, you will need to edit dlt_<plugin>/Makefile.am
# add your .c files to libdltplugin_a_SOURCES
# add your .h files to noinst_HEADERS
# add any other files (like documentation, notes, etc) to EXTRA_DIST
# add your dependancy information (see comment below)

libdltplugin_a_SOURCES += $(srcdir)/dlt_%{plugin}/%{plugin}.c

noinst_HEADERS += $(srcdir)/dlt_%{plugin}/%{plugin}.h dlt_%{plugin}/%{plugin}_stub.h

EXTRA_DIST += $(srcdir)/dlt_%{plugin}/%{plugin}_stub.def $(srcdir)/dlt_%{plugin}/%{plugin}_opts.def


# dependancies for your plugin source code.  Edit as necessary
$(srcdir)/dlt_%{plugin}/%{plugin}.c: $(srcdir)/dlt_%{plugin}/%{plugin}_stub.h \
	$(srcdir)/dlt_%{plugin}/%{plugin}.h $(srcdir)/dlt_plugins.h $(srcdir)/dlt_plugins-int.h

# You probably don't want to touch anything below this line until the end of the plugin

$(srcdir)/dlt_%{plugin}/%{plugin}_stub.h: $(srcdir)/dlt_%{plugin}/%{plugin}_opts.def \
	dlt_%{plugin}/%{plugin}_stub.def
	-cd $(srcdir)/dlt_%{plugin} && @AUTOGEN@ %{plugin}_stub.def

MOSTLYCLEANFILES += $(srcdir)/dlt_%{plugin}/*~

MAINTAINERCLEANFILES += $(srcdir)/dlt_%{plugin}/%{plugin}_stub.h

# END OF: dlt_%{plugin}
