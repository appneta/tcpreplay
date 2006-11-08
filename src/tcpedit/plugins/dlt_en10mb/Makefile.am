# $Id:$
# START OF: dlt_en10mb
# Note, if you add any files to your plugin, you will need to edit dlt_<plugin>/Makefile.am
# add your .c files to libdltplugin_a_SOURCES
# add your .h files to noinst_HEADERS
# add any other files (like documentation, notes, etc) to EXTRA_DIST
# add your dependancy information (see comment below)

libdltplugin_a_SOURCES += $(srcdir)/dlt_en10mb/en10mb.c

noinst_HEADERS += $(srcdir)/dlt_en10mb/en10mb.h dlt_en10mb/en10mb_stub.h

EXTRA_DIST += $(srcdir)/dlt_en10mb/en10mb_stub.def $(srcdir)/dlt_en10mb/en10mb_opts.def


# dependancies for your plugin source code.  Edit as necessary
$(srcdir)/dlt_en10mb/en10mb.c: $(srcdir)/dlt_en10mb/en10mb_stub.h \
	$(srcdir)/dlt_en10mb/en10mb.h $(srcdir)/dlt_plugins.h $(srcdir)/dlt_plugins-int.h

# You probably don't want to touch anything below this line until the end of the plugin

$(srcdir)/dlt_en10mb/en10mb_stub.h: $(srcdir)/dlt_en10mb/en10mb_opts.def \
	dlt_en10mb/en10mb_stub.def
	-cd $(srcdir)/dlt_en10mb && @AUTOGEN@ en10mb_stub.def

MOSTLYCLEANFILES += $(srcdir)/dlt_en10mb/*~

MAINTAINERCLEANFILES += $(srcdir)/dlt_en10mb/en10mb_stub.h

# END OF: dlt_en10mb
