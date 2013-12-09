# $Id:$
# START OF: dlt_en10mb
# Note, if you add any files to your plugin, you will need to edit dlt_<plugin>/Makefile.am
# add your .c files to libtcpedit_a_SOURCES
# add your .h files to noinst_HEADERS
# add any other files (like documentation, notes, etc) to EXTRA_DIST
# add your dependancy information (see comment below)

libtcpedit_a_SOURCES += $(srcdir)/plugins/dlt_en10mb/en10mb.c \
		$(srcdir)/plugins/dlt_en10mb/en10mb_api.c

noinst_HEADERS += $(srcdir)/plugins/dlt_en10mb/en10mb.h \
		$(srcdir)/plugins/dlt_en10mb/en10mb_api.h \
		$(srcdir)/plugins/dlt_en10mb/en10mb_types.h \
		$(srcdir)/tcpedit_types.h

EXTRA_DIST += $(srcdir)/plugins/dlt_en10mb/en10mb_opts.def

# dependancies for your plugin source code.  Edit as necessary
$(srcdir)/plugins/dlt_en10mb/en10mb.c:  $(srcdir)/tcpedit_stub.h $(srcdir)/plugins/dlt_utils.h \
	$(srcdir)/plugins.h $(srcdir)/plugins_api.h $(srcdir)/plugins_types.h \
	$(srcdir)/tcpedit_api.h $(srcdir)/plugins/dlt_en10mb/en10mb.h $(srcdir)/plugins/dlt_en10mb/en10mb_api.h \
	$(srcdir)/plugins/dlt_en10mb/en10mb_types.h

# Note:
# You probably don't want to touch anything below this line until the end of the plugin

MOSTLYCLEANFILES += $(srcdir)/plugins/dlt_en10mb/*~

# END OF: dlt_en10mb
