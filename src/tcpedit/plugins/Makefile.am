# $Id: $

libtcpedit_a_SOURCES += $(srcdir)/plugins/dlt_plugins.c $(srcdir)/plugins/ethernet.c \
	$(srcdir)/plugins/dlt_utils.c

noinst_HEADERS += $(srcdir)/plugins/dlt_plugins.h $(srcdir)/plugins/ethernet.h \
	$(srcdir)/plugins/dlt_utils.c

AM_CFLAGS += -I. -I$(srcdir)/plugins -I$(srcdir)/../common $(LIBOPTS_CFLAGS) 

EXTRA_DIST += $(srcdir)/plugins/dlt_opts.def $(srcdir)/plugins/dlt_stub.def

MOSTLYCLEANFILES += $(srcdir)/plugins/*~

MAINTAINERCLEANFILES += Makefile.in 


DLT_STUB_DEPS = $(srcdir)/plugins/dlt_opts.def 

$(srcdir)/plugins/dlt_stub.def: $(DLT_STUB_DEPS)

########################################################
# Add your plugin Makefile.am's below this line
########################################################
include $(srcdir)/plugins/dlt_en10mb/Makefile.am
include $(srcdir)/plugins/dlt_hdlc/Makefile.am
