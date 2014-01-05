# $Id: $

libtcpedit_a_SOURCES += $(srcdir)/plugins/dlt_plugins.c \
	$(srcdir)/plugins/ethernet.c $(srcdir)/plugins/dlt_utils.c

noinst_HEADERS += $(srcdir)/plugins/ethernet.h \
	$(srcdir)/plugins/dlt_utils.h $(srcdir)/plugins/ethernet.h

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
include $(srcdir)/plugins/dlt_user/Makefile.am
include $(srcdir)/plugins/dlt_raw/Makefile.am
include $(srcdir)/plugins/dlt_null/Makefile.am
include $(srcdir)/plugins/dlt_loop/Makefile.am
include $(srcdir)/plugins/dlt_linuxsll/Makefile.am
include $(srcdir)/plugins/dlt_ieee80211/Makefile.am
include $(srcdir)/plugins/dlt_radiotap/Makefile.am
include $(srcdir)/plugins/dlt_jnpr_ether/Makefile.am
include $(srcdir)/plugins/dlt_pppserial/Makefile.am

