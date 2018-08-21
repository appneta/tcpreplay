# $Id: $

libtcpedit_a_SOURCES += \
	%reldir%/dlt_plugins.c \
	%reldir%/ethernet.c \
	%reldir%/ethernet.h \
	%reldir%/dlt_utils.c \
	%reldir%/dlt_utils.h

noinst_HEADERS += \
	%reldir%/ethernet.h \
	%reldir%/dlt_utils.h

AM_CFLAGS +=  -I$(srcdir)/%reldir% $(LIBOPTS_CFLAGS)

EXTRA_DIST += %reldir%/dlt_opts.def %reldir%/dlt_stub.def

MOSTLYCLEANFILES += *~

MAINTAINERCLEANFILES += %reldir%/Makefile.in


DLT_STUB_DEPS = %reldir%/dlt_opts.def

dlt_stub.def: $(DLT_STUB_DEPS)

########################################################
# Add your plugin Makefile.am's below this line
########################################################
include %reldir%/dlt_en10mb/Makefile.am
include %reldir%/dlt_hdlc/Makefile.am
include %reldir%/dlt_user/Makefile.am
include %reldir%/dlt_raw/Makefile.am
include %reldir%/dlt_null/Makefile.am
include %reldir%/dlt_loop/Makefile.am
include %reldir%/dlt_linuxsll/Makefile.am
include %reldir%/dlt_ieee80211/Makefile.am
include %reldir%/dlt_radiotap/Makefile.am
include %reldir%/dlt_jnpr_ether/Makefile.am
include %reldir%/dlt_pppserial/Makefile.am

