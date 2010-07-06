
dnl $Id$

AC_INIT(tcpreplay)
AC_CONFIG_SRCDIR(src/tcpreplay.c)
AM_CONFIG_HEADER(src/config.h)
AC_CONFIG_AUX_DIR(config)
AM_MAINTAINER_MODE
AM_WITH_DMALLOC

dnl People building from SVN need the same version of Autogen as I'm using
dnl or specify --disable-local-libopts
MAINTAINER_AUTOGEN_VERSION=5.9.7

AC_CONFIG_MACRO_DIR([m4])

dnl Set version info here!
MAJOR_VERSION=3
MINOR_VERSION=4
MICRO_VERSION=5
TCPREPLAY_VERSION=$MAJOR_VERSION.$MINOR_VERSION.$MICRO_VERSION
PACKAGE_URL=http://tcpreplay.synfin.net/

dnl Release is only used for the RPM spec file
TCPREPLAY_RELEASE=1

AC_DEFINE(PACKAGE, [tcpreplay], [This is our package name])
AC_DEFINE_UNQUOTED(VERSION, "$TCPREPLAY_VERSION", [What is our version?])
AC_SUBST(TCPREPLAY_VERSION)
AC_SUBST(TCPREPLAY_RELEASE)

USER_CFLAGS=$CFLAGS
CFLAGS="${CFLAGS} -Wall -O3 -std=gnu99"

dnl Determine OS
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AC_SUBST(host)
AC_SUBST(build)
AC_SUBST(target)

have_cygwin=no
AC_MSG_CHECKING([for cygwin development environment])
if test `echo $target | grep -c cygwin` -gt 0 ; then
    AC_DEFINE([HAVE_WIN32], [1], [Windows/Cygwin])
    AC_MSG_RESULT(yes)
    have_cygwin=yes
else
    AC_MSG_RESULT(no)
fi


AM_INIT_AUTOMAKE(tcpreplay, $TCPREPLAY_VERSION, nodefine)

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AM_PROG_CC_C_O
AC_PROG_CC_STDC
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_LN_S
LT_INIT
AC_PROG_AWK
AC_PROG_SED
AC_PROG_MAKE_SET
AC_EXEEXT
AC_PATH_PROG(PRINTF, printf)
AC_PATH_PROG(ECHO, echo)
AC_PATH_PROG(CUT, cut)
AC_PATH_PROG(AUTOGEN, autogen)
AC_PATH_PROG(GROFF, groff)

dnl check autogen version
AUTOGEN_VERSION=unknown
if test -n "${AUTOGEN}" ; then
    AC_MSG_CHECKING(for autogen version >= 5.9.x)
    ${AUTOGEN} -v >autogen.version
    AUTOGEN_VERSION=`cat autogen.version | ${SED} 's|.*\([[0-9\.]]\{5,\}\).*|\1|'`
    AUTOGEN_MAJOR=`echo ${AUTOGEN_VERSION} | ${CUT} -d '.' -f 1`
    AUTOGEN_MINOR=`echo ${AUTOGEN_VERSION} | ${CUT} -d '.' -f 2`
    if ( test ${AUTOGEN_MAJOR} -eq 5 && test ${AUTOGEN_MINOR} -lt 9 ) || test ${AUTOGEN_MAJOR} -lt 5 ; then
        AC_MSG_RESULT(no)
        AC_MSG_WARN([${AUTOGEN} is too old (${AUTOGEN_VERSION}) for building from SVN.  Please upgrade to 5.9.x)])
    else
        AC_MSG_RESULT(yes)
    fi
    rm -f autogen.version

    dnl Compare the installed version with the maintainer version if building from SVN and not using system libopts
    if test ! -f src/tcpreplay_opts.c && test "x$enable_local_libopts" = "xyes" ; then
        if test $MAINTAINER_AUTOGEN_VERSION != $AUTOGEN_VERSION ; then
            AC_MSG_ERROR([Your version of autogen ($AUTOGEN_VERSION) != libopts tear off ($MAINTAINER_AUTOGEN_VERSION)  Either install the correct version or specify --disable-local-libopts])
        fi
    fi
else
    if test ! -f src/tcpreplay_opts.c ; then
        AC_MSG_ERROR([Please install GNU autogen >= 5.9.x if you are building from SVN])
    fi
fi
AC_DEFINE([AUTOGEN_VERSION], [${AUTOGEN_VERSION}], [What version of autogen is installed on this system])

if test "x$enable_local_libopts" = "xyes" ; then
    AC_MSG_NOTICE([Using included libopts tearoff])
else
    AC_MSG_NOTICE([Using system libopts])
fi

AC_HEADER_STDC
AC_HEADER_MAJOR

dnl Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_C_CONST
AC_C_INLINE
AC_SYS_LARGEFILE

dnl Check for functions
AC_FUNC_FSEEKO

dnl Check for types.
AC_CHECK_TYPE(u_int8_t, uint8_t)
AC_CHECK_TYPE(u_int16_t, uint16_t)
AC_CHECK_TYPE(u_int32_t, uint32_t)
AC_CHECK_TYPE(u_int64_t, uint64_t)

dnl Older versions of GCC don't support these options
AC_MSG_CHECKING(for $CC -Wextra support)
OLD_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS -Wextra"
wextra=""
AC_COMPILE_IFELSE([#include <stdlib.h>
    int main(int argc, char *argv[]) { return(0); }],
    [ AC_MSG_RESULT(yes) 
      wextra="-Wextra" ],
    [ AC_MSG_RESULT(no) ])
CFLAGS="$OLD_CFLAGS $wextra"

AC_MSG_CHECKING(for $CC -Wno-variadic-macros support)
OLD_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS -Wno-variadic-macros"
wno_variadic_macros=""
AC_COMPILE_IFELSE([#include <stdlib.h>
    int main(int argc, char *argv[]) { return(0); }],
    [ AC_MSG_RESULT(yes) 
      wno_variadic_macros="-Wno-variadic-macros" ],
    [ AC_MSG_RESULT(no) ])
CFLAGS="$OLD_CFLAGS $wno_variadic_macros"

AC_MSG_CHECKING(for $CC -Wfatal-errors support)
OLD_CFLAGS=$CFLAGS
CFLAGS="$CFLAGS -Wfatal-errors"
wfatal_errors=""
AC_COMPILE_IFELSE([#include <stdlib.h>
    int main(int argc, char *argv[]) { return(0); }],
    [ AC_MSG_RESULT(yes) 
      wfatal_errors="-Wfatal-errors" ],
    [ AC_MSG_RESULT(no) ])
CFLAGS="$OLD_CFLAGS $wfatal_errors"


dnl Check for other header files
AC_CHECK_HEADERS([fcntl.h stddef.h sys/socket.h  arpa/inet.h sys/time.h signal.h string.h strings.h sys/types.h stdint.h sys/select.h netinet/in.h poll.h sys/poll.h unistd.h sys/param.h])

dnl OpenBSD has special requirements
AC_CHECK_HEADERS([sys/sysctl.h net/route.h], [], [], [
[#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
]])


dnl Checks for libraries.
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(rt, nanosleep)
AC_CHECK_LIB(resolv, resolv)

dnl Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_MEMBERS([struct timeval.tv_sec])

AC_CHECK_FUNCS([gettimeofday ctime memset regcomp strdup strchr strerror strtol strncpy strtoull poll ntohll mmap snprintf vsnprintf strsignal])

dnl Look for strlcpy since some BSD's have it
AC_CHECK_FUNCS([strlcpy],have_strlcpy=true,have_strlcpy=false)
AM_CONDITIONAL(SYSTEM_STRLCPY, [test x$have_strlcpy = xtrue])

AC_C_BIGENDIAN
AM_CONDITIONAL([WORDS_BIGENDIAN], [ test x$ac_cv_c_bigendian = xyes ])


dnl Enable debugging in code/compiler options
debug=no
AC_ARG_ENABLE(debug,
    AC_HELP_STRING([--enable-debug], [Enable debugging code and support for the -d option]),
    [ if test x$enableval = xyes; then
        debug=yes
        CFLAGS="${USER_CFLAGS} -ggdb -std=gnu99 -Wall $wextra $wfatal_errors $wno_variadic_macros"
# We may also want to add:
#         -Wformat-security -Wswitch-default -Wunused-paramter -Wpadded"
        AC_SUBST(debug_flag)
        AC_DEFINE([DEBUG], [1], [Enable debuging code and support for the -d option]) 
    fi])


AC_ARG_ENABLE(dmalloc,
    AC_HELP_STRING([--enable-dmalloc], [Enable linking to dmalloc for better memory debugging]),
    [ if test x$enableval = xyes ; then
        dmalloc=yes
        AC_DEFINE([ENABLE_DMALLOC], [1], [Enable dmalloc])
        AC_DEFINE([DMALLOC_FUNC_CHECK], [1], [Enable dmalloc function arg checking])
        CFLAGS="${CFLAGS} -I/opt/local/include"
        DMALLOC_LIB="/opt/local/lib/libdmalloc.a"
        AC_SUBST(DMALLOC_LIB)
    fi])


AC_ARG_ENABLE(pedantic,
    AC_HELP_STRING([--enable-pedantic], [Enable gcc's -pedantic option]),
    [ if test x$enableval = xyes; then
        CFLAGS="$CFLAGS -pedantic"
      fi ])

dnl Enable Efense
AC_ARG_ENABLE(efence,
    AC_HELP_STRING([--enable-efence], [Enable Electric Fence memory debugger]),
    [ if test x$enableval = xyes; then
          CFLAGS="$CFLAGS -lefence"
          AC_DEFINE([EFENCE], [1], [Enable Electric Fence memory debugger])
      fi])

dnl Enable Gprof
AC_ARG_ENABLE(gprof,
    AC_HELP_STRING([--enable-gprof], [Enable GNU Profiler]),
    [ if test x$enableval = xyes; then
          if test $debug = yes; then
              CFLAGS="$CFLAGS -pg"
          else 
              # GPROF requires gdb
              CFLAGS="$CFLAGS -ggdb -pg -fprofile-arcs"
          fi
          AC_DEFINE([GPROF], [1], [Enable GNU Profiler])
      fi])

dnl Use 64bits for packet counters
use64bit_counters=yes
AC_ARG_ENABLE(64bits,
    AC_HELP_STRING([--disable-64bits], [Do not use 64bit packet counters]),
    [ 
         AC_MSG_NOTICE([Using u_int32_t for packet counters])
    ],
    [
         AC_DEFINE([ENABLE_64BITS], [1], [Use 64bit packet counters])
         AC_MSG_NOTICE([Using u_int64_t for packet counters])
    ])


# If we're running gcc add '-D_U_="__attribute__((unused))"' to CFLAGS as well,
# so we can use _U_ to flag unused function arguments and not get warnings
# about them. Otherwise, add '-D_U_=""', so that _U_ used to flag an unused
# function argument will compile with non-GCC compilers.
#
if test "x$GCC" = "xyes" ; then
    CFLAGS="-D_U_=\"__attribute__((unused))\" $CFLAGS"
else
    CFLAGS="-D_U_=\"\" $CFLAGS"
fi


AC_ARG_ENABLE(force-bpf,
    AC_HELP_STRING([--enable-force-bpf], [Force using BPF for sending packets]),
    [ AC_DEFINE([FORCE_INJECT_BPF], [1], [Force using BPF for sending packet])])

AC_ARG_ENABLE(force-pf, 
    AC_HELP_STRING([--enable-force-pf], [Force using Linux's PF_PACKET for sending packets]),
    [ AC_DEFINE([FORCE_INJECT_PF], [1], [Force using Linux's PF_PACKET for sending packets])])

AC_ARG_ENABLE(force-libdnet,
    AC_HELP_STRING([--enable-force-libdnet], [Force using libdnet for sending packets]),
    [ AC_DEFINE([FORCE_INJECT_LIBDNET], [1], [Force using libdnet for sending packets])])

AC_ARG_ENABLE(force-inject,
    AC_HELP_STRING([--enable-force-inject], [Force using libpcap's pcap_inject() for sending packets]),
    [ AC_DEFINE([FORCE_INJECT_PCAP_INJECT],[1], [Force using libpcap's pcap_inject() for sending packets])])

AC_ARG_ENABLE(force-sendpacket,
    AC_HELP_STRING([--enable-force-sendpacket], [Force using libpcap's pcap_sendpacket() for sending packets]),
    [ AC_DEFINE([FORCE_INJECT_PCAP_SENDPACKET], [1], [Force using libpcap's pcap_sendpacket() for sending packets])])

dnl Dynamic link libraries
dynamic_link=no
AC_ARG_ENABLE(dynamic-link,
    AC_HELP_STRING([--enable-dynamic-link], [Dynamically link libraries]),
    [ if test x$enableval = xyes; then
        AC_DEFINE([ENABLE_DYNAMIC_LINK], [1], [Enable dynamically linking libs])
        dynamic_link=yes
      fi
    ])

dnl Check for inet_aton and inet_pton
AC_CHECK_FUNC(inet_aton, 
    AC_DEFINE([HAVE_INET_ATON], [1], [Do we have inet_aton?]) 
    inet_aton=yes, 
    inet_aton=no)
AC_CHECK_FUNC(inet_pton, 
    AC_DEFINE([HAVE_INET_PTON], [1], [Do we have inet_pton?]) 
    inet_pton=yes, 
    inet_pton=no)
AC_CHECK_FUNC(inet_ntop, 
    AC_DEFINE([HAVE_INET_NTOP], [1], [Do we have inet_ntop?]) 
    inet_ntop=yes, 
    inet_ntop=no)

if test "$inet_ntop" = "no" -a "$inet_pton" = "no" ; then
    AC_MSG_ERROR([We need either inet_ntop or inet_pton])
fi

AC_CHECK_FUNC(inet_addr, 
    AC_DEFINE([HAVE_INET_ADDR], [1], [Do we have inet_addr?]) 
    inet_addr=yes, 
    inet_addr=no)

if test x$inet_addr = no ; then
    AC_MSG_ERROR([We need inet_addr.  See bug 26])
fi

dnl #####################################################
dnl Checks for libpcap
dnl #####################################################
foundpcap=no
trypcapdir=/usr/local
AC_MSG_CHECKING(for libpcap)
AC_ARG_WITH(libpcap,
    AC_HELP_STRING([--with-libpcap=DIR], [Use libpcap in DIR]),
    [trypcapdir=$withval])

for testdir in $trypcapdir /usr/local /opt/local /usr /wpdpack ; do 
    if test -f "${testdir}/include/pcap.h" -a $foundpcap = no ; then
        LPCAPINC="${testdir}/include/pcap.h"
        LPCAPINCDIR="${testdir}/include"
        if test $dynamic_link = yes; then
            if test -f "${testdir}/lib64/libpcap${shrext_cmds}" ; then
                LPCAPLIB="-L${testdir}/lib64 -lpcap"
            elif test -f "${testdir}/lib/libpcap${shrext_cmds}" ; then
                LPCAPLIB="-L${testdir}/lib -lpcap"
            else
                AC_ERROR([Unable to find libpcap in ${testdir}])
            fi
        elif test -f "${testdir}/lib64/libpcap.${libext}" ; then
            LPCAPLIB="${testdir}/lib64/libpcap.${libext}"
        elif test -f "${testdir}/lib/libpcap.${libext}" ; then
            LPCAPLIB="${testdir}/lib/libpcap.${libext}"
        elif test -f "${testdir}/lib/libwpcap.${libext}" ; then
            LPCAPLIB="${testdir}/lib/libwpcap.${libext}"
            AC_DEFINE([HAVE_WINPCAP], [1], [Do we have WinPcap?])
        else
            AC_ERROR([Unable to find matching library for header file in ${testdir}])
        fi
        foundpcap=$testdir
    fi
done

if test $foundpcap = no ; then
    AC_MSG_RESULT(no)
    AC_ERROR(libpcap not found)
else
    AC_MSG_RESULT($foundpcap)
fi

dnl Checks to see what version of libpcap we've got
OLDLIBS="$LIBS"
OLDCFLAGS="$CFLAGS -I$LPCAPINCDIR"
LIBS="$LPCAPLIB"
CFLAGS="$CFLAGS -I$LPCAPINCDIR"

# Does libpcap require libnl?
AC_SEARCH_LIBS([pcap_close], [pcap],
    LPCAPLIB="$LIBS",
    AC_ERROR([Unable to link libpcap in ${foundpcap}]),
    -lnl)

AC_SUBST(LPCAPINC)
AC_SUBST(LPCAPLIB)


dnl Check to see what version of libpcap
dnl this code has been reduced a lot, but probably still could be
dnl reduced quite a bit more if we chose too
AC_MSG_CHECKING(for libpcap version)

dnl 0.9.6 (which is still thinks it is 0.9.5 due to a bug) introduces an important
dnl fix for OSX.  See: http://tcpreplay.synfin.net/trac/ticket/167
libpcap_version_096=no
AC_RUN_IFELSE(AC_LANG_PROGRAM([[
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "$LPCAPINC"
#define PCAP_TEST "0.9.6"
]], [[
/* 
 * simple proggy to test the version of libpcap
 * returns zero if version >= 0.9.6
 * or one otherwise
 */
    if (strncmp(pcap_lib_version(), PCAP_TEST, 5) >= 0)
            exit(0);

    exit(1);
]]), [
    libpcap_version_096=yes
])

libpcap_ver8=no
AC_RUN_IFELSE(AC_LANG_PROGRAM([[
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "$LPCAPINC"
#define PCAP_TEST "0.8"
]], [[
/* 
 * simple proggy to test the version of libpcap
 * returns zero if version >= 0.8.0
 * or one otherwise
 */
    if (strncmp(pcap_lib_version(), PCAP_TEST, 3) >= 0)
        exit(0);

    /* winpcap? */
    if (strncmp(pcap_lib_version(), "WinPcap", 7) == 0)
        exit(0);

    exit(1);
]]), [
    libpcap_ver8=yes
], [
    libpcap_ver8=no
])

libpcap_ver7=no
AC_RUN_IFELSE(AC_LANG_PROGRAM([[
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "$LPCAPINC"
#define PCAP_TEST "0.7.2"
extern const char pcap_version[[]]; /* double up since autoconf escapes things */
]], [[
/* 
 * simple proggy to test the version of libpcap
 * returns zero if version >= 0.7.2
 * or one otherwise
 */

    if (strncmp(pcap_version, PCAP_TEST, 5) >= 0)
            exit(0);

    exit(1);
]]), [
    libpcap_ver7=yes
], [
    libpcap_ver7=no
])

if test x$libpcap_ver8 = xyes ; then
    AC_MSG_RESULT(>= 0.8.0)
elif test x$libpcap_ver7 = xyes ; then
    AC_MSG_RESULT(>= 0.7.2)
else 
    AC_MSG_ERROR([Libpcap versions < 0.7.2 are not supported
    Please upgrade to version 0.7.2 or better])
fi

libpcap_version=unknown
if test x$libpcap_version_096 = xyes ; then
    libpcap_version=">= 0.9.6"
elif test x$libpcap_ver8 = xyes ; then
    libpcap_version=">= 0.8.0"
elif test x$libcap_ver7 = xyes ; then
    libpcap_version=">= 0.7.0"
fi

dnl Check for pcap_setnonblock()
AC_MSG_CHECKING(for pcap_setnonblock)
AC_LINK_IFELSE(AC_LANG_PROGRAM([[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "$LPCAPINC"
]],[[
    pcap_t *p;
    char *errbuf;

    pcap_setnonblock(p, 1, errbuf);
    exit(0);
]]), [
    have_pcap_setnonblock=yes
    AC_MSG_RESULT(yes)
], [
    have_pcap_setnonblock=no
    AC_MSG_RESULT(no)
])

if test $have_pcap_setnonblock = yes ; then
    AC_DEFINE([HAVE_PCAP_SETNONBLOCK], [1], 
              [Does libpcap have pcap_setnonblock?])
fi

dnl Check to see if we've got pcap_datalink_val_to_name()
AC_MSG_CHECKING(for pcap_datalink_val_to_description)
AC_LINK_IFELSE(AC_LANG_PROGRAM([[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "$LPCAPINC"
]],[[
    if (strcmp(pcap_datalink_val_to_description(1), "Ethernet (10Mb)") == 0)
        exit(0);
    exit(1);
]]),[
    have_dlt_to_desc=yes
    AC_MSG_RESULT(yes)
], [
    have_dlt_to_desc=no
    AC_MSG_RESULT(no)
])

if test $have_dlt_to_desc = yes ; then
    AC_DEFINE([HAVE_DLT_VAL_TO_DESC], [1], 
              [Does libpcap have pcap_datalink_val_to_description?])
fi

dnl Check for pcap_get_selectable_fd()
AC_MSG_CHECKING(for pcap_get_selectable_fd)
AC_LINK_IFELSE(AC_LANG_PROGRAM([[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "$LPCAPINC"
]], [[
    int f;
    pcap_t *p;
    f = pcap_get_selectable_fd(p);
    exit(0);
]]), [
    have_pcap_get_selectable_fd=yes
    AC_MSG_RESULT(yes)
], [
    have_pcap_get_selectable_fd=no
    AC_MSG_RESULT(no)
])

if test x$have_pcap_get_selectable_fd = xyes ; then
    AC_DEFINE([HAVE_PCAP_GET_SELECTABLE_FD], [1], 
        [Does libpcap have pcap_get_selectable_fd?])
fi

dnl Important: winpcap apparently defines functions in it's header files
dnl which aren't actually in the library.  Totally fucked up.  Hence, we
dnl must actually LINK the code, not just compile it.

dnl Check to see if we've got pcap_dump_fopen()
AC_MSG_CHECKING(for pcap_dump_fopen)
AC_LINK_IFELSE(AC_LANG_PROGRAM([[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "$LPCAPINC"
]],[[
    pcap_dumper_t *dump;
    pcap_t *pcap;
    FILE *foo;
    dump = pcap_dump_fopen(pcap, foo);
]]),[
    have_pcap_dump_fopen=yes
    AC_MSG_RESULT(yes)
], [
    have_pcap_dump_fopen=no
    AC_MSG_RESULT(no)
])

if test $have_pcap_dump_fopen = yes ; then
    AC_DEFINE([HAVE_PCAP_DUMP_FOPEN], [1], 
              [Does libpcap have pcap_dump_fopen?])
else
    AC_MSG_NOTICE([--verbose mode requires libpcap >= 0.9.0])
fi

have_pcap_inject=no
dnl Check to see if we've got pcap_inject()
AC_MSG_CHECKING(for pcap_inject sending support)
AC_LINK_IFELSE(AC_LANG_PROGRAM([[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "$LPCAPINC"
]],[[
    pcap_t *pcap;
    char *buf;
    pcap_inject(pcap, (void *)buf, 0);
]]),[
    have_pcap_inject=yes
    AC_MSG_RESULT(yes)
], [
    have_pcap_inject=no
    AC_MSG_RESULT(no)
])

if test $have_pcap_inject = yes ; then
    AC_DEFINE([HAVE_PCAP_INJECT], [1], [Does libpcap have pcap_inject?])
fi

have_pcap_sendpacket=no
dnl Check to see if we've got pcap_sendpacket()
AC_MSG_CHECKING(for pcap_sendpacket sending support)
AC_LINK_IFELSE(AC_LANG_PROGRAM([[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "$LPCAPINC"
]],[[
    pcap_t *pcap;
    u_char *buf;
    pcap_sendpacket(pcap, buf, 0);
]]),[
    have_pcap_sendpacket=yes
    AC_MSG_RESULT(yes)
], [
    have_pcap_sendpacket=no
    AC_MSG_RESULT(no)
])

if test $have_pcap_sendpacket = yes ; then
    AC_DEFINE([HAVE_PCAP_SENDPACKET], [1], [Does libpcap have pcap_sendpacket?])
fi

have_pcap_breakloop=no
AC_MSG_CHECKING(for pcap_breakloop)
AC_LINK_IFELSE(AC_LANG_PROGRAM([[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "$LPCAPINC"
]],[[
    pcap_t *pcap;
    pcap_sendpacket(pcap);
]]),[
    have_pcap_breakloop=yes
    AC_MSG_RESULT(yes)
], [
    have_pcap_breakloop=no
    AC_MSG_RESULT(no)
])

if test $have_pcap_breakloop = yes ; then
    AC_DEFINE([HAVE_PCAP_BREAKLOOP], [1], [Does libpcap have pcap_breakloop?])
fi


have_pcap_version=no
dnl Check to see if we have pcap_version[]
AC_MSG_CHECKING(for pcap_version[])
AC_TRY_COMPILE([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "$LPCAPINC"
extern char pcap_version[];
],[
    printf("%s", pcap_version);
],[
    AC_DEFINE([HAVE_PCAP_VERSION],[1], [Does libpcap have pcap_version[]])
    AC_MSG_RESULT(yes)
],[
    AC_MSG_RESULT(no)
])

have_pcap_snapshot=no
dnl Check for pcap_snapshot()
AC_MSG_CHECKING(for pcap_snapshot)
AC_LINK_IFELSE(AC_LANG_PROGRAM([[
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "$LPCAPINC"
]],[[
    pcap_t *p;
    int len;

    len = pcap_snapshot(p);
    exit(0);
]]), [
    have_pcap_snapshot=yes
    AC_MSG_RESULT(yes)
], [
    have_pcap_snapshot=no
    AC_MSG_RESULT(no)
])

if test $have_pcap_snapshot = yes ; then
    AC_DEFINE([HAVE_PCAP_SNAPSHOT], [1], 
              [Does libpcap have pcap_snapshot?])
fi


# Tcpbridge requires libpcap and pcap_sendpacket()
enable_tcpbridge=no
if test x$foundpcap != xno -a x$have_pcap_sendpacket = xyes ; then

    # if we have pcap_sendpacket() then we can build tcpbridge on non-BPF systems
    if test x$have_bpf = xno; then
        AC_DEFINE(ENABLE_TCPBRIDGE, [1], [Compile tcpbridge])
        enable_tcpbridge=yes
        AC_MSG_NOTICE([Building tcpbridge])

    # BPF systems need to also have pcap_setnonblock()
    elif test x$have_pcap_setnonblock = xyes ; then
        AC_DEFINE(ENABLE_TCPBRIDGE, [1], [Compile tcpbridge])
        enable_tcpbridge=yes
        AC_MSG_NOTICE([Building tcpbridge])
    else
        AC_MSG_WARN([Unable to build tcpbridge.  Try installing latest libpcap!])
    fi
fi
AM_CONDITIONAL(COMPILE_TCPBRIDGE, [test x$enable_tcpbridge = xyes ])



have_pf=no
dnl Check for linux PF_PACKET support
AC_MSG_CHECKING(for PF_PACKET socket sending support)
AC_TRY_COMPILE([
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <netinet/in.h>       /* htons */
],[
    int pf_socket;
    pf_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
],[
    AC_DEFINE([HAVE_PF_PACKET], [1],
            [Do we have Linux PF_PACKET socket support?])
    AC_MSG_RESULT(yes)
    have_pf=yes
],[
    AC_MSG_RESULT(no)
])

have_bpf=no
dnl Check for BSD's BPF
AC_MSG_CHECKING(for BPF device sending support)
AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <net/bpf.h>
#include <errno.h>

int 
main(int argc, char *argv[]) {
    int fd;

    fd = open("/dev/bpf0", O_RDONLY, 0);

    /* if we opened it, we're good */
    if (fd > 1)
        exit(0);

    /* if we got EBUSY or permission denied it exists, so we're good */
    if (fd < 0 && (errno == EBUSY || errno == 13))
        exit(0);

    /* else suck, no good */
    exit(-1);
}],
[
    AC_DEFINE([HAVE_BPF], [1], 
            [Do we have BPF device support?])
    AC_MSG_RESULT(yes)
    have_bpf=yes
],[
    AC_MSG_RESULT(no)
])


dnl ##################################################
dnl # Check for libdnet, but only if not Cygwin! 
dnl ##################################################
founddnet=no
have_libdnet=no
libdnet_version=
enable_fragroute=no
trydnetdir=/usr/local

if test $have_cygwin == no ; then
    AC_MSG_CHECKING(for libdnet)
    AC_ARG_WITH(libdnet,
        AC_HELP_STRING([--with-libdnet=DIR], [Use libdnet in DIR]),
        [trydnetdir=$withval])

    for testdir in $trydnetdir /usr/local /opt/local /usr ; do 
        if test -x ${testdir}/bin/dnet-config -a $founddnet = no ; then
            LDNETINC="`$testdir/bin/dnet-config --cflags`"
            LDNETLIB="`$testdir/bin/dnet-config --libs`"
            libdnet_version="`$testdir/bin/dnet-config --version`"
            founddnet=$testdir
        fi
    done

    if test $founddnet = no ; then
        AC_MSG_RESULT(no)
        AC_MSG_WARN([libdnet not found, disabling fragroute feature])
    else
        AC_MSG_RESULT($founddnet)
        enable_fragroute=yes
        have_libdnet=yes
        AC_DEFINE([HAVE_LIBDNET], [1], [Do we have libdnet?])
    fi

else
    AC_MSG_NOTICE([Skipping libdnet check under Cygwin for compatibility reasons])
fi


AC_SUBST(LDNETINC)
AC_SUBST(LDNETLIB)
AC_DEFINE_UNQUOTED([LIBDNET_VERSION], "$libdnet_version", [Version of libdnet])

AM_CONDITIONAL(COMPILE_FRAGROUTE, [test x$founddnet != xno])
if test x$founddnet != xno ; then
    AC_DEFINE(ENABLE_FRAGROUTE, [1], [Enable fragroute module])
fi


dnl Make sure we have a valid packet injection mechanisim
if test $have_bpf = no -a $have_pcap_inject = no -a $have_pcap_sendpacket = no \
    -a $have_libdnet = no -a $have_pf = no ; then
    AC_MSG_ERROR([Unable to find a supported method to send packets.  Please upgrade your libpcap or enable libdnet])
fi

dnl Older versions of libpcap are missing some DLT types
dnl If doesn't exist, we'll define them in src/common/fakepcap.h
AC_MSG_CHECKING(for DLT_LINUX_SLL in libpcap)
AC_TRY_COMPILE([#include "$LPCAPINC"], 
               [ int foo;
                 foo = DLT_LINUX_SLL ],
                [ AC_DEFINE([HAVE_DLT_LINUX_SLL], [1], 
                            [Does pcap.h include a header with DLT_LINUX_SLL?])
                  AC_MSG_RESULT(yes)
                ], 
                AC_MSG_RESULT(no)
               )

AC_MSG_CHECKING(for DLT_C_HDLC in libpcap)
AC_TRY_COMPILE([#include "$LPCAPINC"],
               [ int foo;
                 foo = DLT_C_HDLC ],
                [ AC_DEFINE([HAVE_DLT_C_HDLC], [1], 
                            [Does pcap.h include a header with DLT_C_HDLC?])
                  AC_MSG_RESULT(yes)
                ],
                AC_MSG_RESULT(no)   
               )

PCAP_BPF_H_FILE="$LPCAPINCDIR/pcap-bpf.h"
AC_MSG_CHECKING(for $PCAP_BPF_H_FILE)
AC_TRY_COMPILE([#include <sys/types.h>
                #include <sys/time.h>
                #include <stdint.h>
                #include "$PCAP_BPF_H_FILE"],
               [ int foo;
                 foo = BPF_MAJOR_VERSION; ],
               [ AC_DEFINE([INCLUDE_PCAP_BPF_HEADER], [1],
                           [What is the path (if any) to the pcap-bpf.h
                            header?])
                 AC_MSG_RESULT(yes)
                 AC_SUBST(PCAP_BPF_H_FILE)
               ],
               AC_MSG_RESULT(no)
               )

foundbpfheader=no
AC_MSG_CHECKING(for libpcap bpf header)
for testfile in $LPCAPINCDIR/pcap/bpf.h $LPCAPINCDIR/pcap-bpf.h ; do
    if test -f "${testfile}" -a $foundbpfheader = no ; then
        AC_TRY_COMPILE([
            #include <sys/types.h>
            #include <sys/time.h>
            #include <stdint.h>
            #include "$testfile"],
            [
                int foo;
                foo = BPF_MAJOR_VERSION;
            ],
            [
                foundbpfheader=yes
                PCAP_BPF_H_FILE=$testfile
                AC_SUBST(PCAP_BPF_H_FILE)
                AC_DEFINE([INCLUDE_PCAP_BPF_HEADER], [1],
                        [What is the path (if any) to the libpcap bpf header file?])
                AC_MSG_RESULT($testfile)
            ],
            AC_MSG_RESULT(no)
            )
    fi
done
dnl restore LIBS & CFLAGS
LIBS="$OLDLIBS"
CFLAGS="$OLDCFLAGS"


dnl ##################################################
dnl # Check for pcapnav
dnl ##################################################
pcapnav_ver=no
pcncfg=no
AC_ARG_WITH(pcapnav-config,
    AC_HELP_STRING([--with-pcapnav-config=FILE], [Use given pcapnav-config]),
    [ AC_MSG_CHECKING(for pcapnav-config)
    if test -x $withval ; then
        pcncfg=$withval
        AC_MSG_RESULT($pcncfg)
    elif test x$withval = xno ; then
        AC_MSG_RESULT(no)
    else
        AC_MSG_RESULT([Can't find pcapnav-config: disabling offset jump feature])
    fi ],
    [ AC_PATH_PROG(pcncfg,[pcapnav-config], [no] ) ]
)

if test $pcncfg != no ; then
    LNAVLIB=`$pcncfg --libs`
    LNAV_CFLAGS=`$pcncfg --cflags`
    PCAPNAV_VERSION=`$pcncfg --version`
    AC_SUBST(LNAVLIB)
    AC_SUBST(LNAV_CFLAGS)
    AC_DEFINE_UNQUOTED(PCAPNAV_VERSION, "$PCAPNAV_VERSION", 
                       [libpcapnav's version?])

dnl Check to see what version of libpcapnav
dnl this code has been reduced a lot, but probably still could be
dnl reduced quite a bit more if we chose too
    AC_MSG_CHECKING(for libpcapnav version)
    AC_TRY_RUN([
#include <string.h>
#define PCAPNAV_TEST "0.4"
/* 
 * simple proggy to test the version of libpcapnav
 * returns zero if version >= 0.4
 * or one otherwise
 */

int
main (int argc, char *argv[])
{
    if (strncmp(PCAPNAV_VERSION, PCAPNAV_TEST, 3) >= 0)
        exit(0);
    exit(1);
}           ],
            libpcapnav_ver=yes
            AC_MSG_RESULT(>= 0.4),
            libpcapnav_ver=no
            AC_MSG_RESULT(< 0.4),
            libpcapnav_ver=no
    )


if test x$libpcapnav_ver = xno ; then
    AC_MSG_WARN([Libpcapnav versions < 0.4 are not supported.
    Please upgrade to version 0.4 or better.
    Disabling offset jump feature.])
else
    AC_DEFINE([HAVE_PCAPNAV], [1], [Do we have libpcapnav?])
fi

fi # checking pcapnav version


dnl (shamelessly ripped off from libpcap)
dnl Checks to see if unaligned memory accesses fail
dnl
dnl     FORCE_ALIGN (DEFINED)
dnl
AC_MSG_CHECKING(for requires strict byte alignment)
AC_CACHE_VAL(unaligned_cv_fail,
        [case "$host_cpu" in

        # XXX: should also check that they don't do weird things (like on arm)
        alpha*|arm*|hp*|mips*|sparc*|ia64)
                unaligned_cv_fail=yes
                ;;

        *)
        cat >conftest.c <<EOF
        #include <sys/types.h>
        #include <sys/wait.h>
        #include <stdio.h>
        unsigned char a[[5]] = { 1, 2, 3, 4, 5 };
        main() {
            unsigned int i;
            pid_t pid;
            int status;
            /* avoid "core dumped" message */
            pid = fork();
            if (pid <  0)
                exit(2);
            if (pid > 0) {
                /* parent */
                pid = waitpid(pid, &status, 0);
                if (pid < 0)
                        exit(3);
                exit(!WIFEXITED(status));
            }
            /* child */
            i = *(unsigned int *)&a[[1]];
            printf("%d\n", i);
            exit(0);
        }
EOF
        ${CC-cc} -o conftest $CFLAGS $CPPFLAGS $LDFLAGS \
            conftest.c $LIBS >/dev/null 2>&1
        if test ! -x conftest ; then
            dnl failed to compile for some reason
            unaligned_cv_fail=yes
        else
            ./conftest >conftest.out
            if test ! -s conftest.out ; then
                unaligned_cv_fail=yes
            else
                unaligned_cv_fail=no
            fi
        fi
        rm -f conftest* core core.conftest
        ;;

        esac
    ])
AC_MSG_RESULT($unaligned_cv_fail)
if test $unaligned_cv_fail = yes ; then
    AC_DEFINE([FORCE_ALIGN], [1], [Are we strictly aligned?])
fi

dnl ##################################################
dnl # Check for tcpdump.
dnl ##################################################

tcpdump_path=no
AC_ARG_WITH(tcpdump,
    AC_HELP_STRING([--with-tcpdump=FILE], [Path to tcpdump binary]),
    [ if test -x $withval ; then
          tcpdump_path=$withval
          AC_MSG_RESULT([Using tcpdump in $tcpdump_path])
      else
          AC_MSG_RESULT([Error: $withval does not exist or is not executable])
      fi ],
    [ AC_PATH_PROG(tcpdump_path, tcpdump, "no", [$PATH:/usr/sbin:/sbin:/usr/local/sbin]) ])


if test "$tcpdump_path" = "no"; then
    AC_MSG_WARN([Unable to find tcpdump.  Please specify --with-tcpdump.
                 Disabling --verbose])
else
    AC_DEFINE([HAVE_TCPDUMP], [1], [Do we have tcpdump?])
    AC_DEFINE_UNQUOTED(TCPDUMP_BINARY, "$tcpdump_path", [The tcpdump binary initially used])
fi


AM_CONDITIONAL([ENABLE_TCPDUMP], test "$tcpdump_path" != "no" -a x$have_pcap_dump_fopen = xyes)
if test x$tcpdump_path != xno -a x$have_pcap_dump_fopen = xyes ; then
    AC_DEFINE([ENABLE_VERBOSE], [1], [Do we have tcpdump and pcap_dump_fopen()?])
else
    AC_MSG_WARN([Your version of libpcap is too old for --verbose support])
fi

dnl No 'make test' when cross compile

AC_MSG_CHECKING(for 'make test' profile)
if test "$host" != "$build" ; then
    AC_MSG_WARN(Unable to do tests when cross-compiling)
fi

dnl Allows user to choose which nic to use for testing purposes
AC_ARG_WITH(testnic,
    AC_HELP_STRING([--with-testnic=NIC], [Select which network card to use for testing]),
    [ nic1=$withval
      nic2=$withval
      AC_MSG_RESULT([Using --with-testnic=$withval])],
    [

dnl There's a bug in OS X which causes pcap_findalldevs() to make the wifi NIC to disassociate
dnl so under OSX we disable the interface list feature
disable_pcap_findalldevs=no

osx_frameworks=no
dnl these need to be dynamic based on OS
case $host in
    *-*-linux*)
    nic1=eth0
    nic2=eth0
    AC_MSG_RESULT(Linux)
    ;;

    *-*-solaris*)
    nic1=hme0
    nic2=hme0
    AC_MSG_RESULT(Solaris)
    ;;

    *-*-sunos*)
    nic1=hme0
    nic2=hme0
    AC_MSG_RESULT(SunOS)
    ;;

    *-apple-darwin*)
    nic1=en0
    nic2=en0
    if test x$libpcap_version_096 = xno ; then
        disable_pcap_findalldevs=yes
    fi
    AC_DEFINE([HAVE_ABSOLUTE_TIME], [1], [Have OS X UpTime()/AbsoluteTime high-precision timing])
    osx_frameworks=yes
    AC_DEFINE([HAVE_DARWIN], [1], [Building Apple/Darwin])
    AC_MSG_RESULT(Apple OS X)
    ;;

    *-*-openbsd*)
    nic1=xl0
    nic2=xl0
    AC_MSG_RESULT(OpenBSD)
    ;;

    *-*-cygwin)
    AC_MSG_RESULT(Win32/Cygwin)
    nic1=%0
    nic2=%0
    ;;

    *)
    AC_MSG_RESULT([$host is unknown!  Using first non-loopback interface])
    nic1=%0
    nic2=%0
    ;;
esac])

AM_CONDITIONAL([ENABLE_OSX_FRAMEWORKS], test "$osx_frameworks" == "yes")

AC_ARG_WITH(testnic2,
    AC_HELP_STRING([--with-testnic2=NIC2], [Select an optional 2nd network card to use for testing]),
    [ nic2=$withval ])

AC_MSG_NOTICE([Using $nic1 for 1st test network interface card])
AC_MSG_NOTICE([Using $nic2 for 2nd test network interface card])
AC_SUBST(nic1)
AC_SUBST(nic2)


AC_MSG_CHECKING([if it's ok to use pcap_findalldevs()])
if test x$disable_pcap_findalldevs = xno ; then
    AC_DEFINE([ENABLE_PCAP_FINDALLDEVS], [1], [Enable use of pcap_findalldevs()])
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi

dnl tcpreplay has (so far) been relying on leading-edge autogen.
dnl Therefore, by default:
dnl - use the version we ship with
dnl - do not install it
dnl - build a static copy (AC_DISABLE_SHARED - implicitly done earlier)
case "${enable_local_libopts+set}" in
 set) ;;
 *) enable_local_libopts=yes ;;
esac

case "${enable_libopts_install+set}" in
 set) ;;
 *) enable_libopts_install=no ;;
esac

LIBOPTS_CHECK(libopts)


AC_OUTPUT([Makefile
           doxygen.cfg
           lib/Makefile
           docs/Makefile
           src/Makefile
           src/common/Makefile
           src/tcpedit/Makefile
           src/fragroute/Makefile
           src/defines.h
           test/Makefile
           test/config
           scripts/Makefile])

# Configuration results
AC_MSG_RESULT(
##########################################################################
             TCPREPLAY Suite Configuration Results (${TCPREPLAY_VERSION})
##########################################################################
libpcap:                    ${foundpcap} (${libpcap_version})
libdnet:                    ${founddnet} (${libdnet_version})
autogen:                    ${AUTOGEN} (${AUTOGEN_VERSION})
Use libopts tearoff:        ${enable_local_libopts}
64bit counter support:      ${use64bit_counters}
tcpdump binary path:        ${tcpdump_path}
tcpreplay edit support:     ${tcpreplay_edit}
fragroute support:          ${enable_fragroute}
tcpbridge support:          ${enable_tcpbridge}

Supported Packet Injection Methods (*):
Linux PF_PACKET:            ${have_pf}
BSD BPF:                    ${have_bpf}
libdnet:                    ${have_libdnet}
pcap_inject:                ${have_pcap_inject}
pcap_sendpacket:            ${have_pcap_sendpacket} **

* In order of preference; see configure --help to override
** Required for tcpbridge
)


case $host in
    *-apple-darwin*)
    AC_MSG_WARN([Apple OS X versions prior to 10.5 (Leopard) has a serious problem!
Please see: http://tcpreplay.synfin.net/trac/ticket/142 for more details])
    ;;

    *-*-cygwin)
        AC_MSG_WARN([Windows/Cygwin support is still somewhat experimental. 
Please report any bugs!	http://tcpreplay.synfin.net/trac/newticket])
    ;;
esac

