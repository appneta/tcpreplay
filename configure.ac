dnl $Id$

AC_INIT(libopts_tearoff)
AC_CONFIG_SRCDIR(libopts/autoopts.c)
AC_CONFIG_HEADER(libopts/config.h)
AC_CONFIG_AUX_DIR(config)
AM_MAINTAINER_MODE


AC_DEFINE(PACKAGE, [libopts_tearoff], [This is our package name])


dnl People building from SVN need the same version of Autogen as I'm using
dnl or specify --disable-local-libopts
MAINTAINER_AUTOGEN_VERSION=5.9.7

AC_CONFIG_MACRO_DIR([m4])

dnl Determine OS
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AC_SUBST(host)
AC_SUBST(build)
AC_SUBST(target)

dnl People building from SVN need the same version of Autogen as I'm using
dnl or specify --disable-local-libopts
MAINTAINER_AUTOGEN_VERSION=5.9.7

AM_INIT_AUTOMAKE(libopts_tearoff, ${MAINTAINER_AUTOGEN_VERSION}, nodefine)

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
enable_local_libopts=yes
AUTOGEN_VERSION=unknown
if test -n "${AUTOGEN}" ; then
	AC_MSG_CHECKING(for autogen version >= 5.9.x)
	${AUTOGEN} -v >autogen.version
	AUTOGEN_VERSION=`cat autogen.version | ${SED} 's|.*\([[0-9\.]]\{3,5\}\).*|\1|'`
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
    if test ! -f src/tcpreplay_opts.c && test "x$enable_local_libopts" != "xyes" ; then
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

# Necessary for make test
AC_C_BIGENDIAN
AM_CONDITIONAL([WORDS_BIGENDIAN], [ test x$ac_cv_c_bigendian = xyes ])

AC_ARG_WITH(testnic,
    AC_HELP_STRING([--with-testnic=NIC], [Select which network card to use for testing]),
    [ nic1=$withval
      nic2=$withval
      AC_MSG_RESULT([Using --with-testnic=$withval])],
    [

    case $host in
        *-*-linux*)
            nic1=eth0
            nic2=eth0
            ;;

        *-*-solaris*)
            nic1=hme0
            nic2=hme0
            ;;

        *-*-sunos*)
            nic1=hme0
            nic2=hme0
            ;;

        *-apple-darwin*)
            nic1=en0
            nic2=en0
            ;;

        *-*-openbsd*)
            nic1=xl0
            nic2=xl0
            ;;

        *-*-cygwin)
            nic1=%0
            nic2=%0
            ;;
        
        *)
            AC_MSG_RESULT([$host is unknown!  Using first non-loopback interface])
            nic1=%0
            nic2=%0
            ;;
    esac])

AC_ARG_WITH(testnic2,
    AC_HELP_STRING([--with-testnic2=NIC2], [Select an optional 2nd network card to use for testing]),
    [ nic2=$withval ])

AC_MSG_NOTICE([Using $nic1 for 1st test network interface card])
AC_MSG_NOTICE([Using $nic2 for 2nd test network interface card])
AC_SUBST(nic1)
AC_SUBST(nic2)

AC_ARG_ENABLE(debug,
    AC_HELP_STRING([--enable-debug], [Enable debugging code and support for the -d option]),
    [ if test x$enableval = xyes; then
        debug=yes
    CFLAGS="${USER_CFLAGS} -ggdb -std=gnu99 -Wall $wextra $wfatal_errors $wno_variadic_macros"
         AC_SUBST(debug_flag)
         AC_DEFINE([DEBUG], [1], [Enable debuging code and support for the -d option])
      fi])

LIBOPTS_CHECK(libopts)

# Don't specify libopts/Makefile here.  LIBOPTS_CHECK(libopts) does that for us!
AC_OUTPUT([docs/Makefile test/config test/Makefile])
