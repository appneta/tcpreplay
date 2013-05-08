
/**
 * \file autoopts.c
 *
 *  Time-stamp:      "2012-06-15 12:31:28 bkorb"
 *
 *  This file contains all of the routines that must be linked into
 *  an executable to use the generated option processing.  The optional
 *  routines are in separately compiled modules so that they will not
 *  necessarily be linked in.
 *
 *  This file is part of AutoOpts, a companion to AutoGen.
 *  AutoOpts is free software.
 *  AutoOpts is Copyright (c) 1992-2012 by Bruce Korb - all rights reserved
 *
 *  AutoOpts is available under any one of two licenses.  The license
 *  in use must be one of these two and the choice is under the control
 *  of the user of the license.
 *
 *   The GNU Lesser General Public License, version 3 or later
 *      See the files "COPYING.lgplv3" and "COPYING.gplv3"
 *
 *   The Modified Berkeley Software Distribution License
 *      See the file "COPYING.mbsd"
 *
 *  These files have the following md5sums:
 *
 *  43b91e8ca915626ed3818ffb1b71248b pkg/libopts/COPYING.gplv3
 *  06a1a2e4760c90ea5e1dad8dfaac4d39 pkg/libopts/COPYING.lgplv3
 *  66a5cedaf62c4b2637025f049f9b826f pkg/libopts/COPYING.mbsd
 */

#ifndef WINDOWS_CONFIG_HACKERY
#define WINDOWS_CONFIG_HACKERY 1

/*
 * The definitions below have been stolen from NTP's config.h for Windows.
 * However, they may be kept here in order to keep libopts independent from
 * the NTP project.
 */
#ifndef __windows__
#  define __windows__ 4
#endif

/*
 * Miscellaneous functions that Microsoft maps
 * to other names
 *
 * #define inline __inline
 * #define vsnprintf _vsnprintf
 */
#define snprintf _snprintf
/*
 * #define stricmp _stricmp
 * #define strcasecmp _stricmp
 * #define isascii __isascii
 * #define finite _finite
 * #define random      rand
 * #define srandom     srand
 */

#define SIZEOF_INT   4
#define SIZEOF_CHARP 4
#define SIZEOF_LONG  4
#define SIZEOF_SHORT 2

typedef unsigned long uintptr_t;

/*
 * # define HAVE_NET_IF_H
 * # define QSORT_USES_VOID_P
 * # define HAVE_SETVBUF
 * # define HAVE_VSPRINTF
 * # define HAVE_SNPRINTF
 * # define HAVE_VSNPRINTF
 * # define HAVE_PROTOTYPES             /* from ntpq.mak * /
 * # define HAVE_MEMMOVE
 * # define HAVE_TERMIOS_H
 * # define HAVE_ERRNO_H
 * # define HAVE_STDARG_H
 * # define HAVE_NO_NICE
 * # define HAVE_MKTIME
 * # define TIME_WITH_SYS_TIME
 * # define HAVE_IO_COMPLETION_PORT
 * # define ISC_PLATFORM_NEEDNTOP
 * # define ISC_PLATFORM_NEEDPTON
 * # define NEED_S_CHAR_TYPEDEF
 * # define USE_PROTOTYPES              /* for ntp_types.h * /
 *
 * #define ULONG_CONST(a) a ## UL
 */

#define HAVE_LIMITS_H   1
#define HAVE_STRDUP     1
#define HAVE_STRCHR     1
#define HAVE_FCNTL_H    1

/*
 * VS.NET's version of wspiapi.h has a bug in it
 * where it assigns a value to a variable inside
 * an if statement. It should be comparing them.
 * We prevent inclusion since we are not using this
 * code so we don't have to see the warning messages
 */
#ifndef _WSPIAPI_H_
#define _WSPIAPI_H_
#endif

/* Prevent inclusion of winsock.h in windows.h */
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#ifndef __RPCASYNC_H__
#define __RPCASYNC_H__
#endif

/* Include Windows headers */
#include <windows.h>
#include <winsock2.h>
#include <limits.h>

/*
 * Compatibility declarations for Windows, assuming SYS_WINNT
 * has been defined.
 */
#define strdup  _strdup
#define stat    _stat       /* struct stat from <sys/stat.h> */
#define unlink  _unlink
#define fchmod( _x, _y );
#define ssize_t SSIZE_T

#include <io.h>
#define open    _open
#define close   _close
#define read    _read
#define write   _write
#define lseek   _lseek
#define pipe    _pipe
#define dup2    _dup2

#define O_RDWR     _O_RDWR
#define O_RDONLY   _O_RDONLY
#define O_EXCL     _O_EXCL

#ifndef S_ISREG
#  define S_IFREG _S_IFREG
#  define       S_ISREG(mode)   (((mode) & S_IFREG) == S_IFREG)
#endif

#ifndef S_ISDIR
#  define S_IFDIR _S_IFDIR
#  define       S_ISDIR(mode)   (((mode) & S_IFDIR) == S_IFDIR)
#endif

#endif /* WINDOWS_CONFIG_HACKERY */
