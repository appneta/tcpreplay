/*  -*- Mode: C -*-  */

/* --- fake the preprocessor into handlng portability */

/*
 *  Time-stamp:      "2004-04-02 11:21:26 bkorb"
 *
 * Author:           Gary V Vaughan <gvaughan@oranda.demon.co.uk>
 * Created:          Mon Jun 30 15:54:46 1997
 *
 * $Id: compat.h,v 2.17 2004/04/03 17:01:18 bkorb Exp $
 */
#ifndef COMPAT_H
#define COMPAT_H 1

#include <config.h>

#ifndef HAVE_SYS_TYPES_H
#  error NEED <sys/types.h>
#endif

#ifndef HAVE_SYS_STAT_H
#  error NEED <sys/stat.h>
#endif

#ifndef HAVE_STRING_H
#  error NEED <string.h>
#endif

#ifndef HAVE_ERRNO_H
#  error NEED <errno.h>
#endif

#ifndef HAVE_STDLIB_H
#  error NEED <stdlib.h>
#endif

#ifndef HAVE_MEMORY_H
#  error NEED <memory.h>
#endif

#if (! defined(HAVE_LIMITS_H)) && (! defined(HAVE_SYS_LIMITS_H))
#  error NEED <limits.h> *OR* <sys/limits.h>
#endif

#ifndef HAVE_SETJMP_H
#  error NEED <setjmp.h>
#endif

#ifndef HAVE_STRSIGNAL
   char * strsignal( int signo );
#else
#  define  _GNU_SOURCE /* for strsignal in GNU's libc */
#  define  __USE_GNU   /* exact same thing as above   */
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  SYSTEM HEADERS:
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/param.h>
#if HAVE_SYS_PROCSET_H
#  include <sys/procset.h>
#endif
#include <sys/stat.h>
#include <sys/wait.h>

#if defined( HAVE_POSIX_SYSINFO )
#  include <sys/systeminfo.h>
#elif defined( HAVE_UNAME_SYSCALL )
#  include <sys/utsname.h>
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  USER HEADERS:
 */
#include <stdio.h>
#include <assert.h>
#include <ctype.h>

/*
 *  Directory opening stuff:
 */
# if defined (_POSIX_SOURCE)
/* Posix does not require that the d_ino field be present, and some
   systems do not provide it. */
#    define REAL_DIR_ENTRY(dp) 1
# else /* !_POSIX_SOURCE */
#    define REAL_DIR_ENTRY(dp) (dp->d_ino != 0)
# endif /* !_POSIX_SOURCE */

# if defined (HAVE_DIRENT_H)
#   include <dirent.h>
#   define D_NAMLEN(dirent) strlen((dirent)->d_name)
# else /* !HAVE_DIRENT_H */
#   define dirent direct
#   define D_NAMLEN(dirent) (dirent)->d_namlen
#   if defined (HAVE_SYS_NDIR_H)
#     include <sys/ndir.h>
#   endif /* HAVE_SYS_NDIR_H */
#   if defined (HAVE_SYS_DIR_H)
#     include <sys/dir.h>
#   endif /* HAVE_SYS_DIR_H */
#   if defined (HAVE_NDIR_H)
#     include <ndir.h>
#   endif /* HAVE_NDIR_H */
#   if !defined (HAVE_SYS_NDIR_H) && \
       !defined (HAVE_SYS_DIR_H)  && \
       !defined (HAVE_NDIR_H)
#     include "ndir.h"
#   endif /* !HAVE_SYS_NDIR_H && !HAVE_SYS_DIR_H && !HAVE_NDIR_H */
# endif /* !HAVE_DIRENT_H */

#include <errno.h>
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#if defined(HAVE_LIBGEN) && defined(HAVE_LIBGEN_H)
#  include <libgen.h>
#endif
#ifdef HAVE_LIMITS_H
#  include <limits.h>
#else
#  include <sys/limits.h>
#endif
#include <memory.h>
#include <setjmp.h>
#include <signal.h>

#if defined( HAVE_STDINT_H )
#  include <stdint.h>
#elif defined( HAVE_INTTYPES_H )
#  include <inttypes.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <utime.h>

#ifdef HAVE_UNISTD_H
#   include <unistd.h>
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  FIXUPS and CONVIENCE STUFF:
 */
#ifdef __cplusplus
#   define EXTERN extern "C"
#else
#   define EXTERN extern
#endif

#undef STATIC

#ifdef DEBUG
#  define STATIC
#else
#  define STATIC static
#endif

/* some systems #def errno! and others do not declare it!! */
#ifndef errno
   extern       int     errno;
#endif

/* Some machines forget this! */

# ifndef EXIT_FAILURE
#   define EXIT_SUCCESS 0
#   define EXIT_FAILURE 1
# endif

#ifndef NUL
#  define NUL '\0'
#endif

#if !defined (MAXPATHLEN) && defined (HAVE_SYS_PARAM_H)
#  include <sys/param.h>
#endif /* !MAXPATHLEN && HAVE_SYS_PARAM_H */

#if !defined (MAXPATHLEN) && defined (PATH_MAX)
#  define MAXPATHLEN PATH_MAX
#endif /* !MAXPATHLEN && PATH_MAX */

#if !defined (MAXPATHLEN)
#  define MAXPATHLEN 4096
#endif /* MAXPATHLEN */

# ifndef LONG_MAX
#   define LONG_MAX     ~(1L << (8*sizeof(long) -1))
#   define INT_MAX      ~(1 << (8*sizeof(int) -1))
#   define SHORT_MAX    ~(1 << (8*sizeof(short) -1))
# endif

# ifndef ULONG_MAX
#   define ULONG_MAX    ~(OUL)
#   define UINT_MAX     ~(OU)
#   define USHORT_MAX   ~(OUS)
# endif

/* redefine these for BSD style string libraries */
#ifndef HAVE_STRCHR
#  define strchr        index
#  define strrchr       rindex
#endif

#ifndef HAVE_PATHFIND
  EXTERN char *pathfind(const char *, const char *, const char *);
#endif

#ifndef NULL
#  define NULL 0
#endif

#ifdef USE_FOPEN_BINARY
#  ifndef FOPEN_BINARY_FLAG
#    define FOPEN_BINARY_FLAG   "b"
#  endif
#  ifndef FOPEN_TEXT_FLAG
#    define FOPEN_TEXT_FLAG     "t"
#  endif
#else
#  ifndef FOPEN_BINARY_FLAG
#    define FOPEN_BINARY_FLAG
#  endif
#  ifndef FOPEN_TEXT_FLAG
#    define FOPEN_TEXT_FLAG
#  endif
#endif

#ifndef STR
#  define _STR(s) #s
#  define STR(s)  _STR(s)
#endif

/* ##### Pointer sized word ##### */

/* FIXME:  the MAX stuff in here is broken! */
#if SIZEOF_CHARP > SIZEOF_INT
   typedef long t_word;
   #define WORD_MAX  LONG_MAX
   #define WORD_MIN  LONG_MIN
#else /* SIZEOF_CHARP <= SIZEOF_INT */
   typedef int t_word;
   #define WORD_MAX  INT_MAX
   #define WORD_MIN  INT_MIN
#endif

#endif /* COMPAT_H */
/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 * compat.h ends here */
