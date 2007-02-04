/* $Id: err.h 1594 2006-10-08 22:16:15Z aturner $ */

/*
 * err.h
 *
 * Adapted from OpenBSD libc *err* *warn* code.
 *
 * Copyright (c) 2001-2005 Aaron Turner.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)err.h	8.1 (Berkeley) 6/2/93
 */

#ifndef _ERR_H_
#define _ERR_H_


/*
 * We define five functions for reporting errors, warnings and debug messages:
 * err()   - Fatal error.  Pass exit code followed by static string
 * errx()  - Fatal error.  Pass exit code, format string, one or more variables
 * warn()  - Warning. Pass static string
 * warnx() - Warning. Pass format string, one or more variables
 * dbg()   - Debug. Debug level to trigger, static string
 * dbgx()  - Debug. Debug level to trigger, format string, one or more variables
 * notice() - Informational only via stderr, format string, one or more variables
 */


#define dbg(x, y) _our_verbose_dbg(x, y, __FUNCTION__, __LINE__, __FILE__)
void _our_verbose_dbg(int dbg_level, const char *string, const char *, 
        const int, const char *);

#define dbgx(x, y, ...) _our_verbose_dbgx(x, y, __FUNCTION__, __LINE__, __FILE__, __VA_ARGS__)
void _our_verbose_dbgx(int dbg_level, const char *fmt, const char *, 
        const int, const char *, ...);

void notice(const char *fmt, ...);


#ifdef DEBUG /* then err, errx, warn, warnx print file, func, line */

#define err(x, y) _our_verbose_err(x, y, __FUNCTION__, __LINE__, __FILE__)
void _our_verbose_err(int eval, const char *string, const char *, const int, const char *);

#define warn(x) _our_verbose_warn(x, __FUNCTION__, __LINE__, __FILE__)
void _our_verbose_warn(const char *fmt, const char *, const int, const char *);

#define errx(x, y, ...) _our_verbose_errx(x, y, __FUNCTION__, __LINE__, __FILE__, __VA_ARGS__)
void _our_verbose_errx(int eval, const char *fmt, const char *, const int, const char *, ...);

#define warnx(x, ...) _our_verbose_warnx(x, __FUNCTION__, __LINE__, __FILE__, __VA_ARGS__)
void _our_verbose_warnx(const char *fmt, const char *, const int, const char *, ...);

#else /* no detailed DEBUG info */

#define err(x, y) _our_verbose_err(x, y)
void _our_verbose_err(int eval, const char *string);

#define errx(x, y, ...) _our_verbose_errx(x, y, __VA_ARGS__)
void _our_verbose_errx(int eval, const char *fmt, ...);

#define warn(x) _our_verbose_warn(x)
void _our_verbose_warn(const char *fmt);

#define warnx(x, ...) _our_verbose_warnx(x, __VA_ARGS__)
void _our_verbose_warnx(const char *fmt, ...);

#endif /* DEBUG */


#endif /* !_ERR_H_ */

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/
