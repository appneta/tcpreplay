
/*
 *  $Id: streqv.h,v 2.14 2004/02/16 22:12:50 bkorb Exp $
 *
 *  String Equivalence
 *
 *  These routines allow any character to be mapped to any other
 *  character before comparison.  In processing long option names,
 *  the characters "-", "_" and "^" all need to be equivalent
 *  (because they are treated so by different development environments).
 */

/*
 *  Automated Options copyright 1992-2004 Bruce Korb
 *
 *  Automated Options is free software.
 *  You may redistribute it and/or modify it under the terms of the
 *  GNU General Public License, as published by the Free Software
 *  Foundation; either version 2, or (at your option) any later version.
 *
 *  Automated Options is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Automated Options.  See the file "COPYING".  If not,
 *  write to:  The Free Software Foundation, Inc.,
 *             59 Temple Place - Suite 330,
 *             Boston,  MA  02111-1307, USA.
 *
 * As a special exception, Bruce Korb gives permission for additional
 * uses of the text contained in his release of AutoOpts.
 *
 * The exception is that, if you link the AutoOpts library with other
 * files to produce an executable, this does not by itself cause the
 * resulting executable to be covered by the GNU General Public License.
 * Your use of that executable is in no way restricted on account of
 * linking the AutoOpts library code into it.
 *
 * This exception does not however invalidate any other reasons why
 * the executable file might be covered by the GNU General Public License.
 *
 * This exception applies only to the code released by Bruce Korb under
 * the name AutoOpts.  If you copy code from other sources under the
 * General Public License into a copy of AutoOpts, as the General Public
 * License permits, the exception does not apply to the code that you add
 * in this way.  To avoid misleading anyone as to the status of such
 * modified files, you must delete this exception notice from them.
 *
 * If you write modifications of your own for AutoOpts, it is your choice
 * whether to permit this exception to apply to your modifications.
 * If you do not wish that, delete this exception notice.
 */

#ifndef TOOLS_STREQUIVALENCE
#define TOOLS_STREQUIVALENCE

/* strneqvcmp
 *
 *  Compare a pair of equivalenced strings for a fixed length
 */
extern int strneqvcmp( const char* s1, const char* s2, size_t ct );

/* streqvcmp
 *
 *  Compare a pair of NUL-terminated equivalenced strings
 */
extern int streqvcmp( const char* s1, const char* s2 );

/* strequate
 *
 *  Make all the characters in the NUL-terminated string
 *  compare as equivalent (the second and following characters
 *  will be mapped to the first character).
 */
extern void strequate( const char* s );

/*
 *  streqvmap
 *
 *  Remap a series of characters to another series.
 *  e.g.  "streqvmap( 'a', 'A', 26 )" remaps lower case to upper case.
 *  SPECIAL CASE:  if "ct" is 0 (zero), then all 256 characters will
 *  be remapped to their identities.
 *
 *  DEFAULT STATE:  lower case is mapped to upper with nothing else remapped.
 */
extern void streqvmap( char chFrom, char chTo, int ct );

/*
 *  strtransform
 *
 *  Transform a string according to the current equivalence map.
 */
extern void strtransform( char* d, const char* s );

#endif /* TOOLS_STREQUIVALENCE */
/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/streqv.h */
