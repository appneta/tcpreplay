
/*
 *  $Id: streqvcmp.c,v 2.24 2004/02/02 03:31:51 bkorb Exp $
 *
 *  String Equivalence Comparison
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

/*
 * This array is designed for mapping upper and lower case letter
 * together for a case independent comparison.  The mappings are
 * based upon ascii character sequences.
 */
static unsigned char charmap[] = {
    0x00, 0x01, 0x02, 0x03,  0x04, 0x05, 0x06, '\a',
    '\b', '\t', '\n', '\v',  '\f', '\r', 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13,  0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B,  0x1C, 0x1D, 0x1E, 0x1F,

    ' ',  '!',  '"',  '#',   '$',  '%',  '&',  '\'',
    '(',  ')',  '*',  '+',   ',',  '-',  '.',  '/',
    '0',  '1',  '2',  '3',   '4',  '5',  '6',  '7',
    '8',  '9',  ':',  ';',   '<',  '=',  '>',  '?',

    '@',  'a',  'b',  'c',   'd',  'e',  'f',  'g',
    'h',  'i',  'j',  'k',   'l',  'm',  'n',  'o',
    'p',  'q',  'r',  's',   't',  'u',  'v',  'w',
    'x',  'y',  'z',  '[',   '\\', ']',  '^',  '_',
    '`',  'a',  'b',  'c',   'd',  'e',  'f',  'g',
    'h',  'i',  'j',  'k',   'l',  'm',  'n',  'o',
    'p',  'q',  'r',  's',   't',  'u',  'v',  'w',
    'x',  'y',  'z',  '{',   '|',  '}',  '~',  0x7f,

    0x80, 0x81, 0x82, 0x83,  0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B,  0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93,  0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B,  0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3,  0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB,  0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3,  0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB,  0xBC, 0xBD, 0xBE, 0xBF,

    0xC0, 0xC1, 0xC2, 0xC3,  0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB,  0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3,  0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB,  0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3,  0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB,  0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3,  0xF4, 0xF5, 0xF6, 0xF7,
    0xF8, 0xF9, 0xFA, 0xFB,  0xFC, 0xFD, 0xFE, 0xFF,
};


int
strneqvcmp( s1, s2, ct )
    const char* s1;
    const char* s2;
    size_t      ct;
{
    for (; ct != 0; --ct) {
        unsigned char u1 = (unsigned char) *s1++;
        unsigned char u2 = (unsigned char) *s2++;
        int dif = charmap[ u1 ] - charmap[ u2 ];

        if (dif != 0)
            return dif;

        if (u1 == NUL)
            return 0;
    }

    return 0;
}


int
streqvcmp( s1, s2 )
    const char* s1;
    const char* s2;
{
    for (;;) {
        unsigned char u1 = (unsigned char) *s1++;
        unsigned char u2 = (unsigned char) *s2++;
        int dif = charmap[ u1 ] - charmap[ u2 ];

        if (dif != 0)
            return dif;

        if (u1 == NUL)
            return 0;
    }
}


void
streqvmap( char From, char To, int ct )
{
    if (ct == 0) {
        ct = sizeof( charmap ) - 1;
        do  {
            charmap[ ct ] = ct;
        } while (--ct >= 0);
    }

    else {
        int  chTo   = (int)To   & 0xFF;
        int  chFrom = (int)From & 0xFF;

        do  {
            charmap[ chFrom ] = (unsigned)chTo;
            chFrom++;
            chTo++;
            if ((chFrom >= sizeof( charmap )) || (chTo >= sizeof( charmap )))
                break;
        } while (--ct > 0);
    }
}


void
strequate( s )
    const char* s;
{
    if ((s != NULL) && (*s != NUL)) {
        unsigned char equiv = (unsigned)*s;
        while (*s != NUL)
            charmap[ (unsigned)*(s++) ] = equiv;
    }
}


void
strtransform( d, s )
    char*       d;
    const char* s;
{
    do  {
        *(d++) = (char)charmap[ (unsigned)*s ];
    } while (*(s++) != NUL);
}

/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/streqvcmp.c */
