
/*
 *  $Id: load.c,v 4.7 2005/02/13 01:48:00 bkorb Exp $
 *  Time-stamp:      "2005-02-14 07:25:49 bkorb"
 *
 *  This file contains the routines that deal with processing text strings
 *  for options, either from a NUL-terminated string passed in or from an
 *  rc/ini file.
 */

/*
 *  Automated Options copyright 1992-2005 Bruce Korb
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

/* = = = START-STATIC-FORWARD = = = */
/* static forward declarations maintained by :mkfwd */
static char*
findArg( char* pzTxt, load_mode_t mode );
/* = = = END-STATIC-FORWARD = = = */

/*=export_func  optionMakePath
 * private:
 *
 * what:  translate and construct a path
 * arg:   + char* + pzBuf      + The result buffer +
 * arg:   + int   + bufSize    + The size of this buffer +
 * arg:   + tCC*  + pzName     + The input name +
 * arg:   + tCC*  + pzProgPath + The full path of the current program +
 *
 * ret-type: ag_bool
 * ret-desc: AG_TRUE if the name was handled, otherwise AG_FALSE.
 *           If the name does not start with ``$'', then it is handled
 *           simply by copying the input name to the output buffer.
 *
 * doc:
 *
 *  This routine will copy the @code{pzName} input name into the @code{pzBuf}
 *  output buffer, carefully not exceeding @code{bufSize} bytes.  If the
 *  first character of the input name is a @code{'$'} character, then there
 *  is special handling:
 *  @*
 *  @code{$$} is replaced with the directory name of the @code{pzProgPath},
 *  searching @code{$PATH} if necessary.
 *  @*
 *  @code{$NAME} is replaced by the contents of the @code{NAME} environment
 *  variable.
 *
 *  Please note: both @code{$$} and @code{$NAME} must be at the start of the
 *     @code{pzName} string and must either be the entire string or be followed
 *     by the @code{'/'} character.
 *
 * err:  @code{AG_FALSE} is returned if:
 *       @*
 *       @bullet{} @code{$$} is not the full string and
 *                 the next character is not '/'.
 *       @*
 *       @bullet{} @code{$NAME} is not the full string and
 *                 the next character is not '/'.
 *       @*
 *       @bullet{} @code{NAME} is not a known environment variable
=*/
ag_bool
optionMakePath(
    char*   pzBuf,
    int     bufSize,
    tCC*    pzName,
    tCC*    pzProgPath )
{
    if (bufSize <= strlen( pzName ))
        return AG_FALSE;

    /*
     *  IF not an environment variable, just copy the data
     */
    if (*pzName != '$') {
        strncpy( pzBuf, pzName, bufSize );
        return AG_TRUE;
    }

    /*
     *  IF the name starts with "$$", then it must be "$$" or
     *  it must start with "$$/".  In either event, replace the "$$"
     *  with the path to the executable and append a "/" character.
     */
    if (pzName[1] == '$') {
        tCC*    pzPath;
        tCC*    pz;

        switch (pzName[2]) {
        case '/':
        case NUL:
            break;
        default:
            return AG_FALSE;
        }

        /*
         *  See if the path is included in the program name.
         *  If it is, we're done.  Otherwise, we have to hunt
         *  for the program using "pathfind".
         */
        if (strchr( pzProgPath, '/' ) != NULL)
            pzPath = pzProgPath;
        else {
            pzPath = pathfind( getenv( "PATH" ), (char*)pzProgPath, "rx" );

            if (pzPath == NULL)
                return AG_FALSE;
        }

        pz = strrchr( pzPath, '/' );

        /*
         *  IF we cannot find a directory name separator,
         *  THEN we do not have a path name to our executable file.
         */
        if (pz == NULL)
            return AG_FALSE;

        /*
         *  Skip past the "$$" and, maybe, the "/".  Anything else is invalid.
         */
        pzName += 2;
        switch (*pzName) {
        case '/':
            pzName++;
        case NUL:
            break;
        default:
            return AG_FALSE;
        }

        /*
         *  Concatenate the file name to the end of the executable path.
         *  The result may be either a file or a directory.
         */
        if ((pz - pzPath)+1 + strlen(pzName) >= bufSize)
            return AG_FALSE;

        memcpy( pzBuf, pzPath, (pz - pzPath)+1 );
        strcpy( pzBuf + (pz - pzPath) + 1, pzName );

        /*
         *  If the "pzPath" path was gotten from "pathfind()", then it was
         *  allocated and we need to deallocate it.
         */
        if (pzPath != pzProgPath)
             free( (void*)pzPath );
    }

    /*
     *  See if the env variable is followed by specified directories
     *  (We will not accept any more env variables.)
     */
    else {
        char* pzDir = pzBuf;

        for (;;) {
            char ch = *++pzName;
            if (! ISNAMECHAR( ch ))
                break;
            *(pzDir++) = ch;
        }

        if (pzDir == pzBuf)
            return AG_FALSE;

        *pzDir = NUL;

        pzDir = getenv( pzBuf );

        /*
         *  Environment value not found -- skip the home list entry
         */
        if (pzDir == NULL)
            return AG_FALSE;

        if (strlen( pzDir ) + 1 + strlen( pzName ) >= bufSize)
            return AG_FALSE;

        sprintf( pzBuf, "%s%s", pzDir, pzName );
    }

#ifdef HAVE_REALPATH
    {
        char z[ PATH_MAX+1 ];

        if (realpath( pzBuf, z ) == NULL)
            return AG_FALSE;

        strcpy( pzBuf, z );
    }
#endif

    return AG_TRUE;
}


static char*
findArg( char* pzTxt, load_mode_t mode )
{
    tSCC zBrk[] = " \t:=";
    char* pzEnd = strpbrk( pzTxt, zBrk );
    int   space_break;

    /*
     *  Not having an argument to a configurable name is okay.
     */
    if (pzEnd == NULL)
        return pzTxt + strlen(pzTxt);

    /*
     *  If we are keeping all whitespace, then the value starts with the
     *  character that follows the end of the configurable name, regardless
     *  of which character caused it.
     */
    if (mode == LOAD_KEEP) {
        *(pzEnd++) = NUL;
        return pzEnd;
    }

    /*
     *  If the name ended on a white space character, remember that
     *  because we'll have to skip over an immediately following ':' or '='
     *  (and the white space following *that*).
     */
    space_break = isspace(*pzEnd);
    *(pzEnd++) = NUL;
    while (isspace(*pzEnd))  pzEnd++;
    if (space_break) {
        if ((*pzEnd == ':') || (*pzEnd == '='))
            while (isspace(*++pzEnd))   ;
    }

    /*
     *  Trim off trailing white space
     */
    {
        char* pz = pzEnd + strlen(pzEnd);
        while (isspace(pz[-1]) && (pz > pzEnd))  pz--;
        *pz = NUL;

        if ((mode == LOAD_UNCOOKED) || (pzEnd == pz))
            return pzEnd;

        if ((pz[-1] != '"') && (pz[-1] != '\''))
            return pzEnd;
    }
    if ((*pzEnd != '"') && (*pzEnd != '\''))
        return pzEnd;

    /*
     *  If we got to here, the text starts and ends with a quote character and
     *  we are cooking our quoted strings.
     */
    (void)ao_string_cook( pzEnd, NULL );
    return pzEnd;
}


/*
 *  Load an option from a block of text.  The text must start with the
 *  configurable/option name and be followed by its associated value.
 *  That value may be processed in any of several ways.  See "load_mode_t"
 *  in autoopts.h.
 */
LOCAL void
loadOptionLine(
    tOptions*   pOpts,
    tOptState*  pOS,
    char*       pzLine,
    tDirection  direction,
    load_mode_t load_mode )
{
    while (isspace( *pzLine ))  pzLine++;

    {
        char* pzArg = findArg( pzLine, load_mode );

        if (! SUCCESSFUL( longOptionFind( pOpts, pzLine, pOS )))
            return;
        if (pOS->flags & OPTST_NO_INIT)
            return;
        pOS->pzOptArg = pzArg;
    }

    switch (pOS->flags & (OPTST_IMM|OPTST_DISABLE_IMM)) {
    case 0:
        /*
         *  The selected option has no immediate action.
         *  THEREFORE, if the direction is PRESETTING
         *  THEN we skip this option.
         */
        if (PRESETTING(direction))
            return;
        break;

    case OPTST_IMM:
        if (PRESETTING(direction)) {
            /*
             *  We are in the presetting direction with an option we handle
             *  immediately for enablement, but normally for disablement.
             *  Therefore, skip if disabled.
             */
            if ((pOS->flags & OPTST_DISABLED) == 0)
                return;
        } else {
            /*
             *  We are in the processing direction with an option we handle
             *  immediately for enablement, but normally for disablement.
             *  Therefore, skip if NOT disabled.
             */
            if ((pOS->flags & OPTST_DISABLED) != 0)
                return;
        }
        break;

    case OPTST_DISABLE_IMM:
        if (PRESETTING(direction)) {
            /*
             *  We are in the presetting direction with an option we handle
             *  immediately for disablement, but normally for disablement.
             *  Therefore, skip if NOT disabled.
             */
            if ((pOS->flags & OPTST_DISABLED) != 0)
                return;
        } else {
            /*
             *  We are in the processing direction with an option we handle
             *  immediately for disablement, but normally for disablement.
             *  Therefore, skip if disabled.
             */
            if ((pOS->flags & OPTST_DISABLED) == 0)
                return;
        }
        break;

    case OPTST_IMM|OPTST_DISABLE_IMM:
        /*
         *  The selected option is always for immediate action.
         *  THEREFORE, if the direction is PROCESSING
         *  THEN we skip this option.
         */
        if (PROCESSING(direction))
            return;
        break;
    }

    /*
     *  Fix up the args.
     */
    switch (pOS->pOD->optArgType) {
    case ARG_NONE:
        if (*pOS->pzOptArg != NUL)
            return;
        pOS->pzOptArg = NULL;
        break;

    case ARG_MAY:
        if (*pOS->pzOptArg == NUL)
             pOS->pzOptArg = NULL;
        else AGDUPSTR( pOS->pzOptArg, pOS->pzOptArg, "option argument" );
        break;

    case ARG_MUST:
        if (*pOS->pzOptArg == NUL)
             pOS->pzOptArg = "";
        else AGDUPSTR( pOS->pzOptArg, pOS->pzOptArg, "option argument" );
        break;
    }

    handleOption( pOpts, pOS );
}


/*=export_func  optionLoadLine
 *
 * what:  process a string for an option name and value
 *
 * arg:   tOptions*,   pOpts,  program options descriptor
 * arg:   const char*, pzLine, NUL-terminated text
 *
 * doc:
 *
 * This is a client program callable routine for setting options from, for
 * example, the contents of a file that they read in.  Only one option may
 * appear in the text.  It will be treated as a normal (non-preset) option.
 *
 * When passed a pointer to the option struct and a string, it will
 * find the option named by the first token on the string and set
 * the option argument to the remainder of the string.  The caller must
 * NUL terminate the string.  Any embedded new lines will be included
 * in the option argument.
 *
 * err:   Invalid options are silently ignored.  Invalid option arguments
 *        will cause a warning to print, but the function should return.
=*/
void
optionLoadLine(
    tOptions*  pOpts,
    tCC*       pzLine )
{
    tOptState st = OPTSTATE_INITIALIZER(SET);
    char* pz;
    AGDUPSTR( pz, pzLine, "user option line" );
    loadOptionLine( pOpts, &st, pz, DIRECTION_PROCESS, LOAD_UNCOOKED );
    AGFREE( pz );
}
/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * tab-width: 4
 * indent-tabs-mode: nil
 * tab-width: 4
 * End:
 * end of autoopts/load.c */
