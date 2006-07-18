
/*
 *  $Id: load.c,v 4.18 2006/03/25 19:24:56 bkorb Exp $
 *  Time-stamp:      "2005-10-29 14:45:36 bkorb"
 *
 *  This file contains the routines that deal with processing text strings
 *  for options, either from a NUL-terminated string passed in or from an
 *  rc/ini file.
 */

/*
 *  Automated Options copyright 1992-2006 Bruce Korb
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
 *             51 Franklin Street, Fifth Floor,
 *             Boston, MA  02110-1301, USA.
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
static ag_bool
insertProgramPath(
    char*   pzBuf,
    int     bufSize,
    tCC*    pzName,
    tCC*    pzProgPath );

static ag_bool
insertEnvVal(
    char*   pzBuf,
    int     bufSize,
    tCC*    pzName,
    tCC*    pzProgPath );

static char*
assembleArgValue( char* pzTxt, tOptionLoadMode mode );
/* = = = END-STATIC-FORWARD = = = */

/*=export_func  optionMakePath
 * private:
 *
 * what:  translate and construct a path
 * arg:   + char*       + pzBuf      + The result buffer +
 * arg:   + int         + bufSize    + The size of this buffer +
 * arg:   + const char* + pzName     + The input name +
 * arg:   + const char* + pzProgPath + The full path of the current program +
 *
 * ret-type: ag_bool
 * ret-desc: AG_TRUE if the name was handled, otherwise AG_FALSE.
 *           If the name does not start with ``$'', then it is handled
 *           simply by copying the input name to the output buffer and
 *           resolving the name with either @code{canonicalize_file_name(3GLIBC)}
 *           or @code{realpath(3C)}.
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
 *       @bullet{} The input name exceeds @code{bufSize} bytes.
 *       @*
 *       @bullet{} @code{$$} or @code{$NAME} is not the full string and
 *                 the next character is not '/'.
 *       @*
 *       @bullet{} @code{NAME} is not a known environment variable
 *       @*
 *       @bullet{} @code{canonicalize_file_name} or @code{realpath} return
 *                 errors (cannot resolve the resulting path).
=*/
ag_bool
optionMakePath(
    char*   pzBuf,
    int     bufSize,
    tCC*    pzName,
    tCC*    pzProgPath )
{
    ag_bool res = AG_TRUE;

    if (bufSize <= strlen( pzName ))
        return AG_FALSE;

    /*
     *  IF not an environment variable, just copy the data
     */
    if (*pzName != '$') {
        tCC*  pzS = pzName;
        char* pzD = pzBuf;
        int   ct  = bufSize;

        for (;;) {
            if ( (*(pzD++) = *(pzS++)) == NUL)
                break;
            if (--ct <= 0)
                return AG_FALSE;
        }
    }

    /*
     *  IF the name starts with "$$", then it must be "$$" or
     *  it must start with "$$/".  In either event, replace the "$$"
     *  with the path to the executable and append a "/" character.
     */
    else if (pzName[1] == '$')
        res = insertProgramPath( pzBuf, bufSize, pzName, pzProgPath );
    else
        res = insertEnvVal( pzBuf, bufSize, pzName, pzProgPath );

    if (! res)
        return AG_FALSE;

#if defined(HAVE_CANONICALIZE_FILE_NAME)
    {
        char* pz = canonicalize_file_name(pzBuf);
        if (pz == NULL)
            return AG_FALSE;
        if (strlen(pz) < bufSize)
            strcpy(pzBuf, pz);
        free(pz);
    }

#elif defined(HAVE_REALPATH)
    {
        char z[ PATH_MAX+1 ];

        if (realpath( pzBuf, z ) == NULL)
            return AG_FALSE;

        if (strlen(z) < bufSize)
            strcpy( pzBuf, z );
    }
#endif

    return AG_TRUE;
}


static ag_bool
insertProgramPath(
    char*   pzBuf,
    int     bufSize,
    tCC*    pzName,
    tCC*    pzProgPath )
{
    tCC*    pzPath;
    tCC*    pz;
    int     skip = 2;

    switch (pzName[2]) {
    case '/':
        skip = 3;
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

    pzName += skip;

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
    return AG_TRUE;
}


static ag_bool
insertEnvVal(
    char*   pzBuf,
    int     bufSize,
    tCC*    pzName,
    tCC*    pzProgPath )
{
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
    return AG_TRUE;
}


LOCAL void
mungeString( char* pzTxt, tOptionLoadMode mode )
{
    char* pzE;

    if (mode == OPTION_LOAD_KEEP)
        return;

    if (isspace( *pzTxt )) {
        char* pzS = pzTxt;
        char* pzD = pzTxt;
        while (isspace( *++pzS ))  ;
        while ((*(pzD++) = *(pzS++)) != NUL)   ;
        pzE = pzD-1;
    } else
        pzE = pzTxt + strlen( pzTxt );

    while ((pzE > pzTxt) && isspace( pzE[-1] ))  pzE--;
    *pzE = NUL;

    if (mode == OPTION_LOAD_UNCOOKED)
        return;

    switch (*pzTxt) {
    default: return;
    case '"':
    case '\'': break;
    }

    switch (pzE[-1]) {
    default: return;
    case '"':
    case '\'': break;
    }

    (void)ao_string_cook( pzTxt, NULL );
}


static char*
assembleArgValue( char* pzTxt, tOptionLoadMode mode )
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
    if (mode == OPTION_LOAD_KEEP) {
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
    if (space_break && ((*pzEnd == ':') || (*pzEnd == '=')))
        pzEnd++;

    mungeString( pzEnd, mode );
    return pzEnd;
}


/*
 *  Load an option from a block of text.  The text must start with the
 *  configurable/option name and be followed by its associated value.
 *  That value may be processed in any of several ways.  See "tOptionLoadMode"
 *  in autoopts.h.
 */
LOCAL void
loadOptionLine(
    tOptions*   pOpts,
    tOptState*  pOS,
    char*       pzLine,
    tDirection  direction,
    tOptionLoadMode   load_mode )
{
    while (isspace( *pzLine ))  pzLine++;

    {
        char* pzArg = assembleArgValue( pzLine, load_mode );

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
    if (OPTST_GET_ARGTYPE(pOS->pOD->fOptState) == OPARG_TYPE_NONE) {
        if (*pOS->pzOptArg != NUL)
            return;
        pOS->pzOptArg = NULL;

    } else if (pOS->pOD->fOptState & OPTST_ARG_OPTIONAL) {
        if (*pOS->pzOptArg == NUL)
             pOS->pzOptArg = NULL;
        else AGDUPSTR( pOS->pzOptArg, pOS->pzOptArg, "option argument" );

    } else {
        if (*pOS->pzOptArg == NUL)
             pOS->pzOptArg = zNil;
        else AGDUPSTR( pOS->pzOptArg, pOS->pzOptArg, "option argument" );
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
 *  This is a client program callable routine for setting options from, for
 *  example, the contents of a file that they read in.  Only one option may
 *  appear in the text.  It will be treated as a normal (non-preset) option.
 *
 *  When passed a pointer to the option struct and a string, it will find
 *  the option named by the first token on the string and set the option
 *  argument to the remainder of the string.  The caller must NUL terminate
 *  the string.  Any embedded new lines will be included in the option
 *  argument.  If the input looks like one or more quoted strings, then the
 *  input will be "cooked".  The "cooking" is identical to the string
 *  formation used in AutoGen definition files (@pxref{basic expression}),
 *  except that you may not use backquotes.
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
    loadOptionLine( pOpts, &st, pz, DIRECTION_PROCESS, OPTION_LOAD_COOKED );
    AGFREE( pz );
}
/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/load.c */
