
/*
 *  $Id: load.c,v 1.3 2004/02/02 03:31:50 bkorb Exp $
 *
 *  This file contains the routines that deal with processing text strings
 *  for options, either from a NUL-terminated string passed in or from an
 *  rc/ini file.
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

/* === STATIC PROCS === */
STATIC void
loadOptionLine(
    tOptions*  pOpts,
    tOptState* pOS,
    char*      pzLine,
    tDirection direction );

/* === END STATIC PROCS === */

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
 *
 * doc:
 *  This routine does environment variable expansion if the first character
 *  is a ``$''.  If it starts with two dollar characters, then the path
 *  is relative to the location of the executable.
=*/
ag_bool
optionMakePath(
    char*    pzBuf,
    int      bufSize,
    tCC*     pzName,
    tCC*     pzProgPath )
{
    if (bufSize <= strlen( pzName ))
        return AG_FALSE;

    /*
     *  IF not an environment variable, just copy the data
     */
    if (*pzName != '$') {
        strcpy( pzBuf, pzName );
        return AG_TRUE;
    }

    /*
     *  IF the name starts with "$$", then it must be "$$" or
     *  it must start with "$$/".  In either event, replace the "$$"
     *  with the path to the executable and append a "/" character.
     */
    if (pzName[1] == '$') {
        tCC*  pzPath;
        tCC*  pz;

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

    return AG_TRUE;
}


STATIC void
loadOptionLine(
    tOptions*  pOpts,
    tOptState* pOS,
    char*      pzLine,
    tDirection direction )
{
    /*
     *  Strip off the first token on the line.
     *  No quoting, space separation only.
     */
    {
        char* pz = pzLine;
        while (  (! isspace( *pz ))
              && (*pz != NUL)
              && (*pz != '=' )  ) pz++;

        /*
         *  IF we exited because we found either a space char or an '=',
         *  THEN terminate the name (clobbering either a space or '=')
         *       and scan over any more white space that follows.
         */
        if (*pz != NUL) {
            *pz++ = NUL;
            while (isspace( *pz )) pz++;
        }

        /*
         *  Make sure we can find the option in our tables and initing it is OK
         */
        if (! SUCCESSFUL( longOptionFind( pOpts, pzLine, pOS )))
            return;
        if (pOS->flags & OPTST_NO_INIT)
            return;

        pOS->pzOptArg = pz;
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


/*
 *  filePreset
 *
 *  Load a file containing presetting information (an RC file).
 */
LOCAL void
filePreset(
    tOptions*     pOpts,
    const char*   pzFileName,
    int           direction )
{
    typedef enum { SEC_NONE, SEC_LOOKING, SEC_PROCESS } teSec;
    teSec   sec     = SEC_NONE;
    FILE*   fp      = fopen( pzFileName, (const char*)"r" FOPEN_BINARY_FLAG );
    u_int   saveOpt = pOpts->fOptSet;
    char    zLine[ 0x1000 ];

    if (fp == NULL)
        return;

    /*
     *  DO NOT STOP ON ERRORS.  During preset, they are ignored.
     */
    pOpts->fOptSet &= ~OPTPROC_ERRSTOP;

    /*
     *  FOR each line in the file...
     */
    while (fgets( zLine, sizeof( zLine ), fp ) != NULL) {
        char*  pzLine = zLine;

        for (;;) {
            pzLine += strlen( pzLine );

            /*
             *  IF the line is full, we stop...
             */
            if (pzLine >= zLine + (sizeof( zLine )-2))
                break;
            /*
             *  Trim of trailing white space.
             */
            while ((pzLine > zLine) && isspace(pzLine[-1])) pzLine--;
            *pzLine = NUL;
            /*
             *  IF the line is not continued, then exit the loop
             */
            if (pzLine[-1] != '\\')
                break;
            /*
             *  insert a newline and get the continuation
             */
            pzLine[-1] = '\n';
            fgets( pzLine, sizeof( zLine ) - (int)(pzLine - zLine), fp );
        }

        pzLine = zLine;
        while (isspace( *pzLine )) pzLine++;

        switch (*pzLine) {
        case NUL:
        case '#':
            /*
             *  Ignore blank and comment lines
             */
            continue;

        case '[':
            /*
             *  Enter a section IFF sections are requested and the section
             *  name matches.  If the file is not sectioned,
             *  then all will be handled.
             */
            if (pOpts->pzPROGNAME == NULL)
                goto fileDone;

            switch (sec) {
            case SEC_NONE:
                sec = SEC_LOOKING;
                /* FALLTHROUGH */

            case SEC_LOOKING:
            {
                int secNameLen = strlen( pOpts->pzPROGNAME );
                if (  (strncmp( pzLine+1, pOpts->pzPROGNAME, secNameLen ) != 0)
                   || (pzLine[secNameLen+1] != ']')  )
                    continue;
                sec = SEC_PROCESS;
                break;
            }

            case SEC_PROCESS:
                goto fileDone;
            }
            break;

        default:
            /*
             *  Load the line only if we are not in looking-for-section state
             */
            if (sec == SEC_LOOKING)
                continue;
        }

        {
            tOptState st = { NULL, OPTST_PRESET, TOPT_UNDEFINED, 0, NULL };
            loadOptionLine( pOpts, &st, pzLine, direction );
        }
    } fileDone:;

    pOpts->fOptSet = saveOpt;
    fclose( fp );
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
 * This is a user callable routine for setting options from, for
 * example, the contents of a file that they read in.
 * Only one option may appear in the text.  It will be treated
 * as a normal (non-preset) option.
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
    tOptState st = { NULL, OPTST_SET, TOPT_UNDEFINED, 0, NULL };
    char* pz;
    AGDUPSTR( pz, pzLine, "user option line" );
    loadOptionLine( pOpts, &st, pz, DIRECTION_PROCESS );
    AGFREE( pz );
}


/*=export_func  doLoadOpt
 * private:
 *
 * what:  Load an option rc/ini file
 * arg:   + tOptions* + pOpts    + program options descriptor +
 * arg:   + tOptDesc* + pOptDesc + the descriptor for this arg +
 *
 * doc:
 *  Processes the options found in the file named with pOptDesc->pzLastArg.
=*/
void
doLoadOpt( tOptions* pOpts, tOptDesc* pOptDesc )
{
    /*
     *  IF the option is not being disabled,
     *  THEN load the file.  There must be a file.
     *  (If it is being disabled, then the disablement processing
     *  already took place.  It must be done to suppress preloading
     *  of ini/rc files.)
     */
    if (! DISABLED_OPT( pOptDesc )) {
        struct stat sb;
        if (stat( pOptDesc->pzLastArg, &sb ) != 0) {
            tSCC zMsg[] =
                "File error %d (%s) opening %s for loading options\n";

            if ((pOpts->fOptSet & OPTPROC_ERRSTOP) == 0)
                return;

            fprintf( stderr, zMsg, errno, strerror( errno ),
                     pOptDesc->pzLastArg );
            (*pOpts->pUsageProc)( pOpts, EXIT_FAILURE );
            /* NOT REACHED */
        }

        if (! S_ISREG( sb.st_mode )) {
            if ((pOpts->fOptSet & OPTPROC_ERRSTOP) == 0)
                return;

            fprintf( stderr, zNotFile, pOptDesc->pzLastArg );
            (*pOpts->pUsageProc)( pOpts, EXIT_FAILURE );
            /* NOT REACHED */
        }

        filePreset( pOpts, pOptDesc->pzLastArg, DIRECTION_PROCESS );
    }
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
