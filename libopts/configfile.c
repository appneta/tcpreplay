
/*
 *  $Id: configfile.c,v 4.2 2005/02/13 01:48:00 bkorb Exp $
 * Time-stamp:      "2005-02-14 08:23:50 bkorb"
 *
 *  configuration/rc/ini file handling.
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
handleStructure(
    tOptions*     pOpts,
    tOptState*    pOS,
    char*         pzText,
    int           direction );

static char*
handleConfig(
    tOptions*     pOpts,
    tOptState*    pOS,
    char*         pzText,
    int           direction );

static char*
handleDirective(
    tOptions*     pOpts,
    char*         pzText );

static char*
handleComment( char* pzText );

static char*
handleProgramSection(
    tOptions*     pOpts,
    char*         pzText );

static void
filePreset(
    tOptions*     pOpts,
    const char*   pzFileName,
    int           direction );
/* = = = END-STATIC-FORWARD = = = */

/*
 *  Make sure the option descriptor is there and that we understand it.
 *  This should be called from any user entry point where one needs to
 *  worry about validity.  (Some entry points are free to assume that
 *  the call is not the first to the library and, thus, that this has
 *  already been called.)
 */
LOCAL tSuccess
validateOptionsStruct( tOptions* pOpts, const char* pzProgram )
{
    if (pOpts == NULL) {
        fputs( zAO_Bad, stderr );
        exit( EXIT_FAILURE );
    }

    /*
     *  IF the client has enabled translation and the translation procedure
     *  is available, then go do it.
     */
    if (  ((pOpts->fOptSet & OPTPROC_TRANSLATE) != 0)
       && (pOpts->pTransProc != 0) ) {
        (*pOpts->pTransProc)();
        pOpts->fOptSet &= ~OPTPROC_TRANSLATE;
    }

    /*
     *  IF the struct version is not the current, and also
     *     either too large (?!) or too small,
     *  THEN emit error message and fail-exit
     */
    if (  ( pOpts->structVersion  != OPTIONS_STRUCT_VERSION  )
       && (  (pOpts->structVersion > OPTIONS_STRUCT_VERSION  )
          || (pOpts->structVersion < OPTIONS_MINIMUM_VERSION )
       )  )  {

        fprintf( stderr, zAO_Err, pOpts->origArgVect[0],
                 NUM_TO_VER( pOpts->structVersion ));
        if (pOpts->structVersion > OPTIONS_STRUCT_VERSION )
            fputs( zAO_Big, stderr );
        else
            fputs( zAO_Sml, stderr );

        return FAILURE;
    }

    /*
     *  If the program name hasn't been set, then set the name and the path
     *  and the set of equivalent characters.
     */
    if (pOpts->pzProgName == NULL) {
        const char* pz = strrchr( pzProgram, '/' );

        if (pz == NULL)
             pOpts->pzProgName = pzProgram;
        else pOpts->pzProgName = pz+1;

        pOpts->pzProgPath = pzProgram;

        /*
         *  when comparing long names, these are equivalent
         */
        strequate( zSepChars );
    }

    return SUCCESS;
}


/*
 *  handleStructure -- "pzText" points to a '<' character, followed by an alpha.
 *  The end of the entry is either the "/>" following the name, or else a
 *  "</name>" string.
 */
static char*
handleStructure(
    tOptions*     pOpts,
    tOptState*    pOS,
    char*         pzText,
    int           direction )
{
    size_t cooked_len   = strlen(zLoadCooked);
    size_t uncooked_len = strlen(zLoadUncooked);
    size_t keep_len     = strlen(zLoadKeep);

    load_mode_t   mode  = LOAD_UNCOOKED;
    char* pzName        = ++pzText;
    char* pcNulPoint;

    while (ISNAMECHAR( *pzText ))  pzText++;
    pcNulPoint = pzText;

    switch (*pzText) {
    case ' ':
    case '\t':
    {
        char* pzD;
        pzD = ++pzText;

        while (isspace( *pzText ))    pzText++;

        if (strncmp( pzText, zLoadKeep, keep_len ) == 0) {
            pzText += keep_len;
            memmove( pzD, pzText, strlen(pzText)+1 );
            pzText = pzD;
            mode = LOAD_KEEP;

        } else if (strncmp( pzText, zLoadCooked, cooked_len ) == 0) {
            pzText += cooked_len;
            memset( pzD, ' ', cooked_len );
            mode = LOAD_COOKED;

        } else if (strncmp( pzText, zLoadUncooked, uncooked_len ) == 0) {
            pzText += uncooked_len;
            memset( pzD, ' ', uncooked_len );

        } else while (*pzD != '>') {
            /*
             *  Unrecognized attribute.  Skip the attributes.
             */
            *(pzD++) = ' ';
            if (*pzD == NUL)
                break;
        }
        break;
    }

    case '/':
        if (pzText[1] != '>')
            return NULL;
        *pzText = NUL;
        pzText += 2;
        loadOptionLine( pOpts, pOS, pzName, direction, LOAD_KEEP );
        return pzText;

    case '>':
        break;

    default:
        pzText = strchr( pzText, '>');
        if (pzText != NULL)
            pzText++;
        return pzText;
    }

    /*
     *  If we are here, we have a value.  Separate the name from the
     *  value for a moment.
     */
    *pcNulPoint = NUL;

    /*
     *  Find the end of the option text and NUL terminate it
     */
    {
        char   z[64], *pz = z;
        size_t len = strlen(pzName) + 4;
        if (len > sizeof(z))
            pz = AGALOC(len, "scan name");

        sprintf( pz, "</%s>", pzName );
        *pzText = ' ';
        pzText = strstr( pzText, pz );
        if (pz != z) free(pz);

        if (pzText == NULL)
            return pzText;

        *pzText = NUL;
        
        pzText += len-1;
    }

    /*
     *  Rejoin the name and value for parsing by "loadOptionLine()".
     */
    *pcNulPoint = ' ';

    /*
     *  "pzName" points to what looks like text for one option/configurable.
     *  It is NUL terminated.  Process it.
     */
    loadOptionLine( pOpts, pOS, pzName, direction, mode );

    return pzText;
}


/*
 *  handleConfig -- "pzText" points to the start of some value name.
 *  The end of the entry is the end of the line that is not preceded by
 *  a backslash escape character.  The string value is always processed
 *  in "cooked" mode.
 */
static char*
handleConfig(
    tOptions*     pOpts,
    tOptState*    pOS,
    char*         pzText,
    int           direction )
{
    char* pzName = pzText++;
    char* pzEnd  = strchr( pzText, '\n' );

    while (ISNAMECHAR( *pzText ))  pzText++;
    while (isspace( *pzText )) pzText++;
    if (pzText > pzEnd) {
    name_only:
        *pzEnd++ = NUL;
        loadOptionLine( pOpts, pOS, pzName, direction, LOAD_UNCOOKED );
        return pzEnd;
    }

    /*
     *  Either the first character after the name is a ':' or '=',
     *  or else we must have skipped over white space.  Anything else
     *  is an invalid format and we give up parsing the text.
     */
    if ((*pzText == '=') || (*pzText == ':')) {
        while (isspace( *++pzText ))   ;
        if (pzText > pzEnd)
            goto name_only;
    } else if (! isspace(pzText[-1]))
        return NULL;

    /*
     *  IF the value is continued, remove the backslash escape and push "pzEnd"
     *  on to a newline *not* preceded by a backslash.
     */
    if (pzEnd[-1] == '\\') {
        char* pcD = pzEnd-1;
        char* pcS = pzEnd;

        for (;;) {
            char ch = *(pcS++);
            switch (ch) {
            case NUL:
                pcS = NULL;

            case '\n':
                *pcD = NUL;
                pzEnd = pcS;
                goto copy_done;

            case '\\':
                if (*pcS == '\n') {
                    ch = *(pcS++);
                }
                /* FALLTHROUGH */
            default:
                *(pcD++) = ch;
            }
        } copy_done:;

    } else {
        /*
         *  The newline was not preceded by a backslash.  NUL it out
         */
        *(pzEnd++) = NUL;
    }

    fprintf( stderr, "Loading option:  ``%s''\n", pzName );

    /*
     *  "pzName" points to what looks like text for one option/configurable.
     *  It is NUL terminated.  Process it.
     */
    loadOptionLine( pOpts, pOS, pzName, direction, LOAD_UNCOOKED );

    return pzEnd;
}


/*
 *  handleDirective -- "pzText" points to a "<?" sequence.
 *  For the moment, we only handle "<?program" directives.
 */
static char*
handleDirective(
    tOptions*     pOpts,
    char*         pzText )
{
    char   ztitle[16] = "<?";
    size_t title_len = strlen( zProg );
    size_t name_len;

    if (  (strncmp( pzText+2, zProg, title_len ) != 0)
       || (! isspace( pzText[title_len+2] )) )  {
        pzText = strchr( pzText+2, '>' );
        if (pzText != NULL)
            pzText++;
        return pzText;
    }

    name_len = strlen( pOpts->pzProgName );
    strcpy( ztitle+2, zProg );
    title_len += 2;

    do  {
        pzText += title_len;

        if (isspace(*pzText)) {
            while (isspace(*pzText))  pzText++;
            if (  (strneqvcmp( pzText, pOpts->pzProgName, name_len ) == 0)
               && (pzText[name_len] == '>'))  {
                pzText += name_len + 1;
                break;
            }
        }

        pzText = strstr( pzText, ztitle );
    } while (pzText != NULL);

    return pzText;
}


/*
 *  handleComment -- "pzText" points to a "<!" sequence.
 *  Theoretically, we should ensure that it begins with "<!--",
 *  but actually I don't care that much.  It ends with "-->".
 */
static char*
handleComment( char* pzText )
{
    char* pz = strstr( pzText, "-->" );
    if (pz != NULL)
        pz += 3;
    return pz;
}


/*
 *  handleProgramSection -- "pzText" points to a '[' character.
 *  The "traditional" [PROG_NAME] segmentation of the config file.
 *  Do not ever mix with the "<?program prog-name>" variation.
 */
static char*
handleProgramSection(
    tOptions*     pOpts,
    char*         pzText )
{
    size_t len = strlen( pOpts->pzPROGNAME );
    if (   (strncmp( pzText+1, pOpts->pzPROGNAME, len ) == 0)
        && (pzText[len+1] == ']'))
        return strchr( pzText + len + 2, '\n' );

    if (len > 16)
        return NULL;

    {
        char z[24];
        sprintf( z, "[%s]", pOpts->pzPROGNAME );
        pzText = strstr( pzText, z );
    }

    if (pzText != NULL)
        pzText = strchr( pzText, '\n' );
    return pzText;
}


/*
 *  filePreset
 *
 *  Load a file containing presetting information (a configuration file).
 */
static void
filePreset(
    tOptions*     pOpts,
    const char*   pzFileName,
    int           direction )
{
    tmap_info_t   cfgfile;
    char*         pzFileText =
        text_mmap( pzFileName, PROT_READ|PROT_WRITE, MAP_PRIVATE, &cfgfile );
    char*         pzEndText;
    tOptState     st = OPTSTATE_INITIALIZER(PRESET);

    if (pzFileText == MAP_FAILED)
        return;

    /*
     *  IF this is called via "optionProcess", then we are presetting.
     *  This is the default and the PRESETTING bit will be set.
     *  If this is called via "configFileLoad", then the bit is not set
     *  and we consider stuff set herein to be "set" by the client program.
     */
    if ((pOpts->fOptSet & OPTPROC_PRESETTING) == 0)
        st.flags = OPTST_SET;

    pzEndText = pzFileText + cfgfile.txt_size;

    do  {
        while (isspace( *pzFileText ))  pzFileText++;

        if (isalpha( *pzFileText )) {
            pzFileText = handleConfig( pOpts, &st, pzFileText, direction );

        } else switch (*pzFileText) {
        case '<':
            if (isalpha( pzFileText[1] ))
                pzFileText = handleStructure(pOpts, &st, pzFileText, direction);

            else switch (pzFileText[1]) {
            case '?':
                pzFileText = handleDirective( pOpts, pzFileText );
                break;

            case '!':
                pzFileText = handleComment( pzFileText );
                break;

            case '/':
                pzFileText = strchr( pzFileText+2, '>' );
                if (pzFileText++ != NULL)
                    break;

            default:
                goto all_done;
            }
            break;

        case '[':
            pzFileText = handleProgramSection( pOpts, pzFileText );
            break;

        case '#':
            pzFileText = strchr( pzFileText+1, '\n' );
            break;

        default:
            goto all_done; /* invalid format */
        }
    } while (pzFileText != NULL);

 all_done:
    text_munmap( &cfgfile );
}


LOCAL void
internalFileLoad( tOptions* pOpts )
{
    int     idx;
    int     inc = DIRECTION_PRESET;
    char    zFileName[ 4096 ];

    if (pOpts->papzHomeList == NULL)
        return;

    /*
     *  Find the last RC entry (highest priority entry)
     */
    for (idx = 0; pOpts->papzHomeList[ idx+1 ] != NULL; ++idx)  ;

    /*
     *  For every path in the home list, ...  *TWICE* We start at the last
     *  (highest priority) entry, work our way down to the lowest priority,
     *  handling the immediate options.
     *  Then we go back up, doing the normal options.
     */
    for (;;) {
        struct stat StatBuf;
        cch_t*  pzPath;

        /*
         *  IF we've reached the bottom end, change direction
         */
        if (idx < 0) {
            inc = DIRECTION_PROCESS;
            idx = 0;
        }

        pzPath = pOpts->papzHomeList[ idx ];

        /*
         *  IF we've reached the top end, bail out
         */
        if (pzPath == NULL)
            break;

        idx += inc;

        if (! optionMakePath( zFileName, sizeof( zFileName ),
                              pzPath, pOpts->pzProgPath ))
            continue;

        /*
         *  IF the file name we constructed is a directory,
         *  THEN append the Resource Configuration file name
         *  ELSE we must have the complete file name
         */
        if (stat( zFileName, &StatBuf ) != 0)
            continue; /* bogus name - skip the home list entry */

        if (S_ISDIR( StatBuf.st_mode )) {
            size_t len = strlen( zFileName );
            char* pz;

            if (len + 1 + strlen( pOpts->pzRcName ) >= sizeof( zFileName ))
                continue;

            pz = zFileName + len;
            if (pz[-1] != '/')
                *(pz++) = '/';
            strcpy( pz, pOpts->pzRcName );
        }

        filePreset( pOpts, zFileName, inc );

        /*
         *  IF we are now to skip config files AND we are presetting,
         *  THEN change direction.  We must go the other way.
         */
        if (SKIP_RC_FILES(pOpts) && PRESETTING(inc)) {
            idx -= inc;  /* go back and reprocess current file */
            inc =  DIRECTION_PROCESS;
        }
    } /* For every path in the home list, ... */
}


/*=export_func configFileLoad
 *
 * what: Load the locatable config files, in order
 *
 * arg:  + tOptions*   + pOpts  + program options descriptor +
 * arg:  + const char* + pzProg + program name +
 *
 * ret_type:  int
 * ret_desc:  0 -> SUCCESS, -1 -> FAILURE
 *
 * doc:
 *
 * This function looks in all the specified directories for a configuration
 * file ("rc" file or "ini" file) and processes any found twice.  The first
 * time through, they are processed in reverse order (last file first).  At
 * that time, only "immediate action" configurables are processed.  For
 * example, if the last named file specifies not processing any more
 * configuration files, then no more configuration files will be processed.
 * Such an option in the @strong{first} named directory will have no effect.
 *
 * Once the immediate action configurables have been handled, then the
 * directories are handled in normal, forward order.  In that way, later
 * config files can override the settings of earlier config files.
 *
 * See the AutoOpts documentation for a thorough discussion of the
 * config file format.
 *
 * err:  Returns the value, "-1" if the option (config file) descriptor
 *       is out of date or indecipherable.  Otherwise, the value "0" will
 *       always be returned.
=*/
int
configFileLoad( tOptions* pOpts, const char* pzProgram )
{
    if (! SUCCESSFUL( validateOptionsStruct( pOpts, pzProgram )))
        return -1;

    pOpts->pzProgName = pzProgram;
    internalFileLoad( pOpts );
    return 0;
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
            if ((pOpts->fOptSet & OPTPROC_ERRSTOP) == 0)
                return;

            fprintf( stderr, zFSErrOptLoad, errno, strerror( errno ),
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

        filePreset(pOpts, pOptDesc->pzLastArg, DIRECTION_PROCESS);
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
 * end of autoopts/configfile.c */
