
/*
 *  usage.c  $Id: usage.c,v 2.47 2004/02/02 03:31:51 bkorb Exp $
 *
 *  This module implements the default usage procedure for
 *  Automated Options.  It may be overridden, of course.
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

#define OPTPROC_L_N_S  (OPTPROC_LONGOPT | OPTPROC_SHORTOPT)

#ifndef tSC
#  define tSC static char
#endif

#include "usage-txt.h"

static arg_types_t argTypes;

FILE* option_usage_fp = NULL;
static char    zOptFmtLine[ 16 ];
static ag_bool displayEnum;

/* === STATIC PROCS === */
STATIC void
printProgramDetails( tOptions* pOptions );

STATIC void
printExtendedUsage(
    tOptions*     pOptions,
    tOptDesc*     pOD,
    arg_types_t*  pAT );

STATIC void
printBareUsage(
    tOptions*     pOptions,
    tOptDesc*     pOD,
    arg_types_t*  pAT );

STATIC void
setStdOptFmts( tOptions* pOpts, tCC** ppT );

STATIC void
setGnuOptFmts( tOptions* pOpts, tCC** ppT );

STATIC void
printInitList(
    tCC**    papz,
    ag_bool* pInitIntro,
    tCC*     pzRc,
    tCC*     pzPN );

/* === END STATIC PROCS === */

/*=export_func  optionUsage
 * private:
 *
 * what:  Print usage text
 * arg:   + tOptions* + pOpts    + program options descriptor +
 * arg:   + int       + exitCode + exit code for calling exit(3) +
 *
 * doc:
 *  This routine will print usage in both GNU-standard and AutoOpts-expanded
 *  formats.  The descriptor specifies the default, but AUTOOPTS_USAGE will
 *  over-ride this, providing the value of it is set to either "gnu" or
 *  "autoopts".  This routine will @strong{not} return.
=*/
void
optionUsage(
    tOptions* pOptions,
    int       exitCode )
{
    tCC*    pOptTitle;

    displayEnum = AG_FALSE;

    /*
     *  Paged usage will preset option_usage_fp to an output file.
     *  If it hasn't already been set, then set it to standard output
     *  on successful exit (help was requested), otherwise error out.
     */
    if (option_usage_fp == NULL)
        option_usage_fp = (exitCode != EXIT_SUCCESS) ? stderr : stdout;

    fprintf( option_usage_fp, pOptions->pzUsageTitle, pOptions->pzProgName );

    do {
        char* pz = getenv( "AUTOOPTS_USAGE" );
        if (pz == NULL) break;
        if (streqvcmp( pz, "gnu" ) == 0) {
            pOptions->fOptSet |= OPTPROC_GNUUSAGE;
            break;
        }
        if (streqvcmp( pz, "autoopts" ) == 0) {
            pOptions->fOptSet &= ~OPTPROC_GNUUSAGE;
            break;
        }
    } while (0);

    /*
     *  Determine which header and which option formatting strings to use
     */
    if ((pOptions->fOptSet & OPTPROC_GNUUSAGE) != 0) {
        setGnuOptFmts( pOptions, &pOptTitle );
        fputc( '\n', option_usage_fp );
    }
    else {
        setStdOptFmts( pOptions, &pOptTitle );

        /*
         *  When we exit with EXIT_SUCCESS and the first option is a doc option,
         *  we do *NOT* want to emit the column headers.  Otherwise, we do.
         */
        if (  (exitCode != EXIT_SUCCESS)
           || ((pOptions->pOptDesc->fOptState & OPTST_DOCUMENT) == 0) )

            fputs( pOptTitle, option_usage_fp );
    }

    {
        int        ct     = pOptions->optCt;
        int        optNo  = 0;
        tOptDesc*  pOD    = pOptions->pOptDesc;
        int        docCt  = 0;

        do  {
            if ((pOD->fOptState & OPTST_OMITTED) != 0)
                continue;

            if ((pOD->fOptState & OPTST_DOCUMENT) != 0) {
                if (exitCode == EXIT_SUCCESS) {
                    fprintf(option_usage_fp, argTypes.pzBrk, pOD->pzText,
                            pOptTitle);
                    docCt++;
                }

                continue;
            }

            /*
             *  IF       this is the first auto-opt maintained option
             *    *AND*  we are doing a full help
             *    *AND*  there are documentation options
             *    *AND*  the last one was not a doc option,
             *  THEN document that the remaining options are not user opts
             */
            if (  (pOptions->presetOptCt == optNo)
               && (exitCode == EXIT_SUCCESS)
               && (docCt > 0)
               && ((pOD[-1].fOptState & OPTST_DOCUMENT) == 0) )
                fprintf( option_usage_fp, argTypes.pzBrk, zAuto, pOptTitle );

            printBareUsage( pOptions, pOD, &argTypes );

            /*
             *  IF we were invoked because of the --help option,
             *  THEN print all the extra info
             */
            if (exitCode == EXIT_SUCCESS)
                printExtendedUsage( pOptions, pOD, &argTypes );

        }  while (pOD++, optNo++, (--ct > 0));
    }

    fputc( '\n', option_usage_fp );

    /*
     *  Describe the mechanics of denoting the options
     */
    switch (pOptions->fOptSet & OPTPROC_L_N_S) {
    case OPTPROC_L_N_S:     fputs( zFlagOkay, option_usage_fp ); break;
    case OPTPROC_SHORTOPT:  break;
    case OPTPROC_LONGOPT:   fputs( zNoFlags,  option_usage_fp ); break;
    case 0:                 fputs( zOptsOnly, option_usage_fp ); break;
    }

    if ((pOptions->fOptSet & OPTPROC_NUM_OPT) != 0) {
        fputs( zNumberOpt, option_usage_fp );
    }

    if ((pOptions->fOptSet & OPTPROC_REORDER) != 0) {
        fputs( zReorder, option_usage_fp );
    }

    if (pOptions->pzExplain != NULL)
        fputs( pOptions->pzExplain, option_usage_fp );

    /*
     *  IF the user is asking for help (thus exiting with SUCCESS),
     *  THEN see what additional information we can provide.
     */
    if (exitCode == EXIT_SUCCESS)
        printProgramDetails( pOptions );

    if (pOptions->pzBugAddr != NULL)
        fprintf( option_usage_fp, zPlsSendBugs, pOptions->pzBugAddr );
    fflush( option_usage_fp );

    exit( exitCode );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *   PROGRAM DETAILS
 */
STATIC void
printProgramDetails( tOptions* pOptions )
{
    ag_bool  initIntro = AG_TRUE;

    /*
     *  Display all the places we look for RC files
     */
    printInitList( pOptions->papzHomeList, &initIntro,
                   pOptions->pzRcName, pOptions->pzProgPath );

    /*
     *  Let the user know about environment variable settings
     */
    if ((pOptions->fOptSet & OPTPROC_ENVIRON) != 0) {
        if (initIntro)
            fputs( zPresetIntro, option_usage_fp );

        fprintf( option_usage_fp, zExamineFmt, pOptions->pzPROGNAME );
    }

    /*
     *  IF we found an enumeration,
     *  THEN hunt for it again.  Call the handler proc with a NULL
     *       option struct pointer.  That tells it to display the keywords.
     */
    if (displayEnum) {
        int        ct     = pOptions->optCt;
        int        optNo  = 0;
        tOptDesc*  pOD    = pOptions->pOptDesc;

        fputc( '\n', option_usage_fp );
        fflush( option_usage_fp );
        do  {
            if (pOD->fOptState & (OPTST_ENUMERATION|OPTST_MEMBER_BITS))
                (*(pOD->pOptProc))( NULL, pOD );
        }  while (pOD++, optNo++, (--ct > 0));
    }

    /*
     *  If there is a detail string, now is the time for that.
     */
    if (pOptions->pzDetail != NULL)
        fputs( pOptions->pzDetail, option_usage_fp );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *   PER OPTION TYPE USAGE INFORMATION
 */
STATIC void
printExtendedUsage(
    tOptions*     pOptions,
    tOptDesc*     pOD,
    arg_types_t*  pAT )
{
    /*
     *  IF there are option conflicts or dependencies,
     *  THEN print them here.
     */
    if (  (pOD->pOptMust != NULL)
       || (pOD->pOptCant != NULL) ) {

        fputs( zTabHyp, option_usage_fp );

        /*
         *  DEPENDENCIES:
         */
        if (pOD->pOptMust != NULL) {
            const int* pOptNo = pOD->pOptMust;

            fputs( zReqThese, option_usage_fp );
            for (;;) {
                fprintf( option_usage_fp, zTabout, pOptions->pOptDesc[
                             *pOptNo ].pz_Name );
                if (*++pOptNo == NO_EQUIVALENT)
                    break;
            }

            if (pOD->pOptCant != NULL)
                fputs( zTabHypAnd, option_usage_fp );
        }

        /*
         *  CONFLICTS:
         */
        if (pOD->pOptCant != NULL) {
            const int* pOptNo = pOD->pOptCant;

            fputs( zProhib, option_usage_fp );
            for (;;) {
                fprintf( option_usage_fp, zTabout, pOptions->pOptDesc[
                             *pOptNo ].pz_Name );
                if (*++pOptNo == NO_EQUIVALENT)
                    break;
            }
        }
    }

    /*
     *  IF there is a disablement string
     *  THEN print the disablement info
     */
    if (pOD->pz_DisableName != NULL )
        fprintf( option_usage_fp, zDis, pOD->pz_DisableName );

    /*
     *  IF the numeric option has a special callback,
     *  THEN call it, requesting the range or other special info
     */
    if (  (pOD->fOptState & OPTST_NUMERIC)
       && (pOD->pOptProc != NULL)
       && (pOD->pOptProc != optionNumericVal) ) {
        (*(pOD->pOptProc))( pOptions, NULL );
    }

    /*
     *  IF the option defaults to being enabled,
     *  THEN print that out
     */
    if (pOD->fOptState & OPTST_INITENABLED)
        fputs( zEnab, option_usage_fp );

    /*
     *  IF  the option is in an equivalence class
     *        AND not the designated lead
     *  THEN print equivalence and leave it at that.
     */
    if (  (pOD->optEquivIndex != NO_EQUIVALENT)
       && (pOD->optEquivIndex != pOD->optActualIndex )  )  {
        fprintf( option_usage_fp, zAlt,
                 pOptions->pOptDesc[ pOD->optEquivIndex ].pz_Name );
        return;
    }

    /*
     *  IF this particular option can NOT be preset
     *    AND some form of presetting IS allowed,
     *  THEN advise that this option may not be preset.
     */
    if (  ((pOD->fOptState & OPTST_NO_INIT) != 0)
       && (  (pOptions->papzHomeList != NULL)
          || (pOptions->pzPROGNAME != NULL)
       )  )

        fputs( zNoPreset, option_usage_fp );

    /*
     *  Print the appearance requirements.
     */
    if (pOD->fOptState & OPTST_MEMBER_BITS)
        fputs( zMembers, option_usage_fp );

    else switch (pOD->optMinCt) {
    case 1:
    case 0:
        switch (pOD->optMaxCt) {
        case 0:       fputs( zPreset, option_usage_fp ); break;
        case NOLIMIT: fputs( zNoLim, option_usage_fp );  break;
        case 1:       break;
            /*
             * IF the max is more than one but limited, print "UP TO" message
             */
        default:      fprintf( option_usage_fp, zUpTo, pOD->optMaxCt );  break;
        }
        break;

    default:
        /*
         *  More than one is required.  Print the range.
         */
        fprintf( option_usage_fp, zMust, pOD->optMinCt, pOD->optMaxCt );
    }

    if (  NAMED_OPTS( pOptions )
       && (pOptions->specOptIdx.default_opt == pOD->optIndex))
        fputs( zDefaultOpt, option_usage_fp );
}


STATIC void
printBareUsage(
    tOptions*     pOptions,
    tOptDesc*     pOD,
    arg_types_t*  pAT )
{
    /*
     *  Flag prefix: IF no flags at all, then omit it.  If not printable
     *  (not allowed for this option), then blank, else print it.
     *  Follow it with a comma if we are doing GNU usage and long
     *  opts are to be printed too.
     */
    if ((pOptions->fOptSet & OPTPROC_SHORTOPT) == 0)
        fputs( pAT->pzSpc, option_usage_fp );
    else if (! isgraph( pOD->optValue)) {
        if (  (pOptions->fOptSet & (OPTPROC_GNUUSAGE|OPTPROC_LONGOPT))
           == (OPTPROC_GNUUSAGE|OPTPROC_LONGOPT))
            fputc( ' ', option_usage_fp );
        fputs( pAT->pzNoF, option_usage_fp );
    } else {
        fprintf( option_usage_fp, "   -%c", pOD->optValue );
        if (  (pOptions->fOptSet & (OPTPROC_GNUUSAGE|OPTPROC_LONGOPT))
           == (OPTPROC_GNUUSAGE|OPTPROC_LONGOPT))
            fputs( ", ", option_usage_fp );
    }

    {
        char  z[ 80 ];
        tCC*  pzArgType;
#       define OPTFMT ( OPTST_NUMERIC | OPTST_BOOLEAN | OPTST_ENUMERATION \
                      | OPTST_MEMBER_BITS )

        /*
         *  Determine the argument type string first on its usage, then,
         *  when the option argument is required, base the type string on the
         *  argument type.
         */
        switch (pOD->optArgType) {
        default:       goto bogus_desc;
        case ARG_MAY:  pzArgType = pAT->pzOpt; break;
        case ARG_NONE: pzArgType = pAT->pzNo;  break;
        case ARG_MUST:
            switch ( pOD->fOptState & OPTFMT) {
            case OPTST_ENUMERATION: pzArgType = pAT->pzKey;  break;
            case OPTST_MEMBER_BITS: pzArgType = pAT->pzKeyL; break;
            case OPTST_BOOLEAN:     pzArgType = pAT->pzBool; break;
            case OPTST_NUMERIC:     pzArgType = pAT->pzNum;  break;
            case 0:                 pzArgType = pAT->pzStr;  break;
            default:                goto bogus_desc;         break;
            }
        }

        snprintf( z, sizeof(z), pAT->pzOptFmt, pzArgType, pOD->pz_Name,
                  (pOD->optMinCt != 0) ? pAT->pzReq : pAT->pzOpt );

        fprintf( option_usage_fp, zOptFmtLine, z, pOD->pzText );

        if (pOD->fOptState & (OPTST_ENUMERATION|OPTST_MEMBER_BITS))
            displayEnum |= (pOD->pOptProc != NULL) ? AG_TRUE : AG_FALSE;
    }
    return;

 bogus_desc:
    fprintf( stderr, zInvalOptDesc, pOD->pz_Name );
    exit( EXIT_FAILURE );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *   OPTION LINE FORMATTING SETUP
 *
 *  The "OptFmt" formats receive three arguments:
 *  1.  the type of the option's argument
 *  2.  the long name of the option
 *  3.  "YES" or "no ", depending on whether or not the option must appear
 *      on the command line.
 *  These formats are used immediately after the option flag (if used) has
 *  been printed.
 */
STATIC void
setStdOptFmts( tOptions* pOpts, tCC** ppT )
{
    int  flen = 0;

    argTypes.pzStr  = zStdStrArg;
    argTypes.pzReq  = zStdReqArg;
    argTypes.pzNum  = zStdNumArg;
    argTypes.pzKey  = zStdKeyArg;
    argTypes.pzKeyL = zStdKeyLArg;
    argTypes.pzBool = zStdBoolArg;
    argTypes.pzOpt  = zStdOptArg;
    argTypes.pzNo   = zStdNoArg;
    argTypes.pzBrk  = zStdBreak;
    argTypes.pzNoF  = zFiveSpaces;
    argTypes.pzSpc  = zTwoSpaces;

    switch (pOpts->fOptSet & (OPTPROC_NO_REQ_OPT | OPTPROC_SHORTOPT)) {
    case (OPTPROC_NO_REQ_OPT | OPTPROC_SHORTOPT):
        *ppT = zNoRq_ShrtTtl;
        argTypes.pzOptFmt = zNrmOptFmt;
        flen = 19;
        break;

    case OPTPROC_NO_REQ_OPT:
        *ppT = zNoRq_NoShrtTtl;
        argTypes.pzOptFmt = zNrmOptFmt;
        flen = 19;
        break;

    case OPTPROC_SHORTOPT:
        *ppT = zReq_ShrtTtl;
        argTypes.pzOptFmt = zReqOptFmt;
        flen = 24;
        break;

    case 0:
        *ppT = zReq_NoShrtTtl;
        argTypes.pzOptFmt = zReqOptFmt;
        flen = 24;
    }

    sprintf( zOptFmtLine, zFmtFmt, flen );
}

STATIC void
setGnuOptFmts( tOptions* pOpts, tCC** ppT )
{
    int  flen = 22;
    *ppT = zNoRq_ShrtTtl;

    argTypes.pzStr  = zGnuStrArg;
    argTypes.pzReq  = zOneSpace;
    argTypes.pzNum  = zGnuNumArg;
    argTypes.pzKey  = zGnuKeyArg;
    argTypes.pzKeyL = zGnuKeyLArg;
    argTypes.pzBool = zGnuBoolArg;
    argTypes.pzOpt  = zGnuOptArg;
    argTypes.pzNo   = zOneSpace;
    argTypes.pzBrk  = zGnuBreak;
    argTypes.pzNoF  = zSixSpaces;
    argTypes.pzSpc  = zThreeSpaces;

    switch (pOpts->fOptSet & OPTPROC_L_N_S) {
    case OPTPROC_L_N_S:    argTypes.pzOptFmt = zGnuOptFmt;     break;
    case OPTPROC_LONGOPT:  argTypes.pzOptFmt = zGnuOptFmt;     break;
    case 0:                argTypes.pzOptFmt = zGnuOptFmt + 2; break;
    case OPTPROC_SHORTOPT:
        argTypes.pzOptFmt = zShrtGnuOptFmt;
        zGnuStrArg[0] = zGnuNumArg[0] = zGnuKeyArg[0] = zGnuBoolArg[0] = ' ';
        argTypes.pzOpt = " [arg]";
        flen = 8;
        break;
    }

    sprintf( zOptFmtLine, zFmtFmt, flen );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *   Figure out where all the initialization files might live.
 *   This requires translating some environment variables and
 *   testing to see if a name is a directory or a file.  It's
 *   squishy, but important to tell users how to find these files.
 */
STATIC void
printInitList(
    tCC**    papz,
    ag_bool* pInitIntro,
    tCC*     pzRc,
    tCC*     pzPN )
{
    char zPath[ MAXPATHLEN+1 ];

    if (papz == NULL)
        return;

    fputs( zPresetIntro, option_usage_fp );
    *pInitIntro = AG_FALSE;

    for (;;) {
        const char* pzPath = *(papz++);

        if (pzPath == NULL)
            break;

        if (optionMakePath( zPath, sizeof( zPath ), pzPath, pzPN ))
            pzPath = zPath;

        /*
         *  Print the name of the "homerc" file.  If the "rcfile" name is
         *  not empty, we may or may not print that, too...
         */
        fprintf( option_usage_fp, zPathFmt, pzPath );
        if (*pzRc != NUL) {
            struct stat sb;

            /*
             *  IF the "homerc" file is a directory,
             *  then append the "rcfile" name.
             */
            if (  (stat( pzPath, &sb ) == 0)
              &&  S_ISDIR( sb.st_mode ) ) {
                fputc( '/', option_usage_fp );
                fputs( pzRc, option_usage_fp );
            }
        }

        fputc( '\n', option_usage_fp );
    }
}

/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/usage.c */
