
/*
 *  $Id: autoopts.c,v 3.33 2004/02/16 22:20:45 bkorb Exp $
 *
 *  This file contains all of the routines that must be linked into
 *  an executable to use the generated option processing.  The optional
 *  routines are in separately compiled modules so that they will not
 *  necessarily be linked in.
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

#ifndef HAVE_PATHFIND
#  include "compat/pathfind.c"
#endif

static const char zNil[] = "";

#define ISNAMECHAR( c )    (isalnum(c) || ((c) == '_') || ((c) == '-'))

#define SKIP_RC_FILES(po) \
    DISABLED_OPT(&((po)->pOptDesc[ (po)->specOptIdx.save_opts+1]))

/* === STATIC PROCS === */
STATIC tSuccess
findOptDesc( tOptions* pOpts, tOptState* pOptState );

STATIC tSuccess
nextOption( tOptions* pOpts, tOptState* pOptState );

STATIC tSuccess
doImmediateOpts( tOptions* pOpts );

STATIC void
doEnvPresets( tOptions* pOpts, teEnvPresetType type );

STATIC void
doRcFiles( tOptions* pOpts );

STATIC tSuccess
doPresets( tOptions* pOpts );

STATIC int
checkConsistency( tOptions* pOpts );

/* === END STATIC PROCS === */

/*
 *  handleOption
 *
 *  This routine handles equivalencing, sets the option state flags and
 *  invokes the handler procedure, if any.
 */
LOCAL tSuccess
handleOption( tOptions* pOpts, tOptState* pOptState )
{
    /*
     *  Save a copy of the option procedure pointer.
     *  If this is an equivalence class option, we still want this proc.
     */
    tOptDesc* pOD = pOptState->pOD;
    tOptProc* pOP = pOD->pOptProc;

    pOD->pzLastArg =  pOptState->pzOptArg;

    /*
     *  IF this is an equivalence class option,
     *  THEN
     *      Save the option value that got us to this option
     *      entry.  (It may not be pOD->optChar[0], if this is an
     *      equivalence entry.)
     *      set the pointer to the equivalence class base
     */
    if (pOD->optEquivIndex != NO_EQUIVALENT) {
        tOptDesc*  p = pOpts->pOptDesc + pOD->optEquivIndex;

        /*
         *  Add in the equivalence flag
         */
        pOptState->flags |= OPTST_EQUIVALENCE;
        p->pzLastArg      = pOD->pzLastArg;
        p->optActualValue = pOD->optValue;
        p->optActualIndex = pOD->optIndex;
        pOD = p;

    } else {
        pOD->optActualValue = pOD->optValue;
        pOD->optActualIndex = pOD->optIndex;
    }

    pOD->fOptState &= OPTST_PERSISTENT;
    pOD->fOptState |= (pOptState->flags & ~OPTST_PERSISTENT);

    /*
     *  Keep track of count only for DEFINED (command line) options.
     *  IF we have too many, build up an error message and bail.
     */
    if (  (pOD->fOptState & OPTST_DEFINED)
       && (++pOD->optOccCt > pOD->optMaxCt)  )  {
        const char* pzEqv =
            (pOD->optEquivIndex != NO_EQUIVALENT) ? zEquiv : zNil;

        if ((pOpts->fOptSet & OPTPROC_ERRSTOP) != 0) {
            const char* pzFmt = (pOD->optMaxCt > 1) ? zAtMost : zOnlyOne;
            fputs( zErrOnly, stderr );
            fprintf( stderr, pzFmt, pOD->pz_Name, pzEqv,
                     pOD->optMaxCt );
        }

        return FAILURE;
    }

    /*
     *  If provided a procedure to call, call it
     */
    if (pOP != (tpOptProc)NULL)
        (*pOP)( pOpts, pOD );

    return SUCCESS;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  HUNT FOR OPTIONS IN THE ARGUMENT LIST
 *
 *  The next four procedures are "private" to nextOption().
 *  nextOption() uses findOptDesc() to find the next descriptor and it, in
 *  turn, uses longOptionFind() and shortOptionFind() to actually do the hunt.
 *
 *  longOptionFind
 *
 *  Find the long option descriptor for the current option
 */
LOCAL tSuccess
longOptionFind( tOptions* pOpts, char* pzOptName, tOptState* pOptState )
{
    ag_bool    disable  = AG_FALSE;
    char*      pzEq     = strchr( pzOptName, '=' );
    tOptDesc*  pOD      = pOpts->pOptDesc;
    int        idx      = 0;
    int        idxLim   = pOpts->optCt;
    int        matchCt  = 0;
    int        matchIdx = 0;
    int        nameLen;

    /*
     *  IF the value is attached to the name,
     *  THEN clip it off.
     *  Either way, figure out how long our name is
     */
    if (pzEq != NULL) {
        nameLen = (int)(pzEq - pzOptName);
        *pzEq = NUL;
    } else nameLen = strlen( pzOptName );

    do  {
        if (SKIP_OPT(pOD))
            continue;

        if (strneqvcmp( pzOptName, pOD->pz_Name, nameLen ) == 0) {
            /*
             *  IF we have a complete match
             *  THEN it takes priority over any already located partial
             */
            if (pOD->pz_Name[ nameLen ] == NUL) {
                matchCt  = 1;
                matchIdx = idx;
                break;
            }
        }

        /*
         *  IF       there is a disable name
         *     *AND* no argument value has been supplied
         *              (disabled options may have no argument)
         *     *AND* the option name matches the disable name
         *  THEN ...
         */
        else if (  (pOD->pz_DisableName != NULL)
                && (strneqvcmp( pzOptName, pOD->pz_DisableName, nameLen ) == 0)
                )  {
            disable  = AG_TRUE;

            /*
             *  IF we have a complete match
             *  THEN it takes priority over any already located partial
             */
            if (pOD->pz_DisableName[ nameLen ] == NUL) {
                matchCt  = 1;
                matchIdx = idx;
                break;
            }
        }

        else
            continue;

        /*
         *  We found a partial match, either regular or disabling.
         *  Remember the index for later.
         */
        matchIdx = idx;

        if (++matchCt > 1)
            break;

    } while (pOD++, (++idx < idxLim));

    if (pzEq != NULL)
        *(pzEq++) = '=';

    /*
     *  Make sure we either found an exact match or found only one partial
     */
    if (matchCt == 1) {
        /*
         *  IF we found a disablement name,
         *  THEN set the bit in the callers' flag word
         */
        if (disable)
            pOptState->flags |= OPTST_DISABLED;

        pOptState->pOD      = pOpts->pOptDesc + matchIdx;
        pOptState->pzOptArg = pzEq;
        pOptState->optType  = TOPT_LONG;
        return SUCCESS;
    }

    /*
     *  IF there is no equal sign
     *     *AND* we are using named arguments
     *     *AND* there is a default named option,
     *  THEN return that option.
     */
    if (  (pzEq == NULL)
       && NAMED_OPTS(pOpts)
       && (pOpts->specOptIdx.default_opt != NO_EQUIVALENT)) {
        pOptState->pOD = pOpts->pOptDesc + pOpts->specOptIdx.default_opt;

        pOptState->pzOptArg = pzOptName;
        pOptState->optType  = TOPT_DEFAULT;
        return SUCCESS;
    }

    /*
     *  IF we are to stop on errors (the default, actually)
     *  THEN call the usage procedure.
     */
    if ((pOpts->fOptSet & OPTPROC_ERRSTOP) != 0) {
        fprintf( stderr, zIllOptStr, pOpts->pzProgPath,
                 (matchCt == 0) ? zIllegal : zAmbiguous, pzOptName );
        (*pOpts->pUsageProc)( pOpts, EXIT_FAILURE );
    }

    return FAILURE;
}


/*
 *  shortOptionFind
 *
 *  Find the short option descriptor for the current option
 */
LOCAL tSuccess
shortOptionFind( tOptions* pOpts, tUC optValue, tOptState* pOptState )
{
    tOptDesc*  pRes = pOpts->pOptDesc;
    int        ct   = pOpts->optCt;

    /*
     *  Search the option list
     */
    for (;;) {
        /*
         *  IF the values match,
         *  THEN we stop here
         */
        if ((! SKIP_OPT(pRes)) && (optValue == pRes->optValue)) {
            pOptState->pOD     = pRes;
            pOptState->optType = TOPT_SHORT;
            return SUCCESS;
        }

        /*
         *  Advance to next option description
         */
        pRes++;

        /*
         *  IF we have searched everything, ...
         */
        if (--ct <= 0)
            break;
    }

    /*
     *  IF    the character value is a digit
     *    AND there is a special number option ("-n")
     *  THEN the result is the "option" itself and the
     *       option is the specially marked "number" option.
     */
    if (  isdigit( optValue )
       && (pOpts->specOptIdx.number_option != NO_EQUIVALENT) ) {
        pOptState->pOD = \
        pRes           = pOpts->pOptDesc + pOpts->specOptIdx.number_option;
        (pOpts->pzCurOpt)--;
        pOptState->optType = TOPT_SHORT;
        return SUCCESS;
    }

    /*
     *  IF we are to stop on errors (the default, actually)
     *  THEN call the usage procedure.
     */
    if ((pOpts->fOptSet & OPTPROC_ERRSTOP) != 0) {
        fprintf( stderr, zIllOptChr, pOpts->pzProgPath, optValue );
        (*pOpts->pUsageProc)( pOpts, EXIT_FAILURE );
    }

    return FAILURE;
}


/*
 *  findOptDesc
 *
 *  Find the option descriptor for the current option
 */
STATIC tSuccess
findOptDesc( tOptions* pOpts, tOptState* pOptState )
{
    /*
     *  IF we are continuing a short option list (e.g. -xyz...)
     *  THEN continue a single flag option.
     *  OTHERWISE see if there is room to advance and then do so.
     */
    if ((pOpts->pzCurOpt != NULL) && (*pOpts->pzCurOpt != NUL))
        return shortOptionFind( pOpts, *pOpts->pzCurOpt, pOptState );

    if (pOpts->curOptIdx >= pOpts->origArgCt)
        return PROBLEM; /* NORMAL COMPLETION */

    pOpts->pzCurOpt = pOpts->origArgVect[ pOpts->curOptIdx ];

    /*
     *  IF all arguments must be named options, ...
     */
    if (NAMED_OPTS(pOpts)) {
        char* pz = pOpts->pzCurOpt;
        pOpts->curOptIdx++;

        /*
         *  Skip over any flag/option markers.
         *  In this mode, they are not required.
         */
        while (*pz == '-') pz++;

        return longOptionFind( pOpts, pz, pOptState );
    }

    /*
     *  Note the kind of flag/option marker
     */
    if (*((pOpts->pzCurOpt)++) != '-')
        return PROBLEM; /* NORMAL COMPLETION - this + rest are operands */

    /*
     *  Special hack for a hyphen by itself
     */
    if (*(pOpts->pzCurOpt) == NUL)
        return PROBLEM; /* NORMAL COMPLETION - this + rest are operands */

    /*
     *  The current argument is to be processed as an option argument
     */
    pOpts->curOptIdx++;

    /*
     *  We have an option marker.
     *  Test the next character for long option indication
     */
    if (pOpts->pzCurOpt[0] == '-') {
        if (*++(pOpts->pzCurOpt) == NUL)
            /*
             *  NORMAL COMPLETION - NOT this arg, but rest are operands
             */
            return PROBLEM;

        /*
         *  We do not allow the hyphen to be used as a flag value.
         *  Therefore, if long options are not to be accepted, we punt.
         */
        if ((pOpts->fOptSet & OPTPROC_LONGOPT) == 0) {
            fprintf( stderr, zIllOptStr, pOpts->pzProgPath,
                     zIllegal, pOpts->pzCurOpt-2 );
            return FAILURE;
        }

        return longOptionFind( pOpts, pOpts->pzCurOpt, pOptState );
    }

    /*
     *  If short options are not allowed, then do long
     *  option processing.  Otherwise the character must be a
     *  short (i.e. single character) option.
     */
    if ((pOpts->fOptSet & OPTPROC_SHORTOPT) != 0)
        return shortOptionFind( pOpts, *pOpts->pzCurOpt, pOptState );

    return longOptionFind( pOpts, pOpts->pzCurOpt, pOptState );
}


/*
 *  nextOption
 *
 *  Find the option descriptor and option argument (if any) for the
 *  next command line argument.  DO NOT modify the descriptor.  Put
 *  all the state in the state argument so that the option can be skipped
 *  without consequence (side effect).
 */
STATIC tSuccess
nextOption( tOptions* pOpts, tOptState* pOptState )
{
    tSuccess res;

    res = findOptDesc( pOpts, pOptState );
    if (! SUCCESSFUL( res ))
        return res;
    pOptState->flags |= (pOptState->pOD->fOptState & OPTST_PERSISTENT);

    /*
     *  Figure out what to do about option arguments.  An argument may be
     *  required, not associated with the option, or be optional.  We detect the
     *  latter by examining for an option marker on the next possible argument.
     *  Disabled mode option selection also disables option arguments.
     */
    if ((pOptState->flags & OPTST_DISABLED) != 0)
         pOptState->argType = ARG_NONE;
    else pOptState->argType = pOptState->pOD->optArgType;

    switch (pOptState->argType) {
    case ARG_MUST:
        /*
         *  An option argument is required.  Long options can either have
         *  a separate command line argument, or an argument attached by
         *  the '=' character.  Figure out which.
         */
        switch (pOptState->optType) {
        case TOPT_SHORT:
            /*
             *  See if an arg string follows the flag character
             */
            if (*++(pOpts->pzCurOpt) == NUL)
                pOpts->pzCurOpt = pOpts->origArgVect[ pOpts->curOptIdx++ ];
            pOptState->pzOptArg = pOpts->pzCurOpt;
            break;

        case TOPT_LONG:
            /*
             *  See if an arg string has already been assigned (glued on
             *  with an `=' character)
             */
            if (pOptState->pzOptArg == NULL)
                pOptState->pzOptArg = pOpts->origArgVect[ pOpts->curOptIdx++ ];
            break;

        default:
#ifdef DEBUG
            fputs( "AutoOpts lib error: option type not selected\n",
                   stderr );
            exit( EXIT_FAILURE );
#endif

        case TOPT_DEFAULT:
            /*
             *  The option was selected by default.  The current token is
             *  the option argument.
             */
            break;
        }

        /*
         *  Make sure we did not overflow the argument list.
         */
        if (pOpts->curOptIdx > pOpts->origArgCt) {
            fprintf( stderr, zMisArg, pOpts->pzProgPath,
                     pOptState->pOD->pz_Name );
            return FAILURE;
        }

        pOpts->pzCurOpt = NULL;  /* next time advance to next arg */
        break;

    case ARG_MAY:
        /*
         *  An option argument is optional.
         */
        switch (pOptState->optType) {
        case TOPT_SHORT:
            if (*++pOpts->pzCurOpt != NUL)
                pOptState->pzOptArg = pOpts->pzCurOpt;
            else {
                char* pzLA = pOpts->origArgVect[ pOpts->curOptIdx ];

                /*
                 *  BECAUSE it is optional, we must make sure
                 *  we did not find another flag and that there
                 *  is such an argument.
                 */
                if ((pzLA == NULL) || (*pzLA == '-'))
                    pOptState->pzOptArg = NULL;
                else {
                    pOpts->curOptIdx++; /* argument found */
                    pOptState->pzOptArg = pzLA;
                }
            }
            break;

        case TOPT_LONG:
            /*
             *  Look for an argument if we don't already have one (glued on
             *  with a `=' character) *AND* we are not in named argument mode
             */
            if (  (pOptState->pzOptArg == NULL)
               && (! NAMED_OPTS(pOpts))) {
                char* pzLA = pOpts->origArgVect[ pOpts->curOptIdx ];

                /*
                 *  BECAUSE it is optional, we must make sure
                 *  we did not find another flag and that there
                 *  is such an argument.
                 */
                if ((pzLA == NULL) || (*pzLA == '-'))
                    pOptState->pzOptArg = NULL;
                else {
                    pOpts->curOptIdx++; /* argument found */
                    pOptState->pzOptArg = pzLA;
                }
            }
            break;

        default:
        case TOPT_DEFAULT:
            fputs( "AutoOpts lib error: defaulted to option with optional arg\n",
                   stderr );
            exit( EXIT_FAILURE );
        }

        /*
         *  After an option with an optional argument, we will
         *  *always* start with the next option because if there
         *  were any characters following the option name/flag,
         *  they would be interpreted as the argument.
         */
        pOpts->pzCurOpt = NULL;
        break;

    default: /* CANNOT */
        /*
         *  No option argument.  Make sure next time around we find
         *  the correct option flag character for short options
         */
        if (pOptState->optType == TOPT_SHORT)
            (pOpts->pzCurOpt)++;

        /*
         *  It is a long option.  Make sure there was no ``=xxx'' argument
         */
        else if (pOptState->pzOptArg != NULL) {
            fprintf( stderr, zNoArg, pOpts->pzProgPath,
                     pOptState->pOD->pz_Name );
            return FAILURE;
        }

        /*
         *  It is a long option.  Advance to next command line argument.
         */
        else
            pOpts->pzCurOpt = NULL;
    }

    return SUCCESS;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  DO PRESETS
 *
 *  The next several routines do the immediate action pass on the command
 *  line options, then the environment variables then the RC files in
 *  reverse order.  Once done with that, the order is reversed and all
 *  the RC files and environment variables are processed again, this time
 *  only processing the non-immediate action options.  doPresets() will
 *  then return for optionProcess() to do the final pass on the command
 *  line arguments.
 */

/*
 *  doImmediateOpts - scan the command line for immediate action options
 */
STATIC tSuccess
doImmediateOpts( tOptions* pOpts )
{
    pOpts->curOptIdx = 1;     /* start by skipping program name */
    pOpts->pzCurOpt  = NULL;

    /*
     *  when comparing long names, these are equivalent
     */
    strequate( zSepChars );

    /*
     *  Examine all the options from the start.  We process any options that
     *  are marked for immediate processing.
     */
    for (;;) {
        tOptState optState = OPTSTATE_INITIALIZER;

        switch (nextOption( pOpts, &optState )) {
        case FAILURE: goto optionsDone;
        case PROBLEM: return SUCCESS; /* no more args */
        case SUCCESS: break;
        }

        /*
         *  IF this *is* an immediate-attribute option, then do it.
         */
        switch (optState.flags & (OPTST_DISABLE_IMM|OPTST_IMM)) {
        case 0:                   /* never */
            continue;

        case OPTST_DISABLE_IMM:   /* do enabled options later */
            if ((optState.flags & OPTST_DISABLED) == 0)
                continue;
            break;

        case OPTST_IMM:           /* do disabled options later */
            if ((optState.flags & OPTST_DISABLED) != 0)
                continue;
            break;

        case OPTST_DISABLE_IMM|OPTST_IMM: /* always */
            break;
        }

        if (! SUCCESSFUL( handleOption( pOpts, &optState )))
            break;
    } optionsDone:;

    if ((pOpts->fOptSet & OPTPROC_ERRSTOP) != 0)
        (*pOpts->pUsageProc)( pOpts, EXIT_FAILURE );
    return FAILURE;
}


/*
 *  doEnvPresets - check for preset values from the envrionment
 *  This routine should process in all, immediate or normal modes....
 */
STATIC void
doEnvPresets( tOptions* pOpts, teEnvPresetType type )
{
    int        ct;
    tOptState  st;
    char*      pzFlagName;
    size_t     spaceLeft;
    char       zEnvName[ AO_NAME_SIZE ];

    /*
     *  Finally, see if we are to look at the environment
     *  variables for initial values.
     */
    if ((pOpts->fOptSet & OPTPROC_ENVIRON) == 0)
        return;

    ct  = pOpts->presetOptCt;
    st.pOD = pOpts->pOptDesc;

    pzFlagName = zEnvName
        + snprintf( zEnvName, sizeof( zEnvName ), "%s_", pOpts->pzPROGNAME );
    spaceLeft = AO_NAME_SIZE - (pzFlagName - zEnvName) - 1;

    for (;ct-- > 0; st.pOD++) {
        /*
         *  If presetting is disallowed, then skip this entry
         */
        if ((st.pOD->fOptState & OPTST_NO_INIT) != 0)
            continue;

        /*
         *  IF there is no such environment variable,
         *  THEN skip this entry, too.
         */
        if (strlen( st.pOD->pz_NAME ) >= spaceLeft)
            continue;

        /*
         *  Set up the option state
         */
        strcpy( pzFlagName, st.pOD->pz_NAME );
        st.pzOptArg = getenv( zEnvName );
        if (st.pzOptArg == NULL)
            continue;
        st.flags    = OPTST_PRESET | st.pOD->fOptState;
        st.optType  = TOPT_UNDEFINED;
        st.argType  = 0;

        if (  (st.pOD->pz_DisablePfx != NULL)
           && (streqvcmp( st.pzOptArg, st.pOD->pz_DisablePfx ) == 0)) {
            st.flags |= OPTST_DISABLED;
            st.pzOptArg = NULL;
        }

        switch (type) {
        case ENV_IMM:
            /*
             *  Process only immediate actions
             */
            if (st.flags & OPTST_DISABLED) {
                if ((st.flags & OPTST_DISABLE_IMM) == 0)
                    continue;
            } else {
                if ((st.flags & OPTST_IMM) == 0)
                    continue;
            }
            break;

        case ENV_NON_IMM:
            /*
             *  Process only NON immediate actions
             */
            if (st.flags & OPTST_DISABLED) {
                if ((st.flags & OPTST_DISABLE_IMM) != 0)
                    continue;
            } else {
                if ((st.flags & OPTST_IMM) != 0)
                    continue;
            }
            break;

        default: /* process everything */
            break;
        }

        /*
         *  Make sure the option value string is persistent and consistent.
         *  This may be a memory leak, but we cannot do anything about it.
         *
         *  The interpretation of the option value depends
         *  on the type of value argument the option takes
         */
        if (st.pzOptArg != NULL)
            switch (st.pOD->optArgType) {
            case ARG_MAY:
                if (*st.pzOptArg == NUL) {
                    st.pzOptArg = NULL;
                    break;
                }
                /* FALLTHROUGH */

            case ARG_MUST:
                if (*st.pzOptArg == NUL)
                     st.pzOptArg = zNil;
                else AGDUPSTR( st.pzOptArg, st.pzOptArg, "option argument" );
                break;

            default: /* no argument allowed */
                st.pzOptArg = NULL;
                break;
            }

        handleOption( pOpts, &st );
    }
}


/*
 *  doPresets - check for preset values from an rc file or the envrionment
 */
STATIC void
doRcFiles( tOptions* pOpts )
{
    int   idx;
    int   inc = DIRECTION_PRESET;
    tCC*  pzPath;
    char  zFileName[ 4096 ];

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
         *  IF we are now to skip RC files AND we are presetting,
         *  THEN change direction.  We must go the other way.
         */
        if (SKIP_RC_FILES(pOpts) && PRESETTING(inc)) {
            idx -= inc;  /* go back and reprocess current file */
            inc =  DIRECTION_PROCESS;
        }
    } /* For every path in the home list, ... */
}


/*
 *  doPresets - check for preset values from an rc file or the envrionment
 */
STATIC tSuccess
doPresets( tOptions* pOpts )
{
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

        exit( EXIT_FAILURE );
    }

    /*
     *  IF the client has enabled translation and the translation procedure
     *  is available, then go do it.
     */
    if (  ((pOpts->fOptSet & OPTPROC_TRANSLATE) != 0)
       && (pOpts->pTransProc != 0) ) {
        (*pOpts->pTransProc)();
    }

    {
        const char* pz = strrchr( *pOpts->origArgVect, '/' );

        if (pz == NULL)
             pOpts->pzProgName = *pOpts->origArgVect;
        else pOpts->pzProgName = pz+1;

        pOpts->pzProgPath = *pOpts->origArgVect;
    }

    if (! SUCCESSFUL( doImmediateOpts( pOpts )))
        return FAILURE;

    /*
     *  IF there are no RC files,
     *  THEN do any environment presets and leave.
     */
    if (  (pOpts->papzHomeList == NULL)
       || SKIP_RC_FILES(pOpts) )  {
        doEnvPresets( pOpts, ENV_ALL );
        return SUCCESS;
    }

    doEnvPresets( pOpts, ENV_IMM );
    doRcFiles(    pOpts );
    doEnvPresets( pOpts, ENV_NON_IMM );
    return SUCCESS;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  VERIFY OPTION CONSISTENCY
 *
 *  Make sure that the argument list passes our consistency tests.
 */
STATIC int
checkConsistency( tOptions* pOpts )
{
    int        errCt = 0;
    tOptDesc*  pOD   = pOpts->pOptDesc;
    int        oCt   = pOpts->presetOptCt;

    /*
     *  FOR each of "oCt" options, ...
     */
    for (;;) {
        const int*  pMust = pOD->pOptMust;
        const int*  pCant = pOD->pOptCant;

        /*
         *  IF the current option was provided on the command line
         *  THEN ensure that any "MUST" requirements are not
         *       "DEFAULT" (unspecified) *AND* ensure that any
         *       "CANT" options have not been SET or DEFINED.
         */
        if (SELECTED_OPT(pOD)) {
            if (pMust != NULL) for (;;) {
                tOptDesc*  p = pOpts->pOptDesc + *(pMust++);
                if (UNUSED_OPT(p)) {
                    const tOptDesc* pN = pOpts->pOptDesc + pMust[-1];
                    errCt++;
                    fprintf( stderr, zReqFmt, pOD->pz_Name, pN->pz_Name );
                }

                if (*pMust == NO_EQUIVALENT)
                    break;
            }

            if (pCant != NULL) for (;;) {
                tOptDesc*  p = pOpts->pOptDesc + *(pCant++);
                if (SELECTED_OPT(p)) {
                    const tOptDesc* pN = pOpts->pOptDesc + pCant[-1];
                    errCt++;
                    fprintf( stderr, zCantFmt, pOD->pz_Name, pN->pz_Name );
                }

                if (*pCant == NO_EQUIVALENT)
                    break;
            }
        }

        /*
         *  IF       this option is not equivalenced to another,
         *        OR it is equivalenced to itself (is the equiv. root)
         *  THEN we need to make sure it occurrs often enough.
         */
        if (  (pOD->optEquivIndex == NO_EQUIVALENT)
           || (pOD->optEquivIndex == pOD->optIndex) )   do {
            /*
             *  IF the occurrance counts have been satisfied,
             *  THEN there is no problem.
             */
            if (pOD->optOccCt >= pOD->optMinCt)
                break;

            /*
             *  IF presetting is okay and it has been preset,
             *  THEN min occurrance count doesn't count
             */
#           define PRESET_OK  (OPTST_PRESET | OPTST_MUST_SET)
            if ((pOD->fOptState & PRESET_OK) == PRESET_OK)
                break;

            errCt++;
            if (pOD->optMinCt > 1)
                fprintf( stderr, zNotEnough, pOD->pz_Name, pOD->optMinCt );
            else fprintf( stderr, zNeedOne, pOD->pz_Name );
           } while (0);

        if (--oCt <= 0)
            break;
        pOD++;
    }

    /*
     *  IF we are stopping on errors, check to see if any remaining
     *  arguments are required to be there or prohibited from being there.
     */
    if ((pOpts->fOptSet & OPTPROC_ERRSTOP) != 0) {

        /*
         *  Check for prohibition
         */
        if ((pOpts->fOptSet & OPTPROC_NO_ARGS) != 0) {
            if (pOpts->origArgCt > pOpts->curOptIdx) {
                fprintf( stderr, zNoArgs, pOpts->pzProgName );
                ++errCt;
            }
        }

        /*
         *  ELSE not prohibited, check for being required
         */
        else if ((pOpts->fOptSet & OPTPROC_ARGS_REQ) != 0) {
            if (pOpts->origArgCt <= pOpts->curOptIdx) {
                fprintf( stderr, zArgsMust, pOpts->pzProgName );
                ++errCt;
            }
        }
    }

    return errCt;
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 *  THESE ROUTINES ARE CALLABLE FROM THE GENERATED OPTION PROCESSING CODE
 */
/*=--subblock=arg=arg_type,arg_name,arg_desc =*/
/*=*
 * library:  opts
 * header:   your-opts.h
 *
 * lib_description:
 *
 *  These are the routines that libopts users may call directly from their
 *  code.  There are several other routines that can be called by code
 *  generated by the libopts option templates, but they are not to be
 *  called from any other user code.  The @file{options.h} header is
 *  fairly clear about this, too.
=*/

/*=export_func optionProcess
 *
 * what: this is the main option processing routine
 *
 * arg:  + tOptions* + pOpts + program options descriptor +
 * arg:  + int       + argc  + program arg count  +
 * arg:  + char**    + argv  + program arg vector +
 *
 * ret_type:  int
 * ret_desc:  the count of the arguments processed
 *
 * doc:
 *
 * This is the main entry point for processing options.  It is intended
 * that this procedure be called once at the beginning of the execution of
 * a program.  Depending on options selected earlier, it is sometimes
 * necessary to stop and restart option processing, or to select completely
 * different sets of options.  This can be done easily, but you generally
 * do not want to do this.
 *
 * The number of arguments processed always includes the program name.
 * If one of the arguments is "--", then it is counted and the
 * processing stops.  If an error was encountered and errors are
 * to be tolerated, then the returned value is the index of the
 * argument causing the error.
 *
 * err:  Errors will cause diagnostics to be printed.  @code{exit(3)} may
 *       or may not be called.  It depends upon whether or not the options
 *       were generated with the "allow-errors" attribute, or if the
 *       ERRSKIP_OPTERR or ERRSTOP_OPTERR macros were invoked.
=*/
int
optionProcess(
    tOptions*  pOpts,
    int        argCt,
    char**     argVect )
{
    /*
     *  Establish the real program name, the program full path,
     *  and do all the presetting the first time thru only.
     */
    if ((pOpts->fOptSet & OPTPROC_INITDONE) == 0) {
        pOpts->origArgCt   = argCt;
        pOpts->origArgVect = argVect;
        pOpts->fOptSet    |= OPTPROC_INITDONE;

        if (! SUCCESSFUL( doPresets( pOpts )))
            return 0;

        if ((pOpts->fOptSet & OPTPROC_REORDER) != 0)
            optionSort( pOpts );

        pOpts->curOptIdx   = 1;
        pOpts->pzCurOpt    = NULL;
    }

    /*
     *  IF we are (re)starting,
     *  THEN reset option location
     */
    else if (pOpts->curOptIdx <= 0) {
        pOpts->curOptIdx = 1;
        pOpts->pzCurOpt  = NULL;
    }

    /*
     *  Now, process all the options from our current position onward.
     *  (This allows interspersed options and arguments for the few
     *  non-standard programs that require it.)
     */
    for (;;) {
        tOptState optState = OPTSTATE_INITIALIZER;

        switch (nextOption( pOpts, &optState )) {
        case FAILURE:
            if ((pOpts->fOptSet & OPTPROC_ERRSTOP) != 0)
                (*pOpts->pUsageProc)( pOpts, EXIT_FAILURE );
            goto optionsBad;

        case PROBLEM:
            goto optionsDone;

        case SUCCESS:
            break;
        }

        /*
         *  IF this is not an immediate-attribute option, then do it.
         */
        switch (optState.flags & (OPTST_DISABLE_IMM|OPTST_IMM)) {
        case 0:                   /* always */
            break;

        case OPTST_DISABLE_IMM:   /* disabled options already done */
            if ((optState.flags & OPTST_DISABLED) != 0)
                continue;
            break;

        case OPTST_IMM:           /* enabled options already done */
            if ((optState.flags & OPTST_DISABLED) == 0)
                continue;
            break;

        case OPTST_DISABLE_IMM|OPTST_IMM: /* opt already done */
            continue;
        }

        if (! SUCCESSFUL( handleOption( pOpts, &optState ))) {
            if ((pOpts->fOptSet & OPTPROC_ERRSTOP) != 0)
                (*pOpts->pUsageProc)( pOpts, EXIT_FAILURE );
            break;
        }
    }

 optionsBad:
    return pOpts->origArgCt;

 optionsDone:

    /*
     *  IF    there were no errors
     *    AND we have RC/INI files
     *    AND there is a request to save the files
     *  THEN do that now before testing for conflicts.
     *       (conflicts are ignored in preset options)
     */
    if (pOpts->specOptIdx.save_opts != 0) {
        tOptDesc*  pOD = pOpts->pOptDesc + pOpts->specOptIdx.save_opts;

        if (SELECTED_OPT( pOD )) {
            optionSaveFile( pOpts );
            exit( EXIT_SUCCESS );
        }
    }

    /*
     *  IF we are checking for errors,
     *  THEN look for too few occurrences of required options
     */
    if ((pOpts->fOptSet & OPTPROC_ERRSTOP) != 0) {
        if (checkConsistency( pOpts ) != 0)
            (*pOpts->pUsageProc)( pOpts, EXIT_FAILURE );
    }

    return pOpts->curOptIdx;
}

/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * tab-width: 4
 * indent-tabs-mode: nil
 * tab-width: 4
 * End:
 * end of autoopts/autoopts.c */
