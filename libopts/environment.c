
/*
 *  $Id: environment.c,v 4.17 2008/06/14 22:24:22 bkorb Exp $
 * Time-stamp:      "2007-07-04 11:33:50 bkorb"
 *
 *  This file contains all of the routines that must be linked into
 *  an executable to use the generated option processing.  The optional
 *  routines are in separately compiled modules so that they will not
 *  necessarily be linked in.
 *
 *  This file is part of AutoOpts, a companion to AutoGen.
 *  AutoOpts is free software.
 *  AutoOpts is copyright (c) 1992-2008 by Bruce Korb - all rights reserved
 *  AutoOpts is copyright (c) 1992-2008 by Bruce Korb - all rights reserved
 *
 *  AutoOpts is available under any one of two licenses.  The license
 *  in use must be one of these two and the choice is under the control
 *  of the user of the license.
 *
 *   The GNU Lesser General Public License, version 3 or later
 *      See the files "COPYING.lgplv3" and "COPYING.gplv3"
 *
 *   The Modified Berkeley Software Distribution License
 *      See the file "COPYING.mbsd"
 *
 *  These files have the following md5sums:
 *
 *  239588c55c22c60ffe159946a760a33e pkg/libopts/COPYING.gplv3
 *  fa82ca978890795162346e661b47161a pkg/libopts/COPYING.lgplv3
 *  66a5cedaf62c4b2637025f049f9b826f pkg/libopts/COPYING.mbsd
 */

/* = = = START-STATIC-FORWARD = = = */
/* static forward declarations maintained by mk-fwd */
static void
checkEnvOpt(tOptState * os, char * env_name,
            tOptions* pOpts, teEnvPresetType type);
/* = = = END-STATIC-FORWARD = = = */

/*
 *  doPrognameEnv - check for preset values from the ${PROGNAME}
 *  environment variable.  This is accomplished by parsing the text into
 *  tokens, temporarily replacing the arg vector and calling
 *  doImmediateOpts and/or doRegularOpts.
 */
LOCAL void
doPrognameEnv( tOptions* pOpts, teEnvPresetType type )
{
    char const*   pczOptStr = getenv( pOpts->pzPROGNAME );
    token_list_t* pTL;
    int           sv_argc;
    tAoUI         sv_flag;
    char**        sv_argv;

    /*
     *  IF there is no such environment variable
     *   *or* there is, but we are doing immediate opts and there are
     *        no immediate opts to do (--help inside $PROGNAME is silly,
     *        but --no-load-defs is not, so that is marked)
     *  THEN bail out now.  (
     */
    if (  (pczOptStr == NULL)
       || (  (type == ENV_IMM)
          && ((pOpts->fOptSet & OPTPROC_HAS_IMMED) == 0)  )  )
        return;

    /*
     *  Tokenize the string.  If there's nothing of interest, we'll bail
     *  here immediately.
     */
    pTL = ao_string_tokenize( pczOptStr );
    if (pTL == NULL)
        return;

    /*
     *  Substitute our $PROGNAME argument list for the real one
     */
    sv_argc = pOpts->origArgCt;
    sv_argv = pOpts->origArgVect;
    sv_flag = pOpts->fOptSet;

    /*
     *  We add a bogus pointer to the start of the list.  The program name
     *  has already been pulled from "argv", so it won't get dereferenced.
     *  The option scanning code will skip the "program name" at the start
     *  of this list of tokens, so we accommodate this way ....
     */
    pOpts->origArgVect = (char**)(pTL->tkn_list - 1);
    pOpts->origArgCt   = pTL->tkn_ct   + 1;
    pOpts->fOptSet    &= ~OPTPROC_ERRSTOP;

    pOpts->curOptIdx   = 1;
    pOpts->pzCurOpt    = NULL;

    switch (type) {
    case ENV_IMM:
        /*
         *  We know the OPTPROC_HAS_IMMED bit is set.
         */
        (void)doImmediateOpts( pOpts );
        break;

    case ENV_NON_IMM:
        (void)doRegularOpts( pOpts );
        break;

    default:
        /*
         *  Only to immediate opts if the OPTPROC_HAS_IMMED bit is set.
         */
        if (pOpts->fOptSet & OPTPROC_HAS_IMMED) {
            (void)doImmediateOpts( pOpts );
            pOpts->curOptIdx = 1;
            pOpts->pzCurOpt  = NULL;
        }
        (void)doRegularOpts( pOpts );
        break;
    }

    /*
     *  Free up the temporary arg vector and restore the original program args.
     */
    free( pTL );
    pOpts->origArgVect = sv_argv;
    pOpts->origArgCt   = sv_argc;
    pOpts->fOptSet     = sv_flag;
}

static void
checkEnvOpt(tOptState * os, char * env_name,
            tOptions* pOpts, teEnvPresetType type)
{
    os->pzOptArg = getenv( env_name );
    if (os->pzOptArg == NULL)
        return;

    os->flags    = OPTST_PRESET | OPTST_ALLOC_ARG | os->pOD->fOptState;
    os->optType  = TOPT_UNDEFINED;

    if (  (os->pOD->pz_DisablePfx != NULL)
       && (streqvcmp( os->pzOptArg, os->pOD->pz_DisablePfx ) == 0)) {
        os->flags |= OPTST_DISABLED;
        os->pzOptArg = NULL;
    }

    switch (type) {
    case ENV_IMM:
        /*
         *  Process only immediate actions
         */
        if (DO_IMMEDIATELY(os->flags))
            break;
        return;

    case ENV_NON_IMM:
        /*
         *  Process only NON immediate actions
         */
        if (DO_NORMALLY(os->flags) || DO_SECOND_TIME(os->flags))
            break;
        return;

    default: /* process everything */
        break;
    }

    /*
     *  Make sure the option value string is persistent and consistent.
     *
     *  The interpretation of the option value depends
     *  on the type of value argument the option takes
     */
    if (os->pzOptArg != NULL) {
        if (OPTST_GET_ARGTYPE(os->pOD->fOptState) == OPARG_TYPE_NONE) {
            os->pzOptArg = NULL;
        } else if (  (os->pOD->fOptState & OPTST_ARG_OPTIONAL)
                     && (*os->pzOptArg == NUL)) {
            os->pzOptArg = NULL;
        } else if (*os->pzOptArg == NUL) {
            os->pzOptArg = zNil;
        } else {
            AGDUPSTR( os->pzOptArg, os->pzOptArg, "option argument" );
            os->flags |= OPTST_ALLOC_ARG;
        }
    }

    handleOption( pOpts, os );
}

/*
 *  doEnvPresets - check for preset values from the envrionment
 *  This routine should process in all, immediate or normal modes....
 */
LOCAL void
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

    doPrognameEnv( pOpts, type );

    ct  = pOpts->presetOptCt;
    st.pOD = pOpts->pOptDesc;

    pzFlagName = zEnvName
        + snprintf( zEnvName, sizeof( zEnvName ), "%s_", pOpts->pzPROGNAME );
    spaceLeft = AO_NAME_SIZE - (pzFlagName - zEnvName) - 1;

    for (;ct-- > 0; st.pOD++) {
        /*
         *  If presetting is disallowed, then skip this entry
         */
        if (  ((st.pOD->fOptState & OPTST_NO_INIT) != 0)
           || (st.pOD->optEquivIndex != NO_EQUIVALENT)  )
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
        checkEnvOpt(&st, zEnvName, pOpts, type);
    }

    /*
     *  Special handling for ${PROGNAME_LOAD_OPTS}
     */
    if (pOpts->specOptIdx.save_opts != 0) {
        st.pOD = pOpts->pOptDesc + pOpts->specOptIdx.save_opts + 1;
        strcpy( pzFlagName, st.pOD->pz_NAME );
        checkEnvOpt(&st, zEnvName, pOpts, type);
    }
}

/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/environment.c */
