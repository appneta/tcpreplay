
/**
 * \file makeshell.c
 *
 * Time-stamp:      "2012-08-11 08:51:32 bkorb"
 *
 *  This module will interpret the options set in the tOptions
 *  structure and create a Bourne shell script capable of parsing them.
 *
 *  This file is part of AutoOpts, a companion to AutoGen.
 *  AutoOpts is free software.
 *  AutoOpts is Copyright (c) 1992-2012 by Bruce Korb - all rights reserved
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
 *  43b91e8ca915626ed3818ffb1b71248b pkg/libopts/COPYING.gplv3
 *  06a1a2e4760c90ea5e1dad8dfaac4d39 pkg/libopts/COPYING.lgplv3
 *  66a5cedaf62c4b2637025f049f9b826f pkg/libopts/COPYING.mbsd
 */

tOptions * optionParseShellOptions = NULL;

static char const * shell_prog = NULL;
static char * script_leader    = NULL;
static char * script_trailer   = NULL;
static char * script_text      = NULL;

/* = = = START-STATIC-FORWARD = = = */
static void
emit_var_text(char const * prog, char const * var, int fdin);

static void
text_to_var(tOptions * pOpts, teTextTo whichVar, tOptDesc * pOD);

static void
emit_usage(tOptions * pOpts);

static void
emit_setup(tOptions * pOpts);

static void
emit_action(tOptions * pOpts, tOptDesc* pOptDesc);

static void
emit_inaction(tOptions * pOpts, tOptDesc* pOptDesc);

static void
emit_flag(tOptions * pOpts);

static void
emit_match_expr(char const * pzMatchName, tOptDesc* pCurOpt, tOptions* pOpts);

static void
emit_long(tOptions * pOpts);

static char *
load_old_output(char const * fname);

static void
open_out(char const * fname);
/* = = = END-STATIC-FORWARD = = = */

/*=export_func  optionParseShell
 * private:
 *
 * what:  Decipher a boolean value
 * arg:   + tOptions* + pOpts    + program options descriptor +
 *
 * doc:
 *  Emit a shell script that will parse the command line options.
=*/
void
optionParseShell(tOptions * pOpts)
{
    /*
     *  Check for our SHELL option now.
     *  IF the output file contains the "#!" magic marker,
     *  it will override anything we do here.
     */
    if (HAVE_GENSHELL_OPT(SHELL))
        shell_prog = GENSHELL_OPT_ARG(SHELL);

    else if (! ENABLED_GENSHELL_OPT(SHELL))
        shell_prog = NULL;

    else if ((shell_prog = getenv("SHELL")),
             shell_prog == NULL)

        shell_prog = POSIX_SHELL;

    /*
     *  Check for a specified output file
     */
    if (HAVE_GENSHELL_OPT(SCRIPT))
        open_out(GENSHELL_OPT_ARG(SCRIPT));

    emit_usage(pOpts);
    emit_setup(pOpts);

    /*
     *  There are four modes of option processing.
     */
    switch (pOpts->fOptSet & (OPTPROC_LONGOPT|OPTPROC_SHORTOPT)) {
    case OPTPROC_LONGOPT:
        fputs(LOOP_STR,         stdout);

        fputs(LONG_OPT_MARK,    stdout);
        fputs(INIT_LOPT_STR,    stdout);
        emit_long(pOpts);
        printf(LOPT_ARG_FMT,    pOpts->pzPROGNAME);
        fputs(END_OPT_SEL_STR,  stdout);

        fputs(NOT_FOUND_STR,    stdout);
        break;

    case 0:
        fputs(ONLY_OPTS_LOOP,   stdout);
        fputs(INIT_LOPT_STR,    stdout);
        emit_long(pOpts);
        printf(LOPT_ARG_FMT,    pOpts->pzPROGNAME);
        break;

    case OPTPROC_SHORTOPT:
        fputs(LOOP_STR,         stdout);

        fputs(FLAG_OPT_MARK,    stdout);
        fputs(INIT_OPT_STR,     stdout);
        emit_flag(pOpts);
        printf(OPT_ARG_FMT,     pOpts->pzPROGNAME);
        fputs(END_OPT_SEL_STR,  stdout);

        fputs(NOT_FOUND_STR,    stdout);
        break;

    case OPTPROC_LONGOPT|OPTPROC_SHORTOPT:
        fputs(LOOP_STR,         stdout);

        fputs(LONG_OPT_MARK,    stdout);
        fputs(INIT_LOPT_STR,    stdout);
        emit_long(pOpts);
        printf(LOPT_ARG_FMT,    pOpts->pzPROGNAME);
        fputs(END_OPT_SEL_STR,  stdout);

        fputs(FLAG_OPT_MARK,    stdout);
        fputs(INIT_OPT_STR,     stdout);
        emit_flag(pOpts);
        printf(OPT_ARG_FMT,     pOpts->pzPROGNAME);
        fputs(END_OPT_SEL_STR,  stdout);

        fputs(NOT_FOUND_STR,    stdout);
        break;
    }

    printf(zLoopEnd, pOpts->pzPROGNAME, END_MARK);
    if ((script_trailer != NULL) && (*script_trailer != NUL))
        fputs(script_trailer, stdout);
    else if (ENABLED_GENSHELL_OPT(SHELL))
        printf(SHOW_PROG_ENV, pOpts->pzPROGNAME);

#ifdef HAVE_FCHMOD
    fchmod(STDOUT_FILENO, 0755);
#endif
    fclose(stdout);

    if (ferror(stdout)) {
        fputs(zOutputFail, stderr);
        exit(EXIT_FAILURE);
    }

    AGFREE(script_text);
    script_leader    = NULL;
    script_trailer   = NULL;
    script_text      = NULL;
}

#ifdef HAVE_WORKING_FORK
static void
emit_var_text(char const * prog, char const * var, int fdin)
{
    FILE * fp   = fdopen(fdin, "r" FOPEN_BINARY_FLAG);
    int    nlct = 0; /* defer newlines and skip trailing ones */

    printf(SET_TEXT_FMT, prog, var);
    if (fp == NULL)
        goto skip_text;

    for (;;) {
        int  ch = fgetc(fp);
        switch (ch) {

        case NL:
            nlct++;
            break;

        case '\'':
            while (nlct > 0) {
                fputc(NL, stdout);
                nlct--;
            }
            fputs(apostrophy, stdout);
            break;

        case EOF:
            goto endCharLoop;

        default:
            while (nlct > 0) {
                fputc(NL, stdout);
                nlct--;
            }
            fputc(ch, stdout);
            break;
        }
    } endCharLoop:;

    fclose(fp);

skip_text:

    fputs(END_SET_TEXT, stdout);
}

#endif

/*
 *  The purpose of this function is to assign "long usage", short usage
 *  and version information to a shell variable.  Rather than wind our
 *  way through all the logic necessary to emit the text directly, we
 *  fork(), have our child process emit the text the normal way and
 *  capture the output in the parent process.
 */
static void
text_to_var(tOptions * pOpts, teTextTo whichVar, tOptDesc * pOD)
{
#   define _TT_(n) static char const z ## n [] = #n;
    TEXTTO_TABLE
#   undef _TT_
#   define _TT_(n) z ## n ,
      static char const * apzTTNames[] = { TEXTTO_TABLE };
#   undef _TT_

#if ! defined(HAVE_WORKING_FORK)
    printf(SET_NO_TEXT_FMT, pOpts->pzPROGNAME, apzTTNames[ whichVar]);
#else
    int  pipeFd[2];

    fflush(stdout);
    fflush(stderr);

    if (pipe(pipeFd) != 0) {
        fprintf(stderr, zBadPipe, errno, strerror(errno));
        exit(EXIT_FAILURE);
    }

    switch (fork()) {
    case -1:
        fprintf(stderr, zForkFail, errno, strerror(errno), pOpts->pzProgName);
        exit(EXIT_FAILURE);
        break;

    case 0:
        /*
         * Send both stderr and stdout to the pipe.  No matter which
         * descriptor is used, we capture the output on the read end.
         */
        dup2(pipeFd[1], STDERR_FILENO);
        dup2(pipeFd[1], STDOUT_FILENO);
        close(pipeFd[0]);

        switch (whichVar) {
        case TT_LONGUSAGE:
            (*(pOpts->pUsageProc))(pOpts, EXIT_SUCCESS);
            /* NOTREACHED */

        case TT_USAGE:
            (*(pOpts->pUsageProc))(pOpts, EXIT_FAILURE);
            /* NOTREACHED */

        case TT_VERSION:
            if (pOD->fOptState & OPTST_ALLOC_ARG) {
                AGFREE(pOD->optArg.argString);
                pOD->fOptState &= ~OPTST_ALLOC_ARG;
            }
            pOD->optArg.argString = "c";
            optionPrintVersion(pOpts, pOD);
            /* NOTREACHED */

        default:
            exit(EXIT_FAILURE);
        }

    default:
        close(pipeFd[1]);
    }

    emit_var_text(pOpts->pzPROGNAME, apzTTNames[whichVar], pipeFd[0]);
#endif
}


static void
emit_usage(tOptions * pOpts)
{
    char zTimeBuf[AO_NAME_SIZE];

    /*
     *  First, switch stdout to the output file name.
     *  Then, change the program name to the one defined
     *  by the definitions (rather than the current
     *  executable name).  Down case the upper cased name.
     */
    if (script_leader != NULL)
        fputs(script_leader, stdout);

    {
        char const * out_nm;

        {
            time_t    c_tim = time(NULL);
            struct tm * ptm = localtime(&c_tim);
            strftime(zTimeBuf, AO_NAME_SIZE, TIME_FMT, ptm );
        }

        if (HAVE_GENSHELL_OPT(SCRIPT))
             out_nm = GENSHELL_OPT_ARG(SCRIPT);
        else out_nm = STDOUT;

        if ((script_leader == NULL) && (shell_prog != NULL))
            printf(SHELL_MAGIC, shell_prog);

        printf(PREAMBLE_FMT, START_MARK, out_nm, zTimeBuf);
    }

    printf(END_PRE_FMT, pOpts->pzPROGNAME);

    /*
     *  Get a copy of the original program name in lower case and
     *  fill in an approximation of the program name from it.
     */
    {
        char *       pzPN = zTimeBuf;
        char const * pz   = pOpts->pzPROGNAME;
        char **      pp;

        for (;;) {
            if ((*pzPN++ = (char)tolower(*pz++)) == NUL)
                break;
        }

        pp = (char **)(void *)&(pOpts->pzProgPath);
        *pp = zTimeBuf;
        pp  = (char **)(void *)&(pOpts->pzProgName);
        *pp = zTimeBuf;
    }

    text_to_var(pOpts, TT_LONGUSAGE, NULL);
    text_to_var(pOpts, TT_USAGE,     NULL);

    {
        tOptDesc* pOptDesc = pOpts->pOptDesc;
        int       optionCt = pOpts->optCt;

        for (;;) {
            if (pOptDesc->pOptProc == optionPrintVersion) {
                text_to_var(pOpts, TT_VERSION, pOptDesc);
                break;
            }

            if (--optionCt <= 0)
                break;
            pOptDesc++;
        }
    }
}


static void
emit_setup(tOptions * pOpts)
{
    tOptDesc *   pOptDesc = pOpts->pOptDesc;
    int          optionCt = pOpts->presetOptCt;
    char const * pzFmt;
    char const * pzDefault;

    for (;optionCt > 0; pOptDesc++, --optionCt) {
        char zVal[32];

        /*
         *  Options that are either usage documentation or are compiled out
         *  are not to be processed.
         */
        if (SKIP_OPT(pOptDesc) || (pOptDesc->pz_NAME == NULL))
            continue;

        if (pOptDesc->optMaxCt > 1)
             pzFmt = MULTI_DEF_FMT;
        else pzFmt = SGL_DEF_FMT;

        /*
         *  IF this is an enumeration/bitmask option, then convert the value
         *  to a string before printing the default value.
         */
        switch (OPTST_GET_ARGTYPE(pOptDesc->fOptState)) {
        case OPARG_TYPE_ENUMERATION:
            (*(pOptDesc->pOptProc))(OPTPROC_EMIT_SHELL, pOptDesc );
            pzDefault = pOptDesc->optArg.argString;
            break;

        /*
         *  Numeric and membership bit options are just printed as a number.
         */
        case OPARG_TYPE_NUMERIC:
            snprintf(zVal, sizeof(zVal), "%d",
                     (int)pOptDesc->optArg.argInt);
            pzDefault = zVal;
            break;

        case OPARG_TYPE_MEMBERSHIP:
            snprintf(zVal, sizeof(zVal), "%lu",
                     (unsigned long)pOptDesc->optArg.argIntptr);
            pzDefault = zVal;
            break;

        case OPARG_TYPE_BOOLEAN:
            pzDefault = (pOptDesc->optArg.argBool) ? TRUE_STR : FALSE_STR;
            break;

        default:
            if (pOptDesc->optArg.argString == NULL) {
                if (pzFmt == SGL_DEF_FMT)
                    pzFmt = SGL_NO_DEF_FMT;
                pzDefault = NULL;
            }
            else
                pzDefault = pOptDesc->optArg.argString;
        }

        printf(pzFmt, pOpts->pzPROGNAME, pOptDesc->pz_NAME, pzDefault);
    }
}

static void
emit_action(tOptions * pOpts, tOptDesc* pOptDesc)
{
    if (pOptDesc->pOptProc == optionPrintVersion)
        printf(zTextExit, pOpts->pzPROGNAME, VER_STR);

    else if (pOptDesc->pOptProc == optionPagedUsage)
        printf(zPagedUsageExit, pOpts->pzPROGNAME);

    else if (pOptDesc->pOptProc == optionLoadOpt) {
        printf(zCmdFmt, NO_LOAD_WARN);
        printf(zCmdFmt, YES_NEED_OPT_ARG);

    } else if (pOptDesc->pz_NAME == NULL) {

        if (pOptDesc->pOptProc == NULL) {
            printf(zCmdFmt, NO_SAVE_OPTS);
            printf(zCmdFmt, OK_NEED_OPT_ARG);
        } else
            printf(zTextExit, pOpts->pzPROGNAME, LONG_USE_STR);

    } else {
        if (pOptDesc->optMaxCt == 1)
            printf(SGL_ARG_FMT, pOpts->pzPROGNAME, pOptDesc->pz_NAME);
        else {
            if ((unsigned)pOptDesc->optMaxCt < NOLIMIT)
                printf(zCountTest, pOpts->pzPROGNAME,
                       pOptDesc->pz_NAME, pOptDesc->optMaxCt);

            printf(MULTI_ARG_FMT, pOpts->pzPROGNAME, pOptDesc->pz_NAME);
        }

        /*
         *  Fix up the args.
         */
        if (OPTST_GET_ARGTYPE(pOptDesc->fOptState) == OPARG_TYPE_NONE) {
            printf(zCantArg, pOpts->pzPROGNAME, pOptDesc->pz_NAME);

        } else if (pOptDesc->fOptState & OPTST_ARG_OPTIONAL) {
            printf(zMayArg,  pOpts->pzPROGNAME, pOptDesc->pz_NAME);

        } else {
            fputs(zMustArg, stdout);
        }
    }
    fputs(zOptionEndSelect, stdout);
}


static void
emit_inaction(tOptions * pOpts, tOptDesc* pOptDesc)
{
    if (pOptDesc->pOptProc == optionLoadOpt) {
        printf(zCmdFmt, NO_SUPPRESS_LOAD);

    } else if (pOptDesc->optMaxCt == 1)
        printf(NO_SGL_ARG_FMT, pOpts->pzPROGNAME,
               pOptDesc->pz_NAME, pOptDesc->pz_DisablePfx);
    else
        printf(NO_MULTI_ARG_FMT, pOpts->pzPROGNAME,
               pOptDesc->pz_NAME, pOptDesc->pz_DisablePfx);

    printf(zCmdFmt, NO_ARG_NEEDED);
    fputs(zOptionEndSelect, stdout);
}


static void
emit_flag(tOptions * pOpts)
{
    tOptDesc* pOptDesc = pOpts->pOptDesc;
    int       optionCt = pOpts->optCt;

    fputs(zOptionCase, stdout);

    for (;optionCt > 0; pOptDesc++, --optionCt) {

        if (SKIP_OPT(pOptDesc))
            continue;

        if (IS_GRAPHIC_CHAR(pOptDesc->optValue)) {
            printf(zOptionFlag, pOptDesc->optValue);
            emit_action(pOpts, pOptDesc);
        }
    }
    printf(UNK_OPT_FMT, FLAG_STR, pOpts->pzPROGNAME);
}


/*
 *  Emit the match text for a long option
 */
static void
emit_match_expr(char const * pzMatchName, tOptDesc* pCurOpt, tOptions* pOpts)
{
    tOptDesc* pOD = pOpts->pOptDesc;
    int       oCt = pOpts->optCt;
    int       min = 1;
    char      zName[ 256 ];
    char*     pz  = zName;

    for (;;) {
        int matchCt = 0;

        /*
         *  Omit the current option, Documentation opts and compiled out opts.
         */
        if ((pOD == pCurOpt) || SKIP_OPT(pOD)){
            if (--oCt <= 0)
                break;
            pOD++;
            continue;
        }

        /*
         *  Check each character of the name case insensitively.
         *  They must not be the same.  They cannot be, because it would
         *  not compile correctly if they were.
         */
        while (  toupper(pOD->pz_Name[matchCt])
              == toupper(pzMatchName[matchCt]))
            matchCt++;

        if (matchCt > min)
            min = matchCt;

        /*
         *  Check the disablement name, too.
         */
        if (pOD->pz_DisableName != NULL) {
            matchCt = 0;
            while (  toupper(pOD->pz_DisableName[matchCt])
                  == toupper(pzMatchName[matchCt]))
                matchCt++;
            if (matchCt > min)
                min = matchCt;
        }
        if (--oCt <= 0)
            break;
        pOD++;
    }

    /*
     *  IF the 'min' is all or one short of the name length,
     *  THEN the entire string must be matched.
     */
    if (  (pzMatchName[min  ] == NUL)
       || (pzMatchName[min+1] == NUL) )
        printf(zOptionFullName, pzMatchName);

    else {
        int matchCt = 0;
        for (; matchCt <= min; matchCt++)
            *pz++ = pzMatchName[matchCt];

        for (;;) {
            *pz = NUL;
            printf(zOptionPartName, zName);
            *pz++ = pzMatchName[matchCt++];
            if (pzMatchName[matchCt] == NUL) {
                *pz = NUL;
                printf(zOptionFullName, zName);
                break;
            }
        }
    }
}


/**
 *  Emit GNU-standard long option handling code.
 */
static void
emit_long(tOptions * pOpts)
{
    tOptDesc* pOD = pOpts->pOptDesc;
    int       ct  = pOpts->optCt;

    fputs(zOptionCase, stdout);

    /*
     *  do each option, ...
     */
    do  {
        /*
         *  Documentation & compiled-out options
         */
        if (SKIP_OPT(pOD))
            continue;

        emit_match_expr(pOD->pz_Name, pOD, pOpts);
        emit_action(pOpts, pOD);

        /*
         *  Now, do the same thing for the disablement version of the option.
         */
        if (pOD->pz_DisableName != NULL) {
            emit_match_expr(pOD->pz_DisableName, pOD, pOpts);
            emit_inaction(pOpts, pOD);
        }
    } while (pOD++, --ct > 0);

    printf(UNK_OPT_FMT, OPTION_STR, pOpts->pzPROGNAME);
}

/**
 * Load the previous shell script output file.  We need to preserve any
 * hand-edited additions outside of the START_MARK and END_MARKs.
 *
 * @param[in] fname  the output file name
 */
static char *
load_old_output(char const * fname)
{
    /*
     *  IF we cannot stat the file,
     *  THEN assume we are creating a new file.
     *       Skip the loading of the old data.
     */
    FILE * fp = fopen(fname, "r" FOPEN_BINARY_FLAG);
    struct stat stbf;
    char * text;
    char * scan;

    if (fp == NULL)
        return NULL;

    /*
     * If we opened it, we should be able to stat it and it needs
     * to be a regular file
     */
    if ((fstat(fileno(fp), &stbf) != 0) || (! S_ISREG(stbf.st_mode))) {
        fprintf(stderr, zNotFile, fname);
        exit(EXIT_FAILURE);
    }

    scan = text = AGALOC(stbf.st_size + 1, "f data");

    /*
     *  Read in all the data as fast as our OS will let us.
     */
    for (;;) {
        int inct = fread((void*)scan, (size_t)1, stbf.st_size, fp);
        if (inct == 0)
            break;

        stbf.st_size -= inct;

        if (stbf.st_size == 0)
            break;

        scan += inct;
    }

    *scan = NUL;
    fclose(fp);

    return text;
}

/**
 * Open the specified output file.  If it already exists, load its
 * contents and save the non-generated (hand edited) portions.
 * If a "start mark" is found, everything before it is preserved leader.
 * If not, the entire thing is a trailer.  Assuming the start is found,
 * then everything after the end marker is the trailer.  If the end
 * mark is not found, the file is actually corrupt, but we take the
 * remainder to be the trailer.
 *
 * @param[in] fname  the output file name
 */
static void
open_out(char const * fname)
{

    do  {
        char * txt = script_text = load_old_output(fname);
        char * scn;

        if (txt == NULL)
            break;

        scn = strstr(txt, START_MARK);
        if (scn == NULL) {
            script_trailer = txt;
            break;
        }

        *(scn++) = NUL;
        scn = strstr(scn, END_MARK);
        if (scn == NULL) {
            /*
             * The file is corrupt.
             */
            script_trailer = txt + strlen(txt) + START_MARK_LEN + 1;
            break;
        }

        /*
         *  Check to see if the data contains our marker.
         *  If it does, then we will skip over it
         */
        script_trailer = scn + END_MARK_LEN;
        script_leader  = txt;
    } while (false);

    if (freopen(fname, "w" FOPEN_BINARY_FLAG, stdout) != stdout) {
        fprintf(stderr, zFreopenFail, errno, strerror(errno));
        exit(EXIT_FAILURE);
    }
}


/*=export_func genshelloptUsage
 * private:
 * what: The usage function for the genshellopt generated program
 *
 * arg:  + tOptions* + pOpts    + program options descriptor +
 * arg:  + int       + exitCode + usage text type to produce +
 *
 * doc:
 *  This function is used to create the usage strings for the option
 *  processing shell script code.  Two child processes are spawned
 *  each emitting the usage text in either the short (error exit)
 *  style or the long style.  The generated program will capture this
 *  and create shell script variables containing the two types of text.
=*/
void
genshelloptUsage(tOptions * pOpts, int exitCode)
{
#if ! defined(HAVE_WORKING_FORK)
    optionUsage(pOpts, exitCode);
#else
    /*
     *  IF not EXIT_SUCCESS,
     *  THEN emit the short form of usage.
     */
    if (exitCode != EXIT_SUCCESS)
        optionUsage(pOpts, exitCode);
    fflush(stderr);
    fflush(stdout);
    if (ferror(stdout) || ferror(stderr))
        exit(EXIT_FAILURE);

    option_usage_fp = stdout;

    /*
     *  First, print our usage
     */
    switch (fork()) {
    case -1:
        optionUsage(pOpts, EXIT_FAILURE);
        /* NOTREACHED */

    case 0:
        pagerState = PAGER_STATE_CHILD;
        optionUsage(pOpts, EXIT_SUCCESS);
        /* NOTREACHED */
        _exit(EXIT_FAILURE);

    default:
    {
        int  sts;
        wait(&sts);
    }
    }

    /*
     *  Generate the pzProgName, since optionProcess() normally
     *  gets it from the command line
     */
    {
        char *  pz;
        char ** pp = (char **)(void *)&(optionParseShellOptions->pzProgName);
        AGDUPSTR(pz, optionParseShellOptions->pzPROGNAME, "prog name");
        *pp = pz;
        while (*pz != NUL) {
            *pz = tolower(*pz);
            pz++;
        }
    }

    /*
     *  Separate the makeshell usage from the client usage
     */
    fprintf(option_usage_fp, zGenshell, optionParseShellOptions->pzProgName);
    fflush(option_usage_fp);

    /*
     *  Now, print the client usage.
     */
    switch (fork()) {
    case 0:
        pagerState = PAGER_STATE_CHILD;
        /*FALLTHROUGH*/
    case -1:
        optionUsage(optionParseShellOptions, EXIT_FAILURE);

    default:
    {
        int  sts;
        wait(&sts);
    }
    }

    fflush(stdout);
    if (ferror(stdout)) {
        fputs(zOutputFail, stderr);
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
#endif
}

/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/makeshell.c */
