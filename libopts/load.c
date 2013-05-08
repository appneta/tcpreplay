
/**
 *  \file load.c
 *  Time-stamp:      "2012-08-11 08:20:09 bkorb"
 *
 *  This file contains the routines that deal with processing text strings
 *  for options, either from a NUL-terminated string passed in or from an
 *  rc/ini file.
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

/* = = = START-STATIC-FORWARD = = = */
static bool
add_prog_path(char * pzBuf, int bufSize, char const * pzName,
              char const * pzProgPath);

static bool
add_env_val(char * buf, int buf_sz, char const * name);

static char *
assemble_arg_val(char * txt, tOptionLoadMode mode);
/* = = = END-STATIC-FORWARD = = = */

/*=export_func  optionMakePath
 * private:
 *
 * what:  translate and construct a path
 * arg:   + char*       + pzBuf      + The result buffer +
 * arg:   + int         + bufSize    + The size of this buffer +
 * arg:   + char const* + pzName     + The input name +
 * arg:   + char const* + pzProgPath + The full path of the current program +
 *
 * ret-type: bool
 * ret-desc: true if the name was handled, otherwise false.
 *           If the name does not start with ``$'', then it is handled
 *           simply by copying the input name to the output buffer and
 *           resolving the name with either
 *           @code{canonicalize_file_name(3GLIBC)} or @code{realpath(3C)}.
 *
 * doc:
 *
 *  This routine will copy the @code{pzName} input name into the
 *  @code{pzBuf} output buffer, not exceeding @code{bufSize} bytes.  If the
 *  first character of the input name is a @code{'$'} character, then there
 *  is special handling:
 *  @*
 *  @code{$$} is replaced with the directory name of the @code{pzProgPath},
 *  searching @code{$PATH} if necessary.
 *  @*
 *  @code{$@} is replaced with the AutoGen package data installation directory
 *  (aka @code{pkgdatadir}).
 *  @*
 *  @code{$NAME} is replaced by the contents of the @code{NAME} environment
 *  variable.  If not found, the search fails.
 *
 *  Please note: both @code{$$} and @code{$NAME} must be at the start of the
 *     @code{pzName} string and must either be the entire string or be followed
 *     by the @code{'/'} (backslash on windows) character.
 *
 * err:  @code{false} is returned if:
 *       @*
 *       @bullet{} The input name exceeds @code{bufSize} bytes.
 *       @*
 *       @bullet{} @code{$$}, @code{$@@} or @code{$NAME} is not the full string
 *                 and the next character is not '/'.
 *       @*
 *       @bullet{} libopts was built without PKGDATADIR defined and @code{$@@}
 *                 was specified.
 *       @*
 *       @bullet{} @code{NAME} is not a known environment variable
 *       @*
 *       @bullet{} @code{canonicalize_file_name} or @code{realpath} return
 *                 errors (cannot resolve the resulting path).
=*/
bool
optionMakePath(char * pzBuf, int bufSize, char const * pzName,
               char const * pzProgPath)
{
    size_t name_len = strlen(pzName);

    if (((size_t)bufSize <= name_len) || (name_len == 0))
        return false;

    /*
     *  IF not an environment variable, just copy the data
     */
    if (*pzName != '$') {
        char const*  pzS = pzName;
        char* pzD = pzBuf;
        int   ct  = bufSize;

        for (;;) {
            if ( (*(pzD++) = *(pzS++)) == NUL)
                break;
            if (--ct <= 0)
                return false;
        }
    }

    /*
     *  IF the name starts with "$$", then it must be "$$" or
     *  it must start with "$$/".  In either event, replace the "$$"
     *  with the path to the executable and append a "/" character.
     */
    else switch (pzName[1]) {
    case NUL:
        return false;

    case '$':
        if (! add_prog_path(pzBuf, bufSize, pzName, pzProgPath))
            return false;
        break;

    case '@':
        if (program_pkgdatadir[0] == NUL)
            return false;

        if (snprintf(pzBuf, bufSize, "%s%s", program_pkgdatadir, pzName + 2)
            >= bufSize)
            return false;
        break;

    default:
        if (! add_env_val(pzBuf, bufSize, pzName))
            return false;
    }

#if defined(HAVE_CANONICALIZE_FILE_NAME)
    {
        char * pz = canonicalize_file_name(pzBuf);
        if (pz == NULL)
            return false;

        name_len = strlen(pz);
        if (name_len >= (size_t)bufSize) {
            free(pz);
            return false;
        }

        memcpy(pzBuf, pz, name_len + 1);
        free(pz);
    }

#elif defined(HAVE_REALPATH)
    {
        char z[PATH_MAX+1];

        if (realpath(pzBuf, z) == NULL)
            return false;

        name_len = strlen(z);
        if (name_len >= bufSize)
            return false;

        memcpy(pzBuf, z, name_len + 1);
    }
#endif

    return true;
}

static bool
add_prog_path(char * pzBuf, int bufSize, char const * pzName,
              char const * pzProgPath)
{
    char const*    pzPath;
    char const*    pz;
    int     skip = 2;

    switch (pzName[2]) {
    case DIRCH:
        skip = 3;
    case NUL:
        break;
    default:
        return false;
    }

    /*
     *  See if the path is included in the program name.
     *  If it is, we're done.  Otherwise, we have to hunt
     *  for the program using "pathfind".
     */
    if (strchr(pzProgPath, DIRCH) != NULL)
        pzPath = pzProgPath;
    else {
        pzPath = pathfind(getenv("PATH"), (char*)pzProgPath, "rx");

        if (pzPath == NULL)
            return false;
    }

    pz = strrchr(pzPath, DIRCH);

    /*
     *  IF we cannot find a directory name separator,
     *  THEN we do not have a path name to our executable file.
     */
    if (pz == NULL)
        return false;

    pzName += skip;

    /*
     *  Concatenate the file name to the end of the executable path.
     *  The result may be either a file or a directory.
     */
    if ((pz - pzPath)+1 + strlen(pzName) >= (unsigned)bufSize)
        return false;

    memcpy(pzBuf, pzPath, (size_t)((pz - pzPath)+1));
    strcpy(pzBuf + (pz - pzPath) + 1, pzName);

    /*
     *  If the "pzPath" path was gotten from "pathfind()", then it was
     *  allocated and we need to deallocate it.
     */
    if (pzPath != pzProgPath)
        AGFREE(pzPath);
    return true;
}

static bool
add_env_val(char * buf, int buf_sz, char const * name)
{
    char * dir_part = buf;

    for (;;) {
        int ch = (int)*++name;
        if (! IS_VALUE_NAME_CHAR(ch))
            break;
        *(dir_part++) = (char)ch;
    }

    if (dir_part == buf)
        return false;

    *dir_part = NUL;

    dir_part = getenv(buf);

    /*
     *  Environment value not found -- skip the home list entry
     */
    if (dir_part == NULL)
        return false;

    if (strlen(dir_part) + 1 + strlen(name) >= (unsigned)buf_sz)
        return false;

    sprintf(buf, "%s%s", dir_part, name);
    return true;
}

LOCAL void
mungeString(char * txt, tOptionLoadMode mode)
{
    char * pzE;

    if (mode == OPTION_LOAD_KEEP)
        return;

    if (IS_WHITESPACE_CHAR(*txt)) {
        char * pzS = SPN_WHITESPACE_CHARS(txt+1);
        size_t l   = strlen(pzS) + 1;
        memmove(txt, pzS, l);
        pzE = txt + l - 1;

    } else
        pzE = txt + strlen(txt);

    pzE  = SPN_WHITESPACE_BACK(txt, pzE);
    *pzE = NUL;

    if (mode == OPTION_LOAD_UNCOOKED)
        return;

    switch (*txt) {
    default: return;
    case '"':
    case '\'': break;
    }

    switch (pzE[-1]) {
    default: return;
    case '"':
    case '\'': break;
    }

    (void)ao_string_cook(txt, NULL);
}

static char *
assemble_arg_val(char * txt, tOptionLoadMode mode)
{
    char* pzEnd = strpbrk(txt, ARG_BREAK_STR);
    int   space_break;

    /*
     *  Not having an argument to a configurable name is okay.
     */
    if (pzEnd == NULL)
        return txt + strlen(txt);

    /*
     *  If we are keeping all whitespace, then the  modevalue starts with the
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
    space_break = IS_WHITESPACE_CHAR(*pzEnd);
    *(pzEnd++) = NUL;

    pzEnd = SPN_WHITESPACE_CHARS(pzEnd);
    if (space_break && ((*pzEnd == ':') || (*pzEnd == '=')))
        pzEnd = SPN_WHITESPACE_CHARS(pzEnd+1);

    return pzEnd;
}

/**
 *  Load an option from a block of text.  The text must start with the
 *  configurable/option name and be followed by its associated value.
 *  That value may be processed in any of several ways.  See "tOptionLoadMode"
 *  in autoopts.h.
 *
 * @param[in,out] opts       program options descriptor
 * @param[in,out] opt_state  option processing state
 * @param[in,out] line       source line with long option name in it
 * @param[in]     direction  current processing direction (preset or not)
 * @param[in]     load_mode  option loading mode (OPTION_LOAD_*)
 */
LOCAL void
loadOptionLine(
    tOptions *  opts,
    tOptState * opt_state,
    char *      line,
    tDirection  direction,
    tOptionLoadMode   load_mode )
{
    line = SPN_LOAD_LINE_SKIP_CHARS(line);

    {
        char * arg = assemble_arg_val(line, load_mode);

        if (! SUCCESSFUL(opt_find_long(opts, line, opt_state)))
            return;

        if (opt_state->flags & OPTST_NO_INIT)
            return;

        opt_state->pzOptArg = arg;
    }

    switch (opt_state->flags & (OPTST_IMM|OPTST_DISABLE_IMM)) {
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
            if ((opt_state->flags & OPTST_DISABLED) == 0)
                return;
        } else {
            /*
             *  We are in the processing direction with an option we handle
             *  immediately for enablement, but normally for disablement.
             *  Therefore, skip if NOT disabled.
             */
            if ((opt_state->flags & OPTST_DISABLED) != 0)
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
            if ((opt_state->flags & OPTST_DISABLED) != 0)
                return;
        } else {
            /*
             *  We are in the processing direction with an option we handle
             *  immediately for disablement, but normally for disablement.
             *  Therefore, skip if disabled.
             */
            if ((opt_state->flags & OPTST_DISABLED) == 0)
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
    if (OPTST_GET_ARGTYPE(opt_state->pOD->fOptState) == OPARG_TYPE_NONE) {
        if (*opt_state->pzOptArg != NUL)
            return;
        opt_state->pzOptArg = NULL;

    } else if (opt_state->pOD->fOptState & OPTST_ARG_OPTIONAL) {
        if (*opt_state->pzOptArg == NUL)
             opt_state->pzOptArg = NULL;
        else {
            AGDUPSTR(opt_state->pzOptArg, opt_state->pzOptArg, "opt arg");
            opt_state->flags |= OPTST_ALLOC_ARG;
        }

    } else {
        if (*opt_state->pzOptArg == NUL)
             opt_state->pzOptArg = zNil;
        else {
            AGDUPSTR(opt_state->pzOptArg, opt_state->pzOptArg, "opt arg");
            opt_state->flags |= OPTST_ALLOC_ARG;
        }
    }

    {
        tOptionLoadMode sv = option_load_mode;
        option_load_mode = load_mode;
        handle_opt(opts, opt_state);
        option_load_mode = sv;
    }
}

/*=export_func  optionLoadLine
 *
 * what:  process a string for an option name and value
 *
 * arg:   tOptions*,   opts,  program options descriptor
 * arg:   char const*, line,  NUL-terminated text
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
 *  the string.  The caller need not skip over any introductory hyphens.
 *  Any embedded new lines will be included in the option
 *  argument.  If the input looks like one or more quoted strings, then the
 *  input will be "cooked".  The "cooking" is identical to the string
 *  formation used in AutoGen definition files (@pxref{basic expression}),
 *  except that you may not use backquotes.
 *
 * err:   Invalid options are silently ignored.  Invalid option arguments
 *        will cause a warning to print, but the function should return.
=*/
void
optionLoadLine(tOptions * opts, char const * line)
{
    tOptState st = OPTSTATE_INITIALIZER(SET);
    char* pz;
    AGDUPSTR(pz, line, "user option line");
    loadOptionLine(opts, &st, pz, DIRECTION_PROCESS, OPTION_LOAD_COOKED);
    AGFREE(pz);
}
/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/load.c */
