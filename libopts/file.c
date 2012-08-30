
/**
 * \file file.c
 *
 *  Time-stamp:      "2011-08-06 08:49:35 bkorb"
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

/**
 *  Make sure the directory containing the subject file exists and that
 *  the file exists or does not exist, per the option requirements.
 *
 * @param ftype file existence type flags
 * @param pOpts program option descriptor
 * @param pOD   the option descriptor
 */
static void
check_existence(teOptFileType ftype, tOptions * pOpts, tOptDesc * pOD)
{
    char const * fname = pOD->optArg.argString;
    struct stat sb;

    errno = 0;

    switch (ftype & FTYPE_MODE_EXIST_MASK) {
    case FTYPE_MODE_MUST_NOT_EXIST:
        if ((stat(fname, &sb) == 0) || (errno != ENOENT)) {
            if (errno == 0)
                errno = EINVAL;
            fprintf(stderr, zFSOptError, errno, strerror(errno),
                    zFSOptErrNoExist, fname, pOD->pz_Name);
            pOpts->pUsageProc(pOpts, EXIT_FAILURE);
            /* NOTREACHED */
        }
        /* FALLTHROUGH */

    default:
    case FTYPE_MODE_MAY_EXIST:
    {
        char * p = strrchr(fname, DIRCH);
        size_t l;

        if (p == NULL)
            /*
             *  The file may or may not exist and its directory is ".".
             *  Assume that "." exists.
             */
            break;

        l = p - fname;
        p = AGALOC(l + 1, "fname");
        memcpy(p, fname, l);
        p[l] = NUL;

        if ((stat(p, &sb) != 0) || (errno = EINVAL, ! S_ISDIR(sb.st_mode))) {
            fprintf(stderr, zFSOptError, errno, strerror(errno),
                    zFSOptErrMayExist, fname, pOD->pz_Name);
            pOpts->pUsageProc(pOpts, EXIT_FAILURE);
            /* NOTREACHED */
        }
        AGFREE(p);
        break;
    }

    case FTYPE_MODE_MUST_EXIST:
        if (  (stat(fname, &sb) != 0)
           || (errno = EINVAL, ! S_ISREG(sb.st_mode)) ) {
            fprintf(stderr, zFSOptError, errno, strerror(errno),
                    zFSOptErrMustExist, fname,
                    pOD->pz_Name);
            pOpts->pUsageProc(pOpts, EXIT_FAILURE);
            /* NOTREACHED */
        }
        break;
    }
}

/**
 *  Open the specified file with open(2) and save the FD.
 *
 * @param pOpts program option descriptor
 * @param pOD   the option descriptor
 * @param mode  the open mode (uses int flags value)
 */
static void
open_file_fd(tOptions * pOpts, tOptDesc * pOD, tuFileMode mode)
{
    int fd = open(pOD->optArg.argString, mode.file_flags);
    if (fd < 0) {
        fprintf(stderr, zFSOptError, errno, strerror(errno),
                zFSOptErrOpen, pOD->optArg.argString, pOD->pz_Name);
        pOpts->pUsageProc(pOpts, EXIT_FAILURE);
        /* NOTREACHED */
    }

    if ((pOD->fOptState & OPTST_ALLOC_ARG) != 0)
        pOD->optCookie = (void *)pOD->optArg.argString;
    else
        AGDUPSTR(pOD->optCookie, pOD->optArg.argString, "file name");

    pOD->optArg.argFd = fd;
    pOD->fOptState &= ~OPTST_ALLOC_ARG;
}

/**
 *  Open the specified file with open(2) and save the FD.
 *
 * @param pOpts program option descriptor
 * @param pOD   the option descriptor
 * @param mode  the open mode (uses "char *" mode value)
 */
static void
fopen_file_fp(tOptions * pOpts, tOptDesc * pOD, tuFileMode mode)
{
    FILE* fp = fopen(pOD->optArg.argString, mode.file_mode);
    if (fp == NULL) {
        fprintf(stderr, zFSOptError, errno, strerror(errno),
                zFSOptErrFopen, pOD->optArg.argString, pOD->pz_Name);
        pOpts->pUsageProc(pOpts, EXIT_FAILURE);
        /* NOTREACHED */
    }

    if ((pOD->fOptState & OPTST_ALLOC_ARG) != 0)
        pOD->optCookie = (void *)pOD->optArg.argString;
    else
        AGDUPSTR(pOD->optCookie, pOD->optArg.argString, "file name");

    pOD->optArg.argFp = fp;
    pOD->fOptState &= ~OPTST_ALLOC_ARG;
}

/*=export_func  optionFileCheck
 * private:
 *
 * what:  Decipher a boolean value
 * arg:   + tOptions*     + pOpts    + program options descriptor  +
 * arg:   + tOptDesc*     + pOptDesc + the descriptor for this arg +
 * arg:   + teOptFileType + ftype    + File handling type          +
 * arg:   + tuFileMode    + mode     + file open mode (if needed)  +
 *
 * doc:
 *   Make sure the named file conforms with the file type mode.
 *   The mode specifies if the file must exist, must not exist or may
 *   (or may not) exist.  The mode may also specify opening the
 *   file: don't, open just the descriptor (fd), or open as a stream
 *   (FILE* pointer).
=*/
void
optionFileCheck(tOptions * pOpts, tOptDesc * pOD,
                teOptFileType ftype, tuFileMode mode)
{
    if (pOpts <= OPTPROC_EMIT_LIMIT) {
        if (pOpts != OPTPROC_EMIT_USAGE)
            return;

        switch (ftype & FTYPE_MODE_EXIST_MASK) {
        case FTYPE_MODE_MUST_NOT_EXIST:
            fputs(zFileCannotExist, option_usage_fp);
            break;

        case FTYPE_MODE_MUST_EXIST:
            fputs(zFileMustExist, option_usage_fp);
            break;
        }
        return;
    }

    if ((pOD->fOptState & OPTST_RESET) != 0) {
        if (pOD->optCookie != NULL)
            AGFREE(pOD->optCookie);
        return;
    }

    check_existence(ftype, pOpts, pOD);

    switch (ftype & FTYPE_MODE_OPEN_MASK) {
    default:
    case FTYPE_MODE_NO_OPEN:  break;
    case FTYPE_MODE_OPEN_FD:  open_file_fd( pOpts, pOD, mode); break;
    case FTYPE_MODE_FOPEN_FP: fopen_file_fp(pOpts, pOD, mode); break;
    }
}
/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/file.c */
