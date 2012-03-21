
/**
 * \file time.c
 *
 *  Time-stamp:      "2010-07-17 10:36:19 bkorb"
 *
 *  This file is part of AutoOpts, a companion to AutoGen.
 *  AutoOpts is free software.
 *  AutoOpts is Copyright (c) 1992-2010 by Bruce Korb - all rights reserved
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

#ifndef HAVE_PARSE_DURATION
#include <time.h>

static inline char *
ao_xstrdup(char const * pz)
{
    char * str;
    AGDUPSTR(str, pz, "time val str");
    return str;
}

#define xstrdup(_s) ao_xstrdup(_s)

#include "parse-duration.c"

#undef xstrdup
#endif

/*=export_func  optionTimeVal
 * private:
 *
 * what:  process an option with a time value.
 * arg:   + tOptions* + pOpts    + program options descriptor +
 * arg:   + tOptDesc* + pOptDesc + the descriptor for this arg +
 *
 * doc:
 *  Decipher a time duration value.
=*/
void
optionTimeVal(tOptions* pOpts, tOptDesc* pOD )
{
    long  val;

    if ((pOD->fOptState & OPTST_RESET) != 0)
        return;

    val = parse_duration(pOD->optArg.argString);
    if (errno != 0)
        goto bad_time;

    if (pOD->fOptState & OPTST_ALLOC_ARG) {
        AGFREE(pOD->optArg.argString);
        pOD->fOptState &= ~OPTST_ALLOC_ARG;
    }

    pOD->optArg.argInt = val;
    return;

bad_time:
    fprintf(stderr, zNotNumber, pOpts->pzProgName, pOD->optArg.argString);
    if ((pOpts->fOptSet & OPTPROC_ERRSTOP) != 0)
        (*(pOpts->pUsageProc))(pOpts, EXIT_FAILURE);

    pOD->optArg.argInt = ~0;
}
/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/time.c */
