
/**
 * \file alias.c
 *
 * Time-stamp:      "2012-08-11 08:15:43 bkorb"
 *
 *   Automated Options Paged Usage module.
 *
 *  This routine will forward an option alias to the correct option code.
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

/*=export_func  optionAlias
 * private:
 *
 * what:  relay an option to its alias
 * arg:   + tOptions*    + pOpts    + program options descriptor  +
 * arg:   + tOptDesc*    + pOptDesc + the descriptor for this arg +
 * arg:   + unsigned int + alias    + the aliased-to option index +
 * ret-type: int
 *
 * doc:
 *  Handle one option as if it had been specified as another.  Exactly.
 *  Returns "-1" if the aliased-to option has appeared too many times.
=*/
int
optionAlias(tOptions * pOpts, tOptDesc * pOldOD, unsigned int alias)
{
    tOptDesc * pOD;

    if (pOpts <= OPTPROC_EMIT_LIMIT)
        return 0;

    pOD = pOpts->pOptDesc + alias;
    if ((unsigned)pOpts->optCt <= alias) {
        fwrite(zAliasRange, strlen (zAliasRange), 1, stderr);
        exit(EXIT_FAILURE);
    }

    /*
     *  Copy over the option instance flags
     */
    pOD->fOptState &= OPTST_PERSISTENT_MASK;
    pOD->fOptState |= (pOldOD->fOptState & ~OPTST_PERSISTENT_MASK);
    pOD->optArg.argString = pOldOD->optArg.argString;

    /*
     *  Keep track of count only for DEFINED (command line) options.
     *  IF we have too many, build up an error message and bail.
     */
    if (  (pOD->fOptState & OPTST_DEFINED)
       && (++pOD->optOccCt > pOD->optMaxCt)  )  {

        if ((pOpts->fOptSet & OPTPROC_ERRSTOP) != 0) {
            char const * pzEqv =
                (pOD->optEquivIndex != NO_EQUIVALENT) ? zEquiv : zNil;

            fputs(zErrOnly, stderr);

            if (pOD->optMaxCt > 1)
                fprintf(stderr, zAtMost, pOD->optMaxCt, pOD->pz_Name, pzEqv);
            else
                fprintf(stderr, zOnlyOne, pOD->pz_Name, pzEqv);
        }

        return -1;
    }

    /*
     *  Clear the state bits and counters
     */
    pOldOD->fOptState &= OPTST_PERSISTENT_MASK;
    pOldOD->optOccCt   = 0;

    /*
     *  If there is a procedure to call, call it
     */
    if (pOD->pOptProc != NULL)
        (*pOD->pOptProc)(pOpts, pOD);
    return 0;
}

/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/alias.c */
