/**
 * @file check.c
 *
 * @brief consistency checks.
 *
 *  Time-stamp:      "2012-03-31 13:46:35 bkorb"
 *
 *  This file contains the routines that deal with processing quoted strings
 *  into an internal format.
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
 *  Check for conflicts based on "must" and "cannot" attributes.
 */
static bool
has_conflict(tOptions * pOpts, tOptDesc * pOD)
{
    if (pOD->pOptMust != NULL) {
        int const * pMust = pOD->pOptMust;

        while (*pMust != NO_EQUIVALENT) {
            tOptDesc * p = pOpts->pOptDesc + *(pMust++);
            if (UNUSED_OPT(p)) {
                const tOptDesc * pN = pOpts->pOptDesc + pMust[-1];
                fprintf(stderr, zReqFmt, pOD->pz_Name, pN->pz_Name);
                return true;
            }
        }
    }

    if (pOD->pOptCant != NULL) {
        int const * pCant = pOD->pOptCant;

        while (*pCant != NO_EQUIVALENT) {
            tOptDesc * p = pOpts->pOptDesc + *(pCant++);
            if (SELECTED_OPT(p)) {
                const tOptDesc* pN = pOpts->pOptDesc + pCant[-1];
                fprintf(stderr, zCantFmt, pOD->pz_Name, pN->pz_Name);
                return true;
            }
        }
    }

    return false;
}

/**
 *  Check that the option occurs often enough.  Too often is already checked.
 */
static bool
occurs_enough(tOptions * pOpts, tOptDesc * pOD)
{
    (void)pOpts;

    /*
     *  IF the occurrence counts have been satisfied,
     *  THEN there is no problem.
     */
    if (pOD->optOccCt >= pOD->optMinCt)
        return true;

    /*
     *  IF MUST_SET means SET and PRESET are okay,
     *  so min occurrence count doesn't count
     */
    if (  (pOD->fOptState & OPTST_MUST_SET)
       && (pOD->fOptState & (OPTST_PRESET | OPTST_SET)) )
        return true;

    if (pOD->optMinCt > 1)
         fprintf(stderr, zNotEnough, pOD->pz_Name, pOD->optMinCt);
    else fprintf(stderr, zNeedOne, pOD->pz_Name);
    return false;
}

/**
 *  Verify option consistency.
 *
 *  Make sure that the argument list passes our consistency tests.
 */
LOCAL bool
is_consistent(tOptions * pOpts)
{
    tOptDesc * pOD   = pOpts->pOptDesc;
    int        oCt   = pOpts->presetOptCt;

    /*
     *  FOR each of "oCt" options, ...
     */
    for (;;) {
        /*
         *  IF the current option was provided on the command line
         *  THEN ensure that any "MUST" requirements are not
         *       "DEFAULT" (unspecified) *AND* ensure that any
         *       "CANT" options have not been SET or DEFINED.
         */
        if (SELECTED_OPT(pOD)) {
            if (has_conflict(pOpts, pOD))
                return false;
        }

        /*
         *  IF       this option is not equivalenced to another,
         *        OR it is equivalenced to itself (is the equiv. root)
         *  THEN we need to make sure it occurs often enough.
         */
        if (  (pOD->optEquivIndex == NO_EQUIVALENT)
           || (pOD->optEquivIndex == pOD->optIndex) )

            if (! occurs_enough(pOpts, pOD))
                return false;

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
                fprintf(stderr, zNoArgs, pOpts->pzProgName);
                return false;
            }
        }

        /*
         *  ELSE not prohibited, check for being required
         */
        else if ((pOpts->fOptSet & OPTPROC_ARGS_REQ) != 0) {
            if (pOpts->origArgCt <= pOpts->curOptIdx) {
                fprintf(stderr, zArgsMust, pOpts->pzProgName);
                return false;
            }
        }
    }

    return true;
}
