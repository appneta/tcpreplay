
/*
 *  stack.c
 *  $Id: stack.c,v 2.22 2004/02/02 03:31:51 bkorb Exp $
 *  This is a special option processing routine that will save the
 *  argument to an option in a FIFO queue.
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

#include REGEX_HEADER

/*=export_func  unstackOptArg
 * private:
 *
 * what:  Remove option args from a stack
 * arg:   + tOptions* + pOpts    + program options descriptor +
 * arg:   + tOptDesc* + pOptDesc + the descriptor for this arg +
 *
 * doc:
 *  Invoked for options that are equivalenced to stacked options.
=*/
void
unstackOptArg( pOpts, pOptDesc )
    tOptions*  pOpts;
    tOptDesc*  pOptDesc;
{
    int       res;

    tArgList* pAL = (tArgList*)pOptDesc->optCookie;
    /*
     *  IF we don't have any stacked options,
     *  THEN indicate that we don't have any of these options
     */
    if (pAL == NULL) {
        pOptDesc->fOptState &= OPTST_PERSISTENT;
        if ( (pOptDesc->fOptState & OPTST_INITENABLED) == 0)
            pOptDesc->fOptState |= OPTST_DISABLED;
        return;
    }

    {
        regex_t   re;
        int       i, ct, dIdx;

        if (regcomp( &re, pOptDesc->pzLastArg, REG_NOSUB ) != 0)
            return;

        /*
         *  search the list for the entry(s) to remove.  Entries that
         *  are removed are *not* copied into the result.  The source
         *  index is incremented every time.  The destination only when
         *  we are keeping a define.
         */
        for (i = 0, dIdx = 0, ct = pAL->useCt; --ct >= 0; i++) {
            tCC*      pzSrc = pAL->apzArgs[ i ];
            char*     pzEq  = strchr( pzSrc, '=' );

            if (pzEq != NULL)
                *pzEq = NUL;

            res = regexec( &re, pzSrc, (size_t)0, NULL, 0 );
            switch (res) {
            case 0:
                /*
                 *  Remove this entry by reducing the in-use count
                 *  and *not* putting the string pointer back into
                 *  the list.
                 */
                pAL->useCt--;
                break;

            default:
            case REG_NOMATCH:
                if (pzEq != NULL)
                    *pzEq = '=';

                /*
                 *  IF we have dropped an entry
                 *  THEN we have to move the current one.
                 */
                if (dIdx != i)
                    pAL->apzArgs[ dIdx ] = pzSrc;
                dIdx++;
            }
        }

        regfree( &re );
    }

    /*
     *  IF we have unstacked everything,
     *  THEN indicate that we don't have any of these options
     */
    if (pAL->useCt == 0) {
        pOptDesc->fOptState &= OPTST_PERSISTENT;
        if ( (pOptDesc->fOptState & OPTST_INITENABLED) == 0)
            pOptDesc->fOptState |= OPTST_DISABLED;
        free( (void*)pAL );
        pOptDesc->optCookie = NULL;
    }
}


/*=export_func  stackOptArg
 * private:
 *
 * what:  put option args on a stack
 * arg:   + tOptions* + pOpts    + program options descriptor +
 * arg:   + tOptDesc* + pOptDesc + the descriptor for this arg +
 *
 * doc:
 *  Keep an entry-ordered list of option arguments.
=*/
void
stackOptArg( pOpts, pOptDesc )
    tOptions*  pOpts;
    tOptDesc*  pOptDesc;
{
    tArgList* pAL;
    tCC* pzLast = pOptDesc->pzLastArg;

    if (pOptDesc->optArgType == ARG_NONE)
        return;

    if (pOptDesc->optActualIndex != pOptDesc->optIndex)
        pOptDesc = pOpts->pOptDesc + pOptDesc->optActualIndex;

    /*
     *  Being called is the most authoritative way to be sure an
     *  option wants to have its argument values stacked...
     */
    pOptDesc->fOptState |= OPTST_STACKED;

    /*
     *  IF this is a negated ('+'-marked) option
     *  THEN we unstack the argument
     */
    if (DISABLED_OPT( pOptDesc )) {
        if (pOptDesc->optCookie != NULL) {
            AGFREE( pOptDesc->optCookie );
            pOptDesc->optCookie = NULL;
        }
        pOptDesc->fOptState &= OPTST_PERSISTENT;
        pOptDesc->fOptState |= OPTST_DISABLED;
        return;
    }

    pAL = (tArgList*)pOptDesc->optCookie;

    if (pzLast == NULL)
        return;

    /*
     *  IF we have never allocated one of these,
     *  THEN allocate one now
     */
    if (pAL == NULL) {
        pAL = (tArgList*)AGALOC( sizeof( *pAL ), "new option arg stack" );
        if (pAL == NULL)
            return;
        pAL->useCt   = 0;
        pAL->allocCt = MIN_ARG_ALLOC_CT;
    }

    /*
     *  ELSE if we are out of room
     *  THEN make it bigger
     */
    else if (pAL->useCt >= pAL->allocCt) {
        size_t sz = sizeof( *pAL );
        pAL->allocCt += INCR_ARG_ALLOC_CT;

        /*
         *  The base structure contains space for MIN_ARG_ALLOC_CT
         *  pointers.  We subtract it off to find our augment size.
         */
        sz += sizeof(char*) * (pAL->allocCt - MIN_ARG_ALLOC_CT);
        pAL = (tArgList*)AGREALOC( (void*)pAL, sz, "expanded opt arg stack" );
        if (pAL == NULL)
            return;
    }

    /*
     *  Insert the new argument into the list
     */
    pAL->apzArgs[ (pAL->useCt)++ ] = pzLast;
    pOptDesc->optCookie = (void*)pAL;
}
/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/stack.c */
