
/*
 *  restore.c  $Id: restore.c,v 2.11 2004/02/02 03:31:51 bkorb Exp $
 *
 *  This module's routines will save the current option state to memory
 *  and restore it.  If saved prior to the initial optionProcess call,
 *  then the initial state will be restored.
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

/* === STATIC PROCS === */
/* === END STATIC PROCS === */

/*=export_func optionSaveState
 *
 * what:  saves the option state to memory
 * arg:   tOptions*, pOpts, program options descriptor
 *
 * doc:   This routine will allocate enough memory to save the current
 *        option processing state.  If this routine has been called before,
 *        that memory will be reused.  You may only save one copy of the
 *        option state.  This routine may be called before optionProcess(3AO).
 *        If you do call it before the first call to optionProcess, then
 *        you may also change the contents of argc/argv after you call
 *        optionRestore(3AO)
 *
 * err:   If it fails to allocate the memory,
 *        it will print a message to stderr and exit.
 *        Otherwise, it will always succeed.
=*/
void
optionSaveState( tOptions* pOpts )
{
    if (pOpts->pSavedState == NULL) {
        size_t sz = sizeof( *pOpts ) + (pOpts->optCt * sizeof( tOptDesc ));
        pOpts->pSavedState = AGALOC( sz, "saved option state" );
        if (pOpts->pSavedState == NULL) {
            tCC* pzName = pOpts->pzProgName;
            if (pzName == NULL) {
                pzName = pOpts->pzPROGNAME;
                if (pzName == NULL)
                    pzName = zNil;
            }
            fprintf( stderr, zCantSave, pzName, sz );
            exit( EXIT_FAILURE );
        }
    }

    {
        tOptions* p = pOpts->pSavedState;
        memcpy( p, pOpts, sizeof( *p ));
        memcpy( p + 1, pOpts->pOptDesc, p->optCt * sizeof( tOptDesc ));
    }
}


/*=export_func optionRestore
 *
 * what:  restore option state from memory copy
 * arg:   tOptions*, pOpts, program options descriptor
 *
 * doc:  Copy back the option state from saved memory.
 *       The allocated memory is left intact, so this routine can be
 *       called repeatedly without having to call optionSaveState again.
 *       If you are restoring a state that was saved before the first call
 *       to optionProcess(3AO), then you may change the contents of the
 *       argc/argv parameters to optionProcess.
 *
 * err:  If you have not called @code{optionSaveState} before, a diagnostic is
 *       printed to @code{stderr} and exit is called.
=*/
void
optionRestore( tOptions* pOpts )
{
    tOptions* p = (tOptions*)pOpts->pSavedState;

    if (p == NULL) {
        tCC* pzName = pOpts->pzProgName;
        if (pzName == NULL) {
            pzName = pOpts->pzPROGNAME;
            if (pzName == NULL)
                pzName = zNil;
        }
        fprintf( stderr, zNoState, pzName );
        exit( EXIT_FAILURE );
    }
    memcpy( pOpts, p, sizeof( *p ));
    memcpy( pOpts->pOptDesc, p+1, p->optCt * sizeof( tOptDesc ));
}

/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = */

/*=export_func optionFree
 *
 * what:  free allocated option processing memory
 * arg:   tOptions*, pOpts, program options descriptor
 *
 * doc:   AutoOpts sometimes allocates memory and puts pointers to it in the
 *        option state structures.  This routine deallocates all such memory.
 *
 * err:   As long as memory has not been corrupted,
 *        this routine is always successful.      
=*/
void
optionFree( tOptions* pOpts )
{
    if (pOpts->pSavedState != NULL) {
        AGFREE( pOpts->pSavedState );
        pOpts->pSavedState = NULL;
    }
    {
        tOptDesc* p = pOpts->pOptDesc;
        int ct = pOpts->optCt;
        do  {
            if ((p->fOptState & OPTST_STACKED) && (p->optCookie != NULL)) {
                AGFREE( p->optCookie );
                p->fOptState &= OPTST_PERSISTENT;
                if ((p->fOptState & OPTST_INITENABLED) == 0)
                    p->fOptState |= OPTST_DISABLED;
            }
        } while (p++, --ct > 0);
    }
}
/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/restore.c */
