
/*
 *  $Id: pgusage.c,v 2.19 2004/02/02 03:31:51 bkorb Exp $
 *
 *   Automated Options Paged Usage module.
 *
 *  This routine will run run-on options through a pager so the
 *  user may examine, print or edit them at their leisure.
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

tePagerState pagerState = PAGER_STATE_INITIAL;

/* === STATIC PROCS === */
/* === END STATIC PROCS === */

/*=export_func  doPagedUsage
 * private:
 *
 * what:  Decipher a boolean value
 * arg:   + tOptions* + pOpts    + program options descriptor +
 * arg:   + tOptDesc* + pOptDesc + the descriptor for this arg +
 *
 * doc:
 *  Run the usage output through a pager.
 *  This is very handy if it is very long.
=*/
void
doPagedUsage( tOptions* pOptions, tOptDesc* pOD )
{
    static pid_t     my_pid;
    char zPageUsage[ 1024 ];

    /*
     *  IF we are being called after the usage proc is done
     *     (and thus has called "exit(2)")
     *  THEN invoke the pager to page through the usage file we created.
     */
    switch (pagerState) {
    case PAGER_STATE_INITIAL:
    {
        my_pid  = getpid();
#ifdef HAVE_SNPRINTF
        snprintf( zPageUsage, sizeof(zPageUsage), "/tmp/use.%lu", (tUL)my_pid );
#else
        sprintf( zPageUsage, "/tmp/use.%lu", (tUL)my_pid );
#endif
        unlink( zPageUsage );

        /*
         *  Set usage output to this temporary file
         */
        option_usage_fp = fopen( zPageUsage, "w" FOPEN_BINARY_FLAG );
        if (option_usage_fp == NULL)
            _exit( EXIT_FAILURE );

        pagerState = PAGER_STATE_READY;

        /*
         *  Set up so this routine gets called during the exit logic
         */
        atexit( (void(*)(void))doPagedUsage );

        /*
         *  The usage procedure will now put the usage information into
         *  the temporary file we created above.
         */
        (*pOptions->pUsageProc)( pOptions, EXIT_SUCCESS );

        /*NOTREACHED*/
        _exit( EXIT_FAILURE );
    }

    case PAGER_STATE_READY:
    {
        tSCC zPage[]  = "%1$s /tmp/use.%2$lu ; rm -f /tmp/use.%2$lu";
        char* pzPager = getenv( "PAGER" );

        /*
         *  Use the "more(1)" program if "PAGER" has not been defined
         */
        if (pzPager == NULL)
            pzPager = "more";

        /*
         *  Page the file and remove it when done.
         */
#ifdef HAVE_SNPRINTF
        snprintf( zPageUsage, sizeof(zPageUsage), zPage, pzPager, (tUL)my_pid );
#else
        sprintf( zPageUsage, zPage, pzPager, (tUL)my_pid );
#endif
        fclose( stderr );
        dup2( STDOUT_FILENO, STDERR_FILENO );

        system( zPageUsage );
    }

    case PAGER_STATE_CHILD:
        /*
         *  This is a child process used in creating shell script usage.
         */
        break;
    }
}

/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/pgusage.c */
