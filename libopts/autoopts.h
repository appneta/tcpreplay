
/*
 *  Time-stamp:      "2004-02-16 11:22:13 bkorb"
 *
 *  autoopts.h  $Id: autoopts.h,v 2.46 2004/02/16 22:12:50 bkorb Exp $
 *
 *  This file defines all the global structures and special values
 *  used in the automated option processing library.
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

#ifndef AUTOGEN_AUTOOPTS_H
#define AUTOGEN_AUTOOPTS_H

#define __EXTENSIONS__

#include "config.h"
#include "compat/compat.h"
#include <sys/param.h>
#include <sys/wait.h>
#include <time.h>
#include <utime.h>

#define AO_NAME_LIMIT    127
#define AO_NAME_SIZE     (AO_NAME_LIMIT + 1)
#ifndef MAXPATHLEN
#  define MAXPATHLEN     4096
#endif

/*
 *  Convert the number to a list usable in a printf call
 */
#define NUM_TO_VER(n)       ((n) >> 12), ((n) >> 7) & 0x001F, (n) & 0x007F

#define NAMED_OPTS(po) \
        (((po)->fOptSet & (OPTPROC_SHORTOPT | OPTPROC_LONGOPT)) == 0)

#define SKIP_OPT(p)  (((p)->fOptState & (OPTST_DOCUMENT|OPTST_OMITTED)) != 0)

typedef int tDirection;
#define DIRECTION_PRESET  -1
#define DIRECTION_PROCESS  1
#define PROCESSING(d)     ((d)>0)
#define PRESETTING(d)     ((d)<0)

/*
 *  Procedure success codes
 *
 *  USAGE:  define procedures to return "tSuccess".  Test their results
 *          with the SUCCEEDED, FAILED and HADGLITCH macros.
 */
#define SUCCESS  ((tSuccess) 0)
#define FAILURE  ((tSuccess)-1)
#define PROBLEM  ((tSuccess) 1)

typedef int tSuccess;

#define SUCCEEDED( p )     ((p) == SUCCESS)
#define SUCCESSFUL( p )    SUCCEEDED( p )
#define FAILED( p )        ((p) <  SUCCESS)
#define HADGLITCH( p )     ((p) >  SUCCESS)

/*
 *  The pager state is used by doPagedUsage() procedure.
 *  When it runs, it sets itself up to be called again on exit.
 *  If, however, a routine needs a child process to do some work
 *  before it is done, then 'pagerState' must be set to
 *  'PAGER_STATE_CHILD' so that doPagedUsage() will not try
 *  to run the pager program before its time.
 */
typedef enum {
    PAGER_STATE_INITIAL,
    PAGER_STATE_READY,
    PAGER_STATE_CHILD
} tePagerState;

extern tePagerState pagerState;

typedef enum {
    ENV_ALL,
    ENV_IMM,
    ENV_NON_IMM
} teEnvPresetType;

typedef enum {
    TOPT_UNDEFINED = 0,
    TOPT_SHORT,
    TOPT_LONG,
    TOPT_DEFAULT
} teOptType;

typedef struct {
    tOptDesc*  pOD;
    tUL        flags;
    teOptType  optType;
    int        argType;
    tCC*       pzOptArg;
} tOptState;
#define OPTSTATE_INITIALIZER \
    { NULL, OPTST_DEFINED, TOPT_UNDEFINED, 0, NULL }

#define TEXTTO_TABLE \
        _TT_( LONGUSAGE ) \
        _TT_( USAGE ) \
        _TT_( VERSION )
#define _TT_(n) \
        TT_ ## n ,

typedef enum { TEXTTO_TABLE COUNT_TT } teTextTo;

#undef _TT_

typedef struct {
    tCC*    pzStr;
    tCC*    pzReq;
    tCC*    pzNum;
    tCC*    pzKey;
    tCC*    pzKeyL;
    tCC*    pzBool;
    tCC*    pzOpt;
    tCC*    pzNo;
    tCC*    pzBrk;
    tCC*    pzNoF;
    tCC*    pzSpc;
    tCC*    pzOptFmt;
} arg_types_t;

#  define AGALOC( c, w )        malloc( c )
#  define AGREALOC( p, c, w )   realloc( p, c )
#  define AGFREE( p )           free( p )
#  define AGDUPSTR( p, s, w )   p = strdup( s )
#  define TAGMEM( m, t )

#ifdef AUTOGEN_BUILD
#  include <snprintfv/printf.h>
#endif /* AUTOGEN_BUILD */

/*
 *  Define and initialize all the user visible strings.
 *  We do not do translations.  If translations are to be done, then
 *  the client will provide a callback for that purpose.
 */
#undef DO_TRANSLATIONS
#include "usage-txt.h"

/*
 *  File pointer for usage output
 */
extern FILE* option_usage_fp;

extern tOptProc doVersion, doPagedUsage, doLoadOpt;

#define LOCAL static
#ifdef AUTOOPTS_INTERNAL
/* === LOCAL PROCEDURES === */

/* autoopts.c */
static tSuccess
handleOption( tOptions* pOpts, tOptState* pOptState );

static tSuccess
longOptionFind( tOptions* pOpts, char* pzOptName, tOptState* pOptState );

static tSuccess
shortOptionFind( tOptions* pOpts, tUC optValue, tOptState* pOptState );


/* load.c */
static void
filePreset(
    tOptions*     pOpts,
    const char*   pzFileName,
    int           direction );


/* sort.c */
static void
optionSort( tOptions* pOpts );

/* === END LOCALS === */
#endif /* GUILE_OPTIONS */
#endif /* AUTOGEN_AUTOOPTS_H */
/*
 * Local Variables:
 * mode: C
 * c-file-style: "stroustrup"
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 * end of autoopts/autoopts.h */
