/* -*- buffer-read-only: t -*- vi: set ro:
 *
 * Prototypes for autoopts
 * Generated Mon Feb 14 08:43:14 PST 2005
 */
#ifndef AUTOOPTS_PROTO_H_GUARD
#define AUTOOPTS_PROTO_H_GUARD
#ifndef LOCAL
#  define LOCAL extern
#  define REDEF_LOCAL 1
#else
#  undef  REDEF_LOCAL
#endif
/*
 *  Extracted from autoopts.c
 */
LOCAL tSuccess
handleOption( tOptions* pOpts, tOptState* pOptState );

LOCAL tSuccess
longOptionFind( tOptions* pOpts, char* pzOptName, tOptState* pOptState );

LOCAL tSuccess
shortOptionFind( tOptions* pOpts, tUC optValue, tOptState* pOptState );

LOCAL tSuccess
doImmediateOpts( tOptions* pOpts );

LOCAL tSuccess
doRegularOpts( tOptions* pOpts );

/*
 *  Extracted from configfile.c
 */
LOCAL tSuccess
validateOptionsStruct( tOptions* pOpts, const char* pzProgram );

LOCAL void
internalFileLoad( tOptions* pOpts );

/*
 *  Extracted from environment.c
 */
LOCAL void
doPrognameEnv( tOptions* pOpts, teEnvPresetType type );

LOCAL void
doEnvPresets( tOptions* pOpts, teEnvPresetType type );

/*
 *  Extracted from load.c
 */
LOCAL void
loadOptionLine(
    tOptions*   pOpts,
    tOptState*  pOS,
    char*       pzLine,
    tDirection  direction,
    load_mode_t load_mode );

/*
 *  Extracted from sort.c
 */
LOCAL void
optionSort( tOptions* pOpts );

/*
 *  Extracted from text_mmap.c
 */
LOCAL void*
text_mmap( const char* pzFile, int prot, int flags, tmap_info_t* pMI );

LOCAL int
text_munmap( tmap_info_t* pMI );

#ifdef REDEF_LOCAL
#  undef LOCAL
#  define LOCAL
#endif

#endif /* AUTOOPTS_PROTO_H_GUARD */
