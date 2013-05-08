/* -*- buffer-read-only: t -*- vi: set ro:
 *
 * Prototypes for autoopts
 * Generated Sat Aug 11 09:41:23 PDT 2012
 */
#ifndef AUTOOPTS_PROTO_H_GUARD
#define AUTOOPTS_PROTO_H_GUARD 1

#ifndef LOCAL
#  define LOCAL extern
#  define REDEF_LOCAL 1
#else
#  undef  REDEF_LOCAL
#endif
/*
 *  Extracted from autoopts.c
 */
LOCAL void *
ao_malloc(size_t sz);

LOCAL void *
ao_realloc(void *p, size_t sz);

LOCAL char *
ao_strdup(char const *str);

LOCAL tSuccess
handle_opt(tOptions * pOpts, tOptState* pOptState);

LOCAL tSuccess
immediate_opts(tOptions * pOpts);

LOCAL tSuccess
regular_opts(tOptions * pOpts);

/*
 *  Extracted from check.c
 */
LOCAL bool
is_consistent(tOptions * pOpts);

/*
 *  Extracted from configfile.c
 */
LOCAL void
intern_file_load(tOptions* pOpts);

LOCAL char*
parse_attrs(tOptions * pOpts, char * pzText, tOptionLoadMode * pMode,
            tOptionValue * pType);

LOCAL tSuccess
validate_struct(tOptions * pOpts, char const * pzProgram);

/*
 *  Extracted from env.c
 */
LOCAL void
doPrognameEnv(tOptions * pOpts, teEnvPresetType type);

LOCAL void
env_presets(tOptions * pOpts, teEnvPresetType type);

/*
 *  Extracted from find.c
 */
LOCAL tSuccess
opt_find_long(tOptions * opts, char const * opt_name, tOptState * state);

LOCAL tSuccess
opt_find_short(tOptions* pOpts, uint_t optValue, tOptState* pOptState);

LOCAL tSuccess
get_opt_arg(tOptions * pOpts, tOptState * pOptState);

LOCAL tSuccess
find_opt(tOptions * pOpts, tOptState * pOptState);

/*
 *  Extracted from load.c
 */
LOCAL void
mungeString(char * txt, tOptionLoadMode mode);

LOCAL void
loadOptionLine(
    tOptions *  opts,
    tOptState * opt_state,
    char *      line,
    tDirection  direction,
    tOptionLoadMode   load_mode );

/*
 *  Extracted from nested.c
 */
LOCAL void
unload_arg_list(tArgList* pAL);

LOCAL tOptionValue*
optionLoadNested(char const* pzTxt, char const* pzName, size_t nameLen);

LOCAL int
get_special_char(char const ** ppz, int * ct);

LOCAL void
emit_special_char(FILE * fp, int ch);

/*
 *  Extracted from sort.c
 */
LOCAL void
optionSort(tOptions* pOpts);

/*
 *  Extracted from stack.c
 */
LOCAL void
addArgListEntry(void** ppAL, void* entry);

/*
 *  Extracted from usage.c
 */
LOCAL void
set_usage_flags(tOptions * opts, char const * flg_txt);

#ifdef REDEF_LOCAL
#  undef LOCAL
#  define LOCAL
#endif
#endif /* AUTOOPTS_PROTO_H_GUARD */
