/*
 *  Generated header for gperf generated source Wed Dec 31 19:07:31 PST 2008
 *  This file enumerates the list of names and declares the
 *  procedure for mapping string names to the enum value.
 */
#ifndef AUTOOPTS_XAT_ATTRIBUTE_H_GUARD
#define AUTOOPTS_XAT_ATTRIBUTE_H_GUARD 1

typedef enum {
    XAT_KWD_INVALID,
    XAT_KWD_TYPE,
    XAT_KWD_WORDS,
    XAT_KWD_MEMBERS,
    XAT_KWD_COOKED,
    XAT_KWD_UNCOOKED,
    XAT_KWD_KEEP,
    XAT_COUNT_KWD
} xat_attribute_enum_t;

extern xat_attribute_enum_t
find_xat_attribute_id(char const * str, unsigned int len);
#endif /* AUTOOPTS_XAT_ATTRIBUTE_H_GUARD */
