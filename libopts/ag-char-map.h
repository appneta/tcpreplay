/*
 *   Character mapping generated 08/08/09 10:14:55
 *
 *  This file contains the character classifications
 *  used by AutoGen and AutoOpts for identifying tokens.
 */
#ifndef AG_CHAR_MAP_H_GUARD
#define AG_CHAR_MAP_H_GUARD 1

#ifdef HAVE_CONFIG_H
# if defined(HAVE_INTTYPES_H)
#  include <inttypes.h>
# elif defined(HAVE_STDINT_H)
#  include <stdint.h>

# else
#   ifndef HAVE_INT8_T
        typedef signed char     int8_t;
#   endif
#   ifndef HAVE_UINT8_T
        typedef unsigned char   uint8_t;
#   endif
#   ifndef HAVE_INT16_T
        typedef signed short    int16_t;
#   endif
#   ifndef HAVE_UINT16_T
        typedef unsigned short  uint16_t;
#   endif
#   ifndef HAVE_UINT_T
        typedef unsigned int    uint_t;
#   endif

#   ifndef HAVE_INT32_T
#    if SIZEOF_INT == 4
        typedef signed int      int32_t;
#    elif SIZEOF_LONG == 4
        typedef signed long     int32_t;
#    endif
#   endif

#   ifndef HAVE_UINT32_T
#    if SIZEOF_INT == 4
        typedef unsigned int    uint32_t;
#    elif SIZEOF_LONG == 4
        typedef unsigned long   uint32_t;
#    endif
#   endif
# endif /* HAVE_*INT*_H header */

#else /* not HAVE_CONFIG_H -- */
# ifdef __sun
#  include <inttypes.h>
# else
#  include <stdint.h>
# endif
#endif /* HAVE_CONFIG_H */

#if 0 /* mapping specification source (from autogen.map) */
// 
// %guard          autoopts_internal
// %file           ag-char-map.h
// %table          opt-char-cat
// 
// %comment
//         This file contains the character classifications
//         used by AutoGen and AutoOpts for identifying tokens.
// %
// 
// lower-case      "a-z"
// upper-case      "A-Z"
// alphabetic      +lower-case   +upper-case
// oct-digit       "0-7"
// dec-digit       "89"          +oct-digit
// hex-digit       "a-fA-F"      +dec-digit
// alphanumeric    +alphabetic   +dec-digit
// var-first       "_"           +alphabetic
// variable-name   +var-first    +dec-digit
// option-name     "^-"          +variable-name
// value-name      ":"           +option-name
// horiz-white     "\t "
// compound-name   "[.]"         +value-name   +horiz-white
// whitespace      "\v\f\r\n\b"  +horiz-white
// unquotable      "!-~"         -"\"#(),;<=>[\\]`{}?*'"
// end-xml-token   "/>"          +whitespace
// graphic         "!-~"
// plus-n-space    "+"           +whitespace
// punctuation     "!-~"         -alphanumeric -"_"
// suffix          "-._"         +alphanumeric
// suffix-fmt      "%/"          +suffix     
// false-type      "nNfF0\x00"
//
#endif /* 0 -- mapping spec. source */

typedef uint32_t opt_char_cat_mask_t;
extern opt_char_cat_mask_t const opt_char_cat[128];

static inline int is_opt_char_cat_char(char ch, opt_char_cat_mask_t mask) {
    unsigned int ix = (unsigned char)ch;
    return ((ix < 0x7F) && ((opt_char_cat[ix] & mask) != 0)); }

#define IS_LOWER_CASE_CHAR(_c)     is_opt_char_cat_char((_c), 0x00001)
#define IS_UPPER_CASE_CHAR(_c)     is_opt_char_cat_char((_c), 0x00002)
#define IS_ALPHABETIC_CHAR(_c)     is_opt_char_cat_char((_c), 0x00003)
#define IS_OCT_DIGIT_CHAR(_c)      is_opt_char_cat_char((_c), 0x00004)
#define IS_DEC_DIGIT_CHAR(_c)      is_opt_char_cat_char((_c), 0x0000C)
#define IS_HEX_DIGIT_CHAR(_c)      is_opt_char_cat_char((_c), 0x0001C)
#define IS_ALPHANUMERIC_CHAR(_c)   is_opt_char_cat_char((_c), 0x0000F)
#define IS_VAR_FIRST_CHAR(_c)      is_opt_char_cat_char((_c), 0x00023)
#define IS_VARIABLE_NAME_CHAR(_c)  is_opt_char_cat_char((_c), 0x0002F)
#define IS_OPTION_NAME_CHAR(_c)    is_opt_char_cat_char((_c), 0x0006F)
#define IS_VALUE_NAME_CHAR(_c)     is_opt_char_cat_char((_c), 0x000EF)
#define IS_HORIZ_WHITE_CHAR(_c)    is_opt_char_cat_char((_c), 0x00100)
#define IS_COMPOUND_NAME_CHAR(_c)  is_opt_char_cat_char((_c), 0x003EF)
#define IS_WHITESPACE_CHAR(_c)     is_opt_char_cat_char((_c), 0x00500)
#define IS_UNQUOTABLE_CHAR(_c)     is_opt_char_cat_char((_c), 0x00800)
#define IS_END_XML_TOKEN_CHAR(_c)  is_opt_char_cat_char((_c), 0x01500)
#define IS_GRAPHIC_CHAR(_c)        is_opt_char_cat_char((_c), 0x02000)
#define IS_PLUS_N_SPACE_CHAR(_c)   is_opt_char_cat_char((_c), 0x04500)
#define IS_PUNCTUATION_CHAR(_c)    is_opt_char_cat_char((_c), 0x08000)
#define IS_SUFFIX_CHAR(_c)         is_opt_char_cat_char((_c), 0x1000F)
#define IS_SUFFIX_FMT_CHAR(_c)     is_opt_char_cat_char((_c), 0x3000F)
#define IS_FALSE_TYPE_CHAR(_c)     is_opt_char_cat_char((_c), 0x40000)

#ifdef AUTOOPTS_INTERNAL
opt_char_cat_mask_t const opt_char_cat[128] = {
  /*x00*/ 0x40000, /*x01*/ 0x00000, /*x02*/ 0x00000, /*x03*/ 0x00000,
  /*x04*/ 0x00000, /*x05*/ 0x00000, /*x06*/ 0x00000, /*\a */ 0x00000,
  /*\b */ 0x00400, /*\t */ 0x00100, /*\n */ 0x00400, /*\v */ 0x00400,
  /*\f */ 0x00400, /*\r */ 0x00400, /*x0E*/ 0x00000, /*x0F*/ 0x00000,
  /*x10*/ 0x00000, /*x11*/ 0x00000, /*x12*/ 0x00000, /*x13*/ 0x00000,
  /*x14*/ 0x00000, /*x15*/ 0x00000, /*x16*/ 0x00000, /*x17*/ 0x00000,
  /*x18*/ 0x00000, /*x19*/ 0x00000, /*x1A*/ 0x00000, /*x1B*/ 0x00000,
  /*x1C*/ 0x00000, /*x1D*/ 0x00000, /*x1E*/ 0x00000, /*x1F*/ 0x00000,
  /*   */ 0x00100, /* ! */ 0x0A800, /* " */ 0x0A000, /* # */ 0x0A000,
  /* $ */ 0x0A800, /* % */ 0x2A800, /* & */ 0x0A800, /* ' */ 0x0A000,
  /* ( */ 0x0A000, /* ) */ 0x0A000, /* * */ 0x0A000, /* + */ 0x0E800,
  /* , */ 0x0A000, /* - */ 0x1A840, /* . */ 0x1AA00, /* / */ 0x2B800,
  /* 0 */ 0x42804, /* 1 */ 0x02804, /* 2 */ 0x02804, /* 3 */ 0x02804,
  /* 4 */ 0x02804, /* 5 */ 0x02804, /* 6 */ 0x02804, /* 7 */ 0x02804,
  /* 8 */ 0x02808, /* 9 */ 0x02808, /* : */ 0x0A880, /* ; */ 0x0A000,
  /* < */ 0x0A000, /* = */ 0x0A000, /* > */ 0x0B000, /* ? */ 0x0A000,
  /* @ */ 0x0A800, /* A */ 0x02812, /* B */ 0x02812, /* C */ 0x02812,
  /* D */ 0x02812, /* E */ 0x02812, /* F */ 0x42812, /* G */ 0x02802,
  /* H */ 0x02802, /* I */ 0x02802, /* J */ 0x02802, /* K */ 0x02802,
  /* L */ 0x02802, /* M */ 0x02802, /* N */ 0x42802, /* O */ 0x02802,
  /* P */ 0x02802, /* Q */ 0x02802, /* R */ 0x02802, /* S */ 0x02802,
  /* T */ 0x02802, /* U */ 0x02802, /* V */ 0x02802, /* W */ 0x02802,
  /* X */ 0x02802, /* Y */ 0x02802, /* Z */ 0x02802, /* [ */ 0x0A200,
  /* \ */ 0x0A000, /* ] */ 0x0A200, /* ^ */ 0x0A840, /* _ */ 0x12820,
  /* ` */ 0x0A000, /* a */ 0x02811, /* b */ 0x02811, /* c */ 0x02811,
  /* d */ 0x02811, /* e */ 0x02811, /* f */ 0x42811, /* g */ 0x02801,
  /* h */ 0x02801, /* i */ 0x02801, /* j */ 0x02801, /* k */ 0x02801,
  /* l */ 0x02801, /* m */ 0x02801, /* n */ 0x42801, /* o */ 0x02801,
  /* p */ 0x02801, /* q */ 0x02801, /* r */ 0x02801, /* s */ 0x02801,
  /* t */ 0x02801, /* u */ 0x02801, /* v */ 0x02801, /* w */ 0x02801,
  /* x */ 0x02801, /* y */ 0x02801, /* z */ 0x02801, /* { */ 0x0A000,
  /* | */ 0x0A800, /* } */ 0x0A000, /* ~ */ 0x0A800, /*x7F*/ 0x00000
};
#endif /* AUTOOPTS_INTERNAL */
#endif /* AG_CHAR_MAP_H_GUARD */
