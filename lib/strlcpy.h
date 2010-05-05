#ifndef _STRLCPY_H_
#define _STRLCPY_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif


size_t
strlcpy(char *dst, const char *src, size_t size);

size_t
strlcat(char *dst, const char *src, size_t size);

#endif
#ifdef __cplusplus
}
#endif

