#ifndef _STRLCPY_H_
#define _STRLCPY_H_

#include <sys/types.h>

size_t
strlcpy(char *dst, const char *src, size_t size);

size_t
strlcat(char *dst, const char *src, size_t size);

#endif
