
#ifndef HAVE_VPRINTF
#include "choke-me: no vprintf and no snprintf"
#endif

static int
snprintf(char *str, size_t n, const char *fmt, ...)
{
    va_list ap;
    int rval;

#ifdef VSPRINTF_CHARSTAR
    char *rp;
    va_start(ap, fmt);
    rp = vsprintf(str, fmt, ap);
    va_end(ap);
    rval = strlen(rp);

#else
    va_start(ap, fmt);
    rval = vsprintf(str, fmt, ap);
    va_end(ap);
#endif

    return rval;
}

static int
vsnprintf( char *str, size_t n, const char *fmt, va_list ap )
{
#ifdef VSPRINTF_CHARSTAR
    return (strlen(vsprintf(str, fmt, ap)));
#else
    return (vsprintf(str, fmt, ap));
#endif
}
