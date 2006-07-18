/*
 * Platforms without strdup ?!?!?!
 */

static char *
strdup( const char *s )
{
    char *cp;

    if (s == NULL)
	return NULL;

    cp = (char *) AGALOC((unsigned) (strlen(s)+1), "strdup");

    if (cp != NULL)
	(void) strcpy(cp, s);

    return cp;
}
