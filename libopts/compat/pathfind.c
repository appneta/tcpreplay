/*  -*- Mode: C -*-  */

/* pathfind.c --- find a FILE  MODE along PATH */

/*
 * Author:           Gary V Vaughan <gvaughan@oranda.demon.co.uk>
 * Created:          Tue Jun 24 15:07:31 1997
 * Last Modified:    $Date: 2003/11/23 19:21:57 $
 *            by:    Bruce Korb <bkorb@gnu.org>
 *
 * $Id: pathfind.c,v 2.3 2003/11/23 19:21:57 bkorb Exp $
 */

/* Code: */

#include "compat.h"
#ifndef HAVE_PATHFIND

STATIC char* make_absolute( const char *string, const char *dot_path );
STATIC char* canonicalize_pathname( char *path );
STATIC char* extract_colon_unit( char* dir, const char *string, int *p_index );


/*
 * pathfind looks for a a file with name FILENAME and MODE access
 * along colon delimited PATH, and returns the full pathname as a
 * string, or NULL if not found.
 *          Letter    Meaning
 *          r         readable
 *          w         writable
 *          x         executable
 *          f         normal file    (NOT IMPLEMENTED)
 *          b         block special    (NOT IMPLEMENTED)
 *          c         character special    (NOT IMPLEMENTED)
 *          d         directory        (NOT IMPLEMENTED)
 *          p         FIFO (pipe)    (NOT IMPLEMENTED)
 *          u         set user ID bit    (NOT IMPLEMENTED)
 *          g         set group ID bit    (NOT IMPLEMENTED)
 *          k         sticky bit    (NOT IMPLEMENTED)
 *          s         size nonzero    (NOT IMPLEMENTED)
 */
     char*
pathfind( const char*  path,
          const char*  fileName,
          const char*  mode )
{
    int   p_index   = 0;
    int   mode_bits = 0;
    char* pathName  = NULL;
    char  zPath[ MAXPATHLEN + 1 ];

    if (strchr( mode, 'r' )) mode_bits |= R_OK;
    if (strchr( mode, 'w' )) mode_bits |= W_OK;
    if (strchr( mode, 'x' )) mode_bits |= X_OK;

    /*
     *  FOR each non-null entry in the colon-separated path, DO ...
     */
    for (;;) {
        DIR*  dirP;
        char* colon_unit = extract_colon_unit( zPath, path, &p_index );

        /*
         *  IF no more entries, THEN quit
         */
        if (colon_unit == NULL)
            break;

        dirP = opendir( colon_unit );

        /*
         *  IF the directory is inaccessable, THEN next directory
         */
        if (dirP == NULL)
            continue;

        /*
         *  FOR every entry in the given directory, ...
         */
        for (;;) {
            struct dirent *entP = readdir( dirP );

            if (entP == (struct dirent*)NULL)
                break;

            /*
             *  IF the file name matches the one we are looking for, ...
             */
            if (strcmp( entP->d_name, fileName ) == 0) {
                char* pzFullName = make_absolute( fileName, colon_unit);

                /*
                 *  Make sure we can access it in the way we want
                 */
                if (access( pzFullName, mode_bits ) >= 0) {
                    /*
                     *  We can, so normalize the name and return it below
                     */
                    pathName = canonicalize_pathname( pzFullName );
                }

                free( (void*)pzFullName );
                break;
            }
        }
        
        closedir( dirP );

        if (pathName != NULL)
            break;
    }

    return pathName;
}

/*
 * Turn STRING  (a pathname) into an  absolute  pathname, assuming  that
 * DOT_PATH contains the symbolic location of  `.'.  This always returns
 * a new string, even if STRING was an absolute pathname to begin with.
 */
STATIC char*
make_absolute( const char *string, const char *dot_path )
{
    char *result;
    int result_len;
  
    if (!dot_path || *string == '/') {
        result = strdup( string );
    } else {
        if (dot_path && dot_path[0]) {
            result = malloc( 2 + strlen( dot_path ) + strlen( string ) );
            strcpy( result, dot_path );
            result_len = strlen( result );
            if (result[result_len - 1] != '/') {
                result[result_len++] = '/';
                result[result_len] = '\0';
            }    
        } else {
            result = malloc( 3 + strlen( string ) );
            result[0] = '.'; result[1] = '/'; result[2] = '\0';
            result_len = 2;
        }

        strcpy( result + result_len, string );
    }

    return result;
}

/*
 * Canonicalize PATH, and return a  new path.  The new path differs from
 * PATH in that:
 *
 *    Multiple `/'s     are collapsed to a single `/'.
 *    Leading `./'s     are removed.
 *    Trailing `/.'s    are removed.
 *    Trailing `/'s     are removed.
 *    Non-leading `../'s and trailing `..'s are handled by removing
 *                    portions of the path.
 */
STATIC char*
canonicalize_pathname( char *path )
{
    int i, start;
    char stub_char, *result;

    /* The result cannot be larger than the input PATH. */
    result = strdup( path );

    stub_char = (*path == '/') ? '/' : '.';

    /* Walk along RESULT looking for things to compact. */
    i = 0;
    while (result[i]) {
        while (result[i] != '\0' && result[i] != '/')
            i++;

        start = i++;

        /* If we didn't find any  slashes, then there is nothing left to
         * do.
         */
        if (!result[start])
            break;

        /* Handle multiple `/'s in a row. */
        while (result[i] == '/')
            i++;

#if !defined (apollo)
        if ((start + 1) != i)
#else
        if ((start + 1) != i && (start != 0 || i != 2))
#endif /* apollo */
        {
            strcpy( result + start + 1, result + i );
            i = start + 1;
        }

        /* Handle backquoted `/'. */
        if (start > 0 && result[start - 1] == '\\')
            continue;

        /* Check for trailing `/', and `.' by itself. */
        if ((start && !result[i])
            || (result[i] == '.' && !result[i+1])) {
            result[--i] = '\0';
            break;
        }

        /* Check for `../', `./' or trailing `.' by itself. */
        if (result[i] == '.') {
            /* Handle `./'. */
            if (result[i + 1] == '/') {
                strcpy( result + i, result + i + 1 );
                i = (start < 0) ? 0 : start;
                continue;
            }

            /* Handle `../' or trailing `..' by itself. */
            if (result[i + 1] == '.' &&
                (result[i + 2] == '/' || !result[i + 2])) {
                while (--start > -1 && result[start] != '/')
                    ;
                strcpy( result + start + 1, result + i + 2 );
                i = (start < 0) ? 0 : start;
                continue;
            }
        }
    }

    if (!*result) {
        *result = stub_char;
        result[1] = '\0';
    }

    return result;
}

/*
 * Given a  string containing units of information separated  by colons,
 * return the next one  pointed to by (P_INDEX), or NULL if there are no
 * more.  Advance (P_INDEX) to the character after the colon.
 */
STATIC char*
extract_colon_unit( char* pzDir, const char *string, int *p_index )
{
    char*  pzDest = pzDir;
    const char*  pzSrc  = string + *p_index;

    if (  (string == NULL)
       || (*p_index >= (int) strlen( string )))
        return NULL;

    while (*pzSrc == ':')
        pzSrc++;

    for (;;) {
        char ch = (*pzDest = *pzSrc);
        if (ch == NUL)
            break;
        if (ch == ':') {
            *pzDest = NUL;
            break;
        }
        pzDest++;
        pzSrc++;
    }

    if (*pzDir == NUL)
        return NULL;

    *p_index = (pzSrc - string);
    return pzDir;
}

#endif /* HAVE_PATHFIND */
/* pathfind.c ends here */
