/* $Id: list.c,v 1.12 2004/09/05 19:46:27 aturner Exp $ */

/*
 * Copyright (c) 2001-2004 Aaron Turner.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright owners nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * A generic method to parse a list of integers which are
 * delimited by commas and dashes to indicate individual
 * numbers and ranges
 * Provides both a way to process the list and determine
 * if an integer exists in the list.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <errno.h>

#include "config.h"
#include "tcpreplay.h"
#include "err.h"
#include "cidr.h"
#include "list.h"

#define EBUF_SIZE 256


LIST *
new_list()
{
    LIST *newlist;

    newlist = (LIST *) malloc(sizeof(LIST));
    if (newlist == NULL)
        err(1, "unable to malloc memory for new_list()");

    memset(newlist, 0, sizeof(LIST));
    return (newlist);
}

/*
 * Processes a string (ourstr) containing the list in human readable
 * format and places the data in **list and finally returns 1 for 
 * success, 0 for fail.
 */
int
parse_list(LIST ** listdata, char *ourstr)
{
    LIST *listcur, *list_ptr;
    char *this = NULL;
    char *first, *second;
    int i, rcode;
    regex_t preg;
    char ebuf[EBUF_SIZE];
    char regex[] = "^[0-9]+(-[0-9]+)?$";
    char *token = NULL;


    /* compile the regex first */
    if ((rcode = regcomp(&preg, regex, REG_EXTENDED | REG_NOSUB)) != 0) {
        regerror(rcode, &preg, ebuf, sizeof(ebuf));
        errx(1, "Unable to compile regex (%s): %s", regex, ebuf);
    }

    /* first iteration */
    this = strtok_r(ourstr, ",", &token);
    first = this;
    second = NULL;

    /* regex test */
    if (regexec(&preg, this, 0, NULL, 0) != 0) {
        warnx("Unable to parse: %s", this);
        return 0;
    }


    *listdata = new_list();
    list_ptr = *listdata;
    listcur = list_ptr;

    for (i = 0; i < strlen(this); i++) {
        if (this[i] == '-') {
            this[i] = '\0';
            second = &this[i + 1];
        }
    }

    list_ptr->min = strtoull(first, NULL, 0);
    if (second != NULL) {
        list_ptr->max = strtoull(second, NULL, 0);
    }
    else {
        list_ptr->max = list_ptr->min;
    }

    while (1) {
        this = strtok_r(NULL, ",", &token);
        if (this == NULL)
            break;

        first = this;
        second = NULL;


        /* regex test */
        if (regexec(&preg, this, 0, NULL, 0) != 0) {
            warnx("Unable to parse: %s", this);
            return 0;
        }

        listcur->next = new_list();
        listcur = listcur->next;

        for (i = 0; i < strlen(this); i++) {
            if (this[i] == '-') {
                this[i] = '\0';
                second = &this[i + 1];
            }
        }

        listcur->min = strtoull(first, NULL, 0);
        if (second != NULL) {
            listcur->max = strtoull(second, NULL, 0);
        }
        else {
            listcur->max = listcur->min;
        }

    }

    return 1;
}



/*
 * Checks to see if the given integer exists in the LIST.
 * Returns 1 for true, 0 for false
 */
int
check_list(LIST * list, u_int64_t value)
{
    LIST *current;

    current = list;
    do {
        if ((current->min != 0) && (current->max != 0)) {
            if ((value >= current->min) && (value <= current->max))
                return 1;
        }
        else if (current->min == 0) {
            if (value <= current->max)
                return 1;
        }
        else if (current->max == 0) {
            if (value >= current->min)
                return 1;
        }

        if (current->next != NULL) {
            current = current->next;
        }
        else {
            current = NULL;
        }

    } while (current != NULL);

    return 0;

}


/*
 * Free's all the memory associated with the given LIST
 */
void
free_list(LIST * list)
{

    /* recursively go down the list */
    if (list->next != NULL)
        free_list(list->next);

    free(list);
}
