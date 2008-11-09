/* $Id$ */

/*
 * Copyright (c) 2004 Aaron Turner.
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

#include "config.h"
#include "defines.h"
#include "common.h"

#include <sys/types.h>
#include <regex.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

/**
 * parses /etc/services so we know which ports are service ports
 */
void
parse_services(const char *file, tcpr_services_t *services)
{
    FILE *service = NULL;
    char service_line[MAXLINE], port[10], proto[10];
    regex_t preg;
    u_int16_t portc;
    size_t nmatch = 3;
    regmatch_t pmatch[3];
    char regex[] = "([0-9]+)/(tcp|udp)"; /* matches the port as pmatch[1], service pmatch[2] */

    dbgx(1, "Parsing %s", file);
    memset(service_line, '\0', MAXLINE);

    /* mark all ports not a service */
    memset(services->tcp, '\0', NUM_PORTS);
    memset(services->udp, '\0', NUM_PORTS);

    if ((service = fopen(file, "r")) == NULL) {
        errx(-1, "Unable to open service file: %s\n%s", file, strerror(errno));
    }
    
    /* compile our regexes */
    if ((regcomp(&preg, regex, REG_ICASE|REG_EXTENDED)) != 0) {
        errx(-1, "Unable to compile regex: %s", regex);
    }

    /* parse the entire file */
    while ((fgets(service_line, MAXLINE, service)) != NULL) {
        /* zero out our vars */
        memset(port, '\0', 10);
        memset(proto, '\0', 10);
        portc = 0;
        
        dbgx(4, "Procesing: %s", service_line);
        
        /* look for format of 1234/tcp */
        if ((regexec(&preg, service_line, nmatch, pmatch, 0)) == 0) { /* matches */
            if (nmatch < 2) {
                err(-1, "WTF?  I matched the line, but I don't know where!");
            }

            /* strip out the port & proto from the line */
            strncpy(port, &service_line[pmatch[1].rm_so], (pmatch[1].rm_eo - pmatch[1].rm_so));
            strncpy(proto, &service_line[pmatch[2].rm_so], (pmatch[2].rm_eo - pmatch[2].rm_so));

            /* convert port[] into an integer */
            portc = (u_int16_t)atoi(port);

            /* update appropriate service array with the server port */
            if (strcmp(proto, "tcp") == 0) {
                dbgx(3, "Setting TCP/%d as a server port", portc);
                services->tcp[portc] = 1; /* mark it as a service port */
            } else if (strcmp(proto, "udp") == 0) {
                dbgx(3, "Setting UDP/%d as a server port", portc);
                services->udp[portc] = 1;
            } else {
                warnx("Skipping unknown protocol service %s/%d", proto, portc);
            }
        }
    }
}

/*
 Local Variables:
 mode:c
 indent-tabs-mode:nil
 c-basic-offset:4
 End:
*/

