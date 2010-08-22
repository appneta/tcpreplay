/* $Id$ */

/*
 *   Copyright (c) 2001-2010 Aaron Turner <aturner at synfin dot net>
 *
 *   The Tcpreplay Suite of tools is free software: you can redistribute it 
 *   and/or modify it under the terms of the GNU General Public License as 
 *   published by the Free Software Foundation, either version 3 of the 
 *   License, or with the authors permission any later version.
 *
 *   The Tcpreplay Suite is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with the Tcpreplay Suite.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include "config.h"
#include "defines.h"
#include "common.h"
#include "interface.h"

/**
 * Method takes a user specified device name and returns
 * the canonical name for that device.  This allows me to 
 * create named interface aliases on platforms like Windows
 * which use horrifically long interface names
 * 
 * Returns NULL on error
 * 
 * On success, it *may* malloc() memory equal to the length of *alias.
 */
char *
get_interface(interface_list_t *list, const char *alias)
{
    interface_list_t *ptr;
    char *name;
    
    assert(alias);
    
    if (list != NULL) {        
        ptr = list;
    
        do {
            /* check both the alias & name fields */
            if (strcmp(alias, ptr->alias) == 0)
                return(ptr->name);
        
            if (strcmp(alias, ptr->name) == 0)
                return(ptr->name);
            
            ptr = ptr->next;
        } while (ptr != NULL);
    } else {
        name = (char *)safe_malloc(strlen(alias) + 1);
        strlcpy(name, alias, (strlen(alias) + 1));
        return(name);
    }
    
    return(NULL);
}

/** 
 * Get all available interfaces as an interface_list *
 */
interface_list_t *
get_interface_list(void)
{
    interface_list_t *list_head, *list_ptr;
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *pcap_if, *pcap_if_ptr;
    int i = 0;
    
#ifndef HAVE_WIN32
	/* Unix just has a warning about being root */
	if (geteuid() != 0)
		warn("May need to run as root to get complete list.");
#endif

    if (pcap_findalldevs(&pcap_if, ebuf) < 0)
        errx(-1, "Error: %s", ebuf);
            
    pcap_if_ptr = pcap_if;
    list_head = (interface_list_t *)safe_malloc(sizeof(interface_list_t));
    list_ptr = list_head;
    
    while (pcap_if_ptr != NULL) {
        if (i > 0) {
            list_ptr->next = (interface_list_t *)safe_malloc(sizeof(interface_list_t));
            list_ptr = list_ptr->next;
        }
        strlcpy(list_ptr->name, pcap_if_ptr->name, sizeof(list_ptr->name));
        
        /* description is usually null under Unix */
        if (pcap_if_ptr->description != NULL)
            strlcpy(list_ptr->description, pcap_if_ptr->description, sizeof(list_ptr->description));
            
        sprintf(list_ptr->alias, "%%%d", i++);
        list_ptr->flags = pcap_if_ptr->flags;
        pcap_if_ptr = pcap_if_ptr->next;
    }
    pcap_freealldevs(pcap_if);
    return(list_head);
}

/**
 * Prints all the available interfaces found by get_interface_list()
 */
void
list_interfaces(interface_list_t *list)
{
    interface_list_t *ptr;

    if (list == NULL) {
        printf("No network interfaces available");
        return;
    }

    printf("Available network interfaces:\n");
        
#ifdef HAVE_WIN32  /* Win32 has alias/name/description */
	printf("Alias\tName\tDescription\n");
#endif
    
    
    ptr = list;

    do {
        if (! ptr->flags & PCAP_IF_LOOPBACK) {
#ifdef HAVE_WIN32
            printf("%s\t%s\n\t%s\n", ptr->alias, ptr->name, ptr->description);
#else
			printf("%s\n", ptr->name);
#endif
        }
        ptr = ptr->next;
    } while (ptr != NULL);
}
