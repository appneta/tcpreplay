/*
 * Please see tcpprep.c for license information.
 *
 *  Copyright (c) 2001 Aaron Turner
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif				/* HAVE_CONFIG_H */

#include <err.h>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cidr.h"
#include "tcpreplay.h"

extern CIDR *cidrdata;
extern int debug;

static int ip_in_cidr(const unsigned long, const CIDR *);
static CIDR *cidr2CIDR(char *);

/*
 * prints to stderr all the entries in mycidr
 */
void 
print_cidr(CIDR * mycidr)
{
	CIDR *cidr_ptr;

	fprintf(stderr, "Cidr List: ");

	cidr_ptr = mycidr;
	while (cidr_ptr != NULL) {
		/* print it */
		fprintf(stderr, "%s/%d, ", libnet_host_lookup(cidr_ptr->network, 
			RESOLVE), cidr_ptr->masklen);

		/* go to the next */
		if (cidr_ptr->next != NULL) {
			cidr_ptr = cidr_ptr->next;
		} else {
			break;
		}
	}
	fprintf(stderr, "\n");
}

/*
 * deletes all entries in a cidrdata
 */
void 
delete_cidr(CIDR * cidr)
{

	if (cidr != NULL)
		if (cidr->next != NULL)
			delete_cidr(cidr->next);

	free(cidr);
	return;

}

/*
 * adds a new CIDR entry to cidrdata
 */
void 
add_cidr(CIDR ** newcidr)
{
	CIDR *cidr_ptr;

	if (cidrdata == NULL) {
		cidrdata = *newcidr;
	} else {
		cidr_ptr = cidrdata;

		while (cidr_ptr->next != NULL) {
			cidr_ptr = cidr_ptr->next;
		}

		cidr_ptr->next = *newcidr;
	}
}

/*
 * takes in an IP and masklen, and returns a string in
 * cidr format: x.x.x.x/y.  This malloc's memory.
 */
u_char *
ip2cidr(const unsigned long ip, const int masklen)
{
	u_char *network;
	char mask[3];

	if ((network = (u_char *) malloc(20)) == NULL)
		err(1, "malloc");

	strcpy(network, libnet_host_lookup(ip, RESOLVE));
	strcat(network, "/");
	if (masklen < 10) {
		snprintf(mask, 1, "%d", masklen);
		strncat(network, mask, 1);
	} else {
		snprintf(mask, 2, "%d", masklen);
		strncat(network, mask, 2);
	}

	return (network);
}

/*
 * Mallocs and sets to sane defaults a CIDR structure
 */

CIDR *
new_cidr()
{
	CIDR *newcidr;

	newcidr = (CIDR *) malloc(sizeof(CIDR));
	if (newcidr == NULL)
		err(1, "malloc");

	memset(newcidr, '\0', sizeof(CIDR));
	newcidr->masklen = 99;
	newcidr->next = NULL;

	return (newcidr);
}

/*
 * Converts a single cidr (string) in the form of x.x.x.x/y into a
 * CIDR structure.  Will malloc the CIDR structure.
 */

static CIDR *
cidr2CIDR(char *cidr)
{
	int count = 0;
	unsigned int octets[4];	/* used in sscanf */
	CIDR *newcidr;
	char networkip[16], tempoctet[4], ebuf[EBUF_SIZE];

	if ((cidr == NULL) || (strlen(cidr) > EBUF_SIZE))
		errx(1, "Error parsing: %s", cidr);

	newcidr = new_cidr();

	/*
	 * scan it, and make sure it scanned correctly, also copy over the
	 * masklen
	 */
	count = sscanf(cidr, "%u.%u.%u.%u/%u", &octets[0], &octets[1], 
		&octets[2], &octets[3], &newcidr->masklen);
	if (count != 5)
		goto error;

	/* masklen better be 0 =< masklen <= 32 */
	if (newcidr->masklen > 32)
		goto error;

	/* copy in the ip address */
	memset(networkip, '\0', 16);
	for (count = 0; count < 4; count++) {
		if (octets[count] > 255)
			goto error;

		snprintf(tempoctet, sizeof(octets[count]), "%d", octets[count]);
		strcat(networkip, tempoctet);
		/* we don't want a '.' at the end of the last octet */
		if (count < 3)
			strcat(networkip, ".");
	}

	/* copy over the network address and return */
	newcidr->network = libnet_name_resolve(networkip, RESOLVE);
	return (newcidr);

	/* we only get here on error parsing input */
error:
	memset(ebuf, '\0', EBUF_SIZE);
	strcpy(ebuf, "Unable to parse: ");
	strncat(ebuf, cidr, (EBUF_SIZE - strlen(ebuf) - 1));
	err(1, "%s", ebuf);
	return NULL;
}

/*
 * parses a list of CIDR's input from the user which should be in the form
 * of x.x.x.x/y,x.x.x.x/y...
 * returns 1 for success, or fails to return on failure (exit 1)
 * since we use strtok to process cidr, it gets zeroed out.
 * we add entries to the global CIDR * cidrdata var.
 */

int 
parse_cidr(char *cidrin)
{
	CIDR *cidr_ptr;	/* ptr to current cdir record */
	char *network = NULL;

	/* first itteration of input using strtok */
	network = strtok(cidrin, ",");

	cidrdata = cidr2CIDR(network);
	cidr_ptr = cidrdata;

	/* do the same with the rest of the input */
	while (1) {
		network = strtok(NULL, ",");
		/* if that was the last CIDR, then kickout */
		if (network == NULL)
			break;

		/* next record */
		cidr_ptr->next = cidr2CIDR(network);
		cidr_ptr = cidr_ptr->next;
	}
	return 1;

}


/*
 * checks to see if the ip address is in the cidr
 * returns 1 for true, 0 for false
 */

static int 
ip_in_cidr(const unsigned long ip, const CIDR * mycidr)
{
	unsigned long ipaddr = 0, network = 0, mask = 0;

	/* shift over by the correct number of bits */
	mask = mask >> (32 - mycidr->masklen);

	/* apply the mask to the network and ip */
	ipaddr = ip & mask;
	network = mycidr->network & mask;

	/* if they're the same, then ip is in network */
	if (network == ipaddr) {
#ifdef DEBUG
		if (debug > 1) {
			fprintf(stderr, "The ip %s is inside of %s/%d\n",
				libnet_host_lookup(ip, RESOLVE), libnet_host_lookup(network, RESOLVE), mycidr->masklen);
		}
#endif
		return 1;
	} else {
#ifdef DEBUG
		if (debug > 1) {
			fprintf(stderr, "The ip %s is not inside of %s/%d\n",
				libnet_host_lookup(ip, RESOLVE), libnet_host_lookup(network, RESOLVE), mycidr->masklen);
		}
#endif
		return 0;
	}

}

/*
 * iterates over global CIDR * cidrdata to find if a given ip matches
 * returns 1 for true, 0 for false
 */

int 
check_ip_CIDR(const unsigned long ip)
{
	CIDR *mycidr;

	/* if we have no cidrdata, of course it isn't in there */
	if (cidrdata == NULL)
		return 0;

	mycidr = cidrdata;

	/* loop through cidr */
	while (1) {

		/* if match, return 1 */
		if (ip_in_cidr(ip, mycidr)) {
			return 1;
		}
		/* check for next record */
		if (mycidr->next != NULL) {
			mycidr = mycidr->next;
		} else {
			break;
		}
	}

	/* if we get here, no match */
	return 0;
}
