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
/* required for inet_aton() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tcpreplay.h"
#include "cidr.h"
#include "err.h"


extern int debug;

static int ip_in_cidr(const CIDR *, const unsigned long);
static CIDR *cidr2CIDR(char *);

/*
 * prints to the given fd all the entries in mycidr
 */
void 
print_cidr(CIDR * mycidr)
{
	CIDR *cidr_ptr;

	fprintf(stderr, "Cidr List: ");

	cidr_ptr = mycidr;
	while (cidr_ptr != NULL) {
		/* print it */
#if USE_LIBNET_VERSION == 10
		fprintf(stderr, "%s/%d, ", libnet_host_lookup(cidr_ptr->network, RESOLVE), 
				cidr_ptr->masklen);
#elif USE_LIBNET_VERSION == 11
		fprintf(stderr, "%s/%d, ", libnet_addr2name4(cidr_ptr->network, RESOLVE), 
				cidr_ptr->masklen);
#endif

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
 * deletes all entries in a cidr and destroys the datastructure
 */
void 
destroy_cidr(CIDR * cidr)
{

	if (cidr != NULL)
		if (cidr->next != NULL)
			destroy_cidr(cidr->next);

	free(cidr);
	return;

}

/*
 * adds a new CIDR entry to cidrdata
 */
void 
add_cidr(CIDR * cidrdata, CIDR ** newcidr)
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

#if USE_LIBNET_VERSION == 10
	strncpy(network, libnet_host_lookup(ip, RESOLVE), 19);
#elif USE_LIBNET_VERSION == 11
	strncpy(network, libnet_addr2name4(ip, RESOLVE), 19);
#endif

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
#ifdef INET_ATON
	inet_aton(networkip, (struct in_addr *)&newcidr->network);
#elif INET_ADDR
	newcidr->network = inet_addr(networkip);
#endif

	return (newcidr);

	/* we only get here on error parsing input */
error:
	memset(ebuf, '\0', EBUF_SIZE);
	strncpy(ebuf, "Unable to parse: ", 18);
	strncat(ebuf, cidr, (EBUF_SIZE - strlen(ebuf) - 1));
	err(1, "%s", ebuf);
	return NULL;
}

/*
 * parses a list of CIDR's input from the user which should be in the form
 * of x.x.x.x/y,x.x.x.x/y...
 * returns 1 for success, or fails to return on failure (exit 1)
 * since we use strtok to process cidr, it gets zeroed out.
 */

int 
parse_cidr(CIDR ** cidrdata, char *cidrin)
{
	CIDR *cidr_ptr;	/* ptr to current cidr record */
	char *network = NULL;

	/* first itteration of input using strtok */
	network = strtok(cidrin, ",");

	*cidrdata = cidr2CIDR(network);
	cidr_ptr = *cidrdata;

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
ip_in_cidr(const CIDR * mycidr, const unsigned long ip)
{
	unsigned long ipaddr = 0, network = 0, mask = 0;
	
	mask = ~0; /* turn on all the bits */
	
	/* shift over by the correct number of bits */
	mask = mask << (32 - mycidr->masklen);

	/* apply the mask to the network and ip */
	ipaddr = ntohl(ip) & mask;
	network = htonl(mycidr->network) & mask;

	/* if they're the same, then ip is in network */
	if (network == ipaddr) {
#ifdef DEBUG
		if (debug) {
#if USE_LIBNET_VERSION == 10
			fprintf(stderr, "The ip %s is inside of %s/%d\n",
					libnet_host_lookup(ip, RESOLVE), libnet_host_lookup(htonl(network), RESOLVE), mycidr->masklen);
#elif USE_LIBNET_VERSION == 11
			fprintf(stderr, "The ip %s is inside of %s/%d\n",
					libnet_addr2name4(ip, RESOLVE), libnet_addr2name4(htonl(network), RESOLVE), mycidr->masklen);
#endif
		}
#endif
		return 1;
	} else {
#ifdef DEBUG
		if (debug) {
#if USE_LIBNET_VERSION == 10
			fprintf(stderr, "The ip %s is not inside of %s/%d\n",
				libnet_host_lookup(ip, RESOLVE), libnet_host_lookup(htonl(network), RESOLVE), mycidr->masklen);
#elif USE_LIBNET_VERSION == 11
			fprintf(stderr, "The ip %s is not inside of %s/%d\n",
					libnet_addr2name4(ip, RESOLVE), libnet_addr2name4(htonl(network), RESOLVE), mycidr->masklen);
#endif
		}
#endif
		return 0;
	}

}

/*
 * iterates over cidrdata to find if a given ip matches
 * returns 1 for true, 0 for false
 */

int 
check_ip_CIDR(CIDR * cidrdata, const unsigned long ip)
{
	CIDR *mycidr;

	/* if we have no cidrdata, of course it isn't in there */
	if (cidrdata == NULL)
		return 0;

	mycidr = cidrdata;

	/* loop through cidr */
	while (1) {

		/* if match, return 1 */
		if (ip_in_cidr(mycidr, ip)) {
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


/*
 * cidr2ip takes a CIDR and a delimiter
 * and returns a string which lists all the IP addresses in the cidr
 * deliminated by the given char
 */
char *
cidr2iplist(CIDR *cidr, char delim)
{
	char *list = NULL;
	char ipaddr[16];
	unsigned long size, i;
	unsigned long first, last, numips;
	struct in_addr in;

	/* 
	 * 16 bytes per IP + delim
	 * # of IP's = 2^(32-masklen)
	 */
	numips = 2;
	for (i = 2; i <= (32 - cidr->masklen); i ++) {
		numips *= 2;
	}
	size = 16 * numips;

	if ((list = (char *)malloc(size)) == NULL)
		errx(1, "Unable to malloc %d bytes!  Aborting...", size);

	memset(list, 0, size);
	
	/* first and last should not include network or broadcast */
	first = ntohl(cidr->network) + 1;
	last = first + numips - 3;

	dbg(1, "First: %u\t\tLast: %u", first, last);

	/* loop through all but the last one */
	for (i = first; i < last; i ++) {
		in.s_addr = htonl(i);
		snprintf(ipaddr, 17, "%s%c", inet_ntoa(in), delim);
		dbg(2, "%s", ipaddr);
		strncat(list, ipaddr, size);
	}

	/* last is a special case, end in \0 */
	in.s_addr = htonl(i);
	snprintf(ipaddr, 16, "%s", inet_ntoa(in));
	strncat(list, ipaddr, size);

	return list;
}

