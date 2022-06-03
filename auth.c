/*
 * iothnamed: a domain name server/forwarder/proxy for the ioth
 * Copyright 2021 Renzo Davoli - Federico De Marchi
 *     Virtualsquare & University of Bologna
 *
 * auth.c: manage authorizations
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <iothdns.h>
#include <arpainetx.h>
#include <utils.h>
#include <auth.h>

/* definition of uintnets_t, a bitmap for address to net mapping
 * NETS=8 --> uintnets_t is uint8_t
 * NETS=16 --> uintnets_t is uint16_t
 * NETS=32 --> uintnets_t is uint32_t
 * NETS=64 --> uintnets_t is uint64_t */
#define NETS 64  // this can be 8, 16, 32 or 64
#define __NETSTYPE(N) uint ## N ## _t
#define _NETSTYPE(N) __NETSTYPE(N)
#define uintnets_t _NETSTYPE(NETS)

static pthread_mutex_t confmutex = PTHREAD_MUTEX_INITIALIZER;

#define err_return(err) do {\
	errno = err; \
	pthread_mutex_unlock(&confmutex); \
	return -1; \
} while(0)

/* map names to address spaces (sequence of nets/prefixes) */
struct net {
	struct net *next;
	struct in6_addr addr, mask;
};

static int numnets;
static char *netnames[NETS];
static struct net *netlist[NETS];

/* find the index of the address space given its name.
	 add a new address space if add = ADD_IF_MISSING */
#define ADD_IF_MISSING 1
#define DO_NOT_ADD_IF_MISSING 0
static int getnet (const char *name, int add) {
	int i;
	for (i = 0; i < numnets; i++) {
		if (strcmp(name, netnames[i]) == 0)
			return i;
	}
	if (add & ADD_IF_MISSING) {
		if (numnets >= NETS) return errno = ENOMEM, -1;
		netnames[numnets++] = strdup(name);
		return i;
	} else
		return errno = ENOENT, -1;
}

/* add a network (address/mask) to an address space */
int auth_add_net(const char *name, const char *net) {
	struct in6_addr addr;
	unsigned prefix;
	char saddr[strlen(net) + 1];
	pthread_mutex_lock(&confmutex);
	if (sscanf(net, "%[^/]/%u", saddr, &prefix) != 2)
		err_return(EINVAL);
	if (inet_ptonx(AF_INET6, saddr, &addr) != 1)
		err_return(EINVAL);
	if (IN6_IS_ADDR_V4MAPPED(&addr) && prefix <= 32)
		prefix += 96; // prefix of V4PREFIX
	if (prefix  > 128)
		err_return(EINVAL);
	int netindex = getnet(name, ADD_IF_MISSING);
	if (netindex < 0)
		err_return(ENOMEM);
	struct net *this = malloc(sizeof(*this));
	if (this == NULL)
		err_return(ENOMEM);
	this->next = netlist[netindex];
	this->addr = addr;
	this->mask = prefix2mask(prefix);
	netlist[netindex] = this;
	pthread_mutex_unlock(&confmutex);
	return 0;
}

/* check if an address belongs to a net (addr/mask) */
static int addrmatch(struct in6_addr *a1, struct in6_addr *a2, struct in6_addr *mask) {
	for (int i = 0; i < 16; i++) {
		if ((a1->s6_addr[i] & mask->s6_addr[i]) != (a2->s6_addr[i] & mask->s6_addr[i]))
			return 0;
	}
	return 1;
}

/* return the bit map of all the address spaces 'addr' belogs to */
static uintnets_t cknet(struct in6_addr *addr) {
	uintnets_t rv = 0;
	for (int i = 0; i < numnets; i++) {
		for (struct net *scan = netlist[i]; scan != NULL; scan = scan-> next) {
			if (addrmatch(addr, &scan->addr, &scan->mask)) {
				rv |= (1 << i);
				break;
			}
		}
	}
	return rv;
}

/* return the bit map of the address spaces from a (comma separated) list of names */
static uintnets_t cknetnames(const char *names) {
	uintnets_t rv = 0;
	size_t namelen = strlen(names) + 1;
	char namecp[namelen];
	char *scan, *this;
	snprintf(namecp, namelen, "%s", names);
	for (char *s = namecp ; (this = strtok_r(s, ",", &scan)) != NULL; s = NULL) {
		int net = getnet(this, DO_NOT_ADD_IF_MISSING);
		if (net < 0) return errno = EINVAL, -1;
		rv |= (1 << net);
	}
	return rv;
}

#define _AUTH_TAGS_ITEM(X, Y) #X
static char *auth_labels[AUTH_TAGS_COUNT] = { AUTH_TAGS };
#undef _AUTH_TAGS_ITEM

#define _AUTH_TAGS_ITEM(X, Y) Y
static uint8_t auth_args[AUTH_TAGS_COUNT] = { AUTH_TAGS };
#undef _AUTH_TAGS_ITEM

static uint8_t auth_active[AUTH_TAGS_COUNT];

struct auth_item {
	struct auth_item *next;
	uint8_t type;
	uintnets_t nets;
	char *name;
	struct in6_addr *baseaddr;
	char *pwd;
};

/* head and tail of the auth list */
struct auth_item *authh, *autht;

/* strdup avoiding the final dot */
static char *strdup_nofinaldot(const char *s) {
	size_t len = strlen(s);
	if (s[len - 1] == '.') len--;
	return strndup(s, len);
}

/* add an authorization record */
int auth_add_auth(const char *type_string, const char *nets, const char *name, struct in6_addr *baseaddr, const char *pwd) {
	int type;
	pthread_mutex_lock(&confmutex);
	for (type = 0; type < AUTH_TAGS_COUNT; type++)
		if (strcasecmp(auth_labels[type], type_string) == 0) break;
	if (type >= AUTH_TAGS_COUNT) err_return(EINVAL);
	if ((!(auth_args[type] & AUTH_HAS_NAME)) ^ (name == NULL)) err_return(EINVAL);
	if ((!(auth_args[type] & AUTH_HAS_ADDR)) ^ (baseaddr == NULL)) err_return(EINVAL);
	if ((!(auth_args[type] & AUTH_HAS_PWD)) ^ (pwd == NULL)) err_return(EINVAL);
	errno = 0;
	uintnets_t netsmask = cknetnames(nets);
	if (errno) err_return(errno);
	struct auth_item *new = malloc(sizeof(*new));
	if (new == NULL) {
		err_return(EINVAL);
	}
	new->next = NULL;
	new->type = type;
	new->nets = netsmask;
	new->name = (name == NULL) ? NULL : strdup_nofinaldot(name);
	new->baseaddr = memdup(baseaddr, sizeof(*baseaddr));
	new->pwd = (pwd == NULL) ? NULL : strdup(pwd);
	if (autht == NULL)
		authh = new;
	else
		autht->next = new;
	autht = new;
	auth_active[type] = 1;
	pthread_mutex_unlock(&confmutex);
	return 0;
}

/* return true is name belongs to the doamin i.e. if the trailing
	 part of the fqdn is the same. e.g. x.hash.v2.cs.unibo.it in hash.v2.cs.unibo.it*/
static int namematch(const char *name, const char *domain) {
	size_t namelen = strlen(name);
	size_t domainlen = strlen(domain);
	ssize_t prefixlen = namelen - domainlen;
	if (domainlen == 0) return 1; // an empty domain matches everything
	if (prefixlen < 0) return 0; // name is shorter than domain -> not ok
	if (strcmp(name + prefixlen, domain) != 0) return 0; // prefix must match
	if (prefixlen == 0) return 1; // if it is a perfect match -> ok
	if (domain[0] == '.') return 1; // it is a subdomain match -> ok
	return 0; // no other possibilities left
}

int authck(int type, struct in6_addr *fromaddr) {
	pthread_mutex_lock(&confmutex);
	uintnets_t nets = cknet(fromaddr);
	struct auth_item *scan;
	for (scan = authh; scan != NULL; scan = scan->next)
		if (nets & scan->nets)
			if (scan->type == type)
				break;
	pthread_mutex_unlock(&confmutex);
	return scan != NULL;
}

int auth_isactive(int type) {
	return auth_active[type];
}

struct iothdns_pkt *auth_process_req(struct iothdns_header *h, struct in6_addr *fromaddr,
		proc_req_cb_t proc_req_cb) {
	struct iothdns_pkt *rpkt = NULL;
	pthread_mutex_lock(&confmutex);
	uintnets_t nets = cknet(fromaddr);
	for (struct auth_item *scan = authh; scan != NULL; scan = scan->next)
		if ((nets & scan->nets) && scan->name)
			if (namematch(h->qname, scan->name))
				if ((rpkt = proc_req_cb(scan->type, fromaddr, scan->baseaddr, scan->pwd, h)) != NULL)
					break;
	pthread_mutex_unlock(&confmutex);
	return rpkt;
}


/* management of hash addr reverse resolution policy */

static enum hashrevmode hashrevmode = HASHREV_ALWAYS;

void auth_hashrev_setmode(enum hashrevmode mode) {
	hashrevmode = mode;
}

int auth_hashrev_check(struct in6_addr *addr, struct in6_addr *fromaddr) {
	struct in6_addr same_mask = {.s6_addr =
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
	struct in6_addr net_mask = {.s6_addr =
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
	switch (hashrevmode) {
		case HASHREV_ALWAYS:
		default: return 1;
		case HASHREV_NET: return addrmatch(addr, fromaddr, &net_mask);
		case HASHREV_SAME: return addrmatch(addr, fromaddr, &same_mask);
		case HASHREV_NEVER: return 0;
	}
}

/* print the auth tables (for debugging purposes) */

void auth_printnets(FILE *f) {
	pthread_mutex_lock(&confmutex);
	for (int i = 0; i < numnets; i++) {
		for (struct net *scan = netlist[i]; scan != NULL; scan = scan-> next) {
			char addrbuf[INET6_ADDRSTRLEN], maskbuf[INET6_ADDRSTRLEN];
			fprintf(f, "%3d %-10s: %s %s\n", i, netnames[i],
					inet_ntop(AF_INET6, &scan->addr, addrbuf, INET6_ADDRSTRLEN),
					inet_ntop(AF_INET6, &scan->mask, maskbuf, INET6_ADDRSTRLEN));
		}
	}
	pthread_mutex_unlock(&confmutex);
}

void auth_printauth(FILE *f) {
	pthread_mutex_lock(&confmutex);
	for (struct auth_item *scan = authh; scan != NULL; scan = scan->next) {
		fprintf(f, "%s (", auth_labels[scan->type]);
		char *sep = "";
		for (int i = 0; i < numnets; i++)
			if (scan->nets & (1 << i)) {
				fprintf(f, "%s%s(%d)", sep, netnames[i], i);
				sep = ",";
			}
		fprintf(f,")");
		if (scan->name) fprintf(f," %s", scan->name);
		if (scan->baseaddr) {
			char addrbuf[INET6_ADDRSTRLEN];
			fprintf(f," %s", inet_ntop(AF_INET6, scan->baseaddr, addrbuf, INET6_ADDRSTRLEN));
		}
		if (scan->pwd) fprintf(f," %s", scan->pwd);
		fprintf(f, "\n");
	}
	pthread_mutex_unlock(&confmutex);
}

void auth_cleanall(void) {
	pthread_mutex_lock(&confmutex);
	while (authh != NULL) {
		struct auth_item *next  = authh->next;
		if (authh->name != NULL) free(authh->name);
		if (authh->baseaddr != NULL) free(authh->baseaddr);
		if (authh->pwd != NULL) free(authh->pwd);
		free(authh);
		authh = next;
	}
	autht = NULL;
	for (int i = 0; i < numnets; i++) {
		while (netlist[i]  != NULL) {
			struct net *next = netlist[i]->next;
			free(netlist[i]);
			netlist[i] = next;
		}
		free(netnames[i]);
		netnames[i] = NULL;
	}
	numnets = 0;
	for (int type = 0; type < AUTH_TAGS_COUNT; type++)
		auth_active[type] = 0;
	hashrevmode = HASHREV_ALWAYS;
	pthread_mutex_unlock(&confmutex);
}
