/*
 * iothnamed: a domain name server/forwarder/proxy for the ioth
 * Copyright 2021 Renzo Davoli - Federico De Marchi
 *     Virtualsquare & University of Bologna
 *
 * cache.c: implementation of the cache.
 * also supports static addresses and hash addresses reverse resolution
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

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>

#include <iothdns.h>

#include <list.h>
#include <utils.h>
#include <now.h>
#include <dnsheader_flags.h>
#include <cache.h>

/* it is not INT64_MAX: glibc supports conversions up to year 2147483647 */
#define MAX_TIME \
	((sizeof(time_t) == 8) ? 67767976233521999L : INT32_MAX)

static pthread_mutex_t cachemutex = PTHREAD_MUTEX_INITIALIZER;

/* hash table of names of active cached records */
#define CACHE_HASSIZE_BITS 7             /* 128 */
#define CACHE_HASSIZE (1 << CACHE_HASSIZE_BITS)
#define CACHE_HASSIZE_MASK (CACHE_HASSIZE - 1)
static struct nl_list_head cache_head[CACHE_HASSIZE];
static inline unsigned int cache_hash(const char *name) {
	return simple_stringhash(name) & CACHE_HASSIZE_MASK;
}

/* hash table of names of static records */
#define STATIC_HASSIZE_BITS 4             /* 16 */
#define STATIC_HASSIZE (1 << STATIC_HASSIZE_BITS)
#define STATIC_HASSIZE_MASK (STATIC_HASSIZE - 1)
static struct nl_list_head static_head[STATIC_HASSIZE];
static inline unsigned int static_hash(const char *name) {
  return simple_stringhash(name) & STATIC_HASSIZE_MASK;
}

/* hash table of names of hash reverse records */
#define HREV_HASSIZE_BITS 4             /* 16 */
#define HREV_HASSIZE (1 << HREV_HASSIZE_BITS)
#define HREV_HASSIZE_MASK (HREV_HASSIZE - 1)
static struct nl_list_head hrev_head[HREV_HASSIZE];
static inline unsigned int hrev_hash(const char *name) {
  return simple_stringhash(name) & HREV_HASSIZE_MASK;
}

/* list of resource records
 * sorted in acending order of expire time, for cleaning */
static NL_LIST_HEAD_INIT(rr_head);

__attribute__((constructor))
  static void init(void) {
    for (int i = 0; i < CACHE_HASSIZE; i++)
      NL_INIT_LIST_HEAD(&cache_head[i]);
    for (int i = 0; i < STATIC_HASSIZE; i++)
      NL_INIT_LIST_HEAD(&static_head[i]);
    for (int i = 0; i < HREV_HASSIZE; i++)
      NL_INIT_LIST_HEAD(&hrev_head[i]);
  }


/* name list item */
/* k prefix stands for cache. cname would have beeen ambiguous */
struct kname {
	struct nl_list_head name_list;
	struct nl_list_head namerr_head;
	char name[];
};

/* this union supports the following RR types:
 * A(1), AAAA(28), NS(2), CNAME(5), PTR(12), MX(15), TXT(16)
 */

/* tail of cached resource record items:
 * the contents depends on the record type */
/* the space will be allocated as needed.
 * the size of arrays are just the max size
 * (to avoid  "buffer overflow detected" errors */
union krru {
	struct in_addr a;
	struct in6_addr aaaa;
	char namestr[UINT16_MAX + 1];
	struct {
		uint16_t prio;
		char name[IOTHDNS_MAXNAME];
	} mx;
};

/* cached resource record item.
 * the size of the tail is not computed in sizeof(struct krr) */
struct krr {
	struct nl_list_head namerr_list;
	struct nl_list_head rr_list;
	struct kname *kname;
	uint16_t type;
	uint16_t len;
	time_t expire;
#define rru krru[0]
	union krru krru[];
};

#define ADD_IF_MISSING 1
#define DO_NOT_ADD_IF_MISSING 0
/* search a name item in a name-list, add it if 'add_if_missing' is true */
static struct kname *getkname(struct nl_list_head *head, const char *name, int add_if_missing) {
	struct kname *scan;
	nl_list_for_each_entry(scan, head, name_list)
		if (strcmp(name, scan->name) == 0)
			return scan;
	if (add_if_missing == 0)
		return NULL;
	else {
		scan = malloc(sizeof(*scan) + strlen(name) + 1);
		if (scan) {
			NL_INIT_LIST_HEAD(&scan->namerr_head);
			strcpy(scan->name, name);
			nl_list_add_tail(&scan->name_list, head);
		}
		return scan;
	}
}

/* add a resource record item to the cache */
static void addkrr(struct krr *new) {
	struct krr *scan;
	nl_list_for_each_entry(scan, &new->kname->namerr_head, namerr_list) {
		if (scan->type == new->type && scan->len == new->len &&
				memcmp(&scan->rru, &new->rru, scan->len) == 0) {
			/* renew an existing rr */
			scan->expire = new->expire;
			/* or the furthest in the future?
			 * NO: if the ttl has been reduced expire must be updated consistently */
			nl_list_del(&scan->rr_list);
			free(new);
			new = scan;
			break;
		}
	}
	if (new != scan)
		nl_list_add_tail(&new->namerr_list, &new->kname->namerr_head);
	/* add rr in ascending order of expire */
	nl_list_for_each_entry(scan, &rr_head, rr_list)
		if (scan->expire >= new->expire)
			break;
	nl_list_add_tail(&new->rr_list, &scan->rr_list);
}

/* add a cache resource record
 * (common code for cache_add, cache_static_add and cache_hrev_add) */
static int _cache_add(struct nl_list_head *head, const char *name, uint16_t type,
		time_t expire, va_list ap) {
	struct krr *new = NULL;
	char *namestr;
	uint16_t len = 0;
	pthread_mutex_lock(&cachemutex);
	//printf("_cache_add %s %d\n", name, type);
	switch(type) {
		case IOTHDNS_TYPE_A:
			len = sizeof(new->rru.a);
			new = malloc(sizeof(*new) + len);
			new->rru.a = *va_arg(ap, struct in_addr *);
			break;
		case IOTHDNS_TYPE_AAAA:
			len = sizeof(new->rru.aaaa);
			new = malloc(sizeof(*new) + len);
			new->rru.aaaa = *va_arg(ap, struct in6_addr *);
			break;
		case IOTHDNS_TYPE_NS:
		case IOTHDNS_TYPE_CNAME:
		case IOTHDNS_TYPE_PTR:
			namestr = va_arg(ap, char *);
			len = strlen(namestr) + 1;
			new = malloc(sizeof(*new) + len);
			strcpy(new->rru.namestr, namestr);
			break;
		case IOTHDNS_TYPE_TXT: /* copied as raw data */
			len = va_arg(ap, unsigned int);
			new = malloc(sizeof(*new) + len);
			memcpy(new->rru.namestr, va_arg(ap, char *), len);
			break;
		case IOTHDNS_TYPE_MX:
			{ uint16_t prio = va_arg(ap, unsigned int);
				namestr = va_arg(ap, char *);
				len = sizeof(new->rru.mx.name) + strlen(namestr) + 1;
				new = malloc(sizeof(*new) + len);
				new->rru.mx.prio = prio;
				strcpy(new->rru.mx.name, namestr);
			}
			break;
	}
	va_end(ap);
	if (new) {
		if ((new->kname = getkname(head, name, ADD_IF_MISSING)) == NULL)
			return free(new), -1;
		new->type = type;
		new->len = len;
		new->expire = expire;
		addkrr(new);
		pthread_mutex_unlock(&cachemutex);
		return 0;
	}
	pthread_mutex_unlock(&cachemutex);
	return -1;
}

int cache_add(const char *name, uint16_t type, time_t expire, ...) {
	va_list ap;
	va_start(ap, expire);
	return _cache_add(&cache_head[cache_hash(name)], name, type, expire, ap);
}

int cache_static_add(const char *name, uint16_t type, ...) {
	va_list ap;
	va_start(ap, type);
	return _cache_add(&static_head[static_hash(name)], name, type, MAX_TIME, ap);
}

int cache_hrev_add(const char *name, uint16_t type, time_t expire, ...) {
	va_list ap;
	va_start(ap, expire);
	return _cache_add(&hrev_head[hrev_hash(name)], name, type, expire, ap);
}

/* feed the cache parsing an incoming packet. */
void cache_feed(struct iothdns_pkt *pkt) {
	time_t nowtime = now();
	int section;
	struct iothdns_rr rr;
	char rname[IOTHDNS_MAXNAME];
	while ((section = iothdns_get_rr(pkt, &rr, rname)) != 0) {
		if (section == IOTHDNS_SEC_ANSWER && rr.class == IOTHDNS_CLASS_IN) {
			switch (rr.type) {
				case IOTHDNS_TYPE_A:
					{ struct in_addr a;
						cache_add(rr.name, rr.type, nowtime + rr.ttl,
								iothdns_get_a(pkt, &a));
					}
					break;
				case IOTHDNS_TYPE_AAAA:
					{ struct in6_addr aaaa;
						cache_add(rr.name, rr.type, nowtime + rr.ttl,
								iothdns_get_aaaa(pkt, &aaaa));
					}
					break;
				case IOTHDNS_TYPE_NS:
				case IOTHDNS_TYPE_CNAME:
				case IOTHDNS_TYPE_PTR:
					{ char rrname[IOTHDNS_MAXNAME];
						cache_add(rr.name, rr.type, nowtime + rr.ttl,
								iothdns_get_name(pkt, rrname));
					}
					break;
				case IOTHDNS_TYPE_TXT:
					{ char buf[rr.rdlength];
						cache_add(rr.name, rr.type, nowtime + rr.ttl,
								iothdns_get_data(pkt, buf, rr.rdlength));
					}
					break;
				case IOTHDNS_TYPE_MX:
					{ char rrname[IOTHDNS_MAXNAME];
						uint16_t prio = iothdns_get_int16(pkt);
						cache_add(rr.name, rr.type, nowtime + rr.ttl,
								prio, iothdns_get_name(pkt, rrname));

					}
					break;
			}
		}
	}
}

/* purge the expired entries from the cache */
void cache_clean(time_t now) {
	struct krr *scan, *tmp;
	pthread_mutex_lock(&cachemutex);
	nl_list_for_each_entry_safe(scan, tmp, &rr_head, rr_list) {
		if (scan->expire < now) {
			struct kname *kname = scan->kname;
			nl_list_del(&scan->namerr_list);
			nl_list_del(&scan->rr_list);
			/* purge also the name item if its rr list is empty */
			if (nl_list_empty(&kname->namerr_head)) {
				nl_list_del(&kname->name_list);
				free(kname);
			}
			free(scan);
		} else
			break;
	}
	pthread_mutex_unlock(&cachemutex);
}

/* max ttl value is INT32_MAX (RFC 2181 section 8) */
static inline time_t minttl(time_t expire, time_t now) {
	if (expire <= now) return 0;
	if (expire == MAX_TIME) return INT32_MAX;
	expire -= now;
	if (expire > INT32_MAX) return INT32_MAX;
	return expire;
}

/* try to satisfy a query using the cache.
 * (common code for cache_get, cache_static_get and cache_hrev_get) */
static struct iothdns_pkt *_cache_get(struct iothdns_pkt *rpkt,
		struct nl_list_head *head, struct iothdns_header *h, int is_cache) {
	time_t nowtime = now();
	struct iothdns_header rh = *h;
	pthread_mutex_lock(&cachemutex);
	struct kname *kname = getkname(head, rh.qname, DO_NOT_ADD_IF_MISSING);
	if (kname) {
		struct krr *scan;
		nl_list_for_each_entry(scan, &kname->namerr_head, namerr_list) {
			/* static => missing records = does not exist => generate header w/o rr
			 * cache => missing records = forward the request => NO header, NO rpkt */
			if (rh.qclass == IOTHDNS_CLASS_IN &&
					(scan->type == rh.qtype || !is_cache)) {
				if (rpkt == NULL) {
					rh.flags |= is_cache ? FLAGS_OK(h->flags) : FLAGS_OK_AA(h->flags);
					rpkt = iothdns_put_header(&rh);
				}
				/* static => reply to ANY, cache => forward the request for ANY */
				if (scan->type == rh.qtype ||
						(!is_cache && rh.qtype == IOTHDNS_TYPE_ANY)) {
					struct iothdns_rr rr = {
						.name = rh.qname,
						.type = scan->type,
						.class = IOTHDNS_CLASS_IN,
						.ttl = minttl(scan->expire, nowtime)
					};
					iothdns_put_rr(IOTHDNS_SEC_ANSWER, rpkt, &rr);
					switch (scan->type) {
						case IOTHDNS_TYPE_A:
							iothdns_put_a(rpkt, &scan->rru.a);
							break;
						case IOTHDNS_TYPE_AAAA:
							iothdns_put_aaaa(rpkt, &scan->rru.aaaa);
							break;
						case IOTHDNS_TYPE_NS:
						case IOTHDNS_TYPE_CNAME:
						case IOTHDNS_TYPE_PTR:
							iothdns_put_name(rpkt, scan->rru.namestr);
							break;
						case IOTHDNS_TYPE_TXT:
							iothdns_put_data(rpkt, scan->rru.namestr, scan->len);
							break;
						case IOTHDNS_TYPE_MX:
							iothdns_put_int16(rpkt, scan->rru.mx.prio);
							iothdns_put_name(rpkt, scan->rru.mx.name);
							break;
					}
				}
			}
		}
	}
	//printf("_cache_get %s %d -> %p\n", h->qname, h->qtype, rpkt);
	pthread_mutex_unlock(&cachemutex);
	return rpkt;
}

/* test if there is a cname and add the cname RR */
static const char * _cache_get_kname(struct iothdns_pkt *rpkt, struct nl_list_head *head, struct iothdns_header *h) {
	time_t nowtime = now();
	const char *cname = NULL;
	pthread_mutex_lock(&cachemutex);
	struct kname *kname = getkname(head, h->qname, DO_NOT_ADD_IF_MISSING);
  if (kname) {
    struct krr *scan;
    nl_list_for_each_entry(scan, &kname->namerr_head, namerr_list) {
			if (scan->type == IOTHDNS_TYPE_CNAME) {
				struct iothdns_rr rr = {
					.name = h->qname,
					.type = scan->type,
					.class = IOTHDNS_CLASS_IN,
					.ttl = minttl(scan->expire, nowtime)
				};
				iothdns_put_rr(IOTHDNS_SEC_ANSWER, rpkt, &rr);
				iothdns_put_name(rpkt, scan->rru.namestr);
				cname = scan->rru.namestr;
			}
		}
	}
	pthread_mutex_unlock(&cachemutex);
	return cname;
}

struct iothdns_pkt *cache_get(struct iothdns_header *h) {
	return _cache_get(NULL, &cache_head[cache_hash(h->qname)], h, 1);
}

/* if there is a cname record -> add cname record and data of the aliased name */
struct iothdns_pkt *cache_static_get(struct iothdns_header *h) {
	struct iothdns_pkt * rpkt = _cache_get(NULL, &static_head[static_hash(h->qname)], h, 0);
	if (rpkt) {
		const char *cname = _cache_get_kname(rpkt, &static_head[static_hash(h->qname)], h);
		if (cname != NULL) {
			struct iothdns_header cnameh = *h;
			cnameh.qname = cname;
			rpkt = _cache_get(rpkt, &static_head[static_hash(cnameh.qname)], &cnameh, 0);
		}
	}
	return rpkt;
}

struct iothdns_pkt *cache_hrev_get(struct iothdns_header *h) {
	return _cache_get(NULL, &hrev_head[hrev_hash(h->qname)], h, 0);
}

static int _cache_static_get_data(struct nl_list_head *head, const char *qname,
		uint16_t type, void *data) {
	int rv = 0;
	pthread_mutex_lock(&cachemutex);
	struct kname *kname = getkname(head, qname, DO_NOT_ADD_IF_MISSING);
	if (kname) {
		struct krr *scan;
		nl_list_for_each_entry(scan, &kname->namerr_head, namerr_list) {
			if (scan->type == type) {
				switch (type) {
					case IOTHDNS_TYPE_AAAA:
						*((struct in6_addr *)data) = scan->rru.aaaa;
						rv = 1;
						break;
					case IOTHDNS_TYPE_A:
						*((struct in_addr *)data) = scan->rru.a;
						rv = 1;
						break;
				}
			}
		}
	}
	pthread_mutex_unlock(&cachemutex);
	return rv;
}

int cache_static_get_aaaa(const char *qname, struct in6_addr *addr) {
	return _cache_static_get_data(&static_head[static_hash(qname)],
			qname, IOTHDNS_TYPE_AAAA, addr);
}

int cache_static_get_a(const char *qname, struct in_addr *addr) {
	return _cache_static_get_data(&static_head[static_hash(qname)],
			qname, IOTHDNS_TYPE_A, addr);
}
