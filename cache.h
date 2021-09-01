#ifndef __CACHE_H
#define __CACHE_H
#include <stdint.h>
#include <time.h>

#include <iothdns.h>

/* add a resource record item to the cache */
int cache_add(const char *name, uint16_t type, time_t expire, ...);

/* add a resource record item to the list of static data */
int cache_static_add(const char *name, uint16_t type, ...);

/* add a resource record item to the list of hrev data */
int cache_hrev_add(const char *name, uint16_t type,time_t expire, ...);

/* feed the cache parsing an incoming packet. */
void cache_feed(struct iothdns_pkt *pkt);

/* purge the expired entries from the cache */
void cache_clean(time_t now);

/* try to satisfy a query using the cache. */
struct iothdns_pkt *cache_get(struct iothdns_header *h);

/* try to satisfy a query using static data. */
struct iothdns_pkt *cache_static_get(struct iothdns_header *h);

/* try to satisfy a query using hash reverse data. */
struct iothdns_pkt *cache_hrev_get(struct iothdns_header *h);

#endif
