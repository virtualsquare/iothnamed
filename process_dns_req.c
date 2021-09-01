/*
 * iothnamed: a domain name server/forwarder/proxy for the ioth
 * Copyright 2021 Renzo Davoli - Federico De Marchi
 *     Virtualsquare & University of Bologna
 *
 * process_dns_req.c: process a dns query
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

#include <netinet/in.h>
#include <iothdns.h>
#include <iothaddr.h>
#include <now.h>
#include <auth.h>
#include <cache.h>
#include <arpainetx.h>
#include <dnsheader_flags.h>
#include <process_dns_req.h>

#define FWD_PKT_TAG ((struct iothdns_pkt *) 0x1)

static struct iothdns_pkt *cb (uint8_t type, struct in6_addr *fromaddr,
		struct in6_addr *baseaddr, char *pwd, struct iothdns_header *h) {
	struct iothdns_pkt *rpkt = NULL;
 	switch (type) {
		case AUTH_ERROR:
			h->flags = FLAGS_EPERM(h->flags);
			rpkt = iothdns_put_header(h);
			break;
		case AUTH_STATIC:
			rpkt = cache_static_get(h);
			if (rpkt == NULL) {
				h->flags = FLAGS_ENOENT(h->flags);
				rpkt = iothdns_put_header(h);
			}
			break;
		case AUTH_OTIP:
			h->flags = FLAGS_OK_AA(h->flags);
			rpkt = iothdns_put_header(h);
			if (h->qtype == IOTHDNS_TYPE_AAAA || h->qtype == IOTHDNS_TYPE_ANY) {
				struct in6_addr addr = *baseaddr;
				iothaddr_hash(&addr, h->qname, pwd, 
						iothaddr_otiptime(32, 0));
				struct iothdns_rr rr = {h->qname, IOTHDNS_TYPE_AAAA, IOTHDNS_CLASS_IN, 1, 0};
				iothdns_put_rr(IOTHDNS_SEC_ANSWER, rpkt, &rr);
				iothdns_put_aaaa(rpkt, &addr);
			}
			break;
		case AUTH_HASH:
			h->flags = FLAGS_OK_AA(h->flags);
			rpkt = iothdns_put_header(h);
			if (h->qtype == IOTHDNS_TYPE_AAAA || h->qtype == IOTHDNS_TYPE_ANY) {
				struct in6_addr addr = *baseaddr;
				iothaddr_hash(&addr, h->qname, NULL, 0);
				struct iothdns_rr rr = {h->qname, IOTHDNS_TYPE_AAAA, IOTHDNS_CLASS_IN, 600, 0};
				iothdns_put_rr(IOTHDNS_SEC_ANSWER, rpkt, &rr);
				iothdns_put_aaaa(rpkt, &addr);
				if (auth_isactive(AUTH_HREV) && auth_hashrev_check(&addr, fromaddr)) {
					time_t nowtime = now();
					char buf[INET6_REVSTRLEN];
					cache_hrev_add(inet_ntor(AF_INET6, &addr, buf, INET6_REVSTRLEN), IOTHDNS_TYPE_PTR, nowtime + 600, h->qname);
				}
			}
			break;
		case AUTH_CACHE:
			rpkt = cache_get(h);
			break;
		case AUTH_HREV:
			if (h->qtype == IOTHDNS_TYPE_PTR) {
				rpkt = cache_hrev_get(h);
				if (rpkt == NULL) {
					h->flags = FLAGS_ENOENT(h->flags);
					rpkt = iothdns_put_header(h);
				}
			}
			break;
		case AUTH_FWD:
			rpkt = FWD_PKT_TAG;
			break;
	}
	return rpkt;
}

struct iothdns_pkt *process_dns_req(struct iothdns_header *h, struct in6_addr *fromaddr) {
	struct iothdns_header rh = *h;
	struct iothdns_pkt *rpkt = auth_process_req(&rh, fromaddr, cb);
	if (rpkt == FWD_PKT_TAG)
		return NULL;
	if (rpkt == NULL) {
		h->flags = FLAGS_EPERM(h->flags);
		rpkt = iothdns_put_header(h);
	}
	return rpkt;
}

