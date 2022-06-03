#ifndef PROCESS_DNS_REQ_H
#define PROCESS_DNS_REQ_H

struct iothdns_header;
struct in6_addr;
struct iothdns_pkt *process_dns_req(struct iothdns_header *h, struct in6_addr *fromaddr);
void process_dns_req_set_hashttl(int ttl);

#endif
