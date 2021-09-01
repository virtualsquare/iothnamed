#ifndef DNSREQQ_H
#define DNSREQQ_H
#include <stdint.h>
#include <sys/socket.h>

#define TIMEOUT 3
#define MAXREQ 1024

/* usage CLIENT -> SERVER request
 * // UDP
 * querylen = recvfrom (clientfd, query, buflen, 0, &client_addr, &clientlen)
 * // parse the header
 * serverid = dnsreq_put(clientid, name, qtype, clientfd, client_addr, clientlen);
 * // change the id to serverid
 * sendto(serverfd, query, querylen, 0, serveraddr, serverlen); // (or send, UDP to the server can be connected
 * // TCP
 * querylen = recv (clientfd, query, buflen, 0);
 * // parse the header
 * serverid = dnsreq_put(clientid, name, qtype, clientfd, NULL, 0);
 * // change the id to serverid
 * send(serverfd, query, querylen, 0);
 * 
 * usage SERVER -> CLIENT reply
 * // UDP
 * replylen = recv(serverfd, reply, buflen, 0)
 * // parse the header
 * clientid = dnsreq_get(serverid, name, qtype, &clientfd, &cleintaddr &cliaddrlen);
 * // change the id to clientid
 * sendto(clientfd, reply, replylen, 0, cleintaddr, cliaddrlen
 *  // TCP
 * replylen = recv(serverfd, reply, buflen, 0)
 * // parse the header
 * clientid = dnsreq_get(serverid, name, qtype, &clientfd, NULL, 0);
 * // change the id to clientid
 * send(clientfd, reply, replylen, 0);
 * 
 */ 

int dnsreq_put(uint16_t clientid, const char *name, uint16_t qtype,
		int fd, const struct sockaddr *client_addr, socklen_t clientlen);

int dnsreq_get(uint16_t serverid, const char *name, uint16_t qtype,
		int *fd, struct sockaddr *dest_addr, socklen_t *addrlen);

typedef void delcb(int fd, struct sockaddr *client_addr, socklen_t clientlen, void *arg);

void dnsreq_delfd(int fd, delcb *cb, void *arg);

void dnsreq_clean(time_t now, delcb *cb, void *arg);

#endif
