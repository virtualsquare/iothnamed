#ifndef DNSREQQ_H
#define DNSREQQ_H
#include <stdint.h>
#include <sys/socket.h>

#define TIMEOUT 3
#define MAXREQ 1024

/* This data structure stores info on the pending queries forwarded to remote DNS servers
 * in order to return each reply to the client who issued the query.
 * dnsreq_put -> store the request's info
 * dnsreq_get -> retrieve the client's data (fd, address)
 */

/* usage CLIENT -> SERVER request
 * // UDP
 * querylen = recvfrom (clientfd, query, buflen, 0, &client_addr, &clientlen)
 * // parse the header
 * serverid = dnsreq_put(clientid, name, qtype, clientfd, client_addr, clientlen);
 * // change the id to serverid
 * sendto(serverfd, query, querylen, 0, serveraddr, serverlen);
 *                 // (or simply send: if the UDP socket to the server is connected)
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
 * clientid = dnsreq_get(serverid, name, qtype, &clientfd, &clientaddr, &cliaddrlen);
 * // change the id to clientid
 * sendto(clientfd, reply, replylen, 0, clientaddr, cliaddrlen);
 *  // TCP
 * replylen = recv(serverfd, reply, buflen, 0)
 * // parse the header
 * clientid = dnsreq_get(serverid, name, qtype, &clientfd, NULL, 0);
 * // change the id to clientid
 * send(clientfd, reply, replylen, 0);
 *
 */

int dnsreq_put(uint16_t clientid, const char *name, uint16_t qtype,
		int fd, struct msghdr *msg);

int dnsreq_get(uint16_t serverid, const char *name, uint16_t qtype,
		int *fd, struct msghdr *msg);

/* callback function for dnsreq_delfd and dnsreq_clean */
typedef void delcb(int fd, struct sockaddr *client_addr, socklen_t clientlen, void *arg);

/* delete all the pending queries originated by a specific fd */
void dnsreq_delfd(int fd, delcb *cb, void *arg);

/* delete all the expired queries */
void dnsreq_clean(time_t now, delcb *cb, void *arg);

#endif
