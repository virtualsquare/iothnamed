/*
 * iothnamed: a domain name server/forwarder/proxy for the ioth
 * Copyright 2021 Renzo Davoli - Federico De Marchi
 *     Virtualsquare & University of Bologna
 *
 * mainloop.c: main event loop
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
#include <stdint.h>
#include <stdlib.h>
#include <poll.h>

#include <sys/epoll.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ioth.h>
#include <iothconf.h>
#include <iothdns.h>

#include <utils.h>
#include <arpainetx.h>
#include <tcpq.h>
#include <now.h>
#include <dnsreqq.h>
#include <auth.h>
#include <cache.h>
#include <dnsheader_flags.h>
#include <process_dns_req.h>
#include <fdtimeout.h>

#define DNS_UDP_PORT 53
#define ckretval(retval, X) do { \
	if (retval < 0) { \
		printlog(LOG_ERR, X ": %s", strerror(errno)); \
		return -1; \
	} \
} while (0)

static struct ioth *rstack; // req stack
static struct ioth *fstack; // fwd stack
static struct in6_addr *fwdaddr;
static int fwdaddr_count;
static int fwdaddr_rr; // round robin scan index

static int epollfd;
/* fd names: xyfd where:
	 x == 'u' -> UDP
	 x == 't' -> TCP
	 y == 'r' -> client requests
	 y == 'f' -> forwarding
	 y == 'l' -> listening (tcp) */
static int urfd = -1;  // udp requests fd
static int uffd = -1;  // udp forward fd
static int tlfd = -1;  // tcp listen fd
static int tffd[IOTHDNS_MAXNS] = {-1, -1, -1};  // tcp forward fd

static int tcp_listen_backlog = 5;

static void tcp_timeout_cb(int fd) {
	ioth_shutdown(fd, SHUT_RDWR);
}

void cleaning(time_t now) {
	dnsreq_clean(now, NULL, NULL);
	cache_clean(now);
	fd_timeout_clean(now, tcp_timeout_cb);
}

/* UDP forwarder */

/* POLLIN event from a UDP client */
void process_urfd(void) {
	char buf[IOTHDNS_UDP_MAXBUF];
	struct sockaddr_in6 sock;
	socklen_t socklen = sizeof(sock);
	struct iothdns_header h;
	char qnamebuf[IOTHDNS_MAXNAME];
	size_t len = ioth_recvfrom(urfd, buf, IOTHDNS_UDP_MAXBUF, 0, (struct sockaddr *) &sock, &socklen);
	struct iothdns_pkt *pkt = iothdns_get_header(&h, buf, len, qnamebuf);
	if (pkt) {
		struct iothdns_pkt *rpkt = process_dns_req(&h, &sock.sin6_addr);
		if (rpkt != NULL) {
			size_t buflen = iothdns_buflen(rpkt);
			if (buflen > IOTHDNS_UDP_MAXBUF) {
				struct iothdns_header th = h;
				th.flags = FLAGS_TRUNC(th.flags);
				struct iothdns_pkt *tpkt = iothdns_put_header(&th);
				ioth_sendto(urfd, iothdns_buf(tpkt), iothdns_buflen(tpkt), 0, (struct sockaddr *)&sock, socklen);
				iothdns_free(tpkt);
			} else
				ioth_sendto(urfd, iothdns_buf(rpkt), buflen, 0, (struct sockaddr *)&sock, socklen);
			iothdns_free(rpkt);
		} else if (fwdaddr_count > 0){
			int serverid = dnsreq_put(h.id, h.qname, h.qtype, urfd, (struct sockaddr *) &sock, socklen);
			iothdns_rewrite_header(pkt, serverid, h.flags);
#if FWD_PKT_DUMP
			printf("%d %d\n",h.id,serverid);
			printf("========>>>>>>>>>>>>\n");
			packetdump(stdout, buf, len);
#endif
			struct sockaddr_in6 sfwd = {
				.sin6_family = AF_INET6,
				.sin6_addr = fwdaddr[fwdaddr_rr],
				.sin6_port = htons(DNS_UDP_PORT)};
			ioth_sendto(uffd, buf, len, 0, (struct sockaddr *)&sfwd, sizeof(sfwd));
			fwdaddr_rr = (fwdaddr_rr + 1) % fwdaddr_count;
		}
		iothdns_free(pkt);
	}
}

/* POLLIN event from a UDP remote DNS server (reply to a forwarded request)  */
void process_uffd(void) {
	char buf[IOTHDNS_UDP_MAXBUF];
	struct sockaddr_in6 sock;
	socklen_t socklen = sizeof(sock);
	struct iothdns_header h;
	char qnamebuf[IOTHDNS_MAXNAME];
	size_t len = ioth_recv(uffd, buf, IOTHDNS_UDP_MAXBUF, 0);
#if FWD_PKT_DUMP
	printf("========<<<<<<<<<<<<\n");
	packetdump(stdout, buf, len);
#endif
	struct iothdns_pkt *pkt = iothdns_get_header(&h, buf, len, qnamebuf);
	if (pkt) {
		int fd;
		if (auth_isactive(AUTH_CACHE))
			cache_feed(pkt);
		int clientid = dnsreq_get(h.id, h.qname, h.qtype, &fd, (struct sockaddr *) &sock, &socklen);
#if FWD_PKT_DUMP
		printf("%d %d\n",h.id,clientid);
#endif
		if  (clientid != -1 && fd == urfd) {
			iothdns_rewrite_header(pkt, clientid, h.flags);
			ioth_sendto(urfd, iothdns_buf(pkt), iothdns_buflen(pkt), 0, (struct sockaddr *) &sock, socklen);
		}
		iothdns_free(pkt);
	}
}

/* TCP forwarder */

/* add the TCP header (length) */
ssize_t dns_tcp_send(int fd, void *buf, size_t len, int flags) {
  uint8_t hlen[2];
  struct iovec iov[2] = {{hlen, 2},{buf, len}};
  struct msghdr msg = {.msg_iov = iov, .msg_iovlen = 2};
  hlen[0] = len >> 8;
  hlen[1] = len;
#if FWD_PKT_DUMP
	printf("sendmsg %d\n", fd);
#endif
  return ioth_sendmsg(fd, &msg, flags);
}

struct tcpdata {
	int fd;
	uint16_t len;  /* len of the current request */
	uint16_t pos;  /* offset for reading the remaining part of the request */
	/*                the request is complete when pos == len */
	uint8_t *buf;  /* syn-allocated buffer, NULL if no packet is currently processed */
};

/* reconstruct DNS requests on TCP stream */
ssize_t dns_tcp_recv(struct tcpdata *td) {
	ssize_t rlen;
	if (td->buf == NULL) { /* new packet */
		uint8_t hlen[2] = {0, 0};
		if ((rlen = recv(td->fd, hlen, 2, 0)) <= 0)
			return rlen;
		td->len = (hlen[0] << 8) + hlen[1];
		td->pos = 0;
		td->buf = malloc(td->len);
	} else {
		/* try to get the remaining part of the incoming request */
		if ((rlen = recv(td->fd, td->buf + td->pos, td->len - td->pos, 0)) <= 0)
			return rlen;
		td->pos += rlen;
	}
	return rlen;
}

/* POLLIN event on a TCP listener -> accept */
void process_tlfd(void) {
	struct sockaddr_in6 sock;
	socklen_t socklen = sizeof(sock);
	int connfd = ioth_accept(tlfd, (struct sockaddr *)&sock, &socklen);
	if (connfd >= 0) {
		if (authck(AUTH_ACCEPT, &sock.sin6_addr) == 0)
			close(connfd);
		else {
			struct tcpdata *td = calloc(1, sizeof(*td));
			td->fd = connfd;
			fd_timeout_add(now(), connfd);
			epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &((struct epoll_event){.events=POLLIN, .data.ptr = td}));
		}
	}
}

/* There is data in tcpq to the forwarding server */
static int wake_tcp(void) {
	/* if the connection to the server is not active, do a asynch connect */
	struct epoll_event ev = {
		.events=POLLIN | POLLOUT,
		.data.ptr = &tffd[fwdaddr_rr]
	};
	if (tffd[fwdaddr_rr] < 0) {
		int retval;
		struct sockaddr_in6 sfwd = {.sin6_family = AF_INET6, .sin6_addr = fwdaddr[fwdaddr_rr], .sin6_port = htons(DNS_UDP_PORT)};
		retval = tffd[fwdaddr_rr] = ioth_msocket(fstack, AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
		ckretval(retval, "tcp forward fd msocket");
		retval = ioth_connect(tffd[fwdaddr_rr], (struct sockaddr *)&sfwd, sizeof(sfwd));
		if (retval < 0 && errno != EINPROGRESS)
			ckretval(retval, "tcp forward fd connect");
		epoll_ctl(epollfd, EPOLL_CTL_ADD, tffd[fwdaddr_rr], &ev);
	} else
		epoll_ctl(epollfd, EPOLL_CTL_MOD, tffd[fwdaddr_rr], &ev);
	fwdaddr_rr = (fwdaddr_rr + 1) % fwdaddr_count;
	return 0;
}

/* POLLIN event from a TCP client */
void process_trfd(void *data) {
	struct tcpdata *td = data;
	ssize_t rlen = dns_tcp_recv(td);
	if (rlen <= 0) {
		/* the client prematurely closed the stream */
		/* delete the epoll entry */
		epoll_ctl(epollfd, EPOLL_CTL_DEL, td->fd, NULL);
		/* drop all the pending requests */
		dnsreq_delfd(td->fd, NULL, NULL);
		fd_timeout_del(td->fd);
		close(td->fd);
		if (td->buf) free(td->buf);
		free(td);
	} else if (td->pos == td->len) {
		/* the incoming request is complete, it can be processed */
		struct iothdns_header h;
		char qnamebuf[IOTHDNS_MAXNAME];
		struct iothdns_pkt *pkt = iothdns_get_header(&h, td->buf, td->len, qnamebuf);
		if (pkt) {
			struct sockaddr_in6 sock;
			socklen_t socklen = sizeof(sock);
			fd_timeout_add(now(), td->fd);
			getpeername(td->fd, (struct sockaddr *)&sock, &socklen);
			struct iothdns_pkt *rpkt = process_dns_req(&h, &sock.sin6_addr);
			if (rpkt != NULL) {
				dns_tcp_send(td->fd, iothdns_buf(rpkt), iothdns_buflen(rpkt), 0);
				iothdns_free(rpkt);
			} else {
				/* forward the packet */
				int serverid = dnsreq_put(h.id, h.qname, h.qtype, td->fd, NULL, 0);
				if (serverid >= 0) {
					iothdns_rewrite_header(pkt, serverid, h.flags);
#if FWD_PKT_DUMP
					printf("%d %d\n",h.id,serverid);
					printf("========>>>>>>>>>>>>\n");
					packetdump(stdout, td->buf, td->len);
#endif
					/* tcpq_enqueue delays the send to a POLLOUT event on the connection to the remote DNS server */
					/* the queue is shared: it is more a feature than a bug.
					 * A fast server can steal requests intentionally for another server */
					tcpq_enqueue(td->buf, td->len);
					wake_tcp();
					/* this avoids to free the buf, enqueued for the delayed sending */
					td->buf = NULL;
				}
			}
			iothdns_free(pkt);
		}
		if (td->buf) free(td->buf);
		td->len = td->pos = 0;
		td->buf = NULL;
	}
}

/* POLLIN event from a TCP remote DNS server (reply to a forwarded request) */
void process_tffd(int index, uint32_t events) {
	if (events & POLLOUT) {
		/* POLLOUT event, the stream is connected and ready, send the next packet from tcpq */
		int len;
		void *buf = tcpq_dequeue(&len);
		if (buf == NULL) {
			struct epoll_event ev = {
				.events=POLLIN,
				.data.ptr = &tffd[index]
			};
			/* cease to wait for POLLOUT if no more packets in tcpq */
			epoll_ctl(epollfd, EPOLL_CTL_MOD, tffd[index], &ev);
		} else {
			/* send the pkt and free the buf */
			dns_tcp_send(tffd[index], buf, len, 0);
			free(buf);
		}
	}
	if (events & POLLIN) {
		/* POLLIN -> incoming reply */
		static struct tcpdata td[IOTHDNS_MAXNS];
		td[index].fd = tffd[index];
		ssize_t rlen = dns_tcp_recv(&td[index]);
		if (rlen <= 0) {
			tffd[index] = -1;
			close(td[index].fd);
			if (td[index].buf) free(td[index].buf);
		} else if (td[index].pos == td[index].len) {
			struct iothdns_header h;
			char qnamebuf[IOTHDNS_MAXNAME];
			struct iothdns_pkt *pkt = iothdns_get_header(&h, td[index].buf, td[index].len, qnamebuf);
			if (pkt) {
				int fd;
				if (auth_isactive(AUTH_CACHE))
					cache_feed(pkt);
				int clientid = dnsreq_get(h.id, h.qname, h.qtype, &fd, NULL, NULL);
				if (clientid >= 0) {
					iothdns_rewrite_header(pkt, clientid, h.flags);
#if FWD_PKT_DUMP
					printf("%d %d\n",h.id,clientid);
					printf("========<<<<<<<<<<<<\n");
					packetdump(stdout, iothdns_buf(pkt), iothdns_buflen(pkt));
#endif
					dns_tcp_send(fd, iothdns_buf(pkt), iothdns_buflen(pkt), 0);
				}
				iothdns_free(pkt);
				td[index].len = td[index].pos = 0;
				free(td[index].buf);
				td[index].buf = NULL;
			}
		}
	}
}

#define NEVENTS 8

int mainloop(struct ioth *_rstack, struct ioth *_fstack, struct in6_addr *_fwdaddr, int _fwdaddr_count) {
	int retval;
	rstack = _rstack;
	fstack = _fstack;
	fwdaddr = _fwdaddr;
	fwdaddr_count = _fwdaddr_count;

	struct sockaddr_in6 scli = {.sin6_family = AF_INET6, .sin6_addr = in6addr_any, .sin6_port = htons(DNS_UDP_PORT)};

	retval = urfd = ioth_msocket(rstack, AF_INET6, SOCK_DGRAM, 0);
	ckretval(retval, "udp request fd msocket");
	retval = ioth_bind(urfd, (struct sockaddr *)&scli, sizeof(scli));
	ckretval(retval, "udp request fd bind");

	retval = tlfd = ioth_msocket(rstack, AF_INET6, SOCK_STREAM, 0);
	ckretval(retval, "tcp listening fd msocket");
	retval = ioth_bind(tlfd, (struct sockaddr *)&scli, sizeof(scli));
	ckretval(retval, "tcp listening fd bind");
	retval = ioth_listen(tlfd, tcp_listen_backlog);
	ckretval(retval, "tcp listening fd listen");

	retval = uffd = ioth_msocket(fstack, AF_INET6, SOCK_DGRAM, 0);
	ckretval(retval, "udp forward fd msocket");

	epollfd = epoll_create1(0);
	epoll_ctl(epollfd, EPOLL_CTL_ADD, urfd, &((struct epoll_event){.events=POLLIN, .data.ptr = &urfd}));
	epoll_ctl(epollfd, EPOLL_CTL_ADD, tlfd, &((struct epoll_event){.events=POLLIN, .data.ptr = &tlfd}));
	epoll_ctl(epollfd, EPOLL_CTL_ADD, uffd, &((struct epoll_event){.events=POLLIN, .data.ptr = &uffd}));

	while (alive()) {
		struct epoll_event ev[NEVENTS];
		int nfd = epoll_wait(epollfd, ev, NEVENTS, ms_to_nexttick());
		if (nfd == 0) {
			// new sec: cleaning actions
			time_t newnow = tick();
			cleaning(newnow);
		} else for (int i = 0; i < nfd; i++) {
			struct epoll_event *event = &ev[i];
			if (event->data.ptr == &urfd)          // UDP client request
				process_urfd();
			else if (event->data.ptr == &uffd)     // UDP reply from the server
				process_uffd();
			else if (event->data.ptr == &tlfd)     // TCP new client connection
				process_tlfd();
			else if (event->data.ptr == &tffd[0])     // TCP data from the server 0
				process_tffd(0, event->events);
			else if (event->data.ptr == &tffd[1])     // TCP data from the server 1
				process_tffd(1, event->events);
			else if (event->data.ptr == &tffd[2])     // TCP data from the server 2
				process_tffd(2, event->events);
			else                                   // TCP data from a client
				process_trfd(event->data.ptr);
		}
	}
	return 0;
}

void mainloop_set_hashttl(int ttl) {
	process_dns_req_set_hashttl(ttl);
}

void mainloop_set_tcp_listen_backlog(int backlog) {
	if (backlog >= 0)
		tcp_listen_backlog = backlog;
}

void mainloop_set_tcp_timeout(int timeout) {
	fd_timeout_set(timeout);
}
