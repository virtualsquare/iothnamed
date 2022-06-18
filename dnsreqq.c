/*
 * iothnamed: a domain name server/forwarder/proxy for the ioth
 * Copyright 2021 Renzo Davoli - Federico De Marchi
 *     Virtualsquare & University of Bologna
 *
 * dnsreqq.c: query queue for forwarding
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

#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <list.h>
#include <utils.h>
#include <now.h>
#include <dnsreqq.h>

struct dnsreq {
	struct nl_list_head reqq;
	struct nl_list_head fdlist;
	time_t expire;
	uint64_t namehash;
	uint16_t clientid;
	uint16_t serverid;
	uint16_t qtype;
	int fd;
	socklen_t salen;
	size_t ctllen;
	struct sockaddr sa[];
};

#define TIMEOUT 3

#define MAXREQ 1024
#define FDHASH 128
static NL_LIST_HEAD_INIT(reqq);
static struct dnsreq *reqtab[MAXREQ];
static pthread_mutex_t reqmutex = PTHREAD_MUTEX_INITIALIZER;
static struct nl_list_head fdhash[FDHASH];

#define err_return(err) do {\
	errno = err; \
	pthread_mutex_unlock(&reqmutex); \
	return -1; \
} while(0)

__attribute__((constructor))
	static void init(void) {
		for (int i = 0; i < FDHASH; i++)
			NL_INIT_LIST_HEAD(&fdhash[i]);
	}

static void *controladdr(struct dnsreq *req) {
	uint8_t *addr = (void *) (req->sa);
	return addr + req->salen;
}

int dnsreq_put(uint16_t clientid, const char *name, uint16_t qtype,
		int fd, struct msghdr *msg) {

	uint16_t serverid = random();
	int i;
	pthread_mutex_lock(&reqmutex);
	/* linear probing on retab. In this way the matching reply
	 * can be found in O(1) time */
	for (i = 0; i < MAXREQ; i++, serverid++) {
		if (reqtab[serverid % MAXREQ] == NULL)
			break;
	}
	if (i == MAXREQ)
		err_return(ENOMEM);
	struct dnsreq *new;
	size_t newsize = sizeof(*new) +
		((msg == NULL) ? 0 : (msg->msg_namelen + msg->msg_controllen));
	new = malloc(newsize);
	if (new == NULL)
		err_return(ENOMEM);
	new->expire = now() + TIMEOUT;
	new->namehash = simple_stringhash(name);
	new->clientid = clientid;
	new->serverid = serverid;
	new->qtype = qtype;
	new->fd = fd;
	if (msg == NULL) {
		new->salen = 0;
		new->ctllen = 0;
	} else {
		new->salen = msg->msg_namelen;
		new->ctllen = msg->msg_controllen;
		if (msg->msg_namelen > 0)
			memcpy(new->sa, msg->msg_name, msg->msg_namelen);
		if (msg->msg_controllen > 0)
			memcpy(controladdr(new), msg->msg_control, msg->msg_controllen);
	}
	nl_list_add_tail(&new->reqq, &reqq);
	nl_list_add_tail(&new->fdlist, &fdhash[fd % FDHASH]);
	reqtab[serverid % MAXREQ] = new;
	pthread_mutex_unlock(&reqmutex);
	return serverid;
}

static void dnsreq_del(struct dnsreq *this) {
	nl_list_del(&this->reqq);
	nl_list_del(&this->fdlist);
	reqtab[this->serverid % MAXREQ] = NULL;
	free(this);
}

int dnsreq_get(uint16_t serverid, const char *name, uint16_t qtype,
		int *fd, struct msghdr *msg) {
	struct dnsreq *this = reqtab[serverid % MAXREQ];
	pthread_mutex_lock(&reqmutex);
	if (this == NULL || qtype != this->qtype || serverid != this->serverid ||
			simple_stringhash(name) != this->namehash)
		err_return(ENOENT);
	uint16_t clientid = this->clientid;
	if (msg != NULL) {
		if (this->salen <= msg->msg_namelen) {
			msg->msg_namelen = this->salen;
			memcpy(msg->msg_name, this->sa, this->salen);
		} else
			msg->msg_namelen = 0;
		if (this->ctllen <= msg->msg_controllen) {
			msg->msg_controllen = this->ctllen;
			memcpy(msg->msg_control, controladdr(this), this->ctllen);
		} else
			msg->msg_controllen = 0;
	}
	*fd = this->fd;
	dnsreq_del(this);
	pthread_mutex_unlock(&reqmutex);
	return clientid;
}

void dnsreq_delfd(int fd, delcb *cb, void *arg) {
	struct dnsreq *scan, *tmp;
	pthread_mutex_unlock(&reqmutex);
	nl_list_for_each_entry_safe(scan, tmp, &fdhash[fd % FDHASH], fdlist) {
		if (scan->fd == fd) {
			if (cb)
				cb(scan->fd, scan->salen ? scan->sa : NULL, scan->salen, arg);
			// printf("DELFD %d %d\n", scan->clientid, scan->serverid);
			dnsreq_del(scan);
		}
	}
	pthread_mutex_unlock(&reqmutex);
}

void dnsreq_clean(time_t now, delcb *cb, void *arg) {
	struct dnsreq *scan, *tmp;
	pthread_mutex_unlock(&reqmutex);
	nl_list_for_each_entry_safe(scan, tmp, &reqq, reqq) {
		if (scan->expire < now) {
			if (cb)
				cb(scan->fd, scan->salen ? scan->sa : NULL, scan->salen, arg);
			// printf("DEL %d %d\n", scan->clientid, scan->serverid);
			dnsreq_del(scan);
		} else
			break;
	}
	pthread_mutex_unlock(&reqmutex);
}
