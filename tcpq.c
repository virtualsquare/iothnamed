/*
 * iothnamed: a domain name server/forwarder/proxy for the ioth
 * Copyright 2021 Renzo Davoli - Federico De Marchi
 *     Virtualsquare & University of Bologna
 *
 * tcpq.c: queue of tcp forwarded queries waiting for an available server
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

#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>

#define DEFAULT_MAXQLEN 256

/* TCP queue */
struct tcpq {
	struct tcpq *next;
	int len;
	void *buf;
};

static struct tcpq *tcpqh, *tcpqt;
static pthread_mutex_t tcpqlock = PTHREAD_MUTEX_INITIALIZER;
static int qlen;
static int maxqlen = DEFAULT_MAXQLEN;

void tcpq_setmaxqlen(int value) {
	pthread_mutex_lock(&tcpqlock);
	maxqlen = value;
	pthread_mutex_unlock(&tcpqlock);
}

int tcpq_qlen(void) {
	int rv;
	pthread_mutex_lock(&tcpqlock);
	rv = qlen;
	pthread_mutex_unlock(&tcpqlock);
	return rv;
}

void tcpq_enqueue(void *buf, int len) {
	pthread_mutex_lock(&tcpqlock);
	if (buf != NULL && qlen < maxqlen) {
		struct tcpq *new =malloc(sizeof(*new));
		new->len = len;
		new->buf = buf;
		new->next = NULL;
		if (tcpqt == NULL)
			tcpqh = new;
		else
			tcpqt->next = new;
		tcpqt = new;
		qlen++;
	}
	pthread_mutex_unlock(&tcpqlock);
}

void *tcpq_dequeue(int *len) {
	void *rv = NULL;
	pthread_mutex_lock(&tcpqlock);
	if (tcpqh != NULL) {
		struct tcpq *this = tcpqh;
		rv = this->buf;
		*len = this->len;
		if ((tcpqh = this->next) == NULL)
			tcpqt = NULL;
		free(this);
		qlen--;
	}
	pthread_mutex_unlock(&tcpqlock);
	return rv;
}
