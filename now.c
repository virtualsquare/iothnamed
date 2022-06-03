/*
 * iothnamed: a domain name server/forwarder/proxy for the ioth
 * Copyright 2021 Renzo Davoli - Federico De Marchi
 *     Virtualsquare & University of Bologna
 *
 * now.c: management of 1 sec tick for expired data cleaning
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

#include <time.h>

/* USAGE:
 * now() : # of seconds (monotonic), for timestamps
 *
 * for(;;) {
 *   int nfd = poll(..., ...., ms_to_nexttick());
 *   if (nfd == 0) {
 *     time_t newnow = tick();
 *     //// clean actions
 *     continue
 *   }
 */

static time_t __now;
static time_t latest;

time_t now(void) {
	return __now;
}

time_t tick(void) {
	return __now = latest + 1;
}

long ms_to_nexttick(void) {
	struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
	latest = ts.tv_sec;
	if (__now < latest)
		return 0;
	else {
		return ((1000999999 - ts.tv_nsec) / 1000000);
	}
}

#if 0
/* test code */
#include <stdio.h>
#include <unistd.h>
#include <poll.h>
int main() {
	struct pollfd fds[] = {{0, POLLIN, 0}};
	for(;;) {
		if (poll(fds, 1, ms_to_nexttick()) > 0) {
			if (fds[0].revents) {
				char buf;
				if (read(0, &buf, 1) == 0)
					break;
				write(1, &buf, 1);
			}
		} else {
			time_t cleannow = tick();
			printf("clean %lld\n", cleannow);
			// clean data
		}
		//printf("sec %lld\n", now());
	}
}
#endif
