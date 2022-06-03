#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include <list.h>

static int fdtimeout = 60;

static pthread_mutex_t fdto_mutex = PTHREAD_MUTEX_INITIALIZER;

static NL_LIST_HEAD_INIT(fdtohead);

struct fdto {
	struct nl_list_head fdto_list;
	int fd;
	time_t expiretime;
};

void fd_timeout_set(int timeout) {
	if (timeout > 0)
		fdtimeout = timeout;
}

void fd_timeout_add(time_t now, int fd) {
	struct fdto *scan;
	pthread_mutex_lock(&fdto_mutex);
	nl_list_for_each_entry(scan, &fdtohead, fdto_list) {
		if (scan->fd == fd) {
			scan->expiretime = now + fdtimeout;
			pthread_mutex_unlock(&fdto_mutex);
			return;
		}
	}
	if ((scan = malloc(sizeof(*scan))) != NULL) {
		scan->fd = fd;
		scan->expiretime = now + fdtimeout;
		nl_list_add_tail(&scan->fdto_list, &fdtohead);
	}
	pthread_mutex_unlock(&fdto_mutex);
}

void fd_timeout_del(int fd) {
	struct fdto *scan, *tmp;
	pthread_mutex_lock(&fdto_mutex);
	nl_list_for_each_entry_safe(scan, tmp, &fdtohead, fdto_list) {
		if (scan->fd == fd) {
			nl_list_del(&scan->fdto_list);
			free(scan);
			break;
		}
	}
	pthread_mutex_unlock(&fdto_mutex);
}

typedef void fd_timeout_cb(int fd);
void fd_timeout_clean(time_t now, fd_timeout_cb *cb) {
	struct fdto *scan, *tmp;
	pthread_mutex_lock(&fdto_mutex);
	nl_list_for_each_entry_safe(scan, tmp, &fdtohead, fdto_list) {
		if (scan->expiretime <= now) {
			cb(scan->fd);
			nl_list_del(&scan->fdto_list);
			free(scan);
		}
	}
	pthread_mutex_unlock(&fdto_mutex);
}

#if 0
#include <stdio.h>
#include <unistd.h>
void bb(int fd) {
	printf("clean %d\n", fd);
}

int main(int argc, char *argv[]) {
	fd_timeout_set(3);
	fd_timeout_add(time(NULL), 1);
	fd_timeout_add(time(NULL), 2);
	printf("time %d\n", time(NULL));
	sleep(1); printf("time %d\n", time(NULL)); fd_timeout_clean(time(NULL), bb);
	sleep(1); printf("time %d\n", time(NULL)); fd_timeout_clean(time(NULL), bb);
	sleep(1); printf("time %d\n", time(NULL)); fd_timeout_clean(time(NULL), bb);
	fd_timeout_add(time(NULL), 4);
	fd_timeout_add(time(NULL), 5);
	fd_timeout_add(time(NULL), 6);
	sleep(1); printf("time %d\n", time(NULL)); fd_timeout_clean(time(NULL), bb);
	fd_timeout_del(4);
	fd_timeout_del(5);
	sleep(1); printf("time %d\n", time(NULL)); fd_timeout_clean(time(NULL), bb);
	sleep(1); printf("time %d\n", time(NULL)); fd_timeout_clean(time(NULL), bb);
	sleep(1); printf("time %d\n", time(NULL)); fd_timeout_clean(time(NULL), bb);
	sleep(1); printf("time %d\n", time(NULL)); fd_timeout_clean(time(NULL), bb);
	sleep(1); printf("time %d\n", time(NULL)); fd_timeout_clean(time(NULL), bb);
	sleep(1); printf("time %d\n", time(NULL)); fd_timeout_clean(time(NULL), bb);
}
#endif
