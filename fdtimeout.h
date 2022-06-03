#ifndef FDTIMEOUT_H
#define FDTIMEOUT_H

/* this module is used to close idle tcp client connections */

void fd_timeout_set(int timeout);
void fd_timeout_add(time_t now, int fd);
void fd_timeout_del(int fd);
typedef void fd_timeout_cb(int fd);
void fd_timeout_clean(time_t now, fd_timeout_cb *cb);
#endif
