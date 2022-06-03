#ifndef _MAINLOOP_H
#define _MAINLOOP_H

void mainloop(struct ioth *rstack, struct ioth *fstack, struct in6_addr *fwdaddr, int fwdaddr_count);

void mainloop_set_hashttl(int ttl);
void mainloop_set_tcp_listen_backlog(int backlog);

#endif
