#ifndef _UTILS_H
#define _UTILS_H
#include <stdio.h>
#include <stdint.h>
#include <syslog.h>

void startlog(char *prog, int use_syslog);
void printlog(int priority, const char *format, ...);
void save_pidfile(char *pidfile, char *cwd);
void setsignals(void);
int alive(void);

void *memdup(const void *src, size_t n);

uint64_t simple_stringhash(const char *str);

void packetdump(FILE *f, void *arg,ssize_t len);

#endif
