/*
 * iothnamed: a domain name server/forwarder/proxy for the ioth
 * Copyright 2021 Renzo Davoli - Federico De Marchi
 *     Virtualsquare & University of Bologna
 *
 * main.c: main program
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
#include <stdlib.h>
#include <stddef.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ioth.h>
#include <iothconf.h>
#include <iothdns.h>
#include <stropt.h>

#include <strcase.h>
#include <auth.h>
#include <mainloop.h>
#include <cache.h>
#include <arpainetx.h>
#include <utils.h>

static struct ioth *rstack; // req stack
static struct ioth *fstack; // fwd stack
static int fwdaddr_count;
static struct in6_addr fwdaddr[IOTHDNS_MAXNS];

static int stropt_spaces(const char *input, char **tags, char *buf) {
	return stroptx(input, "'\"\\", " \t", 0, tags, NULL, buf);
}

static int conf_parse_option(char *entry) {
  int tagc = stropt_spaces(entry, NULL, NULL);
  if (tagc < 1)
    return errno = EINVAL, -1;
  else {
    char *tags[tagc];
    stropt_spaces(entry, tags, entry);
    switch(strcase_tolower(tags[0])) {
			case STRCASE(h,r,e,v,m,o,d,e):
				if (tagc != 3)
					return errno = EINVAL, -1;
				switch(strcase_tolower(tags[1])) {
					case STRCASE(a,l,w,a,y,s):
						auth_hashrev_setmode(HASHREV_ALWAYS);
						break;
					case STRCASE(n,e,t):
						auth_hashrev_setmode(HASHREV_NET);
						break;
					case STRCASE(s,a,m,e):
						auth_hashrev_setmode(HASHREV_SAME);
						break;
					case STRCASE(n,e,v,e,r):
						auth_hashrev_setmode(HASHREV_NEVER);
						break;
					default:
						return errno = EINVAL, -1;
				}
				break;
			case STRCASE(h,a,s,h,t,t,l):
				if (tagc != 3)
					return errno = EINVAL, -1;
				mainloop_set_hashttl(strtol(tags[1], NULL, 10));
				break;
			case STRCASE(t,c,p,l,i,s,t,e,n):
				if (tagc != 3)
					return errno = EINVAL, -1;
				mainloop_set_tcp_listen_backlog(strtol(tags[1], NULL, 10));
				break;
			case STRCASE(t,c,p,t,i,m,e,o,u,t):
				if (tagc != 3)
					return errno = EINVAL, -1;
				mainloop_set_tcp_timeout(strtol(tags[1], NULL, 10));
				break;
			default:
				return errno = EINVAL, -1;
		}
	}
	return 0;
}

static int conf_parse_static(char *entry) {
	int tagc = stropt_spaces(entry, NULL, NULL);
	if (tagc < 3)
		return errno = EINVAL, -1;
	else {
		char *tags[tagc];
		stropt_spaces(entry, tags, entry);
		switch(strcase_tolower(tags[0])) {
			case STRCASE(a):
				{
					struct in_addr in;
					if (tagc != 4 || inet_pton(AF_INET, tags[2], &in) != 1)
						return errno = EINVAL, -1;
					cache_static_add(tags[1], IOTHDNS_TYPE_A, &in);
				}
				break;
			case STRCASE(a,a,a,a):
				{
					struct in6_addr in6;
					if (tagc != 4 || inet_pton(AF_INET6, tags[2], &in6) != 1)
						return errno = EINVAL, -1;
					cache_static_add(tags[1], IOTHDNS_TYPE_AAAA, &in6);
				}
				break;
			case STRCASE(p,t,r):
				{
					char revbuf[INET6_REVSTRLEN];
					const char *revname;
					if (tagc != 4 ||
							(revname = inet_ptor(tags[1],  revbuf, INET6_REVSTRLEN)) == NULL)
						return errno = EINVAL, -1;
					cache_static_add(revname, IOTHDNS_TYPE_PTR, tags[2]);
				}
				break;
			case STRCASE(n,s):
				if (tagc != 4)
					return errno = EINVAL, -1;
				cache_static_add(tags[1], IOTHDNS_TYPE_NS, tags[2]);
				break;
			case STRCASE(c,n,a,m,e):
				if (tagc != 4)
					return errno = EINVAL, -1;
				cache_static_add(tags[1], IOTHDNS_TYPE_CNAME, tags[2]);
				break;
			case STRCASE(t,x,t):
				{
					char *buf = NULL;
					size_t len = 0;
					FILE *f = open_memstream(&buf, &len);
					for (int i = 2; i < tagc - 1; i++) {
						size_t slen = strlen(tags[i]);
						if (slen > 255) slen = 255;
						fputc(slen, f);
						fwrite(tags[i], slen, 1, f);
					}
					fclose(f);
					cache_static_add(tags[1], IOTHDNS_TYPE_TXT, len, buf);
					free(buf);
				}
				break;
			case STRCASE(m,x):
				if (tagc != 5)
					return errno = EINVAL, -1;
				cache_static_add(tags[1], IOTHDNS_TYPE_MX, strtol(tags[2], NULL, 10), tags[3]);
				break;
			default:
				return errno = EINVAL, -1;
		}
	}
	return 0;
}

/* lookup in the dns if there is a 'AAAA" match for name */
static int lookup_aaaa(const char *name, struct in6_addr *addr) {
	struct iothdns *iothdns = iothdns_init_strcfg(fstack, "");
	int rv = 0;
	if (iothdns != NULL) {
		iothdns_add_nameserver(iothdns, AF_INET6, &fwdaddr[0]);
		if (iothdns_lookup_aaaa(iothdns, name, addr, 1) > 0)
			rv = 1;
		iothdns_fini(iothdns);
	}
	return rv;
}

/* convert src addrs like "hash.map.v2.cs.unibo.it/64" to a domain name for reverse queries
 * .0.0.f.f.0.0.e.2.0.6.7.0.1.0.0.2.ip6.arpa using an AAAA query
 * (hash.map.v2.cs.unibo.it has IPv6 address 2001:760:2e00:ff00::) */
static const char *inet_aaaator(const char *src, char *dst, socklen_t size) {
	size_t srclen = strlen(src) + 1;
  char _src[srclen];
  char *_prefix;
  snprintf(_src, srclen, "%s", src);
  if ((_prefix  = strchr(_src, '/')) != NULL) {
		struct in6_addr addr;
    *(_prefix++) = '\0';
		if (lookup_aaaa(_src, &addr) > 0) {
			int prefix = (_prefix == NULL) ? 128 : strtol(_prefix, NULL, 10);
			return inet_ntorx(AF_INET6, &addr, prefix, dst, size);
		}
	}
	return src;
}

int parsercfile(char *path) {
	int retvalue = 0;
	FILE *f = fopen(path, "r");
	if (f == NULL) {
		printlog(LOG_ERR, "configuration file: %s", strerror(errno));
		return -1;
	}
	char *line = NULL;
	size_t len;
	for (int lineno = 1; getline(&line, &len, f) > 0; lineno++) { //foreach line
		char *scan = line;
		while (*scan && strchr("\t ", *scan)) scan++; //skip heading spaces
		if (strchr("#\n", *scan)) continue; // comments and empty lines
		int len = strlen(scan);
		char optname[len], value[len];
		// parse the line
		*value = 0;
		/* optname <- the first alphanumeric field (%[a-zA-Z0-9])
			 value <- the remaining of the line not including \n (%[^\n])
			 and discard the \n (%*c) */
		if (sscanf (line, "%[a-zA-Z0-9] %[^\n]%*c", optname, value) > 0) {
			switch(strcase_tolower(optname)) {
				case STRCASE(s,t,a,c,k):
					if (rstack == NULL && fstack == NULL) {
						if ((rstack = fstack = ioth_newstackc(value)) == NULL) {
							printlog(LOG_ERR, "%s (line %d): %s error opening stack", path, lineno, optname);
							errno = EINVAL, retvalue = -1;
						}
					} else {
						printlog(LOG_ERR, "%s (line %d): %s can be defined only once", path, lineno, optname);
						errno = EINVAL, retvalue = -1;
					}
					break;
				case STRCASE(r,s,t,a,c,k):
					if (rstack == NULL) {
						if ((rstack = ioth_newstackc(value)) == NULL) {
							printlog(LOG_ERR, "%s (line %d): %s error opening stack", path, lineno, optname);
							errno = EINVAL, retvalue = -1;
						}
					} else {
						printlog(LOG_ERR, "%s (line %d): %s can be defined only once", path, lineno, optname);
						errno = EINVAL, retvalue = -1;
					}
					break;
				case STRCASE(f,s,t,a,c,k):
					if (fstack == NULL) {
						if ((fstack = ioth_newstackc(value)) == NULL) {
							printlog(LOG_ERR, "%s (line %d): %s error opening stack", path, lineno, optname);
							errno = EINVAL, retvalue = -1;
						}
					} else {
						printlog(LOG_ERR, "%s (line %d): %s can be defined only once", path, lineno, optname);
						errno = EINVAL, retvalue = -1;
					}
					break;
				case STRCASE(d,n,s):
					if (fwdaddr_count >= IOTHDNS_MAXNS) {
						printlog(LOG_ERR, "%s (line %d): up to three %s may be listed", path, lineno, optname);
						errno = EINVAL, retvalue = -1;
					} else {
						if (inet_ptonx(AF_INET6, value, &fwdaddr[fwdaddr_count]) == 1)
							fwdaddr_count++;
						else {
							printlog(LOG_ERR, "%s (line %d): syntax error in %s definition", path, lineno, optname);
							errno = EINVAL, retvalue = -1;
						}
					}
					break;
				case STRCASE(n,e,t):
					{
						int tagc = stropt_spaces(value, NULL, NULL);
						if (tagc != 3) {
							printlog(LOG_ERR, "%s (line %d): arg count mismatch for %s", path, lineno, optname);
							errno = EINVAL, retvalue = -1;
						} else {
							char *tags[tagc];
							stropt_spaces(value, tags, value);
							if (auth_add_net(tags[0], tags[1]) < 0) {
								printlog(LOG_ERR, "%s (line %d): syntax error in %s definition", path, lineno, optname);
								errno = EINVAL, retvalue = -1;
							}
						}
					}
					break;
				case STRCASE(a,u,t,h):
					{
						int tagc = stropt_spaces(value, NULL, NULL);
						if (tagc < 3 || tagc > 6) {
							printlog(LOG_ERR, "%s (line %d): arg count mismatch for %s", path, lineno, optname);
							errno = EINVAL, retvalue = -1;
						} else {
							char *tags[6] ={NULL, NULL, NULL, NULL, NULL, NULL };
							stropt_spaces(value, tags, value);
							const char *addr = NULL;
							struct in6_addr baseaddrbuf;
							struct in6_addr *baseaddr = NULL;
							char revbuf[INET6_REVSTRLEN];
							if (tags[2] != NULL) {
								addr = inet_ptor(tags[2], revbuf, INET6_REVSTRLEN);
								/* if it is not a numeric IPv4/IPv6 addr, try to query the DNS */
								if (addr == tags[2] && strchr(addr, '/') != NULL)
									addr = inet_aaaator(tags[2], revbuf, INET6_REVSTRLEN);
							}
							if (tags[3] != NULL) {
								if (lookup_aaaa(tags[3], &baseaddrbuf))
									baseaddr = &baseaddrbuf;
								if (baseaddr == NULL &&
										inet_ptonx(AF_INET6, tags[3], &baseaddrbuf) == 1)
									baseaddr = &baseaddrbuf;
							}
							if (auth_add_auth(tags[0], tags[1], addr, baseaddr, tags[4]) < 0) {
								printlog(LOG_ERR, "%s (line %d): syntax error in %s definition", path, lineno, optname);
								errno = EINVAL, retvalue = -1;
							}
						}
					}
					break;
				case STRCASE(s,t,a,t,i,c):
					if (conf_parse_static(value) < 0) {
						printlog(LOG_ERR, "%s (line %d): syntax error in %s definition", path, lineno, optname);
						errno = EINVAL, retvalue = -1;
					}
					break;
				case STRCASE(o,p,t,i,o,n):
					if (conf_parse_option(value) < 0) {
						printlog(LOG_ERR, "%s (line %d): syntax error in %s definition", path, lineno, optname);
						errno = EINVAL, retvalue = -1;
					}
					break;
				default:
					printlog(LOG_ERR, "%s (line %d): unknown directive %s", path, lineno, optname);
					errno = EINVAL, retvalue = -1;
			}
		} else {
			printlog(LOG_ERR, "%s (line %d): syntax error", path, lineno);
			errno = EINVAL, retvalue = -1;
		}
	}
	fclose(f);
	if (line) free(line);
	return retvalue;
}

void usage(char *progname)
{
	fprintf(stderr,"Usage: %s OPTIONS CONFFILE\n"
			"\t--daemon|-d\n"
			"\t--pidfile|-p <pidfile>\n"
			"\t--help|-h\n",
			progname);
	exit(1);
}

static char *short_options = "hdp:";
static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"daemon", 0, 0, 'd'},
	{"pidfile", 1, 0, 'p'},
	{0,0,0,0}
};

int main(int argc, char *argv[])
{
	char *progname = basename(argv[0]);
	char *rcfile = NULL;
	char *pidfile = NULL;
	char *cwd;
	int daemonize = 0;
	int option_index;
	while(1) {
		int c;
		if ((c = getopt_long (argc, argv, short_options,
						long_options, &option_index)) < 0)
			break;
		switch (c) {
			case 'd': daemonize = 1;
								break;
			case 'p': pidfile = optarg;
								break;
			default:
								usage(progname); break;
		}
	}
	if (optind + 1 != argc)
		usage(progname);
	rcfile = argv[optind];

	startlog(progname, daemonize);
	setsignals();
	/* saves current path in cwd, because otherwise with daemon() we
	 * forget it */
	if((cwd = getcwd(NULL, 0)) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	if (daemonize && daemon(0, 0)) {
		printlog(LOG_ERR, "daemon: %s", strerror(errno));
		exit(1);
	}

	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(pidfile) save_pidfile(pidfile, cwd);

	if (parsercfile(rcfile) < 0)
		exit(1);
#if 0
	auth_printnets(stderr);
	auth_printauth(stderr);
#endif

	if (mainloop(rstack, fstack, fwdaddr, fwdaddr_count) < 0)
		exit(1);
	return 0;
}
