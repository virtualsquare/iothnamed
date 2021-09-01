#ifndef _ARPAINETX_H
#define _ARPAINETX_H
#include <sys/socket.h>

/* extended version of inet_ntop(3).
 * IPv4-mapped IPv6 addresses are converted as ::ffff:nnn.nnn.nnn.nnn
 * (in all other cases it behaves like inet_ntop) */
const char *inet_ntopx(int af, const void *src, char *dst, socklen_t size);
/* extended version of inet_pton(3).
 * if 'af' is AF_INET6 and src is an address nnn.nnn.nnn.nnn
 * the result in dst is a IPv4-mapped IPv6 network address
 * (in all other cases it behaves like inet_pton) */
int inet_ptonx(int af, const char *src, void *dst);

/* convert an IPV6 prefix to an in6addr mask */
struct in6_addr prefix2mask(unsigned prefix);

#define INET_REVSTRLEN 29
#define INET6_REVSTRLEN 73
/* convert an IP to the domain name for reverse queries:
 * e.g. if af is AF_INET and src is a struct in_addr whose value is  10.20.30.40
 * the result is 40.30.20.10.in-addr.arpa
 * if af is AF_INET6 and src is a struct in6_addr whose value is 2001::3:4, the result is
 * "4.0.0.0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa"
 * the buffer buf must be at least INET_REVSTRLEN of INET6_REVSTRLEN bytes long
 * (for AF_INET or AF_INET6 respectively)
 */
const char *inet_ntor(int af, const void *src, char *dst, socklen_t size);

/* an extension to inet_ntor supporting domains for reverse resolution.
 * 10.20.30.40 prefix = 32 => result = "40.30.20.10.in-addr.arpa"
 * 10.20.30.40 prefix = 24 => result = ".30.20.10.in-addr.arpa"
 * 10.20.30.40 prefix = 16 => result = ".20.10.in-addr.arpa"
 * 10.20.30.40 prefix = 8 => result = ".in-addr.arpa"
 * 2001::3:4 pref 128 => "4.0.0.0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa"
 * 2001::3:4 pref 124 => ".0.0.0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa"
 * 2001::3:4 pref 120 => ".0.0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa"
 * ...
 * 2001::3:4 pref 4 => ".2.ip6.arpa"
 * 2001::3:4 pref 0 => ".ip6.arpa"
 */
const char *inet_ntorx(int af, const void *src, unsigned int prefix,
    char *dst, socklen_t size);

/* if src is an IPv4 network address in the dotted-decimal or an IPv6 address
 * convert it to the domain name for reverse queries
 * (otherwise it returns the src)
 * the buffer buf must be at least INET6_REVSTRLEN bytes long*/
/* "test.foo.bar" -> "test.foo.bar"
 * "10.20.30.40" -> "40.30.20.10.in-addr.arpa"
 * "2001::3:4" -> "4.0.0.0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa"
 * it is possible to specify a prefix e.g. "10.20.30.40/24" or "2001::3:4/64"
 * "10.20.30.40/24" -> ".30.20.10.in-addr.arpa"
 * "2001::3:4/64" -> ".0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa"
 */
const char *inet_ptor(const char *src, char *dst, socklen_t size);

#endif
