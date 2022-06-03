/*
 * iothnamed: a domain name server/forwarder/proxy for the ioth
 * Copyright 2021 Renzo Davoli - Federico De Marchi
 *     Virtualsquare & University of Bologna
 *
 * arpainetx.c: extensions to arpa/inet.h functions
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
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define V4PREFIX "::ffff:"

/* extended version of inet_ntop(3).
 * IPv4-mapped IPv6 addresses are converted as ::ffff:nnn.nnn.nnn.nnn
 * (in all other cases it behaves like inet_ntop) */
const char *inet_ntopx(int af, const void *src, char *dst, socklen_t size) {
	if (af == AF_INET6 && IN6_IS_ADDR_V4MAPPED(src)) {
		const struct in6_addr *in6 = src;
		const void *v4src = &in6->s6_addr[12];
		char buf[INET_ADDRSTRLEN];
		const char *pbuf = inet_ntop(AF_INET, v4src, buf, INET_ADDRSTRLEN);
		if (pbuf == NULL) return NULL;
		if (snprintf(dst, size, V4PREFIX "%s",pbuf) > (int) size)
			return errno = ENOSPC, NULL;
		else
			return dst;
	} else
		return inet_ntop(af, src, dst, size);
}

/* extended version of inet_pton(3).
 * if 'af' is AF_INET6 and src is an address nnn.nnn.nnn.nnn
 * the result in dst is a IPv4-mapped IPv6 network address
 * (in all other cases it behaves like inet_pton) */
int inet_ptonx(int af, const char *src, void *dst) {
	struct in_addr testaddr;
	if (af == AF_INET6 && inet_pton(AF_INET, src, &testaddr) == 1) {
		size_t v4msrclen = strlen(src) + sizeof(V4PREFIX);
		char v4msrc[v4msrclen];
		snprintf(v4msrc, v4msrclen, V4PREFIX "%s", src);
		return inet_pton(AF_INET6, v4msrc, dst);
	} else
		return inet_pton(AF_INET6, src, dst);
}

/* convert an IPV6 prefix to an in6addr mask */
struct in6_addr prefix2mask(unsigned prefix) {
	static uint8_t bytemask[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe};
	struct in6_addr mask;
	unsigned i;
	for (i = 0; i < sizeof(mask.s6_addr) && prefix >= 8; i++, prefix -= 8)
		mask.s6_addr[i] = 0xff;
	if (i < sizeof(mask.s6_addr))
		mask.s6_addr[i++] = bytemask[prefix];
	for ( ; i < sizeof(mask.s6_addr); i++)
		mask.s6_addr[i] = 0x0;
	return mask;
}

static const char *_inet_ntor(const void *src, unsigned int prefix,
		char *dst, socklen_t size);
static const char *_inet6_ntor(const void *src, unsigned int prefix,
		char *dst, socklen_t size);

/* convert an IP to the domain name for reverse queries:
 * e.g. if af is AF_INET and src is a struct in_addr whose value is  10.20.30.40
 * the result is 40.30.20.10.in-addr.arpa
 * if af is AF_INET6 and src is a struct in6_addr whose value is 2001::3:4, the result is
 * "4.0.0.0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa"
 * the buffer buf must be at least INET_REVSTRLEN of INET6_REVSTRLEN bytes long
 * (for AF_INET or AF_INET6 respectively)
 */
const char *inet_ntor(int af, const void *src, char *dst, socklen_t size) {
	switch (af) {
		case AF_INET:
			return _inet_ntor(src, 32, dst, size);
		case AF_INET6:
			return _inet6_ntor(src, 128, dst, size);
		default:
			return errno = EAFNOSUPPORT, NULL;
	}
}

/* an extension to inet_ntor supporting domains for reverse resolution.
 * 10.20.30.40 prefix = 32 => result = "40.30.20.10.in-addr.arpa"
 * 10.20.30.40 prefix = 24 => result = ".30.20.10.in-addr.arpa"
 * 10.20.30.40 prefix = 16 => result = ".20.10.in-addr.arpa"
 * 10.20.30.40 prefix = 8 => result = ".10.in-addr.arpa"
 * 2001::3:4 pref 128 => "4.0.0.0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa"
 * 2001::3:4 pref 124 => ".0.0.0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa"
 * 2001::3:4 pref 120 => ".0.0.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa"
 * ...
 * 2001::3:4 pref 4 => ".2.ip6.arpa"
 * 2001::3:4 pref 0 => ".ip6.arpa"
 */
const char *inet_ntorx(int af, const void *src, unsigned int prefix,
		char *dst, socklen_t size) {
	switch (af) {
		case AF_INET:
			return _inet_ntor(src, prefix, dst, size);
		case AF_INET6:
			return _inet6_ntor(src, prefix, dst, size);
		default:
			return errno = EAFNOSUPPORT, NULL;
	}
}

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
const char *inet_ptor(const char *src, char *dst, socklen_t size) {
	size_t srclen = strlen(src) + 1;
	char _src[srclen];
	char *_prefix;
	uint8_t addr[sizeof(struct in6_addr)];
	snprintf(_src, srclen, "%s", src);
	if ((_prefix	= strchr(_src, '/')) != NULL)
		*(_prefix++) = '\0';
	if (inet_pton(AF_INET6, _src, addr) == 1) {
		int prefix = (_prefix == NULL) ? 128 : strtol(_prefix, NULL, 10);
		return inet_ntorx(AF_INET6, addr, prefix, dst, size);
	} else if (inet_pton(AF_INET, _src, addr) == 1) {
		int prefix = (_prefix == NULL) ? 32 : strtol(_prefix, NULL, 10);
		return inet_ntorx(AF_INET, addr, prefix, dst, size);
	} else
		return src;
}

#define REVTAIL ".in-addr.arpa"
#define REVTAIL6 ".ip6.arpa"
#define INET6_REVPROTO \
	" . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . "

static const char *_inet_ntor(const void *src, unsigned int prefix,
		char *dst, socklen_t size) {
	const uint8_t *v = src;
	socklen_t olen;
	if (prefix > 32) prefix = 32;
	prefix >>= 3; // byte level
	switch (prefix) {
		case 4: olen = snprintf(dst, size, "%u.%u.%u.%u%s",
								v[3], v[2], v[1], v[0], REVTAIL);
						break;
		case 3: olen = snprintf(dst, size, ".%u.%u.%u%s",
								v[2], v[1], v[0], REVTAIL);
						break;
		case 2: olen = snprintf(dst, size, ".%u.%u%s",
								v[1], v[0], REVTAIL);
						break;
		case 1: olen = snprintf(dst, size, ".%u%s",
								v[0], REVTAIL);
						break;
		case 0: olen = snprintf(dst, size, "%s", REVTAIL);
						break;
	}
	if (olen > size)
		return errno = ENOSPC, NULL;
	return dst;
}

static const char *_inet6_ntor(const void *src, unsigned int prefix,
		char *dst, socklen_t size) {
	static const uint8_t hex[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	char buf[] = INET6_REVPROTO;
	prefix >>= 2; // nibble level
	const uint8_t *v = src;
	for (int i = 0; i < 16; i++) {
		uint8_t low = v[i] & 0xf;
		uint8_t hi = v[i] >> 4;
		buf[(15 - i) * 4] = hex[low];
		buf[(15 - i) * 4 + 2] = hex[hi];
	}
	int offset = 0;
	if (prefix < 32)
		offset = (31 - prefix) * 2 + 1;
	if (snprintf(dst, size, "%s" REVTAIL6, buf + offset) > (int) size)
		return errno = ENOSPC, NULL;
	return dst;
}
