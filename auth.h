#ifndef __AUTH_H
#define __AUTH_H
#include <stdio.h>
#include <stdint.h>

#define AUTH_HAS_NAME          0x1
#define AUTH_HAS_ADDR          0x2
#define AUTH_HAS_PWD           0x4
#define AUTH_HAS_NAME_ADDR     AUTH_HAS_NAME | AUTH_HAS_ADDR
#define AUTH_HAS_NAME_ADDR_PWD AUTH_HAS_NAME_ADDR | AUTH_HAS_PWD

#define AUTH_TAGS \
	_AUTH_TAGS_ITEM(ERROR, AUTH_HAS_NAME), \
	_AUTH_TAGS_ITEM(ACCEPT, 0), \
	_AUTH_TAGS_ITEM(STATIC, AUTH_HAS_NAME), \
	_AUTH_TAGS_ITEM(OTIP, AUTH_HAS_NAME_ADDR_PWD), \
	_AUTH_TAGS_ITEM(HASH, AUTH_HAS_NAME_ADDR), \
	_AUTH_TAGS_ITEM(CACHE, AUTH_HAS_NAME), \
	_AUTH_TAGS_ITEM(HREV, AUTH_HAS_NAME), \
	_AUTH_TAGS_ITEM(FWD, AUTH_HAS_NAME)

#define _AUTH_TAGS_ITEM(X, Y) AUTH_ ## X
enum auth_tag { AUTH_TAGS, AUTH_TAGS_COUNT };
#undef _AUTH_TAGS_ITEM

struct iothdns_pkt;
struct iothdns_header;
struct in6_addr;

/* give a name to a net (address space) */
int auth_add_net(const char *name, const char *net);

/* add an authorization for op == type to the networks 'net' (which is a comma sep list) */
int auth_add_auth(const char *type_string, const char *nets,
		const char *name, struct in6_addr *baseaddr, const char *pwd);

/* ck if op == type is permitted for a client whose addr is fromaddr */
int authck(int type, struct in6_addr *fromaddr);
/* ck if there is at least a permission for op == type */
int auth_isactive(int type);

/* authorization request: op == type, fromaddr is the client's address
 * proc_req_cb is called for each matching auth record.
 * this scan terminates when the callback function returns a response packet */
typedef struct iothdns_pkt *(*proc_req_cb_t) (uint8_t type, struct in6_addr *fromaddr,
		struct in6_addr *baseaddr, char *pwd, struct iothdns_header *h);

struct iothdns_pkt *auth_process_req(struct iothdns_header *h, struct in6_addr *fromaddr,
		proc_req_cb_t proc_req_cb);

/* policy for hash based address caching (for a later reverse resolution).
 * SAME => only when a host queries its own address
 * NET => when a the request comes from a host on the same /64 net
 * the default policy is ALWAYS */
enum hashrevmode {HASHREV_ALWAYS, HASHREV_NET, HASHREV_SAME, HASHREV_NEVER};
void auth_hashrev_setmode(enum hashrevmode mode);
int auth_hashrev_check (struct in6_addr *addr, struct in6_addr *fromaddr);

/* print the auth tables (for debugging purposes) */
void auth_printnets(FILE *f);
void auth_printauth(FILE *f);

/* reset all the auth tables. (in case  of configuration reload) */
void auth_cleanall(void);

#endif
