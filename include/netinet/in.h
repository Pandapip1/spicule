/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <netinet/in.h>.
 *
 * struct in6_addr is needed by the pure-C IPv6 text conversion interface
 * even though AF_INET6 sockets remain staged separately (socket(AF_INET6,
 * ...) fails EAFNOSUPPORT, src/socket/socket.c); IPV6_* socket options stay
 * out of scope until the AFD transport supports them. sockaddr_in6 and the
 * IN6_IS_ADDR_/IN6ADDR_..._INIT surface are declared regardless, since a
 * struct and address-predicate macros carry no linkage to be a latent
 * link-error the way an undefined function symbol would. in6addr_any/
 * in6addr_loopback are real data, defined in src/socket/inet.c. */
#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <stdint.h>
#include <sys/socket.h>

typedef uint16_t in_port_t;
typedef uint32_t in_addr_t;

struct in_addr {
	in_addr_t s_addr;
};

struct in6_addr {
	uint8_t s6_addr[16];
};

/* sin_port/sin_addr/sin_zero match TDI_ADDRESS_IP's layout bit-for-bit
 * (src/internal/afd.h): they are copied directly into/out of a
 * TA_ADDRESS's Address[] bytes. */
struct sockaddr_in {
	sa_family_t sin_family;
	in_port_t sin_port;
	struct in_addr sin_addr;
	unsigned char sin_zero[8];
};

/* No AF_INET6 endpoint exists yet to copy this into an AFD wire format, so
 * unlike sockaddr_in there is no TDI layout to match; member order just
 * follows POSIX's listing order. */
struct sockaddr_in6 {
	sa_family_t sin6_family;
	in_port_t sin6_port;
	uint32_t sin6_flowinfo;
	struct in6_addr sin6_addr;
	uint32_t sin6_scope_id;
};

/* Both defined for real in src/socket/inet.c, not just declared. */
#define IN6ADDR_ANY_INIT      {{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}
#define IN6ADDR_LOOPBACK_INIT {{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}}
extern const struct in6_addr in6addr_any;
extern const struct in6_addr in6addr_loopback;

/* Pure byte tests against s6_addr, with no AFD/socket dependency, so
 * nothing here is gated on the transport staging above. */
static __inline int __spicule_in6_is_zero(const struct in6_addr *a, int upto)
{
	int i;
	for (i = 0; i < upto; i++) if (a->s6_addr[i]) return 0;
	return 1;
}

#define IN6_IS_ADDR_UNSPECIFIED(a) (__spicule_in6_is_zero((a), 16))
#define IN6_IS_ADDR_LOOPBACK(a) \
	(__spicule_in6_is_zero((a), 15) && (a)->s6_addr[15] == 1)
#define IN6_IS_ADDR_MULTICAST(a) ((a)->s6_addr[0] == 0xff)
#define IN6_IS_ADDR_LINKLOCAL(a) \
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0x80))
#define IN6_IS_ADDR_SITELOCAL(a) \
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0xc0))
#define IN6_IS_ADDR_V4MAPPED(a) \
	(__spicule_in6_is_zero((a), 10) && (a)->s6_addr[10] == 0xff && \
	 (a)->s6_addr[11] == 0xff)
#define IN6_IS_ADDR_V4COMPAT(a) \
	(__spicule_in6_is_zero((a), 12) && !IN6_IS_ADDR_UNSPECIFIED(a) && \
	 !IN6_IS_ADDR_LOOPBACK(a))
#define IN6_IS_ADDR_MC_NODELOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a) && (((a)->s6_addr[1] & 0xf) == 0x1))
#define IN6_IS_ADDR_MC_LINKLOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a) && (((a)->s6_addr[1] & 0xf) == 0x2))
#define IN6_IS_ADDR_MC_SITELOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a) && (((a)->s6_addr[1] & 0xf) == 0x5))
#define IN6_IS_ADDR_MC_ORGLOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a) && (((a)->s6_addr[1] & 0xf) == 0x8))
#define IN6_IS_ADDR_MC_GLOBAL(a) \
	(IN6_IS_ADDR_MULTICAST(a) && (((a)->s6_addr[1] & 0xf) == 0xe))

/* Only IPPROTO_TCP/IPPROTO_UDP are meaningful (src/socket/socket.c's
 * protocol checks); the rest are declared for header conformance. */
#define IPPROTO_IP   0
#define IPPROTO_ICMP 1
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17
#define IPPROTO_IPV6 41
#define IPPROTO_RAW  255

/* Network byte order is the same in all four bytes for ANY/BROADCAST, so
 * no htonl() is needed to use them directly in a struct in_addr. */
#define INADDR_ANY       ((in_addr_t)0x00000000)
#define INADDR_BROADCAST ((in_addr_t)0xffffffff)
#define INADDR_LOOPBACK  ((in_addr_t)0x7f000001)
#define INADDR_NONE      ((in_addr_t)0xffffffff)

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
