/* C library headers must use the implementation-reserved namespace for guards,
 * type plumbing, and implementation extensions so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * spicule implements its own statically-linked "files"/"dns" NSS
 * services (src/netdb/linux/nsswitch.c) rather than dlopen()ing
 * glibc's libnss_*.so.2. gethostbyname() is kept as a disclosed
 * legacy/XSI extension, a thin front door onto the same
 * __hosts_resolve() walk getaddrinfo() uses.
 *
 * getnameinfo() does a real reverse /etc/hosts walk but sends no PTR
 * DNS query, so a DNS-only name falls back to numeric.
 *
 * No IPv6: this socket layer has no IPv6 support, so
 * ai_family == AF_INET6 fails with EAI_FAMILY rather than degrading to
 * IPv4 or fabricating an IPv6 result.
 *
 * struct addrinfo's ai_addr/ai_canonname are heap-owned by
 * getaddrinfo() and released by freeaddrinfo().
 */
#ifndef _NETDB_H
#define _NETDB_H
#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define __NEED_size_t
#include <bits/alltypes.h>

/* This implementation only ever fills AF_INET/4 entries. */
struct hostent {
	char *h_name;
	char **h_aliases;
	int h_addrtype;
	int h_length;
	char **h_addr_list;
};

struct addrinfo {
	int ai_flags;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	socklen_t ai_addrlen;
	struct sockaddr *ai_addr;
	char *ai_canonname;
	struct addrinfo *ai_next;
};

/* AI_V4MAPPED/AI_ALL/AI_ADDRCONFIG are declared for header completeness
 * but have no observable effect: they only modify AF_INET6 behavior,
 * which this implementation never returns. */
#define AI_PASSIVE     0x0001
#define AI_CANONNAME   0x0002
#define AI_NUMERICHOST 0x0004
#define AI_NUMERICSERV 0x0008
#define AI_V4MAPPED    0x0010
#define AI_ALL         0x0020
#define AI_ADDRCONFIG  0x0040

/* NI_NOFQDN is declared for header completeness but has no observable
 * effect: this implementation's /etc/hosts walk never returns more of
 * a name than the file itself spells out. */
#define NI_NOFQDN       0x0001
#define NI_NUMERICHOST  0x0002
#define NI_NAMEREQD     0x0004
#define NI_NUMERICSERV  0x0008
#define NI_DGRAM        0x0010
#define NI_MAXHOST      1025
#define NI_MAXSERV      32

/* Numeric values are this implementation's own; callers must treat
 * these as opaque, not as errno-shaped integers. */
#define EAI_AGAIN     (-3)  /* the name could not be resolved at this time */
#define EAI_BADFLAGS  (-1)  /* the flags parameter had an invalid value */
#define EAI_FAIL      (-4)  /* a non-recoverable error occurred */
#define EAI_FAMILY    (-6)  /* the address family was not recognized, or the address length was invalid for the specified family */
#define EAI_MEMORY    (-10) /* memory allocation failure */
#define EAI_NONAME    (-2)  /* the name does not resolve for the supplied parameters */
#define EAI_SERVICE   (-8)  /* the service passed was not recognized for the specified socket type */
#define EAI_SOCKTYPE  (-7)  /* the intended socket type was not recognized */
#define EAI_SYSTEM    (-11) /* a system error occurred; the error code is in errno */
#define EAI_OVERFLOW  (-12) /* an argument buffer overflowed */

/* NT backend (src/netdb/nt/plat_netdb.c) only answers the AI_NUMERICHOST
 * case, which needs no resolver; every other node still gets EAI_FAIL. */
int getaddrinfo(const char *__restrict, const char *__restrict,
                 const struct addrinfo *__restrict, struct addrinfo **__restrict)
    __attribute__((nonnull(4)));
void freeaddrinfo(struct addrinfo *);
const char *gai_strerror(int);

/* NT backend is numeric-only (src/netdb/nt/plat_netdb.c). */
int getnameinfo(const struct sockaddr *__restrict, socklen_t,
                 char *__restrict, socklen_t, char *__restrict, socklen_t, int)
    __attribute__((nonnull(1)));

/* XSI/legacy, removed from this edition of POSIX, kept as a disclosed
 * extension (see banner above). Non-reentrant per its historical
 * contract, like getpwnam() (src/misc/pwd.c). */
struct hostent *gethostbyname(const char *)
    __attribute__((nonnull(1)));

void sethostent(int);
struct hostent *gethostent(void);
void endhostent(void);

struct netent {
	char *n_name;
	char **n_aliases;
	int n_addrtype;
	uint32_t n_net;
};

/* A missing /etc/networks (src/netdb/linux/networks.c) is treated as a
 * normal empty database, not an error -- most real machines have none. */
void setnetent(int);
struct netent *getnetent(void);
void endnetent(void);
struct netent *getnetbyname(const char *)
    __attribute__((nonnull(1)));
struct netent *getnetbyaddr(uint32_t, int);

struct protoent {
	char *p_name;
	char **p_aliases;
	int p_proto;
};

void setprotoent(int);
struct protoent *getprotoent(void);
void endprotoent(void);
struct protoent *getprotobyname(const char *)
    __attribute__((nonnull(1)));
struct protoent *getprotobynumber(int);

struct servent {
	char *s_name;
	char **s_aliases;
	int s_port;
	char *s_proto;
};

/* proto is optional: a null proto matches any value of s_proto. */
void setservent(int);
struct servent *getservent(void);
void endservent(void);
struct servent *getservbyname(const char *, const char *)
    __attribute__((nonnull(1)));
struct servent *getservbyport(int, const char *);

/* h_errno: gethostbyname()'s non-POSIX error-reporting channel, kept
 * for the same legacy reason. herror()/hstrerror() are not provided. */
extern int h_errno;
#define HOST_NOT_FOUND 1
#define TRY_AGAIN      2
#define NO_RECOVERY    3
#define NO_DATA        4

#ifdef __cplusplus
}
#endif
#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
