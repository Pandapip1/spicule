/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Every real NSS-style database this pass reads (/etc/hosts,
 * /etc/passwd, /etc/group, /etc/resolv.conf, /etc/nsswitch.conf
 * itself) lives at a fixed system path with no configurable base
 * directory in any real implementation -- glibc does not offer one
 * either, so there is no "real" design this deviates from by using a
 * #define.
 *
 * That is a genuine problem for hermetic testing, though: this
 * process's actual /etc/passwd is real, host-specific system state
 * (fine to READ and assert stable facts about, e.g. root existing at
 * uid 0 -- test/posix-netdb.c's own getservbyname test already relies
 * on the identical stability of /etc/services' http entry), but a
 * fixture-driven test of, say, "an admin-configured nsswitch.conf
 * with passwd's files service removed makes getpwnam() honestly
 * report not-found" cannot be written against the real
 * /etc/nsswitch.conf at all without mutating real host configuration,
 * which this library must never do as a side effect of running its
 * own test suite.
 *
 * __nss_path() is the deliberate, disclosed answer: each of the five
 * paths above can be overridden by an spicule-internal, UNDOCUMENTED
 * environment variable (never mentioned in any public header, never
 * part of any POSIX contract) that this library's own test fixtures
 * set and every other caller leaves unset. This is not a new idea in
 * Unix libc history -- TZ overriding zoneinfo's own search path and
 * HOSTALIASES overriding /etc/hosts for gethostbyname() are both real,
 * long-standing precedents for "an env var is the sanctioned way to
 * redirect a libc database lookup" -- this is the same shape, scoped
 * to spicule's own test harness rather than end-user configuration.
 *
 * UPDATE (this pass): three more real flat-file databases join the
 * same seam -- /etc/services, /etc/protocols, /etc/networks, backing
 * src/netdb/linux/services.c, protocols.c, networks.c respectively.
 * /etc/networks in particular is routinely just absent on a real
 * machine (most distros ship no networks at all); that is this
 * database's own normal empty state, not a fixture-only concern, but
 * the same override still lets a test assert real parsing behavior
 * against a controlled fixture rather than whatever this host happens
 * to have (or not have) at /etc/networks today. */
#ifndef _SPICULE_NSS_PATHS_H
#define _SPICULE_NSS_PATHS_H

#include <stdlib.h>

/* var/dflt required: every real call site below passes a string
 * literal for both, never NULL, and getenv()'s own contract already
 * tolerates any `var`; the unconditional `*p` dereference on the
 * getenv() result is guarded by the `p &&` immediately before it, not
 * by this attribute -- var/dflt describe this function's OWN
 * parameters, not what it does with getenv()'s return. */
static inline const char *__nss_path(const char *var, const char *dflt)
    __attribute__((nonnull(1, 2)));
static inline const char *__nss_path(const char *var, const char *dflt)
{
	const char *p = getenv(var);
	return (p && *p) ? p : dflt;
}

#define __NSS_HOSTS_PATH()     __nss_path("SPICULE_TEST_HOSTS_PATH",     "/etc/hosts")
#define __NSS_PASSWD_PATH()    __nss_path("SPICULE_TEST_PASSWD_PATH",    "/etc/passwd")
#define __NSS_GROUP_PATH()     __nss_path("SPICULE_TEST_GROUP_PATH",     "/etc/group")
#define __NSS_RESOLV_PATH()    __nss_path("SPICULE_TEST_RESOLV_PATH",    "/etc/resolv.conf")
#define __NSS_NSSWITCH_PATH()  __nss_path("SPICULE_TEST_NSSWITCH_PATH",  "/etc/nsswitch.conf")
#define __NSS_SERVICES_PATH()  __nss_path("SPICULE_TEST_SERVICES_PATH",  "/etc/services")
#define __NSS_PROTOCOLS_PATH() __nss_path("SPICULE_TEST_PROTOCOLS_PATH", "/etc/protocols")
#define __NSS_NETWORKS_PATH()  __nss_path("SPICULE_TEST_NETWORKS_PATH",  "/etc/networks")

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
