/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A real /etc/nsswitch.conf parser, shared by src/netdb/linux/ (the
 * "hosts" database) and src/misc/linux/{pwd,grp}.c (the "passwd" and
 * "group" databases) -- one order-of-services decision, reused by
 * every Linux-side NSS-style lookup in this tree rather than
 * reimplemented per database.
 *
 * Scope: this parses the real nsswitch.conf(5) `db: service...` line
 * shape, including `#` comments and `[NOTFOUND=return]`-style bracket
 * groups (skipped as a unit, never interpreted -- see
 * src/netdb/linux/nsswitch.c's own header for why the action-list
 * semantics themselves are deliberately not implemented). Only two
 * service tokens are ever recognized -- "files" and "dns" -- because
 * those are the only two backends this pass builds (see
 * src/netdb/linux/ and top-level task banner: no dlopen()'d NSS
 * module story, matching musl's own real-world precedent). Any other
 * token (nis, ldap, systemd, compat, ...) parses fine but is simply
 * never emitted into the returned order: this library has no backend
 * for it, and silently pretending otherwise would be worse than
 * honestly acting as if that service were absent from the line.
 *
 * Defaults (used when /etc/nsswitch.conf is missing, unreadable, or
 * does not mention the requested database at all): "files dns" for
 * hosts, "files" for passwd/group -- the same defaults glibc itself
 * ships as nsswitch.conf's own commented-out template, and the only
 * ones consistent with this pass having no directory-service backend
 * for passwd/group at all.
 */
#ifndef _SPICULE_NSSWITCH_H
#define _SPICULE_NSSWITCH_H

enum __nss_service {
	__NSS_SVC_FILES,
	__NSS_SVC_DNS
};

/* Fills out[0..N) with the service order configured for database `db`
 * ("hosts", "passwd", or "group"), stopping at `max` entries, and
 * returns the count actually written (0 if the database's configured
 * order names no service this library implements -- see this header's
 * own banner: that is a real, honest "not found" for every subsequent
 * lookup, not a bug). db/out required: every real caller
 * (src/netdb/linux/addrinfo.c, src/misc/linux/pwd.c, src/misc/linux/
 * grp.c) passes a real string literal and the address of its own
 * local array, never NULL, and this function's body indexes out[]
 * and calls strcmp(db, ...) unconditionally. */
int __nsswitch_order(const char *db, enum __nss_service *out, int max)
    __attribute__((nonnull(1, 2)));

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
