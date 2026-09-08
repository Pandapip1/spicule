/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

typedef __SIZE_TYPE__ size_t;
int open(const char *, int, ...);
int close(int);
long write(int, const void *, size_t);
int mkstemp(char *);

/* A literal, made-up descriptor -- concretely known to this analysis to
 * not be the result of any open()/socket()/... it could have tracked
 * (it is not even a symbol, see ResourceLifecycleChecker::checkResource's
 * own comment), and not one of the standard streams isStandardDescriptor()
 * recognises either. Real, checked evidence of a bug, unlike an opaque
 * parameter (see resource-safe.c's descriptor_borrow for why that shape
 * is trusted instead). */
void bogus_literal(void)
{
	write(99, "x", 1); /* ownership-expect: resource-unproved */
}

void release_twice(void)
{
	int fd = open("name", 0);
	if (fd < 0)
		return;
	close(fd);
	close(fd); /* ownership-expect: resource-released */
}

void use_after_release(void)
{
	int fd = open("name", 0);
	if (fd < 0)
		return;
	close(fd);
	write(fd, "x", 1); /* ownership-expect: resource-use-released */
}

/* mkstemp()'s own fd shares open()'s Descriptor family (see
 * resource-safe.c's descriptor_via_mkstemp) -- pins acquiredFamily()'s
 * mkstemp/mkostemp entries against a regression to the wrong family
 * (e.g. Stream, which would turn this into a "family does not match"
 * finding on the first close(fd) instead), mirroring release_twice
 * above. */
void release_twice_mkstemp(void)
{
	char tmpl[] = "nameXXXXXX";
	int fd = mkstemp(tmpl);
	if (fd < 0)
		return;
	close(fd);
	close(fd); /* ownership-expect: resource-released */
}

typedef struct file FILE;
FILE *fopen(const char *, const char *);
int fclose(FILE *);
int write_body(FILE *, int);

/* The short-circuit-past-cleanup shape src/util/get.c's get_one() used to
 * have (fixed by 906692a9): `||` short-circuits, so fclose(g) never runs
 * on the branch where write_body() itself already failed, leaking the
 * FILE* on exactly that path. */
int short_circuit_leak(const char *path, int lines)
{
	int rc = 0;
	FILE *g = fopen(path, "wb");
	if (!g)
		return 1;
	if (write_body(g, lines) != 0 || fclose(g) != 0)
		rc = 1;
	return rc; /* ownership-expect: resource-leak */
}

/* Adversarial twin of resource-safe.c's redirect_onto_borrowed_target_safe:
 * the SAME comparison against a borrowed parameter, but only on the
 * branch where newfd and fd are proven to actually DIFFER -- unlike the
 * safe version, this branch never releases anything, so the resource
 * genuinely leaks whenever newfd != fd. Pins that ResourceLifecycleChecker's
 * new "retired by aliasing" carve-out only ever forgives the branch
 * where the constraint manager actually proves the aliasing, never the
 * other one. */
int redirect_param_mismatch_leak(int fd)
{
	int newfd = open("name", 0);
	if (newfd < 0)
		return 1;
	if (newfd != fd) {
		/* never closes newfd here */
	}
	return 0; /* ownership-expect: resource-leak */
}

/* Adversarial twin of resource-safe.c's redirect_onto_standard_stream_safe:
 * bounded against a literal that does NOT prove the value is one of the
 * standard streams 0/1/2 -- fd == 3, 4, or 5 on the untaken branch is a
 * genuinely unclosed, ordinary descriptor, not a standard stream. */
int bounded_close_leak(void)
{
	int fd = open("name", 0);
	if (fd < 0)
		return 1;
	if (fd > 5)
		close(fd);
	return 0; /* ownership-expect: resource-leak */
}

/* Adversarial twin of resource-safe.c's array_release_loop_safe: the
 * same acquire-into-a-local-array-by-runtime-index loop, but with no
 * release loop anywhere in this function -- a real "opened every file,
 * closed none of them" leak of the identical shape, which
 * arrayHasCorrelatedReleaseCall's positive release-loop search must not
 * mistake for the safe version's own correlated close loop. */
int array_no_release_leak(int n)
{
	FILE *files[64];
	int j;
	for (j = 0; j < n; j++)
		files[j] = fopen("name", "r");
	return 0; /* ownership-expect: resource-leak */
}

/* Adversarial twin of resource-safe.c's argv_element_proven_nonnull_safe:
 * the identical shape, but `argv` carries no elements_withtok(null_
 * terminated, argc) contract, so argv[1] is never proven nonnull and the
 * (real-world impossible, but still UNPROVEN) null path genuinely stays
 * reachable here -- pinning that ResourceLifecycleChecker's own
 * checkPostStmt(ImplicitCastExpr) only forgives the annotated case,
 * never plain, uncontracted pointer arithmetic of the same shape. */
int argv_element_not_proven_nonnull_leak(int argc, char **argv)
{
	const char *src_path;
	FILE *in;
	if (argc < 2)
		return 1;
	src_path = argv[1];
	in = fopen(src_path, "rb");
	if (!in)
		return 1;
	if (src_path)
		fclose(in);
	return 0; /* ownership-expect: resource-leak */
}
