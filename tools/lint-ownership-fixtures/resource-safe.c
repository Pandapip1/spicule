/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

typedef __SIZE_TYPE__ size_t;
typedef struct file FILE;
int open(const char *, int, ...);
int close(int);
long write(int, const void *, size_t);
FILE *fopen(const char *, const char *);
int fclose(FILE *);
int fflush(FILE *);
int mkstemp(char *);
int mkostemp(char *, int);

void descriptor(void)
{
	int fd = open("name", 0);
	if (fd < 0)
		return;
	write(fd, "x", 1);
	close(fd);
}

/* mkstemp()/mkostemp() return a real fd exactly like open() does (see
 * src/stdlib/mktemp.c's mkostemps(), which every one of this codebase's
 * real callers -- src/stdio/misc.c, src/util/crond.c, src/util/
 * crontab.c, src/util/man.c, src/util/m4.c -- routes through). */
void descriptor_via_mkstemp(void)
{
	char tmpl[] = "nameXXXXXX";
	int fd = mkstemp(tmpl);
	if (fd < 0)
		return;
	write(fd, "x", 1);
	close(fd);
}

void descriptor_via_mkostemp(void)
{
	char tmpl[] = "nameXXXXXX";
	int fd = mkostemp(tmpl, 0);
	if (fd < 0)
		return;
	write(fd, "x", 1);
	close(fd);
}

void stream(void)
{
	FILE *file = fopen("name", "r");
	if (file)
		fclose(file);
}

/* NT's own syscalls, unlike open()/socket()/..., never return the handle
 * they acquire -- they return an NTSTATUS and write the handle through
 * an out-pointer instead. Without ResourceLifecycleChecker knowing that
 * shape, this exact function would have reported "resource is not
 * proven live" on NtClose(h) below: acquiredFamily()'s old
 * Call.getReturnValue()-only tracking could never see a handle that
 * never comes back as a return value, so this codebase's entire NT
 * backend -- every NtCreateFile/NtOpenFile/NtCreateEvent/... acquisition
 * followed by NtClose -- was structurally unprovable. Pinned here so a
 * regression in handleOutParamArgument() is caught locally rather than
 * silently reappearing as ~100 findings tree-wide. */
typedef long NTSTATUS;
typedef void *HANDLE;
NTSTATUS NtCreateFile(HANDLE *out, int access, void *oa, void *io,
                      long alloc, unsigned attrs, unsigned share,
                      unsigned disp, unsigned options, void *ea,
                      unsigned ealength);
NTSTATUS NtClose(HANDLE h);

void handle_lifecycle(void)
{
	HANDLE h;
	NtCreateFile(&h, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	NtClose(h);
}

/* An opaque handle received from a caller is the HANDLE analogue of
 * descriptor_borrow below.  Pointer-valued resources do not always retain
 * a recoverable SymbolRef in the analyzer, but that representation detail
 * cannot make a direct parameter look like a fabricated resource. */
void handle_borrow(HANDLE h)
{
	NtClose(h);
}

/* A descriptor received as a plain parameter -- posix_close(int fd)'s
 * own shape (src/unistd/posix_close.c: `return close(fd);`), and
 * closedir()'s `dp->fd` read through a borrowed struct pointer. Just
 * like Ownership's release_borrow (see safe.c's own comment for the
 * full reasoning), ResourceMap can only ever gain a live entry for a
 * symbol by watching THIS analysis's own open()/socket()/opendir()/...
 * acquire it; a parameter's value exists before any code in this
 * function has run, so no code on the callee side can ever satisfy that
 * check. A literal, made-up descriptor is real evidence of a bug and is
 * still reported (see resource-unsafe.c's bogus_literal). */
void descriptor_borrow(int fd)
{
	write(fd, "x", 1);
}

/* fflush(NULL) is ISO C's own "flush every open stream" spelling (7.21.5.2p2),
 * not a use of any one, specific FILE* this checker could ever have proof
 * for -- see __assert_fail's real fflush(0) in src/exit/assert.c, matching
 * musl's own convention here. */
void flush_all(void)
{
	fflush(0);
}

/* A bounded loop's own induction variable, checked live against this
 * process's own table before being closed -- src/internal/fd.c's own
 * __fd_close_all_cloexec() shape. clang's analyzer only explores a
 * handful of concrete values of `i` before widening it away, so on
 * those first few concrete iterations `i` looks, by SVal alone,
 * indistinguishable from a hand-authored literal -- but the source
 * never wrote any number down, and `live[i]` is real evidence (of
 * exactly the same "someone else's acquire, invisible to this
 * per-function analysis" shape as a borrowed parameter) that this slot
 * really is open. See isLiteralArgument's own comment for why this
 * carve-out is scoped to Descriptor only. */
static int live[8];
void close_table(void)
{
	int i;
	for (i = 0; i < 8; i++)
		if (live[i]) close(i);
}

/* vdprintf()'s own shape (src/stdio/printf.c): a throwaway stack FILE,
 * never passed through fopen/fdopen/tmpfile/popen, used directly and
 * never fclose()d -- flushed here exactly like sem_wait(&s) uses an
 * unnamed, stack semaphore directly. fclose(&f) on this same object
 * would still be a real bug, so the carve-out only ever applies to a
 * *use*, never Consume (see checkResource's own comment). */
void flush_stack_file(void)
{
	FILE f;
	fflush(&f);
}

/* A pipe array closed across two passes gated by a shared, once-set
 * boolean array -- src/sh/execute.c's __sh_exec_pipeline() shape (pass
 * 1 closes stage i's pipe ends if `!deferred[i]`, pass 2 closes the
 * same index's ends if `deferred[i]`, so every index is closed in
 * exactly one pass). Under a widened, symbolic loop index, RegionStore's
 * default-value binding can return the exact same SymbolRef for
 * `pipes[i][1]` at two logically different indices/passes, so this
 * checker's per-symbol ResourceMap cannot tell them apart -- neither
 * "acquired but not seen" nor "already released" is provable once the
 * underlying model itself conflates the two elements, so
 * hasSymbolicArrayIndex() treats a symbolic-index resource operation as
 * "no information", the same as any other opaque-provenance case. */
void close_pipe_array(int pipes[][2], char *deferred, int n)
{
	int i;
	for (i = 0; i < n; i++)
		if (!deferred[i] && i + 1 < n)
			close(pipes[i][1]);
	for (i = 0; i < n; i++)
		if (deferred[i] && i + 1 < n)
			close(pipes[i][1]);
}
