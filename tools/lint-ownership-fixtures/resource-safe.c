/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

typedef __SIZE_TYPE__ size_t;
typedef struct file FILE;
int open(const char *, int, ...);
int close(int);
long write(int, const void *, size_t);
FILE *fopen(const char *, const char *);
FILE *fdopen(int, const char *);
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

/* Adversarial cases for checkEndFunction's leak-at-exit scan: each of
 * these acquires a real, trackable resource and must NOT be flagged. */

/* Two differently-shaped branches, each releasing on its own -- unlike
 * the single shared `if (... || fclose(g) ...)` release call this check
 * exists to catch (see resource-unsafe.c's short_circuit_leak), neither
 * branch here skips the release call it does reach. */
void mode_branch_release(int mode)
{
	FILE *g = fopen("name", "w");
	if (!g)
		return;
	if (mode) {
		fflush(g);
		fclose(g);
	} else {
		fclose(g);
	}
}

/* A resource closed by a small helper this analysis inlines, not by the
 * acquiring function itself -- ResourceMap's ordinary release-call check
 * already discharges it wherever the actual fclose() call is reached, so
 * the leak scan (keyed on ResourceMap, not on which lexical function
 * issued the call) sees it released same as any other. */
static void release_stream(FILE *f)
{
	fclose(f);
}

void cleanup_helper_release(void)
{
	FILE *g = fopen("name", "w");
	if (!g)
		return;
	release_stream(g);
}

/* Returning the resource is a deliberate hand-off to the caller, the
 * same "borrow across a function boundary is opaque to this per-function
 * analysis, so trust it" reasoning descriptor_borrow/handle_borrow above
 * already rely on, just crossed outward instead of inward. */
FILE *open_log(void)
{
	return fopen("name", "a");
}

/* src/stdio/file.c's own __stdio_exit(): iterates a global list of
 * already-open streams flushing each one before the process exits,
 * without closing any of them (NtTerminateProcess reclaims everything
 * at once). None of these FILE*s were acquired by this function --
 * belongsToFrame's own frame-scoping is exactly what keeps a resource
 * this function only borrowed from a global out of its own obligation,
 * the same reasoning descriptor_borrow/handle_borrow rely on for a
 * parameter instead of a global. */
static FILE *open_files;
void flush_all_open_streams(void)
{
	FILE *f;
	for (f = open_files; f; f = 0)
		fflush(f);
}

/* NT's out-parameter handles that escape straight into the caller's own
 * storage (this codebase's dominant shape, e.g.
 * src/thread/nt/plat_thread.c's __plat_semaphore_create()) are never this
 * frame's obligation at all -- see checkPostCall's own
 * isDirectParameterArgument() carve-out. */
typedef long NTSTATUS;
typedef void *HANDLE;
NTSTATUS NtCreateSemaphore(HANDLE *, int, void *, long, long);
int make_semaphore(HANDLE *out)
{
	return NtCreateSemaphore(out, 0, 0, 0, 0);
}

/* src/misc/linux/grp.c's getgrent() shape: a static/global FILE* cache,
 * stored into directly (no struct field, no out-parameter) and never
 * fclose()d by this function on purpose -- later calls reuse it, and
 * process exit reclaims it. isTrustedResourceDestination() has to trust
 * a plain global-storage destination unconditionally, the same way it
 * already trusts a struct field, or every getXXXent()/setXXXent() cache
 * in this codebase would still be a false leak. */
static FILE *g_cached_stream;
void cache_into_global(void)
{
	if (!g_cached_stream)
		g_cached_stream = fopen("name", "r");
}

/* src/socket/socketpair.c's `pair[0] = client;`: the out-parameter-deref
 * shape above (make_semaphore) spelled with subscript sugar on a `T *`
 * parameter instead of an explicit `*out = `. Semantically identical --
 * `pair[0]` is `*(pair + 0)` -- but a different AST shape
 * isTrustedResourceDestination() has to recognize separately. */
void store_into_out_array(int pair[2])
{
	pair[0] = open("name", 0);
}

/* src/dirent/opendir.c's opendir()/alloc_dir() shape: open() acquires fd
 * in THIS frame, then hands it by value into a small same-TU helper that
 * the analyzer inlines, which stores it into a struct field from ITS OWN
 * (callee) frame. isTrustedResourceDestination() trusts the store
 * unconditionally, but checkPostStmt must not additionally require the
 * store to happen in the acquiring frame -- ownership transfer is a fact
 * about the value, not about which frame's instruction does the store. */
struct wrapper { int fd; };
static struct wrapper *wrap_fd(int fd)
{
	static struct wrapper w;
	w.fd = fd;
	return &w;
}

void store_via_inlined_helper(void)
{
	int fd = open("name", 0);
	if (fd < 0)
		return;
	(void)wrap_fd(fd);
}

/* src/util/crontab.c's do_edit()/src/util/spool.c's __spool_new_job()
 * shape: mkstemp()'s fd is immediately handed to fdopen(), which on
 * success absorbs it into the FILE* it returns instead of ever calling
 * close() on it directly -- fclose() on the FILE* closes the fd from
 * here on. consumedDescriptorArgument() has to know fdopen() (and
 * src/stdio/file.c's __file_new(), fopen()/fdopen()/tmpfile()'s own
 * shared helper) retires the fd argument on success, or every
 * mkstemp()+fdopen() pairing in this codebase is a false leak -- and the
 * retirement has to be success-gated, not unconditional like close()'s
 * own release() entry, or the real close(fd) on fdopen()'s OWN failure
 * path right below becomes a false double-release instead. */
void fd_retired_via_fdopen(void)
{
	char tmpl[] = "nameXXXXXX";
	int fd = mkstemp(tmpl);
	FILE *f;
	if (fd < 0)
		return;
	f = fdopen(fd, "w");
	if (!f) { close(fd); return; }
	fclose(f);
}
