/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal interfaces shared between the parts of ntlibc.  Nothing in here
 * is visible to programs; everything begins with a double underscore.
 */
#ifndef _NTLIBC_LIBC_H
#define _NTLIBC_LIBC_H

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <errno.h>
#include <wordexp.h>
#include "nt.h"
#include "thread_annotations.h"
#include "plat_handle.h"

/* ---- lockset (Clang Thread Safety Analysis) capability tokens ---------
 * Two internal locks get a NTLIBC_CAPABILITY token here: __sig_lock()/
 * __sig_unlock() (a real function pair, acquire/release-annotated
 * directly below) and the ntdll PEB lock, reached everywhere in this
 * tree only through the RtlAcquirePebLock()/RtlReleasePebLock() macros
 * below -- so the *real* RtlAcquirePebLock/RtlReleasePebLock functions
 * (declared by nt.h, above) are the ones annotated: every macro call
 * site's self-referential expansion (see the macros' own comment)
 * resolves to these exact declarations, so no call site anywhere in the
 * tree needs to change for this to take effect.
 *
 * Both are gated the same way every NTLIBC_* macro is: invisible outside
 * clang, and invisible outside tools/lint.sh's `lockset` stage even under
 * clang.  See thread_annotations.h. */
#ifdef NTLIBC_LOCKSET_ANALYSIS
extern __ntlibc_lock_capability __ntlibc_sig_lock_token;
extern __ntlibc_lock_capability __ntlibc_peb_lock_token;
void NTAPI RtlAcquirePebLock(void) NTLIBC_ACQUIRE(__ntlibc_peb_lock_token);
void NTAPI RtlReleasePebLock(void) NTLIBC_RELEASE(__ntlibc_peb_lock_token);
#endif

/* ---- process-wide state ------------------------------------------------ */
extern PPEB __peb;                           /* this process's PEB */
extern char **environ;
#define __environ environ
extern char **__argv;
extern int __argc;
extern char *__progname;                     /* argv[0] */
extern char *__progname_full;                /* image path, UTF-8 */

/* Internal users need the thread id regardless of whether the public
 * GNU-extension declaration in <unistd.h> is visible under the current
 * feature-test macros. */
pid_t gettid(void);
int __verify_ldbl_layout(void);

/* environ helpers shared by getenv.c and setenv.c.  __env_find returns the
 * slot in environ holding "name=..." for the first l bytes of name, or
 * NULL.  __putenv installs s (which must contain a '='; l is the length of
 * the name part) and takes ownership of `owned` if non-NULL.
 *
 * name/s are required at every one of this tree's own call sites (each
 * already validated -- getenv's/putenv's own now-nonnull parameter,
 * setenv's malloc() result already null-checked, unsetenv's own
 * already-checked name); owned is deliberately left unmarked, since NULL
 * is its documented, legitimate "no ownership to transfer" value. */
char **__env_find(const char *name, size_t l) __attribute__((nonnull(1)));
int __putenv(char *s, size_t l, char *owned) __attribute__((nonnull(1)));

PTEB __teb(void) __attribute__((returns_nonnull)); /* this thread's TEB */
extern void *__entry_arg0;                   /* raw arg 1 to _start; measured, never used */
extern void *__entry_arg1;                   /* raw arg 2 slot; the control for __entry_arg0 */
#define __process_heap() (__peb->ProcessHeap)

/* ---- NT kernel version ------------------------------------------------- *
 * Read src/internal/ntversion.c's banner before using either of these.
 * Version-gating is a last resort in this library, reserved for wire
 * formats that changed between NT releases, carry no discriminator, and
 * *succeed* when handed the wrong layout -- which is the one case a
 * capability probe cannot cover.  Everything else probes.
 *
 * These report the kernel's version (PEB.OSMajorVersion/OSMinorVersion),
 * which is unrelated to, and never a statement about, ntlibc's minimum
 * supported Windows version, which is set by the ntdll imports in
 * tools/ntdll.def. */
int __nt_os_version(unsigned *major, unsigned *minor); /* 1 if measured, 0 if assumed */
int __nt_version_at_least(unsigned major, unsigned minor);

/* ---- errno ------------------------------------------------------------- */
int __errno_from_status(NTSTATUS);           /* map, do not set */
int __set_errno_status(NTSTATUS);            /* errno = map(st); return -1 */
int __errno_from_doserror(unsigned);

/* ---- UTF-8 <-> UTF-16 -------------------------------------------------- */
/* Convert a NUL-terminated UTF-8 string into a freshly malloc'd
 * NUL-terminated UTF-16 one; NULL with errno on failure.  *wlen, if not
 * NULL, receives the length in WCHARs excluding the terminator. */
withtok(internal_heap_allocated)
WCHAR *__utf8_to_utf16(const char *, size_t *wlen);
/* Convert n WCHARs into a freshly malloc'd NUL-terminated UTF-8 string. */
withtok(internal_heap_allocated)
char *__utf16_to_utf8(const WCHAR *, size_t n);
/* Convert into a caller-supplied buffer; returns bytes written excluding
 * the terminator, or -1 with errno (ERANGE if the buffer is too small). */
int __utf16_to_utf8_buf(const WCHAR *, size_t n, char *, size_t);
/* Required, the same as libc's own strlen -- no caller in this tree
 * passes it a possibly-null buffer, and its body dereferences s
 * unconditionally with no NUL/NULL special case. */
size_t wcslen_(const WCHAR *) __attribute__((nonnull(1)));

/* ---- Unicode Character Database classification / case mapping ---------- */
/* Real Unicode-driven backing for isw*()/tow*()/wcwidth() (src/ctype/isw*.c,
 * src/ctype/tow*.c, src/string/wcwidth.c, src/string/wcswidth.c), over the
 * generated range tables in src/internal/unicode_tables.c (produced by
 * tools/gen-unicode-tables.py -- see that script's own docstring for which
 * Unicode property backs each one and why). Implemented in
 * src/internal/unicode_data.c. Every function here takes/returns a plain
 * code point (as an unsigned int); every table it consults only ever holds
 * entries at or below 0xffff (ntlibc's wchar_t is one UTF-16 code unit --
 * wctype.h), so a cp above that, WEOF included, simply misses every table
 * and gets that table's "not a member" answer with no separate bounds
 * check needed anywhere except __unicode_is_print() (documented on its own
 * declaration below: it is the one predicate defined as a complement, so
 * out-of-table does NOT mean "false" for it alone). All are total,
 * deterministic, side-effect-free functions of their one argument. */
int __unicode_is_alpha(unsigned cp) __attribute__((__pure__));
int __unicode_is_upper(unsigned cp) __attribute__((__pure__));
int __unicode_is_lower(unsigned cp) __attribute__((__pure__));
int __unicode_is_digit(unsigned cp) __attribute__((__pure__));
int __unicode_is_space(unsigned cp) __attribute__((__pure__));
int __unicode_is_cntrl(unsigned cp) __attribute__((__pure__));
int __unicode_is_xdigit(unsigned cp) __attribute__((__pure__));
int __unicode_is_blank(unsigned cp) __attribute__((__pure__));
/* The complement of Cc+Cf+Cs+Co+Cn(unassigned)+Zl+Zp -- unlike every
 * other predicate above, "not found in a table" means true here, so this
 * one function does its own cp > 0xffff bounds check rather than relying
 * on a table miss. */
int __unicode_is_print(unsigned cp) __attribute__((__pure__));
/* Mn+Me: the zero-width "combining mark" set wcwidth() reports column
 * width 0 for. */
int __unicode_is_combining(unsigned cp) __attribute__((__pure__));
/* East_Asian_Width Wide or Fullwidth: the set wcwidth() reports column
 * width 2 for. */
int __unicode_is_wide(unsigned cp) __attribute__((__pure__));
/* Simple (1:1, locale-blind) case mapping. Returns cp unchanged when no
 * mapping exists -- including when cp has no simple mapping at all (e.g.
 * towupper of sharp s 'ß') and when cp is out of every table's domain
 * (WEOF, a lone surrogate, ...), exactly the "not in this mapping's
 * domain" answer towupper()/towlower() are specified to give. */
unsigned __unicode_to_upper(unsigned cp) __attribute__((__pure__));
unsigned __unicode_to_lower(unsigned cp) __attribute__((__pure__));

/* ---- UNICODE_STRING ---------------------------------------------------- */
/* The longest string a UNICODE_STRING can describe: Length counts bytes
 * in a USHORT, and MaximumLength has to hold Length plus a terminating
 * NUL, so 65535 bytes minus that NUL -- 32766 UTF-16 code units.  A
 * longer string narrowed into those fields does not truncate, it wraps,
 * and the object manager is handed some prefix of what was meant; every
 * hand-built UNICODE_STRING that a caller's data reaches checks against
 * this before narrowing. */
#define __US_MAX_WCHARS ((size_t)((0xffffu - sizeof(WCHAR)) / sizeof(WCHAR)))

/* ---- paths ------------------------------------------------------------- */
/* A path ready to hand to the object manager: the NT path in a
 * UNICODE_STRING, the OBJECT_ATTRIBUTES wrapping it, and the buffer it
 * lives in, which __ntpath_free releases. */
struct __ntpath {
	UNICODE_STRING nt;
	OBJECT_ATTRIBUTES oa;
	WCHAR *dos;            /* the DOS (Win32) form, for RtlDosSearchPath etc. */
	void *buf;             /* RtlDosPathNameToNtPathName_U's allocation */
};
/* Translate a POSIX-ish path into NT form.  Forward slashes become
 * backslashes; "/dev/null" becomes NUL; a relative path is resolved
 * against the current directory by the Rtl.  Returns 0 or -1 with errno. */
/* The shall-fail per-component [ENAMETOOLONG] check every path-taking
 * interface owes: 1 when some component of `path` is longer than
 * {NAME_MAX} bytes.  __ntpath()/__ntpath_at() apply it themselves, via
 * the path builder they share; chdir(), which builds its own
 * UNICODE_STRING, calls it directly.  See src/internal/path.c for why
 * this is NOT the whole-path __US_MAX_WCHARS bound next to it. */
int __name_too_long(const char *path);
int __ntpath(const char *path, struct __ntpath *out, ULONG attributes);
int __ntpath_native(const char *path, struct __ntpath *out, ULONG attributes);
/* Like __ntpath but the path is relative to the directory handle dirfd
 * refers to (AT_FDCWD for the current directory). */
int __ntpath_at(int dirfd, const char *path, struct __ntpath *out, ULONG attributes);
int __ntpath_at_native(int dirfd, const char *path, struct __ntpath *out, ULONG attributes);
void __ntpath_free(struct __ntpath *);
/* POSIX's [ENOTDIR] for a path prefix component that exists and is not a
 * directory, which NT reports identically to a prefix that is not there
 * (STATUS_OBJECT_PATH_NOT_FOUND for both).  Walks the prefix of an
 * already-built NT path with handle-less queries; root is the
 * RootDirectory the path is relative to, or 0.  Returns 1 for the
 * ENOTDIR case, 0 otherwise, and leaves errno alone.  __ntpath() and
 * __ntpath_at() apply it themselves; chdir(), which builds its own NT
 * path, calls it directly.
 *
 * nt is required: src/internal/nt/path.c's own body dereferences it
 * unconditionally, starting with its very first statement
 * (`UNICODE_STRING cut = *nt;`), with no NULL check anywhere. Both
 * real call sites -- that same file's reject_if_prefix_not_dir()
 * (`&out->nt`, a struct field's address) and src/unistd/nt/
 * plat_unistd.c's own call (`&nt`, a local's address) -- always pass
 * the address of a real object, never NULL. */
int __nt_prefix_not_dir(const UNICODE_STRING *nt, HANDLE root)
    __attribute__((nonnull(1)));
/* The DOS-form absolute path of a handle, UTF-8, malloc'd. */
withtok(internal_heap_allocated)
char *__handle_path(HANDLE);

/* The guts of open()/openat(): resolve and open, handing back the raw
 * handle and its __FD_* classification without installing a descriptor.
 * Returns 0, or -1 with errno.
 *
 * out/typeout/vfsout/vfsnativeout are all required: src/fcntl/open.c's
 * own body writes through vfsout/vfsnativeout unconditionally as its
 * very first two statements (`*vfsout = __VFS_NONE; *vfsnativeout =
 * 0;`), and through out/typeout unconditionally along every real
 * success-return path (the /dev/std* special case, or forwarded into
 * __plat_open() -- see src/internal/plat_fcntl.h's own comment on
 * that function's identical contract), with no NULL check of any of
 * the four anywhere. Its one real call site, that same file's own
 * openat(), always passes `&h, &type, &vfs, &vfs_native`, four real
 * locals' addresses, never NULL. path is deliberately left unmarked:
 * `if (!path) { errno = EFAULT; return -1; }` is a real, load-bearing
 * check of it, not decoration. */
int __open_handle(int dirfd, const char *path, int flags, unsigned mode,
                  HANDLE *out, int *typeout, int *vfsout, int *vfsnativeout)
    __attribute__((nonnull(5, 6, 7, 8)));
/* The current umask (src/stat/chmod.c owns umask_value), as plain
 * unsigned rather than mode_t so this header does not need mode_t
 * defined -- not every includer has pulled in <sys/stat.h>/<fcntl.h>
 * first.  On NT, which has no OS-level umask concept of its own,
 * callers that create a file apply it to the mode they were given
 * themselves, the way open()/creat()/mkdir() do (umask() also pushes
 * every value it records out to the real kernel mask via
 * __plat_umask_apply() -- src/internal/plat_stat.h -- but that is a
 * documented no-op on NT); on Linux, the real kernel-level mask that
 * call keeps in sync is exactly what the real openat()/mkdirat()/
 * mknodat() syscalls already honor themselves, so no Linux caller
 * needs to consult this at all. */
unsigned __umask_get(void);
/* The guts of unlink()/rmdir()/unlinkat(); isdir selects the rmdir
 * behaviour.  Returns 0, or -1 with errno. */
int __unlink_at(int dirfd, const char *path, int isdir);
/* The guts of stat()/fstat() is __plat_fstat() (src/internal/plat_stat.h)
 * now; struct stat is still forward-declared here for __vfs_stat() below. */
struct stat;

/* ---- the descriptor table ---------------------------------------------- */
#define FD_MAX 1024

enum {
	__FD_FILE = 1,         /* a disk file */
	__FD_DIR,              /* a directory handle */
	__FD_CONSOLE,          /* a console (ConDrv) handle */
	__FD_PIPE,             /* a pipe, named or anonymous */
	__FD_CHAR,             /* NUL, COM, and other character devices */
	__FD_SOCKET,
	__FD_UNKNOWN
};

/* The fixed POSIX namespace layered over NT paths.  Zero means that the
 * descriptor/path belongs to the native filesystem. */
enum {
	__VFS_NONE = 0,
	__VFS_ROOT,
	__VFS_DEV,
	__VFS_CONSOLE,
	__VFS_NULL,
	__VFS_TTY,
	__VFS_MISSING
};
#define __VFS_NATIVE 0x100
#define __VFS_KIND(v) ((v) & 0xff)

struct __fd {
	__plat_handle_t h;     /* NULL when the slot is free */
	unsigned flags;        /* O_ACCMODE, O_APPEND, O_NONBLOCK, O_CLOEXEC as given
	                        * to open -- the access mode is load-bearing, not
	                        * decorative: write() refuses an O_RDONLY descriptor,
	                        * and O_RDONLY is 0, so a slot filled in without it
	                        * silently reads back as read-only */
	unsigned char type;    /* __FD_* */
	unsigned char eof;     /* a pipe/console that has reported end of input */
	unsigned char dirflag; /* for directories: 0 or FILE_OPEN_REPARSE_POINT used */
	unsigned char pad;     /* socket connection state (AFD_ST_*) */
	unsigned char vfs;     /* one of __VFS_* above; zero for an NT object */
	unsigned char vfs_native; /* vfs names a native object, not a fallback */
	unsigned char vseen;   /* mandatory native-directory entries observed */
	unsigned char vnext;   /* next fallback entry for getdents() */
	/* AF_INET peer cached when connect()/accept() establishes it.  AFD's
	 * undocumented GET_PEER_NAME ioctl is not a stable Windows ABI; the
	 * peer cannot change during a stream socket's connected lifetime, so
	 * remembering the address that established the connection is both
	 * sufficient and avoids depending on that ioctl. */
	unsigned char peer[16];
	unsigned char peer_len;
	unsigned char shm_mode_valid; /* mode below came from shm_open metadata */
	unsigned short shm_mode;
	long long pos;         /* the position of an O_APPEND/async-opened handle; -1 = use the kernel's */
	/* getdents()'s own continuation state (src/dirent/getdents.c),
	 * separate from a DIR's (dirent_internal.h's __dirstream, which
	 * owns its buffer for its own lifetime): getdents() reads directly
	 * off a bare fd with no such object to hold one, and a single
	 * backend fill can legitimately decode into more records than the
	 * caller's own buffer has room for -- see getdents.c's own comment
	 * on why the leftover has to survive to the fd's NEXT getdents()
	 * call rather than being re-fetched (the backend's read position
	 * has already moved past it by then). dbuf is lazily __malloc()'d
	 * on this fd's first getdents() call, NULL until then; freed by
	 * __fd_release_dynamic() before this slot is ever repurposed. */
	unsigned char *dbuf;
	size_t dbufpos;         /* byte offset in dbuf of the next undecoded record */
	size_t dbuflen;         /* bytes of dbuf holding real records; 0 = empty */
};

extern struct __fd __fds[FD_MAX];

/* The runtime descriptor ceiling: no descriptor >= __fd_limit is ever
 * handed out.  Starts at FD_MAX (the table's own size, which remains the
 * hard ceiling) and is lowered by setrlimit(RLIMIT_NOFILE) --
 * setrlimit.html defines that resource as "a number one greater than the
 * maximum value that the system may assign to a newly-created
 * descriptor", and on this platform "the system" is this library: the
 * table is ours, so the limit is ours to enforce.  See src/misc/
 * resource.c. */
extern int __fd_limit;

void __pthread_atfork_prepare(void);
void __pthread_atfork_parent(void);
void __pthread_atfork_child(void);
void __pthread_reset_after_fork(void);

int __fd_alloc(int lowest);                  /* a free slot >= lowest, or -1 (EMFILE) */
int __fd_install(HANDLE, unsigned flags, int type);    /* alloc + fill; -1 with errno */
int __fd_install_at(int fd, HANDLE, unsigned flags, int type);
struct __fd *__fd_get(int fd);               /* NULL with errno=EBADF */
/* Frees whatever this slot owns on the heap on its own (getdents()'s
 * dbuf -- see struct __fd's own comment) before the slot is wiped and
 * repurposed for a new open, dup2() target, or posix_spawn() close
 * action.  A no-op on a slot that never allocated one (dbuf is NULL,
 * either never used with getdents() or already released), which is
 * also true of every zero-initialized slot in __fds[] that has never
 * been installed into at all. f is required: every call site below
 * already holds a real &__fds[i] (an array element's address is never
 * NULL) or an already-__fd_get()-checked pointer. */
void __fd_release_dynamic(struct __fd *f) __attribute__((nonnull(1)));
HANDLE __fd_handle(int fd);                  /* NULL with errno=EBADF */
/* pos is required: both real bodies (src/internal/nt/fdpos.c's
 * `*pos = pi.CurrentByteOffset;` on the NT_SUCCESS path,
 * src/internal/linux/fdpos.c's unconditional `*pos = 0;`) write
 * through it with no NULL check of pos itself -- only the NT side's
 * *value* is conditional on the query succeeding, not the pointer's
 * own nullness. Every real call site (src/unistd/read.c, write.c,
 * src/stat/nt/plat_stat.c) always passes `&saved`, a real local's
 * address, never NULL. */
int __fd_pos_save(HANDLE, long long *pos) __attribute__((nonnull(2)));   /* FilePositionInformation; -1 with errno */
void __fd_pos_restore(HANDLE, long long pos);/* put it back after positioned I/O */
int __handle_type(HANDLE);                   /* classify by device type */
int __fd_close_all_cloexec(void);
void __fd_init(void);                        /* fds 0-2 from the PEB, 3+ from RuntimeData */
/* src/internal/ldbl_layout_check.c -- called by every platform's own
 * __libc_start_main()/__linux_start_main() as early as that platform
 * can while still being able to report a real diagnostic on failure
 * (on NT: right after pp->StandardError exists; on Linux: literally
 * first, since fd 2 needs no setup), before any long double bit-layout
 * assumption (src/internal/ldbl_format.h) is trusted. 1 if this
 * build's real `long double` layout matches what was assumed at
 * compile time, 0 if not -- the caller writes a diagnostic and
 * terminates the process on 0, using its own platform's native
 * mechanism, since every math function touching a long double's raw
 * bits is unsafe past this point otherwise. */
int __verify_ldbl_layout(void);
/* Forget src/unistd/ids.c's own cached getuid()/getgid() answers, so the
 * next call re-derives them via __plat_detect_uid()/__plat_detect_gid()
 * (src/internal/plat_unistd.h) instead of returning a now-stale value.
 * Called by the Linux-only setresuid()/setresgid()
 * (src/unistd/linux/plat_ids.c) after a successful real identity change;
 * unused, and harmless, on NT, whose token never changes underneath the
 * cache. */
void __ids_creds_cache_invalidate(void);
void __mq_fd_closed(int);                    /* release side handles for an mqd_t */
void __mq_fd_replaced(int, __plat_handle_t);  /* follow fork/fcntl handle remakes */
/* Serialise the inheritable part of the descriptor table into a freshly
 * malloc'd blob for a child's RTL_USER_PROCESS_PARAMETERS RuntimeData;
 * *len receives its size.  When making a descriptor inheritable replaces
 * its handle, update any matching standard-handle snapshot too, so the
 * process parameters do not retain the now-closed old value.  NULL with
 * errno on failure. */
void *__fd_runtime_data(size_t *len, __plat_handle_t std[3])
    __attribute__((nonnull(1, 2)));

/* Resolve a path in the fixed POSIX namespace.  __VFS_NONE means the path
 * is native, __VFS_MISSING means it is inside the namespace but absent,
 * and -1 is a path error with errno set. */
int __vfs_resolve_at(int dirfd, const char *path);
int __vfs_open_dir(int kind, int cloexec, HANDLE *out);
int __vfs_stat(int kind, struct stat *st);
int __vfs_cwd_get(void);
void __vfs_cwd_set(int kind);

/* ---- select()/pselect()/poll() shared readiness core (src/select/) ----
 * A per-descriptor-type, non-blocking readiness probe plus a "wait on
 * what is waitable, sleep the rest" primitive that select.c and poll.c
 * both build their own (differently shaped) polling loop around -- see
 * src/select/select.c's file banner for the design writeup. */

/* Non-blocking, instantaneous readiness check for one already-open
 * descriptor.  Never blocks and never touches f->h's console-input wait
 * state.  *canread and *canwrite are set to 0 or 1; *hup is set to 1 when the
 * peer end of a pipe is gone (broken/disconnected), which also forces
 * *canread and *canwrite to 1 -- a read or write on it would return
 * immediately (with 0/EOF or an error), so it counts as "ready" the same
 * way select(2) treats a hung-up descriptor.  __FD_CONSOLE's read side is
 * deliberately left as *canread = 0 here: a console input handle is a
 * real NT wait object, so the caller waits on f->h directly instead of
 * polling it (see __fd_wait_or_delay below).
 *
 * __FD_SOCKET is probed the same "instantaneous, no wait" way, by a
 * single zero-timeout IOCTL_AFD_SELECT (test/networking-audit.md sec
 * 3); *hup is set for an AFD close/abort/disconnect exactly as it is
 * for a broken pipe, and also when the probe ioctl itself fails, which
 * is reported ready-and-hung-up rather than never-ready so that an
 * unprobeable socket cannot hang an infinite-timeout select()/poll().
 *
 * The shapes with no probe at all -- __FD_FILE/__FD_DIR/__FD_CHAR/
 * __FD_UNKNOWN -- report always ready, which is what select.html
 * requires for regular files and the only honest answer for the rest:
 * nothing in this library blocks a read or write to them past the
 * syscall itself.  Callers must route by *probeability*, not by a
 * single named type: routing only __FD_PIPE here once left sockets
 * silently reporting ready unconditionally.
 *
 * All four pointers are required. f->type is read unconditionally by
 * the switch itself; *hup = 0 is the very first statement in the body.
 * canread/canwrite are written directly on every one of the three
 * branches that touch them at all (__FD_PIPE, __FD_CONSOLE, the
 * always-ready default) and forwarded, still required there, to
 * __plat_socket_probe() on the fourth (__FD_SOCKET) -- no branch of
 * this exhaustive switch leaves either untouched. Every real call site
 * (src/select/select.c's poll_pass(), src/select/poll.c's own loop)
 * passes `f` fresh from an already-checked __fd_get(d) and &cr/&cw/&hup,
 * the addresses of its own locals -- never NULL. */
void __fd_probe(struct __fd *f, int *canread, int *canwrite, int *hup)
    __attribute__((nonnull(1, 2, 3, 4)));

/* src/unistd/pipe.c: the raw handle pair behind pipe2(), without any fd
 * table involvement.  The read end is the pipe's server end, the write
 * end its client end.  `inherit` requests OBJ_INHERIT.  Used by pipe2()
 * and by select.c's WriteQuotaAvailable capability probe. */
NTSTATUS __pipe_handles(HANDLE *rp, HANDLE *wp, int inherit);

/* The "wait" half: block for up to wait_ticks 100ns units (relative),
 * waking early if any of the `ncons` console handles becomes signalled,
 * or indefinitely if `infinite` is non-zero (wait_ticks is then
 * ignored).  Used as the sleep between __fd_probe() polls of pipes --
 * see the caller for how the interval is chosen. */
/* console_handles required: subscripted unconditionally
 * (`console_handles[i]`) whenever ncons >= 1, with no NULL check
 * anywhere in this function's body. Both real call sites
 * (src/select/select.c's select_core(), src/select/poll.c's own loop)
 * always pass console_h, the address of their own fixed-size local
 * array, never NULL -- ncons can be 0, but the pointer itself is never
 * absent. */
void __fd_wait_or_delay(__plat_handle_t *console_handles, int ncons, long long wait_ticks, int infinite)
    __attribute__((nonnull(1)));

/* ---- children ---------------------------------------------------------- */
/* The size of the statically allocated part of the child table.  It is
 * not a limit: the table grows onto the heap past this point rather than
 * dropping a child's process handle, which would make the child
 * unreapable for good (see src/process/children.c). */
#define CHILD_MAX_ 256

/* Refuse to grow the child table past this many entries; a process with
 * a million unreaped children has a leak, not a capacity problem, and
 * the cap keeps child_grow()'s doubling away from integer overflow.
 *
 * This, not CHILD_MAX_, is what sysconf(_SC_CHILD_MAX) reports: NT has
 * no fixed per-user process limit for it to describe, so the honest
 * answer is the ceiling on what this libc can still waitpid() for.
 * Reporting CHILD_MAX_ there would understate it by four orders of
 * magnitude now that the table grows. */
#define CHILD_CAP_LIMIT_ (1 << 20)
struct __child {
	int pid;
	__plat_handle_t h;
	/* The NT job object this child (and, transitively, anything it goes
	 * on to spawn itself) was placed in at creation time, before its
	 * first instruction ever ran -- __PLAT_HANDLE_NULL if job creation/
	 * assignment failed (best-effort, same tolerance as
	 * src/misc/resource.c's own job for RLIMIT_NPROC/CPU/AS/DATA) or on
	 * a backend that has no such concept (Linux: always
	 * __PLAT_HANDLE_NULL).  wait.c's fill_child_rusage() reads this
	 * job's JobObjectBasicAccountingInformation instead of a bare
	 * NtQueryInformationProcess(ProcessTimes) so that a grandchild this
	 * child already reaped -- CPU time this process has no other way to
	 * read out of the child's own address space -- is folded in too;
	 * see that function's own comment. */
	__plat_handle_t job;
	int done;               /* reaped status is available */
	int status;
	/* Job control.  A stop sent by this parent is recorded by kill(); a
	 * child that stops itself publishes a named event which wait.c folds
	 * into these same fields.  stopsig is the signal the child is stopped
	 * with right now,
	 * or 0 if it is running; jobstat is the stop-or-continue wait
	 * status that has not yet been reported to a waiter, or 0 if there
	 * is none, which is how waitpid(WUNTRACED)/waitid(WSTOPPED) meet
	 * "whose status has not yet been reported since they stopped"
	 * (wait.html) -- reporting clears it. */
	int stopsig;
	int jobstat;
};
/* The two wait statuses that are not a process exit, in the encoding
 * <sys/wait.h>'s WIFSTOPPED/WSTOPSIG/WIFCONTINUED decode -- the same
 * one Linux and the BSDs use, so a program that inspects the raw int
 * sees what it does there.  Kept here rather than in <sys/wait.h>: POSIX
 * gives applications the decoding macros and no constructors, and these
 * are only ever built by the library. */
#define __W_STOPPED(sig) (((int)(sig) << 8) | 0x7f)
#define __W_CONTINUED    0xffff
extern struct __child *__children;   /* __child_cap entries, pid==0 is free */
extern int __child_cap;
int __child_add(int pid, __plat_handle_t, __plat_handle_t job);
struct __child *__child_find(int pid);
/* c required: src/process/children.c's own __child_remove() dereferences
 * c->h unconditionally at entry, with no NULL check anywhere in its
 * body. Every real call site (src/process/wait.c's do_waitpid(), three
 * of them) only reaches it from inside a branch that has already
 * dereferenced c itself moments earlier (c->done, c->status, c->pid) --
 * c is always either __child_find()'s already-checked result or
 * &__children[i] from a live loop index, never NULL. */
void __child_remove(struct __child *) __attribute__((nonnull(1)));
/* Resume every child this process left stopped, and forget the stop.
 * Called on the way out of exit()/_exit() (src/exit/exit.c) -- see
 * children.c for the exit.html clause it stands in for. */
void __child_resume_stopped(void);
/* Drop the stop bookkeeping without resuming anything: fork()'s
 * child-side only, which inherits the parent's table but stopped none
 * of it (src/process/fork.c). */
void __child_forget_stops(void);
/* RUSAGE_CHILDREN: the running total src/process/wait.c folds every
 * reaped child's ProcessTimes into, read out by getrusage()
 * (src/misc/resource.c). */
struct rusage;
/* ru required: src/process/wait.c's own __rusage_children() calls
 * memset(ru, 0, sizeof *ru) unconditionally as its first statement, with
 * no NULL check anywhere in its body. Both real call sites
 * (src/misc/resource.c's getrusage(), which already null-checks its own
 * ru before forwarding it; src/misc/times.c's times(), which passes
 * &cru, a local) are never NULL. */
void __rusage_children(struct rusage *) __attribute__((nonnull(1)));
/* Zero that running total.  fork()'s child-side only: fork.html
 * requires the child's tms_cutime/tms_cstime be 0, and the clone
 * arrives with the parent's accumulators in its copied address
 * space. */
void __rusage_children_reset(void);

/* Start a program: the equivalent of posix_spawn.  Returns the child pid
 * (tracked in __children) or -1 with errno. */
int __spawn(const char *path, char *const argv[], char *const envp[]);
/* Resolve a program name the way execvp does: PATH search plus the .exe
 * suffix Windows wants.  Returns a malloc'd absolute path or NULL. */
/* name is required: dereferenced unconditionally at entry
 * (`if (!name[0]) ...`), and every real call site already requires it
 * for its own reasons (execvpe()'s own `strchr(file, ...)` calls
 * before forwarding it as name; posix_spawn.c's/execute.c's own
 * argv[0]-derived strings, never NULL). */
withtok(heap_allocated) __attribute__((nonnull(1)))
char *__find_program(const char *name, int use_path);
int __is_program(const char *path);
/* WSL/ntfs3's four-byte little-endian $LXMOD extended attribute.  Only the
 * mode attribute is used: ntlibc must not manufacture Linux UID/GID values.
 * The platform calls that read/write it are __plat_lxmod_get()/
 * __plat_lxmod_set() (src/internal/plat_stat.h); only the buffer builder,
 * which makes no platform call, is declared cross-module here. */
unsigned __lxmod_create_buffer(
    void *buffer withtok(writable_span(19)), unsigned mode); /* NtCreateFile EA */
/* The [ENOEXEC] command interpreter of XSH exec and XCU 2.9.1: runs
 * argv -- { arg0, command_file, argument..., 0 } -- as one invocation
 * of sh(1p) in this process, and returns its exit status.  Shared by
 * execvp()/execlp() (src/process/exec.c) and the shell's own command
 * search (src/sh/execute.c), so the two clauses are one mechanism.  See
 * src/sh/script.c, and src/process/exec.c for why it is a call and not
 * a second image. */
int __sh_run_script(int argc, char *const argv[]);

/* ---- the in-process shell (src/sh/, see test/sh-design.md) -------------
 *
 * The one entry point outside src/sh/ that reaches into the shell:
 * src/wordexp/wordexp.c's command-substitution call-out.  Everything
 * else in src/sh/ is declared in src/sh/sh.h, which is private to that
 * directory (plus test/sh.c's relative #include) -- this is here rather
 * than there because libc.h is where a declaration shared *between*
 * source directories belongs (see src/wordexp/internal.h's own header
 * comment saying exactly that).
 *
 * Runs `program` (the text between a "$(" and its matching ')', or the
 * escape-processed text between a matching pair of backquotes -- the
 * caller has already found the extent and, for the backquoted form,
 * applied XCU 2.6.3's backslash rule) as a complete_command in a
 * subshell environment, and hands back its standard output with
 * trailing <newline> sequences removed, exactly as XCU 2.6.3 requires.
 *
 * On success returns 0 with *out a __malloc'd, NUL-terminated capture
 * the caller owns and *status the command's exit status (2.9.1's "the
 * exit status of the last command substitution performed").  Returns -1
 * with *out NULL and *status untouched for a syntax error in `program`,
 * for a construct src/sh/execute.c still cannot execute (its own -1
 * convention -- see sh.h), or on resource failure; there is no way to
 * distinguish those here and no caller that would act differently.
 */
int __sh_cmdsub(const char *program, char **out, int *status)
    __attribute__((nonnull(2, 3)));

/* The other direction: the shell asks wordexp() to expand a word *as a
 * shell would*, which differs from the public wordexp() in exactly one
 * respect -- the special and positional parameters of XCU 2.5.1/2.5.2
 * ("$1", "${10}", "$@", "$*", "$#") are expanded, against the list
 * src/sh/param.c owns.  wordexp() itself must not do that: it is a
 * library call in an arbitrary program, which has no positional
 * parameters at all, and XCU's own wordexp page describes it in terms
 * of expanding words, not of being a shell with an argument list.  So
 * the behaviour is a parameter of one shared scan rather than a second
 * copy of it -- "$@" expands to several *fields* from one word, and
 * only the scan that already tracks what is quoted can produce those.
 *
 * Same arguments, same return values and same wordexp_t ownership rules
 * as wordexp(); see <wordexp.h>. */
int __wordexp_sh(const char *words, wordexp_t *pwordexp, int flags);

/* The three read-only accessors that expansion needs, and only those:
 * src/sh/param.c owns the list and src/sh/sh.h declares the rest of its
 * interface (replace/shift/save/restore), which is private to src/sh/.
 * These are here for the same reason __sh_cmdsub() is -- they cross a
 * source-directory boundary, into src/wordexp/wordexp.c's scan. */
const char *__sh_param_zero(void);
int __sh_param_count(void);
const char *__sh_param_get(int n);
/* XCU 2.5.2 '?': "Expands to the decimal exit status of the most recent
 * pipeline."  src/sh/execute.c maintains it in __sh_exec_pipeline(), which
 * is the one place every status this shell produces funnels through --
 * so "the most recent pipeline" is what the variable already holds,
 * not an approximation of it. */
int __sh_last_status(void);

/* ---- heap -------------------------------------------------------------- */
withtok(internal_heap_allocated)
withtok(writable_span(size))
void *__malloc(size_t size);
#ifdef NTLIBC_ARITHMETIC_ANALYSIS
__attribute__((annotate("ntlibc_arith_scalar_noop")))
#endif
void __free(void * consume(internal_heap_allocated));

/* ---- time -------------------------------------------------------------- */
#define __TICKS_PER_SEC 10000000LL
#define __TICKS_1601_TO_1970 116444736000000000LL
static inline long long __ticks_to_unix_sec(long long t)
{
	unsigned long long delta;
	if (t >= __TICKS_1601_TO_1970)
		return (t - __TICKS_1601_TO_1970) / __TICKS_PER_SEC;
	delta = (unsigned long long)__TICKS_1601_TO_1970 - (unsigned long long)t;
	return -(long long)(delta / __TICKS_PER_SEC);
}
static inline long __ticks_to_unix_nsec(long long t)
{
	unsigned long long delta;
	if (t >= __TICKS_1601_TO_1970)
		return (long)((t - __TICKS_1601_TO_1970) % __TICKS_PER_SEC) * 100;
	delta = (unsigned long long)__TICKS_1601_TO_1970 - (unsigned long long)t;
	return -(long)(delta % __TICKS_PER_SEC) * 100;
}
static inline int __unix_to_ticks(long long sec, long nsec, long long *result)
{
	long long ticks, subsecond = nsec / 100;
	if (sec > INT64_MAX / __TICKS_PER_SEC ||
	    sec < INT64_MIN / __TICKS_PER_SEC) return 0;
	ticks = sec * __TICKS_PER_SEC;
	if (subsecond > 0 && ticks > INT64_MAX - subsecond) return 0;
	if (subsecond < 0 && ticks < INT64_MIN - subsecond) return 0;
	ticks += subsecond;
	if (ticks > INT64_MAX - __TICKS_1601_TO_1970) return 0;
	*result = ticks + __TICKS_1601_TO_1970;
	return 1;
}

/* Successful kernel queries are still a trust boundary.  Keep their signed
 * counters out of unchecked arithmetic so a malformed response cannot turn
 * into libc UB before it can be rejected. */
static inline int __clock_combine_cpu_ticks(long long kernel,
	long long user, long long *result)
{
	if (kernel < 0 || user < 0 || kernel > INT64_MAX - user) return 0;
	*result = kernel + user;
	return 1;
}

static inline int __clock_qpc_to_timespec(long long count, long long freq,
	long long *sec, long *nsec)
{
	double scaled;
	if (count < 0 || freq <= 0) return 0;
	*sec = count / freq;
	/* The remainder can be almost INT64_MAX, so multiplying it by 1e9
	 * as an integer is not representable.  Floating scaling is bounded
	 * here; clamp the possible final rounding-up to a valid timespec. */
	scaled = (double)(count % freq) * 1000000000.0 / (double)freq;
	*nsec = scaled >= 1000000000.0 ? 999999999L : (long)scaled;
	return 1;
}

static inline int __clock_qpc_resolution(long long freq,
	long long *sec, long *nsec)
{
	if (freq <= 0) return 0;
	if (freq == 1) {
		*sec = 1;
		*nsec = 0;
	} else {
		*sec = 0;
		*nsec = freq > 1000000000LL ? 1L
			: (long)(1000000000LL / freq);
	}
	return 1;
}

/* File positions and sizes arrive as signed LARGE_INTEGER fields even when
 * the successful operation should only produce nonnegative values.  Keep a
 * malformed kernel/stub response out of signed arithmetic in the callers. */
static inline int __file_offset_add(long long base, long long delta,
	long long *result)
{
	if (base < 0) return 0;
	if (delta > 0 && base > INT64_MAX - delta) return 0;
	if (delta < 0 && delta < -base) return 0;
	*result = base + delta;
	return 1;
}

static inline int __file_remaining_count(long long end, long long pos,
	int *result)
{
	long long remain;
	if (end < 0 || pos < 0) return 0;
	if (end <= pos) { *result = 0; return 1; }
	remain = end - pos;
	*result = remain > INT32_MAX ? INT32_MAX : (int)remain;
	return 1;
}

static inline int __file_allocation_blocks(long long allocation,
	long long *result)
{
	if (allocation < 0) return 0;
	*result = allocation / 512 + (allocation % 512 != 0);
	return 1;
}

static inline int __size_add_checked(size_t left, size_t right, size_t *result)
{
	if (right > (size_t)-1 - left) return 0;
	*result = left + right;
	return 1;
}

static inline int __size_mul_checked(size_t left, size_t right, size_t *result)
{
	if (right && left > (size_t)-1 / right) return 0;
	*result = left * right;
	return 1;
}

/* Size the buffers passed through ntdll's ULONG-length UTF conversion
 * interfaces.  These checks cover both size_t arithmetic and the narrower
 * length fields before either value is cast. */
static inline int __utf8_to_utf16_allocation(size_t bytes, size_t *allocation)
{
	size_t units;
	if (bytes > UINT32_MAX / sizeof(WCHAR)) return 0;
	return __size_add_checked(bytes, 1, &units) &&
	       __size_mul_checked(units, sizeof(WCHAR), allocation);
}

static inline int __utf16_input_bytes(size_t units, size_t *bytes)
{
	return units <= UINT32_MAX / sizeof(WCHAR) &&
	       __size_mul_checked(units, sizeof(WCHAR), bytes);
}

static inline int __utf16_to_utf8_capacity(size_t units, size_t *capacity)
{
	size_t bytes;
	if (!__utf16_input_bytes(units, &bytes) ||
	    !__size_mul_checked(units, 3, &bytes) || bytes > UINT32_MAX) return 0;
	return __size_add_checked(bytes, 1, capacity);
}

/* True if c is an ASCII letter, 'A'-'Z' or 'a'-'z' -- the drive-letter
 * check a DOS-ish path's "X:..." prefix and an NT "\??\C:\" prefix both
 * need, folded to one case with the standard bit-5 lowercase trick. */
static inline int __nt_is_drive_letter(int c)
{
	return (c | 0x20) >= 'a' && (c | 0x20) <= 'z';
}

/* Appends the 8 lowercase hex digits of val, most significant first, to
 * name starting at index i, and returns the index just past them.  Used
 * to build the fixed-width hex-pid/serial suffix of named NT kernel
 * objects (pipes, mutants, events) from several unrelated call sites. */
static inline int __nt_append_hex32(WCHAR *name, int i, unsigned val)
{
	static const char digits[] = "0123456789abcdef";
	int shift;
	for (shift = 28; shift >= 0; shift -= 4)
		name[i++] = (unsigned char)digits[(val >> shift) & 15];
	return i;
}

/* Choose a geometrically grown array capacity without letting either the
 * requested element count or its byte size wrap.  Growth is bounded by the
 * machine word width: when another doubling would exceed the representable
 * byte limit, use the exact requested capacity instead. */
static inline int __array_next_capacity(size_t current, size_t used, // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
	size_t additional, size_t initial, size_t element_size, size_t *result)
{
	size_t minimum, maximum, capacity;

	if (!initial || !element_size ||
	    !__size_add_checked(used, additional, &minimum)) return 0;
	maximum = (size_t)-1 / element_size;
	if (minimum > maximum || current > maximum) return 0;
	capacity = current < initial ? initial : current;
	if (capacity > maximum) capacity = minimum;
	while (capacity < minimum) {
		if (capacity > maximum / 2) { capacity = minimum; break; }
		capacity *= 2;
	}
	*result = capacity;
	return 1;
}

/* Return the positive distance from start to end in NT's 100 ns units,
 * rounded up and saturated at the largest relative LARGE_INTEGER.  The
 * unsigned subtraction is intentional: after the lexical ordering check it
 * is the mathematical difference even when the two signed seconds straddle
 * zero, without evaluating an overflowing signed subtraction first. */
static inline long long __timespec_diff_ticks(long long end_sec, long end_nsec,
	long long start_sec, long start_nsec)
{
	unsigned long long seconds;
	long nseconds;
	long long subsecond;
	if (end_sec < start_sec ||
	    (end_sec == start_sec && end_nsec <= start_nsec)) return 0;
	seconds = (unsigned long long)end_sec - (unsigned long long)start_sec;
	nseconds = end_nsec - start_nsec;
	if (nseconds < 0) {
		seconds--;
		nseconds += 1000000000L;
	}
	subsecond = (nseconds + 99L) / 100L;
	if (seconds > (unsigned long long)(INT64_MAX - subsecond) /
	    (unsigned long long)__TICKS_PER_SEC) return INT64_MAX;
	return (long long)seconds * __TICKS_PER_SEC + subsecond;
}

/* Non-negative relative duration to 100 ns units.  A LARGE_INTEGER cannot
 * describe all of time_t in one kernel wait; saturation makes an oversized
 * request the longest representable wait (roughly 29,000 years) instead of
 * signed-overflowing into an already-expired or short interval.  Absolute
 * deadline callers naturally recompute after a wake; relative callers expose
 * this kernel-representation ceiling only if that entire wait elapses. */
static inline long long __duration_ticks(long long seconds, long nseconds)
{
	long long subsecond = (nseconds + 99L) / 100L;
	if ((unsigned long long)seconds >
	    (unsigned long long)(INT64_MAX - subsecond) /
	    (unsigned long long)__TICKS_PER_SEC) return INT64_MAX;
	return seconds * __TICKS_PER_SEC + subsecond;
}

/* src/unistd/sleep.c's alertable, signal-interruptible wait -- the one
 * place nanosleep()/sleep()/usleep() actually honour EINTR against a
 * signal-catching function.  Shared with clock_nanosleep()
 * (src/time/clock_nanosleep.c), which used to call NtDelayExecution()
 * directly, non-alertably, and therefore could never be interrupted or
 * report EINTR at all -- see that file for the rest of the story.
 * Returns 0 if the whole interval (`ticks`, 100ns units) elapsed, or -1
 * with errno=EINTR and *left set to the 100ns units still owed if a
 * signal-catching function ran first. */
int __alertable_delay(long long ticks, long long *left, const char *operation);

/* ---- stdio internals --------------------------------------------------- */
void __stdio_exit(void);                     /* flush everything at exit */

/* ---- exit -------------------------------------------------------------- */
/* How many atexit() handlers src/exit/exit.c's fixed table holds.  It
 * lives here rather than in that file because sysconf(_SC_ATEXIT_MAX)
 * (src/unistd/sysconf.c) reports it, and a limit published in one place
 * and enforced in another drifts.  C99 and POSIX both floor it at 32. */
#define ATEXIT_CAP_ 128
void __funcs_on_exit(void);
void __libc_exit_fini(void);
_Noreturn void __exit_internal(int);

/* Keep the unnamed semaphore limit reported by sysconf() coupled to the
 * implementation that enforces it. */
#define SEM_NSEMS_MAX_ 64

/* ---- signals ------------------------------------------------------------ */
/* Windows has no separate "killed by signal" field: a process exit code is
 * one 32-bit DWORD, and waitpid() has nothing else to look at.  A process
 * this library ends on behalf of a signal (kill(), abort(), the default
 * action in __raise_internal(), the vectored exception handler) therefore
 * exits with __ENCODE_SIGNAL_EXIT(sig) and waitpid() decodes exactly that.
 *
 * 0xE0DE0000 is an NTSTATUS with severity error (bits 31-30) and the
 * customer-defined bit (bit 29) set, so it can never be an NT status code
 * the system produces, and it is far outside the 0..255 an exit() can
 * return -- the two spaces cannot collide.  (The old scheme, 128 + signo,
 * is a *shell* convention; using it here stole exit codes 129..192 from
 * exit() and made e.g. exit(130) look like death by SIGABRT.) */
#define __SIGNAL_EXIT_BASE 0xE0DE0000u
#define __ENCODE_SIGNAL_EXIT(sig) ((int)(__SIGNAL_EXIT_BASE | ((unsigned)(sig) & 0x7fu)))
#define __IS_SIGNAL_EXIT(code) (((unsigned)(code) & ~0x7fu) == __SIGNAL_EXIT_BASE)

void __signal_init(void);
/* Capture the startup floating-point environment for FE_DFL_ENV
 * (src/math/fenv.c).  Must run before anything can change it. */
void __fenv_init(void);
/* RLIMIT_FSIZE, enforced by ntlibc's own write paths because NT has no
 * per-process file-size primitive and needs none (src/misc/resource.c).
 * __fsize_limited() is the cheap predicate to test first; __fsize_clamp()
 * returns how many of `count` bytes may be written on a handle, or -1
 * with EFBIG; __fsize_allow() answers for an operation that cannot
 * partially succeed (ftruncate, posix_fallocate).  __fsize_exceeded() is
 * the single refusal all three end in -- it raises SIGXFSZ and then sets
 * errno to EFBIG, in that order, and is what a caller that decides the
 * limit is blown for itself (pwrite) must return.  It is ONLY for the
 * process limit: [EFBIG] from an offset maximum or a volume's own
 * maximum file size is not setrlimit.html's clause and raises nothing. */
/* The offset maximum established in an open file description, i.e. the
 * largest value an off_t can hold.  off_t is _Int64 unconditionally
 * (include/alltypes.h.in), so this is not arch-dependent.  write.html
 * DESCRIPTION -- "For regular files, no data transfer shall occur past
 * the offset maximum established in the open file description
 * associated with fildes" -- and its shall-fail [EFBIG] both turn on
 * this value; see src/unistd/write.c. */
#define __OFF_MAX 0x7fffffffffffffffLL

int __fsize_limited(void);
long long __fsize_clamp(__plat_handle_t h, int append, size_t count);
long long __fsize_room_at(long long off);
int __fsize_allow(long long size);
int __fsize_exceeded(void);
int __raise_internal(int) NTLIBC_REQUIRES(__ntlibc_sig_lock_token);
int __raise_internal_info(int, const void *)
    NTLIBC_REQUIRES(__ntlibc_sig_lock_token);
int __sig_queue_process_info(int, const void *);
/* How many times a signal-catching function has been entered.  Compared
 * across an alertable wait by src/unistd/sleep.c to tell a caught signal
 * (the wait ends, [EINTR]) from an ignored one (it does not) -- see the
 * comment on caught_count in src/signal/signal.c. */
unsigned long __sig_caught_count(void);
/* Same count, restricted to handlers entered by the calling thread. */
unsigned long __sig_thread_caught_count(void);
/* Subset of that count whose installed action requested SA_RESTART. */
unsigned long __sig_thread_restart_count(void);
/* Deliver pending signals which the calling thread can accept. */
void __sig_drain_pending(void);
/* Per-thread signal state shared with the pthread implementation. */
struct __sigset_t;
/* mask required at both real call sites (src/thread/pthread.c:
 * &self->sigmask, &thread->sigmask, never NULL) and unconditionally
 * dereferenced -- *mask = blocked / blocked = *mask -- with no guard
 * in either body. */
void __sig_current_mask_copy(struct __sigset_t *) __attribute__((nonnull(1)));
void __sig_current_mask_install(const struct __sigset_t *) __attribute__((nonnull(1)));
/* posix_spawn()'s POSIX_SPAWN_SETSIGMASK, for a non-empty mask: the one
 * piece of state src/process/posix_spawn.c has that __spawn() itself
 * (src/process/spawn.c) takes no parameter for.  spawn_common() sets
 * this immediately before calling __spawn() and clears it immediately
 * after, success or failure, so it can never leak onto an unrelated
 * spawn.  The NT __fd_runtime_data()/__fd_init() pair
 * (src/internal/nt/plat_fd_init.c) is the only consumer: it rides the
 * mask to the child in a trailer appended to the same RuntimeData blob
 * that already carries the inherited-descriptor table, and __fd_init()
 * installs it (__sig_current_mask_install(), above) before main() ever
 * runs. Defined in src/internal/fd.c, the portable file, so
 * posix_spawn.c needs no NT-specific include -- Linux's own
 * __fd_runtime_data() (src/internal/linux/plat_fd_init.c) simply never
 * calls the getter, the same "set but never consulted" shape
 * struct __plat_fork_result.job (plat_process.h) uses on that backend. */
void __spawn_set_pending_sigmask(const struct __sigset_t *) __attribute__((nonnull(1)));
void __spawn_clear_pending_sigmask(void);
const struct __sigset_t *__spawn_pending_sigmask(void);
/* posix_spawn()'s POSIX_SPAWN_SETSCHEDPARAM/POSIX_SPAWN_SETSCHEDULER:
 * the nice-scale priority hint (see setpriority()'s own [-NZERO,
 * NZERO-1] clamp, src/misc/resource.c, reused verbatim here) to apply
 * to a freshly spawned child, set by spawn_common() immediately before
 * __spawn() and cleared immediately after, exactly like
 * __spawn_set_pending_sigmask() above (same lifetime, same reason).
 * Unlike the sigmask, no cross-process channel is needed: NT's
 * __plat_process_spawn() (src/process/nt/plat_process.c) already has
 * the suspended child's own process handle in hand at the point it
 * would call this, in the very same window create_child_job() uses, so
 * it applies the priority itself, directly, with
 * __plat_priority_set() (plat_misc.h) -- the identical call
 * src/misc/resource.c's own setpriority() makes for a non-self target.
 * Linux's __plat_process_spawn() never calls the getter, the same
 * "declared, only the NT backend consults it" shape as the sigmask
 * pair. */
void __spawn_set_pending_priority(int nice_value);
void __spawn_clear_pending_priority(void);
/* 1 with *out set if a priority is pending, 0 otherwise. out required:
 * the one real call site (src/process/nt/plat_process.c) only ever
 * passes the address of its own local, never NULL, and this always
 * writes through it before returning 1. */
int __spawn_pending_priority(int *out) __attribute__((nonnull(1)));

/* One posix_spawn_file_actions_adddup2() target above 2, as it stood
 * after every recorded file action had replayed on the parent's own
 * __fds[] table (src/process/posix_spawn.c's spawn_common()) -- `fd` is
 * the target descriptor number the caller asked for, `h` is the
 * parent's own handle currently filed under it (__fd_get(fd)->h at that
 * moment).
 *
 * Exists only for Linux's own __plat_process_spawn()
 * (src/process/linux/plat_process.c) to consume, the same "set by
 * spawn_common(), read back by exactly one backend's own spawn call"
 * shape __spawn_pending_priority()/__spawn_set_pending_sigmask() above
 * already use -- except mirrored: those two are NT-only concerns Linux
 * never reads back, and this one is a Linux-only concern NT never reads
 * back (its own __fd_runtime_data(), src/internal/nt/plat_fd_init.c,
 * already serialises the parent's ENTIRE __fds[] table by logical
 * index, so a target above 2 is already correct there with nothing
 * extra to tell it).
 *
 * Why Linux needs telling at all, when NT does not: a Linux child
 * inherits real kernel descriptor NUMBERS across clone()+execve(), not
 * table indices (src/process/linux/plat_process.c's own banner) -- and
 * do_action()'s __SPAWN_DUP2 case (posix_spawn.c) makes its duplicate
 * with a plain, arbitrary-numbered __plat_dup(), because forcing the
 * real number to match `fd` would mean mutating the PARENT's own real
 * descriptor table just to satisfy something that should only affect
 * the CHILD (see posix_spawn.c's own banner and
 * src/internal/linux/plat_fd_init.c's known-gap note). The arbitrary
 * real number this list carries is exactly what still needs moving onto
 * `fd`, but only in the child, after clone(2) and before execve(2) --
 * see __plat_process_spawn()'s own comment for where that happens,
 * generalizing the mv[]/dup3 staging it already does for fd 0/1/2. */
struct __spawn_dup2_target {
	int fd;
	__plat_handle_t h;
};
/* `list` is not copied: it must stay valid (spawn_common()'s own `extra`
 * array, a local) for as long as it takes __spawn() to return, exactly
 * like __spawn_set_pending_sigmask()'s own `mask` argument. */
void __spawn_set_pending_dup2s(const struct __spawn_dup2_target *list, int n)
    __attribute__((nonnull(1)));
void __spawn_clear_pending_dup2s(void);
/* *out_n set to the pending count (0 if none pending) and the list
 * pointer returned; NULL iff *out_n is 0. out_n required: the one real
 * call site (src/process/linux/plat_process.c) always passes the
 * address of its own local, never NULL. */
const struct __spawn_dup2_target *__spawn_pending_dup2s(int *out_n)
    __attribute__((nonnull(1)));

int __raise_thread_internal(int) NTLIBC_REQUIRES(__ntlibc_sig_lock_token);
/* Nonzero if SIGCHLD's installed sa_flags has SA_NOCLDWAIT set -- see the
 * comment on __sigchld_nocldwait() in src/signal/signal.c. */
int __sigchld_nocldwait(void);
/* Forget this process's pending alarm(), without touching NT.  fork()'s
 * child-side only: fork.html requires the child's alarm to be cancelled,
 * and the clone arrives with the parent's deadline in its copied address
 * space (src/unistd/sleep.c). */
void __alarm_reset_after_fork(void);
/* Cancellation-point hook used by alertable sleeps without forcing a
 * pthread control block to be allocated for threads with no request. */
void __pthread_testcancel(void);
void __pthread_cancel_unsafe_enter(const char *);
void __pthread_cancel_unsafe_leave(void);
void __pthread_cancel_defer_enter(void);
void __pthread_cancel_defer_leave(void);

/* Asynchronous cancellation must never redirect a thread while it owns the
 * PEB lock, or between the kernel consuming that lock's event and the Rtl
 * publishing its ownership metadata.  Make ownership a cancellation-deferred
 * region.  The self-reference in each replacement list intentionally resolves
 * to the real ntdll function while that macro is disabled during expansion. */
#define RtlAcquirePebLock() \
	(__pthread_cancel_defer_enter(), RtlAcquirePebLock())
#define RtlReleasePebLock() \
	(RtlReleasePebLock(), __pthread_cancel_defer_leave())

/* ---- cross-process signal delivery (src/signal/nt/sigdelivery.c,
 * src/signal/linux/sigdelivery.c) ---------------------------------------- */
/* Started by __signal_init(); see src/signal/nt/sigdelivery.c's banner
 * for the full NT design (a named-pipe-plus-mutant RPC, since NT has
 * no real signal delivery of its own) and src/signal/linux/
 * sigdelivery.c's own banner for what Linux does instead and does not
 * yet do. __sig_delivery_event() is select()'s (src/select/select.c)
 * read of the per-process "signal state changed" auto-reset event -- 0
 * if this process never got a working listener, which select() must
 * treat as "nothing to add to the wait set", not an error.
 * __sig_try_deliver_remote() is kill()'s (src/signal/signal.c)
 * cross-process arm. __sig_lock()/__sig_unlock() guard every piece of
 * shared state signal.c's own functions touch, now that a second real
 * thread exists to race them; __raise_internal() itself assumes the
 * caller already holds this lock rather than taking it -- see
 * sigdelivery.c's banner for why. */
void __sig_delivery_init(void);
void __sig_delivery_reinit_after_fork(void);
__plat_handle_t __sig_delivery_event(void);
NTSTATUS __sig_wait_delivery(LARGE_INTEGER *timeout);
void __sig_notify_delivery(void);
int __sig_try_deliver_remote(int pid, int sig);
int __sig_try_deliver_remote_info(int pid, int sig, const void *);
int __sig_try_deliver_remote_nondefault(int pid, int sig);
int __sig_disposition_is_default(int sig)
    NTLIBC_REQUIRES(__ntlibc_sig_lock_token);
int __sig_consume_child_stop(int pid);
void __sigchld_job_control(struct __child *, int sig);
void __sig_pending_reset_after_fork(void);
int __sig_pending_member(int sig);
void __timer_reinit_after_fork(void);
void __mman_reset_after_fork(void);
int __mman_fault_is_object_error(const void *);
int __mman_address_is_live(const void *);
int __mman_range_is_live(const void *, size_t);
void __aio_reset_after_fork(void);
void __sig_lock(void) NTLIBC_ACQUIRE(__ntlibc_sig_lock_token);
void __sig_unlock(void) NTLIBC_RELEASE(__ntlibc_sig_lock_token);
int __sig_unlock_for_handler(void);
void __sig_relock_after_handler(int);

/* Pure exit-code -> wait-status mapping used by waitpid()/wait()/wait3()/
 * wait4() (src/process/wait.c); exposed non-static so tests can drive its
 * boundary cases directly instead of only through a spawned process. */
int __wait_encode_status(int);

/* ---- misc -------------------------------------------------------------- */
int __is_wow64(void);
unsigned __rand_next(void);
/* getopt's diagnostic writer, shared with getopt_long. */
void __getopt_msg(const char *msg, const char *optname, size_t l);
/* The strerror table lookup, shared with strerror_r.  Never NULL. */
const char *__strerror_msg(int e);

/* ---- WOW64 clone repair (see arch/i386/src/wow64_fixup.c) -------------- */
/* Repair the FS-base and stuck-SRW-lock damage RtlCloneUserProcess leaves
 * in a cloned child under WOW64 -- see fork.c's header comment and
 * wow64_fixup.c's for why this is needed and what it does.  process and
 * thread are the clone's handles, still CREATE_SUSPENDED; call this
 * before ever resuming the thread.  Only meaningful, and only
 * implemented, on i386 -- WOW64 has no meaning for a native x86_64
 * ntlibc process, so this is a no-op there. */
#ifdef __i386__
void __wow64_fixup_clone(HANDLE process, HANDLE thread);
#else
static inline void __wow64_fixup_clone(HANDLE process, HANDLE thread) { (void)process; (void)thread; } // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
#endif

#define __container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
