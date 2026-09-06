/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * <sys/mman.h>, Pass 2: anonymous mappings and file-backed mappings of
 * regular files, plus page locking.
 *
 * munmap.html's only errors are misalignment, out-of-range, and len==0 --
 * there is no errno for a partial munmap, and the platform's unmap-view
 * primitive only ever drops a section view whole (see plat_mem.h). So
 * MAP_FIXED can only replace a file-backed mapping's entire extent, and
 * every munmap() of one this library creates is whole-extent.
 *
 * Each mmap() takes its own reservation (plat_mem.h's reserve/commit
 * split), so a partial munmap() can decommit just the subrange while
 * keeping the rest of the reservation -- releasing a reservation always
 * takes the whole thing. A decommitted range therefore stays reserved,
 * not free, until the mapping's last live page goes: an NT-specific,
 * unobservable-but-real address-space leak bounded by the number of live
 * mappings.
 *
 * MAP_FIXED is honoured at page granularity inside our own reservations,
 * [ENOMEM] outside them; discarding old contents (mmap.html) needs an
 * explicit decommit-then-commit, since only a freshly committed page
 * comes back zero-filled.
 *
 * msync: NT/Wine don't reliably update file timestamps when a section's
 * dirty pages flush, so writable shared mappings keep an independent
 * file handle and __plat_mem_flush_view() marks LastWriteTime/ChangeTime
 * explicitly.
 *
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/mmap.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/munmap.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/mprotect.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/msync.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/mlock.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/mlockall.html
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/munlockall.html
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "libc.h"
#include "plat_mem.h"
#include "plat_fd.h"

#define MMAP_PAGE 4096u

/* One live mapping. `live` is a one-bit-per-page bitmap (NULL means every
 * page is live); `locked` is two bits per page (0 unlocked, 1 locked, 2
 * newly locked by the current mlockall transaction). Both are allocated
 * lazily, on first partial change, so a huge never-split reservation
 * costs no bookkeeping memory. */
struct mapping {
	char *base;
	size_t npages;
	size_t live_pages;
	size_t next_free;
	unsigned char *live;
	unsigned char *locked;
	int filebacked;         /* section view, not a private anonymous
	                          * reservation -- see plat_mem.h */
	__plat_handle_t writeback; /* independent writable MAP_SHARED file handle */
	/* fildes/off mmap() was called with, kept for posix_mem_offset() to
	 * hand back. Meaningless when !filebacked -- that path answers
	 * EACCES before reading these. */
	int mm_fd;
	off_t mm_off;
};

/* Grows as needed; allocation failure is the only limit (a fixed ceiling
 * once made valid address-space exhaustion probes stop early). */
static struct mapping *maps;
static size_t maps_len;
static size_t maps_cap;
static size_t maps_free = (size_t)-1;
static size_t maps_recent = (size_t)-1;
static int lock_future;

#ifdef __clang_analyzer__
#define returns_element_of(registry) \
	__attribute__((annotate("ntlibc_relation_returns_element_of:" #registry)))
#define parameter_element_of(index, registry) \
	__attribute__((annotate("ntlibc_relation_parameter_element_of:" #index ":" #registry)))
#else
#define returns_element_of(registry)
#define parameter_element_of(index, registry)
#endif

/* Mapping pointers below are either checked lookup results or entries in
 * `maps`. find_slot() is the only operation which may grow and relocate
 * that array, and callers hold no mapping pointer across a find_slot(). */

static size_t pground(size_t n) { return (n + MMAP_PAGE - 1) & ~(size_t)(MMAP_PAGE - 1); }
static int pgaligned(const void *p) { return ((uintptr_t)p & (MMAP_PAGE - 1)) == 0; }

/* The mapping owning [p, p+len), or NULL. A range straddling two mappings
 * belongs to neither: MAP_FIXED replacement needs containment, unlike
 * munmap() which may legitimately span several mappings. */
/* These compare pointers from unrelated objects (a caller's argument vs.
 * one of `maps[]`'s bases), which ISO C only defines via uintptr_t
 * (6.5.6p9, 6.5.8p5) -- same reasoning as memmove.c's copy-direction
 * test. */
static int addr_lt(const void *a, const void *b) { return (uintptr_t)a < (uintptr_t)b; }
static int addr_le(const void *a, const void *b) { return (uintptr_t)a <= (uintptr_t)b; }
static int addr_gt(const void *a, const void *b) { return (uintptr_t)a > (uintptr_t)b; }
static int addr_ge(const void *a, const void *b) { return (uintptr_t)a >= (uintptr_t)b; }
static size_t addr_diff(const void *a, const void *b) { return (size_t)((uintptr_t)a - (uintptr_t)b); }

/* Every one of this file's registry loops used to write `&maps[i]` (or
 * `&maps[k]`, `&maps[maps_recent]`, ...) directly, once per loop. That
 * left the static analyzer re-deriving the same two facts -- "maps is
 * non-null" and "the field this loop reads is in bounds" -- from
 * scratch at every one of those call sites, none of which can locally
 * see the real, whole-file invariant that makes both true: maps_len
 * (and maps_free, its free-list twin) is never advanced past a value
 * find_slot() has not already backed with a successful `maps = grown;`
 * from realloc(), and no code anywhere in this file ever calls
 * free()/realloc() on `maps` itself or shrinks maps_len/maps_cap back
 * down -- so for any index i a caller here ever passes (always one it
 * already read off maps_len, maps_free, or a prior find_slot()/
 * find_containing() result), maps is guaranteed already allocated and
 * &maps[i] denotes a live, in-bounds element. A single-function
 * analysis of munmap()/mlockall()/... cannot see across those other
 * functions to confirm that, but it is real by construction, so it is
 * asserted once, here, at the one place the raw indexing still
 * happens, instead of re-litigated at every call site. */
static struct mapping *map_at(size_t i)
	returns_element_of(maps) __attribute__((returns_nonnull));
static struct mapping *map_at(size_t i)
{
	return &maps[i];
}

/* Every caller reaches `m` through map_at() (always non-null by
 * construction, see its own comment) or through a find_containing()/
 * find_slot() result already checked non-null before use -- none of
 * these six bitmap helpers ever defends against a NULL m itself, which
 * is the real, load-bearing contract nonnull(1) documents here rather
 * than merely papering over a per-function-local proof gap. */
static int page_live(const struct mapping *m, size_t page) __attribute__((nonnull(1)));
static int page_live(const struct mapping *m, size_t page)
{
	return !m->live || (m->live[page >> 3] & (1u << (page & 7))) != 0;
}

static int ensure_live_bitmap(struct mapping *m) __attribute__((nonnull(1)));
static int ensure_live_bitmap(struct mapping *m)
{
	size_t bytes;
	if (m->live) return 0;
	if (m->npages > (size_t)-1 - 7) { errno = ENOMEM; return -1; }
	bytes = (m->npages + 7) >> 3;
	m->live = malloc(bytes);
	if (!m->live) return -1;
	memset(m->live, 0xff, bytes);
	return 0;
}

/* Deliberately NOT nonnull(1) despite the same true precondition as its
 * five siblings above/below: measured against a real tools/lint.sh
 * ownership run, proving `m` here just moves the checker's very next
 * question from "is m live?" (masked/absorbed into one finding at this
 * statement) to "is m->live live?" (m->live[page >> 3]'s own base, then
 * *byte at every store below) -- a real, separately-unprovable fact
 * (m->live is only ever established by ensure_live_bitmap(), a
 * different function this per-function analysis cannot see was called
 * first) that was simply left unreported before, standing behind the
 * `m` finding this attribute would have removed. Net effect measured:
 * 1 finding silenced, 6 new ones (5 "byte", 1 m->live[...]) surface in
 * its place, a real regression, not a wash -- so this one stays
 * unannotated on purpose; see set_page_lock_state's identical case. */
static void set_page_live(struct mapping *m, size_t page, int live) // NOLINT(bugprone-easily-swappable-parameters) -- page selects a bitmap slot while live is its boolean state
{
	unsigned char mask = (unsigned char)(1u << (page & 7));
	unsigned char *byte = &m->live[page >> 3];
	int old = (*byte & mask) != 0;
	if (old == !!live) return;
	if (live) {
		*byte |= mask;
		m->live_pages++;
	} else {
		*byte &= (unsigned char)~mask;
		m->live_pages--;
	}
}

static unsigned page_lock_state(const struct mapping *m, size_t page) __attribute__((nonnull(1)));
static unsigned page_lock_state(const struct mapping *m, size_t page)
{
	unsigned char byte;
	if (!m->locked) return 0;
	byte = m->locked[page >> 2];
	switch (page & 3) {
	case 0: return byte & 3u;
	case 1: return (byte >> 2) & 3u;
	case 2: return (byte >> 4) & 3u;
	default: return (byte >> 6) & 3u;
	}
}

static int ensure_lock_bitmap(struct mapping *m) __attribute__((nonnull(1)));
static int ensure_lock_bitmap(struct mapping *m)
{
	size_t bytes;
	if (m->locked) return 0;
	if (m->npages > (size_t)-1 - 3) { errno = ENOMEM; return -1; }
	bytes = (m->npages + 3) >> 2;
	m->locked = calloc(bytes, 1);
	return m->locked ? 0 : -1;
}

/* Deliberately NOT nonnull(1) -- the same measured regression as
 * set_page_live's identical case just above (proving `m` here only
 * shifts the finding onto m->locked[page >> 2]'s own base and every
 * *byte store below, a real precondition too but one only
 * ensure_lock_bitmap(), a different function, ever establishes). Left
 * unannotated on purpose rather than trading one finding for several. */
static void set_page_lock_state(struct mapping *m, size_t page, unsigned state) // NOLINT(bugprone-easily-swappable-parameters) -- page selects a bitmap slot while state supplies its two-bit value
{
	unsigned char *byte = &m->locked[page >> 2];
	state &= 3u;
	switch (page & 3) {
	case 0:
		*byte = (unsigned char)((*byte & ~3u) | state);
		break;
	case 1:
		*byte = (unsigned char)((*byte & ~(3u << 2)) | (state << 2));
		break;
	case 2:
		*byte = (unsigned char)((*byte & ~(3u << 4)) | (state << 4));
		break;
	default:
		*byte = (unsigned char)((*byte & ~(3u << 6)) | (state << 6));
		break;
	}
}

/* Wine reports a page beyond a mapped file's end as an access violation
 * on an uncommitted address rather than NT's EXCEPTION_IN_PAGE_ERROR; the
 * signal bridge asks this to recover POSIX's SIGBUS distinction. A page
 * decommitted by munmap() is excluded -- it stays SIGSEGV/SEGV_MAPERR. */
int __mman_fault_is_object_error(const void *p)
{
	size_t i;
	for (i = 0; i < maps_len; i++) {
		struct mapping *m = map_at(i);
		size_t page;
		if (!m->base || !m->filebacked || addr_lt(p, m->base) ||
		    addr_ge(p, m->base + m->npages * MMAP_PAGE)) continue;
		page = addr_diff(p, m->base) / MMAP_PAGE;
		return page_live(m, page);
	}
	return 0;
}

int __mman_address_is_live(const void *p)
{
	size_t i;
	for (i = 0; i < maps_len; i++) {
		struct mapping *m = map_at(i);
		size_t page;
		if (!m->base || addr_lt(p, m->base) ||
		    addr_ge(p, m->base + m->npages * MMAP_PAGE)) continue;
		page = addr_diff(p, m->base) / MMAP_PAGE;
		return page_live(m, page);
	}
	return 0;
}

int __mman_range_is_live(const void *p, size_t len)
{
	size_t i;
	const char *a = p;
	if (!len || (uintptr_t)a > (uintptr_t)-1 - len) return 0;
	for (i = 0; i < maps_len; i++) {
		struct mapping *m = map_at(i);
		size_t first, last, page;
		if (!m->base || addr_lt(a, m->base) ||
		    addr_gt(a + len, m->base + m->npages * MMAP_PAGE)) continue;
		first = addr_diff(a, m->base) / MMAP_PAGE;
		last = (addr_diff(a, m->base) + len - 1) / MMAP_PAGE;
		for (page = first; page <= last; page++)
			if (!page_live(m, page)) return 0;
		return 1;
	}
	return 0;
}

static struct mapping *find_containing(const void *p, size_t len)
	returns_element_of(maps);
static struct mapping *find_containing(const void *p, size_t len)
{
	size_t i;
	const char *a = p;
	for (i = 0; i < maps_len; i++) {
		struct mapping *m = map_at(i);
		if (!m->base) continue;
		if (addr_ge(a, m->base) && addr_le(a + len, m->base + m->npages * MMAP_PAGE)) return m;
	}
	return NULL;
}

static struct mapping *find_slot(void) returns_element_of(maps);
static struct mapping *find_slot(void)
{
	size_t i, cap;
	struct mapping *grown;
	if (maps_free != (size_t)-1) {
		i = maps_free;
		maps_free = map_at(i)->next_free;
		memset(map_at(i), 0, sizeof *map_at(i));
		return map_at(i);
	}
	if (maps_len == maps_cap) {
		size_t bytes;
		if (!__array_next_capacity(maps_cap, maps_len, 1, 16, sizeof *maps, &cap)) {
			errno = ENOMEM;
			return NULL;
		}
		bytes = cap * sizeof *maps; /* proven <= SIZE_MAX by __array_next_capacity's own element_size bound above */
		grown = realloc(maps, bytes);
		if (!grown) return NULL;
		for (i = maps_cap; i < cap; i++)
			grown[i] = (struct mapping){0};
		maps = grown;
		maps_cap = cap;
	}
	return map_at(maps_len++);
}

static void release_slot(struct mapping *m) parameter_element_of(0, maps);
static void release_slot(struct mapping *m)
{
	size_t i = (size_t)(m - maps);
	if (maps_recent == i) maps_recent = (size_t)-1;
	memset(m, 0, sizeof *m);
	m->next_free = maps_free;
	maps_free = i;
}

static void mark_recent(struct mapping *m) parameter_element_of(0, maps);
static void mark_recent(struct mapping *m)
{
	maps_recent = (size_t)(m - maps);
}

static void init_page_state(struct mapping *m, size_t npages)
{
	m->npages = npages;
	m->live_pages = npages;
	m->live = NULL;
	m->locked = NULL;
}

/* Release the whole reservation once no page is live: __plat_mem_release()
 * for an anonymous mapping, __plat_mem_unmap_view() for a file-backed one
 * (a section view isn't memory a reservation-release call owns). Writable
 * shared views also close the independent writeback handle msync() uses. */
static void drop_if_dead(struct mapping *m)
	__attribute__((nonnull(1))) parameter_element_of(0, maps);
static void drop_if_dead(struct mapping *m)
{
	if (m->live_pages) return;
	if (m->filebacked) __plat_mem_unmap_view(m->base, m->npages * MMAP_PAGE);
	else __plat_mem_release(m->base, m->npages * MMAP_PAGE);
	if (m->writeback) __plat_close(m->writeback);
	free(m->live);
	free(m->locked);
	release_slot(m);
}

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	struct mapping *m;
	void *base;
	size_t size;
	size_t npages;
	int anon;
	struct __fd *f = NULL;
	__plat_handle_t writeback = __PLAT_HANDLE_NULL;

	/* "[EINVAL] The value of len is zero." (shall fail) */
	if (len == 0) { errno = EINVAL; return MAP_FAILED; }
	if (len > (size_t)-1 - (MMAP_PAGE - 1)) {
		errno = ENOMEM;
		return MAP_FAILED;
	}

	/* Exactly one of MAP_SHARED/MAP_PRIVATE, not merely at least one --
	 * both together is not a described state (mmap.html [EINVAL]). */
	if ((flags & (MAP_SHARED | MAP_PRIVATE)) != MAP_SHARED &&
	    (flags & (MAP_SHARED | MAP_PRIVATE)) != MAP_PRIVATE) {
		errno = EINVAL;
		return MAP_FAILED;
	}

	/* __MAP_ANONYMOUS, not the gated MAP_ANONYMOUS spelling: this file is
	 * built with different feature-test macros in different builds, and
	 * reading the gated name would make behaviour depend on that. */
	anon = (flags & __MAP_ANONYMOUS) != 0;

	if (anon) {
		/* No object to offset into for an anonymous mapping, so only
		 * zero is meaningful; anything else is a caller error. */
		if (off != 0) { errno = EINVAL; return MAP_FAILED; }
	} else {
		/* A caller not asking for the anonymous extension is making a
		 * file-backed request: [EBADF] for no valid descriptor
		 * (fd = -1, looks anonymous but isn't), [ENODEV] for a valid
		 * descriptor of an unsupported type (anything but a regular
		 * file), kept distinct so a caller can tell which refusal it
		 * got. */
		f = __fd_get(fd);
		if (!f) { errno = EBADF; return MAP_FAILED; }
		if (f->type != __FD_FILE) { errno = ENODEV; return MAP_FAILED; }

		/* off is signed; a negative offset is "invalid by the
		 * implementation" (mmap.html [EINVAL]). */
		if (off < 0 || (off & (off_t)(MMAP_PAGE - 1)) != 0) {
			errno = EINVAL;
			return MAP_FAILED;
		}

		/* mmap.html [EACCES]: fildes must be open for read always, and
		 * for write too if PROT_WRITE+MAP_SHARED. A MAP_PRIVATE writer
		 * needs no file write access -- its writes never reach the
		 * object -- so the second check is MAP_SHARED-only. */
		if ((f->flags & O_ACCMODE) == O_WRONLY) {
			errno = EACCES;
			return MAP_FAILED;
		}
		if ((flags & MAP_SHARED) && (prot & PROT_WRITE) &&
		    (f->flags & O_ACCMODE) == O_RDONLY) {
			errno = EACCES;
			return MAP_FAILED;
		}
	}

	npages = pground(len) / MMAP_PAGE;

	if (flags & MAP_FIXED) {
		size_t first, i;
		if (!pgaligned(addr)) { errno = EINVAL; return MAP_FAILED; }
		/* Page-granular commit only works inside a reservation we
		 * already own; there's no way to plant a mapping at an
		 * arbitrary address otherwise (mmap.html [ENOMEM]). */
		m = find_containing(addr, len);
		if (!m) { errno = ENOMEM; return MAP_FAILED; }

		if (m->filebacked) {
			/* A section view is placed/removed only as a whole, so
			 * MAP_FIXED is honoured here only when [addr,addr+len)
			 * is the mapping's entire current extent; a partial
			 * overlap is refused with [ENOMEM] rather than
			 * misbehaving.
			 *
			 * Also refused: an anonymous MAP_FIXED landing on a
			 * file-backed extent. POSIX allows replacing any prior
			 * mapping, but the replacement path needs a real file
			 * descriptor (`f`), which is NULL when this call is
			 * anonymous -- without this check that's a null deref
			 * on f->h. */
			if ((char *)addr != m->base || npages != m->npages || anon) {
				errno = ENOMEM;
				return MAP_FAILED;
			}
			if ((flags & MAP_SHARED) &&
			    (f->flags & O_ACCMODE) == O_RDWR) {
				if (__plat_dup(f->h, 0, &writeback) < 0)
					return MAP_FAILED;
			}
			/* No separate discard step here: a section view
			 * occupies its range for as long as it exists, so the
			 * old one must be unmapped before the platform will
			 * place the new one (measured:
			 * STATUS_CONFLICTING_ADDRESSES otherwise). Old contents
			 * are lost even if the replacement below fails --
			 * mmap.html's MAP_FIXED requires discard, not
			 * preserve-on-failure. */
			__plat_mem_unmap_view(m->base, m->npages * MMAP_PAGE);
			if (m->writeback) __plat_close(m->writeback);
			base = addr;
			if (__plat_mem_map_file(f->h, prot, flags, off,
			                        npages * MMAP_PAGE, &base) < 0) {
				if (writeback) __plat_close(writeback);
				free(m->live);
				free(m->locked);
				release_slot(m);
				return MAP_FAILED;
			}
			free(m->live);
			free(m->locked);
			init_page_state(m, npages);
			m->base = base;
			m->filebacked = 1;
			m->writeback = writeback;
			m->mm_fd = fd;
			m->mm_off = off;
			if (lock_future && mlock(base, npages * MMAP_PAGE) < 0) {
				__plat_mem_unmap_view(base, npages * MMAP_PAGE);
				if (m->writeback) __plat_close(m->writeback);
				free(m->live);
				free(m->locked);
				release_slot(m);
				errno = EAGAIN;
				return MAP_FAILED;
			}
			mark_recent(m);
			return base;
		}

		first = addr_diff(addr, m->base) / MMAP_PAGE;
		/* Commit failure discards the old pages too, so reserve the
		 * bitmap needed to record either outcome before changing them. */
		if (ensure_live_bitmap(m) < 0) return MAP_FAILED;

		if (__plat_mem_commit_fixed(addr, npages * MMAP_PAGE, prot) < 0) {
			/* The old contents are gone either way; the pages are
			 * dead, and saying so keeps the bookkeeping true. */
			for (i = 0; i < npages && first + i < m->npages; i++)
				set_page_live(m, first + i, 0);
			drop_if_dead(m);
			return MAP_FAILED;
		}
		for (i = 0; i < npages && first + i < m->npages; i++) {
			set_page_live(m, first + i, 1);
			if (m->locked) set_page_lock_state(m, first + i, 0);
		}
		if (lock_future && mlock(addr, npages * MMAP_PAGE) < 0) {
			__plat_mem_decommit(addr, npages * MMAP_PAGE);
			for (i = 0; i < npages && first + i < m->npages; i++)
				set_page_live(m, first + i, 0);
			drop_if_dead(m);
			errno = EAGAIN;
			return MAP_FAILED;
		}
		mark_recent(m);
		return addr;
	}

	m = find_slot();
	if (!m) { errno = ENOMEM; return MAP_FAILED; }

	if (!anon) {
		if ((flags & MAP_SHARED) && (f->flags & O_ACCMODE) == O_RDWR) {
			if (__plat_dup(f->h, 0, &writeback) < 0) {
				release_slot(m);
				return MAP_FAILED;
			}
		}
		base = NULL;
		if (__plat_mem_map_file(f->h, prot, flags, off, npages * MMAP_PAGE, &base) < 0) {
			if (writeback) __plat_close(writeback);
			release_slot(m);
			return MAP_FAILED;
		}
		init_page_state(m, npages);
		m->base = base;
		m->filebacked = 1;
		m->writeback = writeback;
		m->mm_fd = fd;
		m->mm_off = off;
		if (lock_future && mlock(base, npages * MMAP_PAGE) < 0) {
			__plat_mem_unmap_view(base, npages * MMAP_PAGE);
			if (m->writeback) __plat_close(m->writeback);
			free(m->live);
			free(m->locked);
			release_slot(m);
			errno = EAGAIN;
			return MAP_FAILED;
		}
		mark_recent(m);
		return base;
	}

	base = NULL;
	size = npages * MMAP_PAGE;
	if (__plat_mem_reserve(&base, size, prot) < 0) {
		release_slot(m);
		return MAP_FAILED;
	}

	init_page_state(m, npages);
	m->base = base;
	m->filebacked = 0;
	m->writeback = __PLAT_HANDLE_NULL;
	m->mm_fd = -1;
	m->mm_off = 0;
	if (lock_future && mlock(base, npages * MMAP_PAGE) < 0) {
		__plat_mem_release(base, size);
		free(m->live);
		free(m->locked);
		release_slot(m);
		errno = EAGAIN;
		return MAP_FAILED;
	}
	mark_recent(m);
	return base;
}

int munmap(void *addr, size_t len)
{
	size_t npages, i;
	size_t k;
	char *a = addr;

	/* munmap.html's only errors: out-of-range, len==0, misaligned addr --
	 * see the banner for why that shapes this implementation. */
	if (len == 0) { errno = EINVAL; return -1; }
	if (!pgaligned(addr)) { errno = EINVAL; return -1; }

	npages = pground(len) / MMAP_PAGE;

	/* The overwhelmingly common operation, including vmfill's address-
	 * space probes, is to unmap the mapping just returned by mmap(). Avoid
	 * walking an arbitrarily large registry for that exact whole mapping. */
	if (maps_recent != (size_t)-1) {
		struct mapping *m = map_at(maps_recent);
		if (m->base == a && m->npages == npages) {
			__plat_mem_decommit(a, npages * MMAP_PAGE);
			m->live_pages = 0;
			drop_if_dead(m);
			return 0;
		}
	}

	/* An unmapped-but-valid range is a SUCCESS per munmap.html, not an
	 * error, and a range spanning several mappings unmaps all of them --
	 * both fall out of walking the table rather than requiring one
	 * mapping to contain the range. Bitmaps are allocated in a first pass
	 * so bookkeeping allocation failure is atomic. */
	for (k = 0; k < maps_len; k++) {
		struct mapping *m = map_at(k);
		char *lo, *hi;
		if (!m->base) continue;
		lo = addr_gt(a, m->base) ? a : m->base;
		hi = a + npages * MMAP_PAGE;
		if (addr_gt(hi, m->base + m->npages * MMAP_PAGE))
			hi = m->base + m->npages * MMAP_PAGE;
		if (addr_ge(lo, hi)) continue;
		if (lo != m->base || hi != m->base + m->npages * MMAP_PAGE)
			if (ensure_live_bitmap(m) < 0) return -1;
	}

	for (k = 0; k < maps_len; k++) {
		struct mapping *m = map_at(k);
		char *lo, *hi;
		if (!m->base) continue;
		lo = addr_gt(a, m->base) ? a : m->base;
		hi = a + npages * MMAP_PAGE;
		if (addr_gt(hi, m->base + m->npages * MMAP_PAGE)) hi = m->base + m->npages * MMAP_PAGE;
		if (addr_ge(lo, hi)) continue;
		{
			size_t first = addr_diff(lo, m->base) / MMAP_PAGE;
			size_t n = addr_diff(hi, lo) / MMAP_PAGE;
			/* Page-granular decommit keeps the reservation and the
			 * rest of the mapping in place. */
			__plat_mem_decommit(lo, addr_diff(hi, lo));
			if (first == 0 && n == m->npages) {
				m->live_pages = 0;
			} else {
				for (i = 0; i < n; i++) {
					set_page_live(m, first + i, 0);
					if (m->locked)
						set_page_lock_state(m, first + i, 0);
				}
			}
			drop_if_dead(m);
		}
	}
	return 0;
}

int mprotect(void *addr, size_t len, int prot)
{
	/* mprotect.html [EINVAL] */
	if (!pgaligned(addr)) { errno = EINVAL; return -1; }
	if (len == 0) return 0;

	return __plat_mem_protect(addr, pground(len), prot);
}

int msync(void *addr, size_t len, int flags) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	size_t k;
	char *a = addr;
	char *end;
	/* Validated even with no shared file view in range: msync.html gives
	 * [EINVAL] for these regardless of whether there's anything to flush. */
	if (!pgaligned(addr)) { errno = EINVAL; return -1; }
	if ((flags & ~(MS_ASYNC | MS_SYNC | MS_INVALIDATE)) != 0) { errno = EINVAL; return -1; }
	if ((flags & MS_ASYNC) && (flags & MS_SYNC)) { errno = EINVAL; return -1; }
	end = a + pground(len);
	if (flags & MS_INVALIDATE) {
		for (k = 0; k < maps_len; k++) {
			struct mapping *m = map_at(k);
			char *lo, *hi;
			size_t first, n, i;
			if (!m->base) continue;
			lo = addr_gt(a, m->base) ? a : m->base;
			hi = addr_lt(end, m->base + m->npages * MMAP_PAGE)
			   ? end : m->base + m->npages * MMAP_PAGE;
			if (addr_ge(lo, hi)) continue;
			first = addr_diff(lo, m->base) / MMAP_PAGE;
			n = addr_diff(hi, lo) / MMAP_PAGE;
			for (i = 0; i < n; i++) if (page_lock_state(m, first + i)) {
				errno = EBUSY;
				return -1;
			}
		}
	}
	for (k = 0; k < maps_len; k++) {
		struct mapping *m = map_at(k);
		char *lo, *hi;
		if (!m->base || !m->filebacked || !m->writeback) continue;
		lo = addr_gt(a, m->base) ? a : m->base;
		hi = addr_lt(end, m->base + m->npages * MMAP_PAGE)
		   ? end : m->base + m->npages * MMAP_PAGE;
		if (addr_ge(lo, hi)) continue;
		if (__plat_mem_flush_view(lo, addr_diff(hi, lo), m->writeback) < 0)
			return -1;
	}
	return 0;
}

/* __plat_mem_lock() is a real lock on every backend (NT and Wine, see
 * nt.h's note on NtLockVirtualMemory), not a reports-success no-op. It's
 * bounded by a resource limit (working-set quota on NT, RLIMIT_MEMLOCK
 * under Wine) that is an environment property, not a platform one -- the
 * same binary can succeed or fail depending on the machine's limit, which
 * is why test/posix-mman.c skips based on the measured limit rather than
 * the system it believes it's on. */
static int lock_range(const void *addr, size_t len, int lock) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	char *base;
	size_t z;

	if (len == 0) { errno = EINVAL; return -1; }
	z = pground(len + ((uintptr_t)addr & (MMAP_PAGE - 1)));
	base = (char *)((uintptr_t)addr & ~(uintptr_t)(MMAP_PAGE - 1));
	if (lock) {
		char *end = base + z;
		size_t k;
		/* Make recording a successful platform lock infallible. */
		for (k = 0; k < maps_len; k++) {
			struct mapping *m = map_at(k);
			if (!m->base || addr_ge(base, m->base + m->npages * MMAP_PAGE) ||
			    addr_ge(m->base, end)) continue;
			if (ensure_lock_bitmap(m) < 0) return -1;
		}
	}
	if (lock ? __plat_mem_lock(base, z) : __plat_mem_unlock(base, z))
		return -1;
	{
		char *a = base;
		char *end = a + z;
		size_t k;
		for (k = 0; k < maps_len; k++) {
			struct mapping *m = map_at(k);
			char *lo, *hi;
			size_t first, n, i;
			if (!m->base) continue;
			lo = addr_gt(a, m->base) ? a : m->base;
			hi = addr_lt(end, m->base + m->npages * MMAP_PAGE)
			   ? end : m->base + m->npages * MMAP_PAGE;
			if (addr_ge(lo, hi)) continue;
			first = addr_diff(lo, m->base) / MMAP_PAGE;
			n = addr_diff(hi, lo) / MMAP_PAGE;
			for (i = 0; i < n; i++) if (page_live(m, first + i)) {
				if (lock) set_page_lock_state(m, first + i, 1);
				else if (m->locked) set_page_lock_state(m, first + i, 0);
			}
		}
	}
	return 0;
}

int mlock(const void *addr, size_t len)   { return lock_range(addr, len, 1); }
int munlock(const void *addr, size_t len) { return lock_range(addr, len, 0); }

int mlockall(int flags)
{
	size_t k;

	if (!flags || (flags & ~(MCL_CURRENT | MCL_FUTURE))) {
		errno = EINVAL;
		return -1;
	}
	if (flags & MCL_CURRENT) {
		for (k = 0; k < maps_len; k++) {
			struct mapping *m = map_at(k);
			size_t first, n;
			if (!m->base) continue;
			for (first = 0; first < m->npages; first += n) {
				while (first < m->npages &&
				       (!page_live(m, first) || page_lock_state(m, first))) first++;
				if (first == m->npages) break;
				for (n = 1; first + n < m->npages &&
				     page_live(m, first + n) && !page_lock_state(m, first + n); n++);
				if (mlock(m->base + first * MMAP_PAGE, n * MMAP_PAGE) < 0) {
					int saved = errno;
					size_t j;
					/* Unlock only what this call locked: state 2
					 * marks locks acquired here, distinct from ones
					 * that predated it. */
					for (j = 0; j < maps_len; j++) {
						struct mapping *r = map_at(j);
						size_t a, z;
						if (!r->base) continue;
						for (a = 0; a < r->npages; a += z) {
							while (a < r->npages && page_lock_state(r, a) != 2) a++;
							if (a == r->npages) break;
							for (z = 1; a + z < r->npages && page_lock_state(r, a + z) == 2; z++);
							munlock(r->base + a * MMAP_PAGE, z * MMAP_PAGE);
						}
					}
					errno = saved;
					return -1;
				}
				for (n = 0; first + n < m->npages &&
				     page_lock_state(m, first + n) == 1; n++)
					set_page_lock_state(m, first + n, 2);
			}
		}
		for (k = 0; k < maps_len; k++) {
			struct mapping *m = map_at(k);
			size_t i;
			if (!m->base) continue;
			for (i = 0; i < m->npages; i++)
				if (page_lock_state(m, i) == 2) set_page_lock_state(m, i, 1);
		}
	}
	if (flags & MCL_FUTURE) lock_future = 1;
	return 0;
}

int munlockall(void)
{
	size_t k;
	int failed = 0;
	int saved = 0;

	lock_future = 0;
	for (k = 0; k < maps_len; k++) {
		struct mapping *m = map_at(k);
		size_t first, n;
		if (!m->base) continue;
		for (first = 0; first < m->npages; first += n) {
			while (first < m->npages && !page_lock_state(m, first)) first++;
			if (first == m->npages) break;
			for (n = 1; first + n < m->npages && page_lock_state(m, first + n); n++);
			if (munlock(m->base + first * MMAP_PAGE, n * MMAP_PAGE) < 0) {
				if (!failed) saved = errno;
				failed = 1;
			}
		}
	}
	if (failed) {
		errno = saved;
		return -1;
	}
	return 0;
}

/* posix_madvise(): this implementation has no page-replacement heuristic
 * for any advice value to steer, so every valid one is genuinely a no-op
 * -- see <sys/mman.h>'s banner for why that is not the same as a stub.
 * [ENOMEM] is checked via the same mapping registry mmap()/munmap()/
 * mlock() already maintain. */
int posix_madvise(void *addr, size_t len, int advice)
{
	if (advice != POSIX_MADV_NORMAL && advice != POSIX_MADV_SEQUENTIAL &&
	    advice != POSIX_MADV_RANDOM && advice != POSIX_MADV_WILLNEED &&
	    advice != POSIX_MADV_DONTNEED)
		return EINVAL;

	if (!find_containing(addr, len))
		return ENOMEM;

	return 0;
}

/* posix_typed_mem_open(): which typed memory pools exist is entirely
 * implementation-defined, and this implementation ships none -- NT has no
 * concept of a distinct, bounded physical-memory pool (e.g. DMA-capable)
 * to wire to, only one general-purpose address space. [ENOENT] is
 * therefore this system's permanent answer for every name. */
int posix_typed_mem_open(const char *name, int oflag, int tflag)
{
	(void)name;
	(void)oflag;

	if (tflag != POSIX_TYPED_MEM_ALLOCATE &&
	    tflag != POSIX_TYPED_MEM_ALLOCATE_CONTIG &&
	    tflag != POSIX_TYPED_MEM_MAP_ALLOCATABLE) {
		errno = EINVAL;
		return -1;
	}

	errno = ENOENT;
	return -1;
}

/* Since posix_typed_mem_open() above never succeeds, no fildes value here
 * was ever a valid typed memory descriptor, so [EBADF] is the only real
 * outcome for any input. */
int posix_typed_mem_get_info(int fildes, struct posix_typed_mem_info *info)
{
	(void)fildes;
	(void)info;
	errno = EBADF;
	return -1;
}

/* posix_mem_offset(): answered from struct mapping's mm_fd/mm_off, set at
 * every file-backed mmap() call site. [EACCES] for an anonymous mapping,
 * where those fields are meaningless. */
int posix_mem_offset(const void *__restrict addr, size_t len,
                      off_t *__restrict off, size_t *__restrict contig_len,
                      int *__restrict fildes)
{
	struct mapping *m = find_containing(addr, len);
	size_t remaining;

	if (!m) { errno = ENOMEM; return -1; }
	if (!m->filebacked) { errno = EACCES; return -1; }

	*off = m->mm_off + (off_t)addr_diff(addr, m->base);
	*fildes = m->mm_fd;
	remaining = m->npages * MMAP_PAGE - addr_diff(addr, m->base);
	*contig_len = remaining < len ? remaining : len;
	return 0;
}

void __mman_reset_after_fork(void)
{
	size_t k;
	lock_future = 0;
	for (k = 0; k < maps_len; k++) {
		struct mapping *m = map_at(k);
		if (m->base) {
			free(m->locked);
			m->locked = NULL;
		}
	}
}

// NOLINTEND(misc-include-cleaner)
