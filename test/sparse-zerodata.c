/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * FSCTL_SET_ZERO_DATA: at what granularity NT releases allocation, and
 * whether the sparse mark is what enables it.  A table of ranges --
 * covering whole allocation units, covering none, straddling two,
 * covering the whole file, and past/inverted/negative -- each run
 * against a file marked sparse with FSCTL_SET_SPARSE and against one
 * that was never marked.
 *
 * It also measures FileAllocationInformation (info class 19) against the
 * sparse attribute, which nothing else does: every published number for
 * that class was taken on dense files.
 *
 * WHY THIS FILE EXISTS
 *
 * Wine answers FSCTL_SET_SPARSE with STATUS_SUCCESS and does nothing
 * else: in wine-9.0, which is what the CI Wine legs run,
 * dlls/ntdll/unix/file.c:6156-6160 is literally
 * `TRACE("FSCTL_SET_SPARSE: Ignoring request")` followed by
 * `status = STATUS_SUCCESS`.  Nothing is persisted, so the file never
 * acquires FILE_ATTRIBUTE_SPARSE_FILE -- measured here, and the reason
 * this file reports the attribute rather than trusting the ioctl's
 * return value.  (A `user.WINESPARSE` extended attribute that does
 * remember the mark exists only in *our* Wine fork, added by
 * 6ccc83feb "ntdll: Allocate real blocks when extending a file that is
 * not sparse", which is on Pandapip1/wine master and in no upstream Wine
 * release; it is not what stock Wine does and must not be described as
 * such.)
 *
 * FSCTL_SET_ZERO_DATA -- the call that actually punches the hole -- has
 * no implementation in stock Wine at all, so every question about the
 * resulting file's *allocation* is unanswerable there.  This binary is
 * therefore a probe whose only real oracle is the `windows-test` CI leg
 * (real Windows Server 2025); under Wine it exits 77 naming the missing
 * mechanism rather than passing vacuously.
 *
 * WHAT NT ACTUALLY DOES (measured; two earlier rules here were WRONG)
 *
 * On Windows Server 2025 build 26100, NTFS:
 *
 *   On a file MARKED SPARSE, NTFS releases exactly those allocation
 *   units WHOLLY COVERED by the requested range, and zeroes the
 *   remainder of the range in place.  On a file not marked sparse it
 *   only zeroes, and releases nothing.
 *
 *   The unit is min(16 * cluster, 65536): sixteen clusters, capped at
 *   64 KB.  That is NTFS's compression unit.
 *
 * The cap is not decoration, and it is why this file derives the unit
 * from FileFsSizeInformation instead of writing 65536 down.  Measured
 * across three cluster regimes, with the 4096 leg run first as a control
 * against the already-known answer so the instrument was validated
 * before it was trusted:
 *
 *     cluster    16 x cluster    MEASURED granularity
 *      1024          16384             16384
 *      4096          65536             65536   <- control
 *      8192         131072             65536
 *
 * NEITHER of the two candidates this file previously entertained is
 * right.  "A constant 64 KB" holds at and above 4 KB clusters and fails
 * below.  "16 x the cluster size" holds at and below 4 KB clusters and
 * fails above.  Each is correct in exactly half the range, which is
 * precisely why 4 KB-cluster data -- everything anyone had -- could not
 * separate them: 4096 is the crossover point.
 *
 * Note what 8192 does, because it is the trap.  It sits on the FLAT part
 * of the curve, above the crossover, and measures 65536 -- the same
 * number the incumbent 4 KB volume gives.  Run as a lone "discriminating"
 * cell against the framing "128 KB if the rule is 16 x cluster, 64 KB if
 * it is constant", a clean 65536 reads as constant-64 KB CONFIRMED.  It
 * would have been a false confirmation of the favoured hypothesis, from
 * a passing run with a passing control, and it was very nearly built.
 * A cell that can only produce the incumbent answer is not a test of the
 * incumbent, however carefully the rest of it is constructed.  The
 * discriminating regimes are BELOW 4096.
 *
 * The banner that used to stand here said the opposite -- that the
 * UNMARKED case was the discriminating one -- and asserted, as fact,
 * that NT never deallocates and that the granularity was a matter of
 * *cluster* alignment.  Both are refuted.
 * The discriminating case is the SPARSE one with a range that covers at
 * least one whole 64 KB unit; the unmarked case is the control.  Cluster
 * alignment is not the rule: a range can be perfectly cluster-aligned,
 * as [32768,98304) is on 4 KB clusters, and still release nothing,
 * because it covers no whole allocation unit.
 *
 * HOW THE WRONG RULE GOT HERE, AND WHY THE TABLE BELOW EXISTS
 *
 * This file used to have three constants: FILE_SIZE 65536, ZERO_FROM
 * 8192, ZERO_TO 40960.  A 32 KB range inside a 65536-byte file -- that
 * is, a range sitting entirely within the file's single 64 KB allocation
 * unit.  No unit was wholly covered, so no unit COULD be released, so
 * the sparse and unmarked cases were guaranteed to print identical
 * output and VERDICT=DEALLOCATED was unreachable by construction.  The
 * probe was structurally incapable of discriminating what it existed to
 * discriminate, and it printed PASS while doing so.
 *
 * Two independent oracles agreed on the wrong answer, because both
 * varied the *implementation* and neither varied the *stimulus*.  When
 * an earlier fix chasing the anomaly added two new observations -- the
 * sparse attribute and the extent list -- it left FILE_SIZE,
 * ZERO_FROM and ZERO_TO exactly as they were.  Varying the observation
 * is not varying the input.
 *
 * So the parameters are now a TABLE, not three #defines, and every row
 * states what a different outcome would have meant.  Rows that must
 * release and rows that must NOT release are both present and both
 * asserted: the sub-unit rows are what make the releasing rows mean
 * something, and dropping them as uninteresting is how the file got into
 * its previous state.
 *
 * WHICH CLUSTER REGIME DID THIS RUN SEE?
 *
 * FileFsSizeInformation is queried once, unconditionally, and the unit
 * every expected value below is computed from is DERIVED from it --
 * min(16 * cluster, 65536) -- rather than written down.  On the 4 KB
 * runners that still evaluates to 65536, so nothing about the existing
 * rows changes; the point is that the rule in the file is now the rule
 * NTFS has, so a run on any other volume computes the right expectation
 * instead of the 4 KB one.  Every row is asserted on every cluster size,
 * because the rule is now known for every cluster size.
 *
 * Point SPICULE_ZD_DIR at another volume, and SPICULE_ZD_CLUSTER at the
 * cluster size that was asked for, and this file measures there instead
 * -- after reading the size back off the filesystem and refusing to run
 * if it is not what was requested.  Building the volume is not this
 * file's job.  A hosted Windows runner can attach a VHD; 1024 needs
 * New-VHD -PhysicalSectorSizeBytes 512, because NTFS requires the
 * cluster to be a multiple of the physical sector and a VHD presents
 * 4096 by default.
 *
 * If a future run ever wants to re-measure the rule rather than assume
 * it, the regime to build is BELOW 4096 -- 1024 or 2048.  2048 predicts
 * 32768, which nothing else predicts.  Do not reach for 8192: see the
 * trap described above.
 *
 * WHAT IS ASSERTED AND WHAT IS ONLY MEASURED
 *
 * Asserted, on a 4 KB-cluster volume, for every row: if the ioctl
 * reports success then the requested range reads back as zero, the bytes
 * on either side are untouched, EndOfFile is unchanged (zeroing is not a
 * truncation), AllocationSize equals the before value minus the wholly
 * covered 64 KB units, and FSCTL_QUERY_ALLOCATED_RANGES returns exactly
 * the extents that release implies.  AllocationSize used to be measured
 * and never asserted; it is the claim, so it is now asserted.
 *
 * Only measured, never asserted: everything on a volume whose cluster
 * size is not 4096 (see above).
 *
 * If the ioctl fails, the contract assertions have no input to run
 * against.  A not-supported-family status makes the whole binary
 * unverified (rc=77) naming the status; any other failure status is
 * printed just as prominently and also leaves the row unverified,
 * because a status is a measurement and this file's job is to report
 * measurements.
 *
 * Constants and structure layouts are copied by hand from mingw-w64's
 * winioctl.h (FSCTL_SET_SPARSE / FSCTL_SET_ZERO_DATA at :1509-1510,
 * FILE_SET_SPARSE_BUFFER at :1905, FILE_ZERO_DATA_INFORMATION at :1909)
 * and from src/internal/nt.h (FILE_STANDARD_INFORMATION,
 * FileStandardInformation = 5), because the test/ tree is not built with
 * src/internal/ on the include path -- the same hand-declaration
 * convention test/posix-errno.c and test/posix-signal.c already use.
 */
/* mkdtemp() is feature-test gated in include/stdlib.h; same define
 * most other tests in test/ already carry for the same reason (see
 * test/posix-glob.c's comment on this exact define). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

static int fails;
static int unverified;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* ---- hand-declared NT surface ---------------------------------- */
typedef int NTSTATUS;
typedef void *HANDLE;
typedef void *PVOID;
/* NT's ULONG is 32-bit on every target NT runs on, and `unsigned long`
 * is 32-bit under LLP64 -- so spelling it that way is correct for the
 * PE build and silently wrong anywhere `unsigned long` is 64 bits.  The
 * native AddressSanitizer build (tools/asan-build.sh) is exactly that:
 * LP64 ELF, where it made FILE_FS_SIZE_INFORMATION's two trailing
 * ULONGs 8 bytes each, so SectorsPerAllocationUnit read back as
 * (BytesPerSector << 32) | SectorsPerAllocationUnit and BytesPerSector
 * read past the structure as 0 -- a bytes-per-cluster of 0 that looked
 * like a filesystem with no geometry.  Fixed width, as
 * src/internal/nt.h:36 spells it, is right on both. */
typedef uint32_t ULONG;
typedef unsigned char BOOLEAN;
typedef long long LONGLONG;
#ifdef __i386__
#define NTAPI __attribute__((stdcall))
typedef unsigned long ULONG_PTR;
#else
#define NTAPI
typedef unsigned long long ULONG_PTR;
#endif
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

typedef struct _IO_STATUS_BLOCK {
	union { NTSTATUS Status; PVOID Pointer; };
	ULONG_PTR Information;
} IO_STATUS_BLOCK;

typedef struct _FILE_STANDARD_INFORMATION {
	LONGLONG AllocationSize;
	LONGLONG EndOfFile;
	ULONG NumberOfLinks;
	BOOLEAN DeletePending;
	BOOLEAN Directory;
} FILE_STANDARD_INFORMATION;
#define FileStandardInformation 5

typedef struct _FILE_BASIC_INFORMATION {
	LONGLONG CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
	ULONG FileAttributes;
} FILE_BASIC_INFORMATION;
#define FileBasicInformation 4
#define FILE_ATTRIBUTE_SPARSE_FILE 0x00000200UL

typedef struct _FILE_ALLOCATED_RANGE_BUFFER {
	LONGLONG FileOffset;
	LONGLONG Length;
} FILE_ALLOCATED_RANGE_BUFFER;

typedef struct _FILE_SET_SPARSE_BUFFER { BOOLEAN SetSparse; } FILE_SET_SPARSE_BUFFER;
typedef struct _FILE_ZERO_DATA_INFORMATION {
	LONGLONG FileOffset;
	LONGLONG BeyondFinalZero;
} FILE_ZERO_DATA_INFORMATION;

/* CTL_CODE(FILE_DEVICE_FILE_SYSTEM=9, fn, METHOD_BUFFERED=0, access)
 * == (9 << 16) | (access << 14) | (fn << 2) | 0.
 * SET_SPARSE:    fn 49, FILE_SPECIAL_ACCESS (== FILE_ANY_ACCESS, 0).
 * SET_ZERO_DATA: fn 50, FILE_WRITE_DATA (2). */
#define FSCTL_SET_SPARSE     0x000900C4UL
#define FSCTL_SET_ZERO_DATA  0x000980C8UL
/* fn 51, METHOD_NEITHER (3), FILE_READ_DATA (1):
 * (9 << 16) | (1 << 14) | (51 << 2) | 3. */
#define FSCTL_QUERY_ALLOCATED_RANGES 0x000940CFUL

#define STATUS_NOT_IMPLEMENTED        ((NTSTATUS)0xC0000002L)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010L)
#define STATUS_NOT_SUPPORTED          ((NTSTATUS)0xC00000BBL)

NTSTATUS NTAPI NtFsControlFile(HANDLE, HANDLE, PVOID, PVOID, IO_STATUS_BLOCK *, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtQueryInformationFile(HANDLE, IO_STATUS_BLOCK *, PVOID, ULONG, int);

/* src/internal/libc.h: "HANDLE __fd_handle(int fd)  -- NULL with errno=EBADF". */
HANDLE __fd_handle(int fd);


/* ---- probe parameters -------------------------------------------
 *
 * FILE_SIZE is 1 MB: sixteen 64 KB allocation units, so a range can be
 * wholly inside one unit, cover exactly one, cover several, straddle
 * two, or cover the lot -- distinctions a 65536-byte file cannot make,
 * which is why the previous 65536 could not discriminate anything.
 */
#define FILE_SIZE  1048576
#define FILL_BYTE  0xAB

/* The sparse allocation unit is min(16 * cluster, UNIT_CAP): sixteen
 * clusters, capped at 64 KB.  That is NTFS's compression unit, and it is
 * derived from the volume's measured cluster size rather than written
 * down as a number, because writing it down as a number is what was
 * wrong before.  See the banner for the measurements. */
#define UNIT_CAP         65536
#define REGIME_CLUSTER   4096

#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)

/* FILE_FS_SIZE_INFORMATION / FileFsSizeInformation, hand-declared for the
 * same reason as everything else here (the test/ tree has no src/internal on
 * the include path).  cluster = SectorsPerAllocationUnit * BytesPerSector. */
typedef struct _FILE_FS_SIZE_INFORMATION {
	LONGLONG TotalAllocationUnits;
	LONGLONG AvailableAllocationUnits;
	ULONG SectorsPerAllocationUnit;
	ULONG BytesPerSector;
} FILE_FS_SIZE_INFORMATION;
#define FileFsSizeInformation 3
NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE, IO_STATUS_BLOCK *, PVOID, ULONG, int);

/* FileAllocationInformation, for the class-19 section at the bottom. */
#define FileAllocationInformation 19
NTSTATUS NTAPI NtSetInformationFile(HANDLE, IO_STATUS_BLOCK *, PVOID, ULONG, int);

/* Measured once, then asserted -- see run_probe().  A probe that records
 * the cluster regime without asserting it can silently run on the wrong
 * volume and reproduce this file's whole failure one level up: correct
 * arithmetic applied to a stimulus that was never the one requested. */
static long long g_cluster;      /* bytes per cluster, measured */
static long long g_unit;         /* min(16 * g_cluster, UNIT_CAP), derived */
static int       rows_measured;

static int not_supported(NTSTATUS st)
{
	return st == STATUS_NOT_SUPPORTED || st == STATUS_INVALID_DEVICE_REQUEST ||
	       st == STATUS_NOT_IMPLEMENTED;
}

/* Bytes NTFS should release for [off,beyond) if the unit is `unit`:
 * exactly the unit-aligned units WHOLLY covered by the range, after the
 * range is clamped to the file.  Cluster alignment does not enter into
 * it -- [32768,98304) is cluster-aligned on any volume at or below 32 KB
 * clusters and still covers no whole 64 KB unit. */
static long long released_bytes(long long off, long long beyond, long long unit)
{
	long long lo, hi;
	if (off < 0) off = 0;
	if (beyond > FILE_SIZE) beyond = FILE_SIZE;
	if (beyond <= off) return 0;
	lo = ((off + unit - 1) / unit) * unit;
	hi = (beyond / unit) * unit;
	return hi > lo ? hi - lo : 0;
}

static int query_std(HANDLE h, FILE_STANDARD_INFORMATION *si, const char *when, const char *tag)
{
	IO_STATUS_BLOCK io;
	NTSTATUS st;
	memset(si, 0, sizeof *si);
	st = NtQueryInformationFile(h, &io, si, (ULONG)sizeof *si, FileStandardInformation);
	if (!NT_SUCCESS(st)) {
		printf("zerodata[%s]: NtQueryInformationFile(FileStandardInformation) %s "
		       "-> 0x%08lX; nothing further can be measured for this case\n",
		       tag, when, (unsigned long)(unsigned)st);
		return 0;
	}
	return 1;
}

/* Is FILE_ATTRIBUTE_SPARSE_FILE actually set right now?  Printed rather
 * than asserted: FSCTL_SET_SPARSE reporting success and the attribute
 * being observable afterwards are two different claims, and on a volume
 * that does not support sparse files they can come apart.  Without this
 * line a sparse row that quietly behaved like an unmarked one would be
 * indistinguishable from NT declining to release. */
static void report_sparse_attr(HANDLE h, const char *tag, const char *when)
{
	IO_STATUS_BLOCK io;
	FILE_BASIC_INFORMATION bi;
	NTSTATUS st;
	memset(&bi, 0, sizeof bi);
	st = NtQueryInformationFile(h, &io, &bi, (ULONG)sizeof bi, FileBasicInformation);
	if (!NT_SUCCESS(st)) {
		printf("zerodata[%s]: FileAttributes %s -> query failed 0x%08lX\n",
		       tag, when, (unsigned long)(unsigned)st);
		return;
	}
	printf("zerodata[%s]: FileAttributes %s = 0x%08lX (FILE_ATTRIBUTE_SPARSE_FILE: %s)\n",
	       tag, when, (unsigned long)bi.FileAttributes,
	       (bi.FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) ? "set" : "clear");
}

/* The allocated extents of the whole file, straight from the filesystem.
 * This is the direct form of the claim AllocationSize makes only in
 * aggregate: a released hole shows up here as a gap, with its boundaries
 * snapped to the real allocation unit -- so the extent list states the
 * unit in bytes, whatever it is, including a value neither hypothesis
 * anticipated.  Returned into the caller's array so it can be asserted
 * and not merely printed. */
static int report_allocated_ranges(HANDLE h, const char *tag, const char *when,
                                   FILE_ALLOCATED_RANGE_BUFFER *out, unsigned cap,
                                   unsigned *n_out)
{
	IO_STATUS_BLOCK io;
	FILE_ALLOCATED_RANGE_BUFFER in;
	NTSTATUS st;
	unsigned n, i;

	*n_out = 0;
	in.FileOffset = 0;
	in.Length = FILE_SIZE;
	memset(out, 0, cap * sizeof *out);
	io.Information = 0;
	st = NtFsControlFile(h, 0, 0, 0, &io, FSCTL_QUERY_ALLOCATED_RANGES,
	                     &in, (ULONG)sizeof in, out, (ULONG)(cap * sizeof *out));
	if (!NT_SUCCESS(st)) {
		printf("zerodata[%s]: FSCTL_QUERY_ALLOCATED_RANGES %s -> 0x%08lX "
		       "(extents not measured)\n", tag, when, (unsigned long)(unsigned)st);
		return 0;
	}
	n = (unsigned)(io.Information / sizeof out[0]);
	if (n > cap) n = cap;
	*n_out = n;
	printf("zerodata[%s]: allocated extents %s: %u range(s)%s\n",
	       tag, when, n, n == 0 ? " -- the file is entirely unallocated" : "");
	for (i = 0; i < n; i++)
		printf("zerodata[%s]:   extent %u: [%lld,%lld)\n", tag, i,
		       (long long)out[i].FileOffset,
		       (long long)(out[i].FileOffset + out[i].Length));
	return 1;
}

/* ---- the table --------------------------------------------------
 *
 * Every row says what it asks and what a DIFFERENT outcome would have
 * looked like.  A row whose two outcomes are the same number does not
 * belong in this file; that is what the old [8192,40960) row was.
 */
enum { EXPECT_OK, EXPECT_INVALID, EXPECT_MEASURE };

struct row {
	const char *name;
	long long   off, beyond;
	unsigned    in_size;   /* declared input length; 0 => sizeof the struct */
	int         null_in;   /* 0 = real buffer, 1 = NULL, 2 = unmapped non-NULL */
	int         readonly;  /* reopen without write access before the FSCTL */
	int         expect;
	const char *asks;
	const char *otherwise;
};

static const struct row rows[] = {
/* --- release rows: each covers at least one whole 64 KB unit --- */
{ "whole-file",      0,        FILE_SIZE, 0,0,0, EXPECT_OK,
  "the entire file: all sixteen units wholly covered",
  "sparse: Alloc 1048576->0 and no extents. If Alloc stays at 1048576 here the apparatus "
  "cannot observe release at all and every no-release row below is uninterpretable." },
{ "interior-512k",   262144,   786432,    0,0,0, EXPECT_OK,
  "aligned interior 512 KB: eight whole units",
  "sparse: Alloc drops by exactly 524288, extents [0,262144) and [786432,1048576). A drop of "
  "some other size means the unit is not 64 KB." },
{ "one-unit",        65536,    131072,    0,0,0, EXPECT_OK,
  "exactly one aligned 64 KB unit",
  "sparse: Alloc drops by exactly 65536. No drop means the unit is LARGER than 64 KB, which on "
  "a 4 KB volume would refute the whole rule." },
{ "measure-the-unit", 4096,    FILE_SIZE - 4096, 0,0,0, EXPECT_OK,
  "everything but one 4 KB slice at each end: ends aligned to no candidate unit, so the "
  "retained head/tail extents STATE the real unit in bytes",
  "head extent [0,65536) => unit is a constant 64 KB; [0,16*cluster) => unit is 16 x cluster; "
  "[0,cluster) => cluster granularity; no gap at all => no release" },
/* --- no-release rows: controls, and they are what make the rows above
 *     mean anything.  Both are cluster-aligned on a 4 KB volume, so if
 *     the rule were about cluster alignment they would release. --- */
{ "sub-cluster",     4096,     8192,      0,0,0, EXPECT_OK,
  "4 KB wholly inside the first unit: no unit can be released",
  "any drop in Alloc, or any gap in the extent list, means the granularity is FINER than 64 KB" },
{ "straddle-two",    32768,    98304,     0,0,0, EXPECT_OK,
  "64 KB long, cluster-aligned, but straddling two units so covering neither whole",
  "no drop => coverage of a whole unit is the rule; a 65536 drop => length alone decides, and "
  "the whole-unit story is wrong" },
/* --- edges --- */
{ "past-eof",        FILE_SIZE + 4096, FILE_SIZE + 8192, 0,0,0, EXPECT_OK,
  "a range entirely past EOF",
  "EndOfFile stays 1048576 => the FSCTL does not extend a file; EndOfFile grows => it does" },
{ "inverted",        8192,     4096,      0,0,0, EXPECT_INVALID,
  "BeyondFinalZero < FileOffset",
  "STATUS_INVALID_PARAMETER expected; success would mean NT normalises the range" },
{ "negative-offset", -4096,    4096,      0,0,0, EXPECT_INVALID,
  "a negative FileOffset",
  "STATUS_INVALID_PARAMETER expected; success would mean the offset is treated as unsigned" },
/* --- input-length rows.  The length check is `<`, not `!=`: a SURPLUS
 *     declared length succeeds on NT and the request is honoured.  `!=`
 *     is the obvious thing to write and it silently rejects valid
 *     callers, so the surplus rows are here to pin that down rather
 *     than leave a new probe encoding the wrong rule. --- */
{ "inlen-short",     65536,    131072,    8,  0,0, EXPECT_INVALID,
  "input length 8, one field short of the structure",
  "STATUS_INVALID_PARAMETER expected; success would mean NT reads past the declared length" },
{ "inlen-exact",     65536,    131072,    16, 0,0, EXPECT_OK,
  "input length exactly sizeof(FILE_ZERO_DATA_INFORMATION)",
  "must succeed and release 65536; anything else contradicts the release rows above" },
{ "inlen-surplus17", 65536,    131072,    17, 0,0, EXPECT_OK,
  "input length 17: one byte MORE than the structure",
  "must SUCCEED and honour the request. A failure here would mean the check is `!=` rather "
  "than `<`, and an implementation copying that would reject valid callers." },
{ "inlen-surplus24", 65536,    131072,    24, 0,0, EXPECT_OK,
  "input length 24: eight bytes more than the structure",
  "same as inlen-surplus17; two surplus lengths so a single odd byte count cannot pass by luck" },
/* --- pointer rows.  DELIBERATELY measured, not asserted.  The claim
 *     "NT rejects a bad pointer before dereferencing, because the FSCTL
 *     is METHOD_BUFFERED and the I/O manager captures behind
 *     ProbeForRead" is an inference from the control code, not something
 *     any run has shown.  It is a strong prior and it is still a guess,
 *     and asserting a mechanism passes exactly as green as measuring one
 *     -- a status code says WHAT NT returned, never WHY.  The length
 *     claim above is measured and is asserted; this is not, and these
 *     rows exist to make it measurable.  A bad pointer paired with a bad
 *     length would not separate the two, since the length is checked
 *     first, so both rows here carry a VALID 16-byte length. --- */
{ "null-input-len16", 65536,   131072,    16, 1,0, EXPECT_MEASURE,
  "a NULL input pointer with a length NT is known to accept",
  "unasserted. INVALID_PARAMETER and ACCESS_VIOLATION are both plausible and they say different "
  "things about where the rejection happens; neither is established, so this row reports the "
  "raw status." },
{ "bad-input-len16",  65536,   131072,    16, 2,0, EXPECT_MEASURE,
  "a non-NULL but unmapped input pointer with a length NT accepts: the only shape that can "
  "distinguish a pointer check from a NULL check, and nobody has run it",
  "unasserted. If this differs from null-input-len16 then NULL is special-cased rather than "
  "being one unreadable address among many." },
/* --- access.  Deliberately EXPECT_MEASURE: nobody has measured what NT
 *     returns without FILE_WRITE_DATA, and inventing a value is what
 *     this file exists to stop. --- */
{ "no-write-access", 65536,    131072,    0,  0,1, EXPECT_MEASURE,
  "the same request on a handle opened WITHOUT write access",
  "unmeasured until now: this row reports the raw status rather than asserting one. "
  "ACCESS_DENIED and INVALID_DEVICE_REQUEST are both plausible and they mean different things." },
};
#define NROWS ((int)(sizeof rows / sizeof rows[0]))

/* Runs one row against one sparse/unmarked variant. */
static void run_row(const struct row *r, int mark_sparse)
{
	char path[96], tag[96];
	unsigned char *buf;
	FILE_STANDARD_INFORMATION before, after;
	FILE_ALLOCATED_RANGE_BUFFER ext_before[32], ext_after[32];
	unsigned n_before = 0, n_after = 0;
	IO_STATUS_BLOCK io;
	/* Padded, so a surplus declared length still names memory we own --
	 * otherwise inlen-surplus24 would have NT capture eight bytes past
	 * the end of a stack object and the row would be testing our bug. */
	struct { FILE_ZERO_DATA_INFORMATION z; unsigned char pad[16]; } zbuf;
	NTSTATUS st_sparse = 0, st_zero;
	HANDLE h;
	int fd, ok_before, ok_after_ext, data_row;
	long long expect_rel, expect_rel_16x, expect_rel_cap, observed_rel;
	unsigned in_len;

	snprintf(tag, sizeof tag, "%s/%s", r->name, mark_sparse ? "sparse" : "unmarked");
	snprintf(path, sizeof path, "zd-%s-%d.bin", r->name, mark_sparse);

	buf = malloc(FILE_SIZE);
	if (!buf) { printf("FAIL %s: malloc\n", tag); fails++; return; }

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) { printf("FAIL %s: open: %s\n", tag, strerror(errno)); fails++; free(buf); return; }
	h = __fd_handle(fd);
	if (!h) { printf("FAIL %s: __fd_handle: %s\n", tag, strerror(errno)); fails++; close(fd); free(buf); return; }

	/* Mark sparse before the data is written -- the canonical order, and
	 * the one a caller that wants a sparse file would use. */
	if (mark_sparse) {
		FILE_SET_SPARSE_BUFFER sb;
		sb.SetSparse = 1;
		st_sparse = NtFsControlFile(h, 0, 0, 0, &io, FSCTL_SET_SPARSE, &sb, (ULONG)sizeof sb, 0, 0);
		if (!NT_SUCCESS(st_sparse)) {
			printf("SKIP zerodata[%s]: the file could not be marked sparse "
			       "(FSCTL_SET_SPARSE -> 0x%08lX), so this row was not measured\n",
			       tag, (unsigned long)(unsigned)st_sparse);
			unverified++; close(fd); free(buf); return;
		}
	}

	memset(buf, FILL_BYTE, FILE_SIZE);
	if (write(fd, buf, FILE_SIZE) != FILE_SIZE) {
		printf("FAIL %s: short write: %s\n", tag, strerror(errno)); fails++;
		close(fd); free(buf); return;
	}
	if (fsync(fd) != 0) { printf("FAIL %s: fsync: %s\n", tag, strerror(errno)); fails++; }

	if (r->readonly) {
		close(fd);
		fd = open(path, O_RDONLY);
		if (fd < 0) { printf("FAIL %s: reopen O_RDONLY: %s\n", tag, strerror(errno)); fails++; free(buf); return; }
		h = __fd_handle(fd);
		if (!h) { printf("FAIL %s: __fd_handle after reopen\n", tag); fails++; close(fd); free(buf); return; }
	}

	printf("zerodata[%s]: ASKS      %s\n", tag, r->asks);
	/* The row's OTHERWISE is written for the sparse variant, which is the
	 * one that can release.  The unmarked variant is the control and its
	 * expectation is the same for every row, so say that here rather than
	 * printing sparse-flavoured text against an unmarked measurement. */
	if (mark_sparse)
		printf("zerodata[%s]: OTHERWISE %s\n", tag, r->otherwise);
	else
		printf("zerodata[%s]: OTHERWISE control: on a file never marked sparse nothing "
		       "may be released for ANY row -- AllocationSize unchanged and one extent "
		       "covering the whole file. A release here would mean the sparse mark is "
		       "not what enables it, refuting the rule for every row above.\n", tag);

	ok_before = query_std(h, &before, "before", tag);
	if (!ok_before) { unverified++; close(fd); free(buf); return; }
	report_sparse_attr(h, tag, "before");
	report_allocated_ranges(h, tag, "before", ext_before, 32, &n_before);

	memset(&zbuf, 0, sizeof zbuf);
	zbuf.z.FileOffset = r->off;
	zbuf.z.BeyondFinalZero = r->beyond;
	in_len = r->in_size ? r->in_size : (unsigned)sizeof zbuf.z;
	st_zero = NtFsControlFile(h, 0, 0, 0, &io, FSCTL_SET_ZERO_DATA,
	                          r->null_in == 1 ? (PVOID)0 :
	                          r->null_in == 2 ? (PVOID)(ULONG_PTR)0x10 : (PVOID)&zbuf,
	                          (ULONG)in_len, 0, 0);

	printf("zerodata[%s]: FSCTL_SET_ZERO_DATA [%lld,%lld) inlen=%u%s%s -> 0x%08lX\n",
	       tag, r->off, r->beyond, in_len,
	       r->null_in == 1 ? " input=NULL" : r->null_in == 2 ? " input=0x10(unmapped)" : "",
	       r->readonly ? " handle=O_RDONLY" : "",
	       (unsigned long)(unsigned)st_zero);
	rows_measured++;

	if (!query_std(h, &after, "after", tag)) { unverified++; close(fd); free(buf); return; }
	report_sparse_attr(h, tag, "after");
	ok_after_ext = report_allocated_ranges(h, tag, "after", ext_after, 32, &n_after);

	printf("zerodata[%s]: EndOfFile      before=%lld after=%lld\n",
	       tag, (long long)before.EndOfFile, (long long)after.EndOfFile);
	printf("zerodata[%s]: AllocationSize before=%lld after=%lld\n",
	       tag, (long long)before.AllocationSize, (long long)after.AllocationSize);

	observed_rel = (long long)before.AllocationSize - (long long)after.AllocationSize;

	/* One prediction, from the rule, on every volume.  The two refuted
	 * candidates are printed beside it so a reader can see at a glance
	 * which half of the curve this volume sits on -- below the cap the
	 * rule tracks 16 x cluster, at or above it the rule is the cap --
	 * and so that a disagreement names which candidate it matches. */
	expect_rel      = mark_sparse ? released_bytes(r->off, r->beyond, g_unit) : 0;
	expect_rel_16x  = mark_sparse ? released_bytes(r->off, r->beyond, 16 * g_cluster) : 0;
	expect_rel_cap  = mark_sparse ? released_bytes(r->off, r->beyond, UNIT_CAP) : 0;
	printf("zerodata[%s]: released observed=%lld  predicted=%lld (unit=%lld)  "
	       "[refuted candidates: 16x-cluster(%lld)=%lld  constant-64K=%lld]\n",
	       tag, observed_rel, expect_rel, g_unit,
	       16 * g_cluster, expect_rel_16x, expect_rel_cap);

	if (r->expect == EXPECT_INVALID) {
		printf("zerodata[%s]: status expectation: STATUS_INVALID_PARAMETER (0xC000000D)\n", tag);
		if (not_supported(st_zero)) {
			printf("SKIP zerodata[%s]: FSCTL_SET_ZERO_DATA is unimplemented here "
			       "(0x%08lX) -- stock Wine. Real NT is required.\n",
			       tag, (unsigned long)(unsigned)st_zero);
			unverified++;
		} else {
			/* Unconditional: whether an inverted or negative range is
			 * rejected has nothing to do with the volume's cluster
			 * size, so there is no regime in which this goes unchecked. */
			CHECK(st_zero == STATUS_INVALID_PARAMETER);
			CHECK(after.EndOfFile == before.EndOfFile);
			CHECK(after.AllocationSize == before.AllocationSize);
		}
		close(fd); free(buf); return;
	}

	if (r->expect == EXPECT_MEASURE) {
		printf("zerodata[%s]: MEASURED-ONLY: status 0x%08lX is the result; no value is "
		       "asserted because none has been established.\n",
		       tag, (unsigned long)(unsigned)st_zero);
		unverified++;
		close(fd); free(buf); return;
	}

	if (!NT_SUCCESS(st_zero)) {
		if (not_supported(st_zero))
			printf("SKIP zerodata[%s]: FSCTL_SET_ZERO_DATA is unimplemented in this "
			       "environment (status 0x%08lX) -- this is what stock Wine does. "
			       "Wine's FSCTL_SET_SPARSE returns STATUS_SUCCESS while ignoring "
			       "the request (wine-9.0 dlls/ntdll/unix/file.c:6156), so no hole "
			       "is ever punched and no allocation question can be answered "
			       "here.  Real NT is required to answer this probe.\n",
			       tag, (unsigned long)(unsigned)st_zero);
		else
			printf("SKIP zerodata[%s]: FSCTL_SET_ZERO_DATA failed with 0x%08lX -- "
			       "that status IS the measurement for this row; the success "
			       "contract below could not be evaluated.\n",
			       tag, (unsigned long)(unsigned)st_zero);
		unverified++; close(fd); free(buf); return;
	}

	/* ---- contract assertions (success path) ---- */
	data_row = r->off >= 0 && r->beyond <= FILE_SIZE && r->beyond > r->off;

	/* Zeroing a range is not a truncation, and it does not extend a file. */
	CHECK(after.EndOfFile == before.EndOfFile);
	CHECK(after.EndOfFile == FILE_SIZE);

	/* AllocationSize: asserted, not merely measured.  It IS the claim.
	 * Asserted on EVERY cluster size, because the rule is now known for
	 * every cluster size rather than only for 4096. */
	CHECK(observed_rel == expect_rel);

	/* The extent list, which is the same claim stated directly.  Release
	 * of [lo,hi) leaves [0,lo) and [hi,FILE_SIZE); no release leaves one
	 * extent covering everything. */
	{
		long long lo = 0, hi = 0, exp_off[2], exp_len[2];
		unsigned exp_n = 0, i;
		if (expect_rel > 0) {
			lo = ((r->off + g_unit - 1) / g_unit) * g_unit;
			hi = lo + expect_rel;
			if (lo > 0)         { exp_off[exp_n] = 0;  exp_len[exp_n] = lo; exp_n++; }
			if (hi < FILE_SIZE) { exp_off[exp_n] = hi; exp_len[exp_n] = FILE_SIZE - hi; exp_n++; }
		} else {
			exp_off[0] = 0; exp_len[0] = FILE_SIZE; exp_n = 1;
		}
		printf("zerodata[%s]: extents expected: %u range(s)\n", tag, exp_n);
		if (!ok_after_ext) {
			/* report_allocated_ranges() already printed the failing
			 * status.  n_after is 0 here because the query never ran,
			 * NOT because it measured zero extents -- asserting against
			 * it would be scoring "the instrument is broken" as "the
			 * claim is false".  This is FSCTL_QUERY_ALLOCATED_RANGES,
			 * a DIFFERENT ioctl from FSCTL_SET_ZERO_DATA above: on
			 * Pandapip1/wine as of this file's writing, SET_ZERO_DATA
			 * is implemented (the release-size and read-back checks
			 * above ran and passed) but QUERY_ALLOCATED_RANGES is not,
			 * so the direct extent-list claim can't be posed on this
			 * runtime even though the aggregate one (AllocationSize)
			 * could be. Real NT (windows-test CI) answers this ioctl
			 * and this exact assertion runs and passes there. */
			printf("SKIP zerodata[%s]: FSCTL_QUERY_ALLOCATED_RANGES is unimplemented "
			       "in this runtime, so the extent-list claim (as opposed to the "
			       "AllocationSize one already checked above) cannot be posed here\n",
			       tag);
			unverified++;
		} else {
			CHECK(n_after == exp_n);
			for (i = 0; i < exp_n && i < n_after; i++) {
				CHECK(ext_after[i].FileOffset == exp_off[i]);
				CHECK(ext_after[i].Length == exp_len[i]);
			}
		}
		(void)n_before;
	}

	if (data_row) {
		int i, range_zero = 1, outside_intact = 1;
		size_t got = 0;
		memset(buf, 0x5A, FILE_SIZE);   /* poison, so a short read cannot look like zeros */
		if (lseek(fd, 0, SEEK_SET) != 0) { printf("FAIL %s: lseek\n", tag); fails++; }
		while (got < FILE_SIZE) {
			ssize_t n = read(fd, buf + got, FILE_SIZE - got);
			if (n <= 0) break;
			got += (size_t)n;
		}
		CHECK(got == FILE_SIZE);
		if (got != FILE_SIZE) { close(fd); free(buf); return; }
		for (i = (int)r->off; i < (int)r->beyond; i++) if (buf[i] != 0) { range_zero = 0; break; }
		for (i = 0; i < (int)r->off; i++) if (buf[i] != FILL_BYTE) { outside_intact = 0; break; }
		for (i = (int)r->beyond; i < FILE_SIZE; i++) if (buf[i] != FILL_BYTE) { outside_intact = 0; break; }
		printf("zerodata[%s]: range reads back as zero: %s; bytes outside still 0x%02X: %s\n",
		       tag, range_zero ? "yes" : "NO", FILL_BYTE, outside_intact ? "yes" : "NO");
		CHECK(range_zero);
		CHECK(outside_intact);
	}

	close(fd); free(buf);
}

/* ---- FileAllocationInformation (info class 19) x the sparse mark ----
 *
 * Every published number for class 19 was taken on a file that was not
 * marked sparse, and the two features are now implemented together
 * downstream, so their interaction is live code with no measurements
 * behind it.  Measured, never asserted: there is nothing established to
 * assert against, and putting a guess here would be the same mistake
 * this file was rewritten to correct.
 */
static void run_alloc_class19(const char *name, int mark_sparse, long long punch_from,
                              long long punch_to, long long request)
{
	char path[96], tag[96];
	unsigned char *buf;
	FILE_STANDARD_INFORMATION before, after;
	FILE_ALLOCATED_RANGE_BUFFER ext[32];
	unsigned n = 0;
	IO_STATUS_BLOCK io;
	NTSTATUS st;
	HANDLE h;
	int fd;

	snprintf(tag, sizeof tag, "class19/%s/%s", name, mark_sparse ? "sparse" : "unmarked");
	snprintf(path, sizeof path, "c19-%s-%d.bin", name, mark_sparse);

	buf = malloc(FILE_SIZE);
	if (!buf) { printf("FAIL %s: malloc\n", tag); fails++; return; }
	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) { printf("FAIL %s: open: %s\n", tag, strerror(errno)); fails++; free(buf); return; }
	h = __fd_handle(fd);
	if (!h) { printf("FAIL %s: __fd_handle\n", tag); fails++; close(fd); free(buf); return; }

	if (mark_sparse) {
		FILE_SET_SPARSE_BUFFER sb;
		sb.SetSparse = 1;
		st = NtFsControlFile(h, 0, 0, 0, &io, FSCTL_SET_SPARSE, &sb, (ULONG)sizeof sb, 0, 0);
		if (!NT_SUCCESS(st)) {
			printf("SKIP zerodata[%s]: FSCTL_SET_SPARSE -> 0x%08lX\n",
			       tag, (unsigned long)(unsigned)st);
			unverified++; close(fd); free(buf); return;
		}
	}
	memset(buf, FILL_BYTE, FILE_SIZE);
	if (write(fd, buf, FILE_SIZE) != FILE_SIZE) {
		printf("FAIL %s: short write\n", tag); fails++; close(fd); free(buf); return;
	}
	fsync(fd);

	if (punch_to > punch_from) {
		FILE_ZERO_DATA_INFORMATION z;
		z.FileOffset = punch_from; z.BeyondFinalZero = punch_to;
		st = NtFsControlFile(h, 0, 0, 0, &io, FSCTL_SET_ZERO_DATA, &z, (ULONG)sizeof z, 0, 0);
		printf("zerodata[%s]: pre-punch [%lld,%lld) -> 0x%08lX\n",
		       tag, punch_from, punch_to, (unsigned long)(unsigned)st);
		if (!NT_SUCCESS(st)) {
			printf("SKIP zerodata[%s]: the pre-punch failed, so the retained-extent "
			       "question this row exists to ask cannot be posed\n", tag);
			unverified++; close(fd); free(buf); return;
		}
	}

	if (!query_std(h, &before, "before", tag)) { unverified++; close(fd); free(buf); return; }
	report_allocated_ranges(h, tag, "before", ext, 32, &n);
	printf("zerodata[%s]: before EndOfFile=%lld AllocationSize=%lld\n",
	       tag, (long long)before.EndOfFile, (long long)before.AllocationSize);

	st = NtSetInformationFile(h, &io, &request, (ULONG)sizeof request, FileAllocationInformation);
	printf("zerodata[%s]: NtSetInformationFile(FileAllocationInformation, %lld) -> 0x%08lX\n",
	       tag, request, (unsigned long)(unsigned)st);

	if (!query_std(h, &after, "after", tag)) { unverified++; close(fd); free(buf); return; }
	report_allocated_ranges(h, tag, "after", ext, 32, &n);
	printf("zerodata[%s]: after  EndOfFile=%lld AllocationSize=%lld\n",
	       tag, (long long)after.EndOfFile, (long long)after.AllocationSize);
	printf("zerodata[%s]: MEASURED-ONLY: EndOfFile %lld->%lld tells whether class 19 still "
	       "truncates on a sparse file; AllocationSize %lld->%lld tells whether it tracks the "
	       "REQUEST (%lld) or the RETAINED EXTENTS. Paired with its %s twin so any difference "
	       "is attributable to the sparse mark and nothing else.\n",
	       tag, (long long)before.EndOfFile, (long long)after.EndOfFile,
	       (long long)before.AllocationSize, (long long)after.AllocationSize,
	       request, mark_sparse ? "unmarked" : "sparse");

	close(fd); free(buf);
}

int main(void)
{
	char dir[] = "zerodatXXXXXX";
	const char *want = getenv("SPICULE_ZD_DIR");
	FILE_FS_SIZE_INFORMATION fsi;
	IO_STATUS_BLOCK io;
	NTSTATUS st;
	HANDLE h;
	int fd, i, total_rows;

	/* SPICULE_ZD_DIR points the probe at a volume other than the default
	 * one -- .github/probes/ntfs-sparse-granularity.ps1 builds a
	 * 1 KB-cluster VHD and sets it.  Failing to chdir is fatal, not a
	 * fallback to the default volume: running the whole battery on 4 KB
	 * clusters while the log says a non-4 KB regime was requested is a
	 * silent substitution of a weaker stimulus, which is exactly the
	 * class of error this file was rewritten to remove. */
	if (want && *want) {
		if (chdir(want) != 0) {
			printf("FAIL zerodata: SPICULE_ZD_DIR=%s but chdir failed: %s\n",
			       want, strerror(errno));
			return 1;
		}
		printf("zerodata: SPICULE_ZD_DIR=%s (a non-default volume was requested)\n", want);
	}

	if (!mkdtemp(dir)) { printf("FAIL mkdtemp: %s\n", strerror(errno)); return 1; }
	if (chdir(dir) != 0) { printf("FAIL chdir: %s\n", strerror(errno)); return 1; }

	/* Which cluster regime is this?  Asserted, not just logged: a probe
	 * that records the regime without checking it can run on the wrong
	 * volume and produce arithmetic that is internally consistent and
	 * about the wrong filesystem. */
	fd = open("regime.bin", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) { printf("FAIL zerodata: open regime.bin: %s\n", strerror(errno)); return 1; }
	h = __fd_handle(fd);
	if (!h) { printf("FAIL zerodata: __fd_handle for regime.bin\n"); return 1; }
	memset(&fsi, 0, sizeof fsi);
	st = NtQueryVolumeInformationFile(h, &io, &fsi, (ULONG)sizeof fsi, FileFsSizeInformation);
	if (!NT_SUCCESS(st)) {
		printf("FAIL zerodata: NtQueryVolumeInformationFile(FileFsSizeInformation) -> "
		       "0x%08lX; without the cluster size no row's expected value can be "
		       "computed and none may be asserted\n", (unsigned long)(unsigned)st);
		close(fd);
		return 1;
	}
	g_cluster = (long long)fsi.SectorsPerAllocationUnit * (long long)fsi.BytesPerSector;
	printf("zerodata: volume geometry: BytesPerSector=%lu SectorsPerAllocationUnit=%lu "
	       "=> bytes-per-cluster=%lld\n",
	       (unsigned long)fsi.BytesPerSector, (unsigned long)fsi.SectorsPerAllocationUnit,
	       g_cluster);
	close(fd);

	if (g_cluster <= 0) {
		printf("FAIL zerodata: computed bytes-per-cluster is %lld, which is not a "
		       "usable geometry\n", g_cluster);
		return 1;
	}
	/* The one-level-up failure, made loud.
	 *
	 * A caller that points SPICULE_ZD_DIR at a volume built for a
	 * different cluster size must also say which size it asked for, via
	 * SPICULE_ZD_CLUSTER, and the two are compared against what the
	 * filesystem reports.  This is not belt-and-braces.  Formatting a
	 * volume with a chosen allocation unit can fail while leaving the
	 * volume mounted and perfectly usable at the default 4096 -- a
	 * rejected AllocationUnitSize, a silent rounding to the physical
	 * sector size -- and the battery would then run to completion,
	 * cleanly, on a duplicate of the volume we already have, and
	 * "confirm" the incumbent 64 KB rule.  A false confirmation of the
	 * hypothesis under test, indistinguishable in the log from a real
	 * one.  That is the whole failure mode of this file reproduced one
	 * level up, and the readback is what stops it.
	 *
	 * Such a run is VOID, not failed, and the two are labelled
	 * differently because they mean different things: failed says a
	 * claim about NTFS was contradicted, void says no claim was tested.
	 * Void still cannot report green -- it exits 77, which the CI
	 * harness surfaces as UNVERIFIED rather than PASS. */
	if (want && *want) {
		const char *cs = getenv("SPICULE_ZD_CLUSTER");
		long long asked = cs && *cs ? strtoll(cs, 0, 10) : 0;
		if (!asked) {
			printf("VOID zerodata: SPICULE_ZD_DIR=%s names a volume chosen for its "
			       "cluster size, but SPICULE_ZD_CLUSTER does not say which size was "
			       "asked for, so the %lld bytes per cluster reported here cannot be "
			       "checked against anything. Nothing was tested.\n", want, g_cluster);
			return 77;
		}
		if (asked != g_cluster) {
			printf("VOID zerodata: SPICULE_ZD_CLUSTER=%lld was requested, but the volume "
			       "at %s reports %lld bytes per cluster. The format did not take -- and "
			       "a volume that is still mounted and usable at the wrong cluster size "
			       "produces a complete, clean-looking run on the regime this was "
			       "supposed to leave. Nothing was tested.\n", asked, want, g_cluster);
			return 77;
		}
		printf("zerodata: SPICULE_ZD_CLUSTER=%lld requested, %lld measured: the volume is "
		       "the one that was asked for.\n", asked, g_cluster);
	}

	g_unit = 16 * g_cluster;
	if (g_unit > UNIT_CAP) g_unit = UNIT_CAP;
	printf("zerodata: file size %d, fill byte 0x%02X, %d row(s) x {sparse, unmarked}\n",
	       FILE_SIZE, FILL_BYTE, NROWS);
	printf("zerodata: allocation unit = min(16 * %lld, %d) = %lld  [%s the cap]\n",
	       g_cluster, UNIT_CAP, g_unit,
	       16 * g_cluster >= UNIT_CAP ? "at or above" : "below");
	if (g_cluster != REGIME_CLUSTER)
		printf("zerodata: this is NOT the %d-byte-cluster regime the rows were first "
		       "written against; the expected releases below are derived from the rule "
		       "and this volume's cluster size, not carried over.\n", REGIME_CLUSTER);

	for (i = 0; i < NROWS; i++) {
		run_row(&rows[i], 1);
		run_row(&rows[i], 0);
	}

	/* Class 19.  (a) shrink far below EOF; (b) punch first, then request
	 * the original size, so retained extents and the request differ by a
	 * known amount -- on a dense file they are equal and the question
	 * cannot even be posed, which is why the existing table is silent on
	 * it; (c) grow past EOF; (d) zero. */
	for (i = 0; i < 2; i++) {
		run_alloc_class19("shrink",      i, 0, 0, 4096);
		run_alloc_class19("vs-extents",  i, 262144, 786432, FILE_SIZE);
		run_alloc_class19("grow",        i, 0, 0, 4 * (long long)FILE_SIZE);
		run_alloc_class19("zero",        i, 0, 0, 0);
	}

	total_rows = NROWS * 2;
	if (fails) { printf("FAILED %d check(s)\n", fails); return 1; }
	if (rows_measured == 0) {
		printf("FAILED zerodata: not one row reached the FSCTL. This binary verified "
		       "nothing, which is not the same as passing.\n");
		return 1;
	}
	if (unverified) {
		printf("UNVERIFIED zerodata: %d measurement(s) went unverified in this "
		       "environment (see the SKIP / MEASURED-ONLY lines above for "
		       "which and why), across %d SET_ZERO_DATA rows and 8 class-19 rows; %d row(s) "
		       "did reach the FSCTL. No failures in what did run -- and note that the "
		       "MEASURED-ONLY rows are unverified BY DESIGN, because no value has been "
		       "established for them to be checked against.\n",
		       unverified, total_rows, rows_measured);
		return 77;
	}
	printf("PASS zerodata\n");
	return 0;
}
