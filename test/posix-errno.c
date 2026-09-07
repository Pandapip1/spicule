/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Table-driven tests for the pure NTSTATUS/Win32-error -> errno mapping
 * functions in src/internal/errno.c.  These are already factored as pure
 * functions (src/internal/libc.h: "map, do not set"), so they are tested
 * directly here rather than indirectly through a syscall wrapper.
 *
 * The test/ sources are built with -Iarch/$(ARCH) -Iarch/generic -Iobj/include
 * -Iinclude only (see Makefile) -- src/internal/ is NOT on the include
 * path, so the NTSTATUS values below are copied by hand from
 * src/internal/nt.h and the three prototypes are declared locally, the
 * same way test/misc.c declares __spawn().  If src/internal/nt.h's
 * values ever change, this file will not notice; that is the accepted
 * cost of not exposing an internal header to tests (see report).
 */
#include "test-policy.h"
#include <stdio.h>
#include <stddef.h>	/* size_t, for the group U test below */
#include <string.h>	/* strerror(), for the group U test below */
#include <errno.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

typedef int NTSTATUS;
int __errno_from_status(NTSTATUS);
int __errno_from_doserror(unsigned);
int __set_errno_status(NTSTATUS);

/* Copied from src/internal/nt.h. */
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_BUFFER_OVERFLOW          ((NTSTATUS)0x80000005L)
#define STATUS_DATATYPE_MISALIGNMENT    ((NTSTATUS)0x80000002L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED          ((NTSTATUS)0xC0000002L)
#define STATUS_INVALID_INFO_CLASS       ((NTSTATUS)0xC0000003L)
#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004L)
#define STATUS_INVALID_HANDLE           ((NTSTATUS)0xC0000008L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_NO_SUCH_DEVICE           ((NTSTATUS)0xC000000EL)
#define STATUS_NO_SUCH_FILE             ((NTSTATUS)0xC000000FL)
#define STATUS_INVALID_DEVICE_REQUEST   ((NTSTATUS)0xC0000010L)
#define STATUS_END_OF_FILE              ((NTSTATUS)0xC0000011L)
#define STATUS_NO_MEMORY                ((NTSTATUS)0xC0000017L)
#define STATUS_ACCESS_DENIED            ((NTSTATUS)0xC0000022L)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#define STATUS_OBJECT_TYPE_MISMATCH     ((NTSTATUS)0xC0000024L)
#define STATUS_OBJECT_NAME_INVALID      ((NTSTATUS)0xC0000033L)
#define STATUS_OBJECT_NAME_NOT_FOUND    ((NTSTATUS)0xC0000034L)
#define STATUS_OBJECT_NAME_COLLISION    ((NTSTATUS)0xC0000035L)
#define STATUS_OBJECT_PATH_INVALID      ((NTSTATUS)0xC0000039L)
#define STATUS_OBJECT_PATH_NOT_FOUND    ((NTSTATUS)0xC000003AL)
#define STATUS_OBJECT_PATH_SYNTAX_BAD   ((NTSTATUS)0xC000003BL)
#define STATUS_DATA_ERROR               ((NTSTATUS)0xC000003EL)
#define STATUS_SHARING_VIOLATION        ((NTSTATUS)0xC0000043L)
#define STATUS_DELETE_PENDING           ((NTSTATUS)0xC0000056L)
#define STATUS_DISK_FULL                ((NTSTATUS)0xC000007FL)
#define STATUS_TOO_MANY_OPENED_FILES    ((NTSTATUS)0xC000011FL)
#define STATUS_FILE_IS_A_DIRECTORY      ((NTSTATUS)0xC00000BAL)
#define STATUS_NOT_SUPPORTED            ((NTSTATUS)0xC00000BBL)
#define STATUS_PIPE_BROKEN              ((NTSTATUS)0xC000014BL)
#define STATUS_PIPE_DISCONNECTED        ((NTSTATUS)0xC00000B0L)
#define STATUS_PIPE_EMPTY               ((NTSTATUS)0xC00000D9L)
#define STATUS_PIPE_LISTENING           ((NTSTATUS)0xC00000B3L)
#define STATUS_PIPE_CLOSING             ((NTSTATUS)0xC00000B1L)
#define STATUS_PIPE_NOT_AVAILABLE       ((NTSTATUS)0xC00000ACL)
#define STATUS_DIRECTORY_NOT_EMPTY      ((NTSTATUS)0xC0000101L)
#define STATUS_NOT_A_DIRECTORY          ((NTSTATUS)0xC0000103L)
#define STATUS_NAME_TOO_LONG            ((NTSTATUS)0xC0000106L)
#define STATUS_CANNOT_DELETE            ((NTSTATUS)0xC0000121L)
#define STATUS_FILE_DELETED             ((NTSTATUS)0xC0000123L)
#define STATUS_PROCESS_IS_TERMINATING   ((NTSTATUS)0xC000010AL)
#define STATUS_MEDIA_WRITE_PROTECTED    ((NTSTATUS)0xC00000A2L)
#define STATUS_INVALID_IMAGE_FORMAT     ((NTSTATUS)0xC000007BL)
#define STATUS_INVALID_IMAGE_NOT_MZ     ((NTSTATUS)0xC000012FL)
#define STATUS_INVALID_IMAGE_PROTECT    ((NTSTATUS)0xC0000130L)
#define STATUS_INVALID_IMAGE_WIN_32     ((NTSTATUS)0xC0000359L)
#define STATUS_INVALID_IMAGE_WIN_64     ((NTSTATUS)0xC000035AL)
#define STATUS_NOT_SAME_DEVICE          ((NTSTATUS)0xC00000D4L)
#define STATUS_FILE_CLOSED              ((NTSTATUS)0xC0000128L)
#define STATUS_IO_TIMEOUT               ((NTSTATUS)0xC00000B5L)
#define STATUS_CANCELLED                ((NTSTATUS)0xC0000120L)
#define STATUS_QUOTA_EXCEEDED           ((NTSTATUS)0xC0000044L)
#define STATUS_IO_REPARSE_TAG_NOT_HANDLED ((NTSTATUS)0xC0000279L)
#define STATUS_DLL_NOT_FOUND            ((NTSTATUS)0xC0000135L)
#define STATUS_ENTRYPOINT_NOT_FOUND     ((NTSTATUS)0xC0000139L)
#define STATUS_FILE_INVALID             ((NTSTATUS)0xC0000098L)
#define STATUS_TOO_MANY_LINKS           ((NTSTATUS)0xC0000265L)
#define STATUS_NOT_A_REPARSE_POINT      ((NTSTATUS)0xC0000275L)
#define STATUS_PRIVILEGE_NOT_HELD       ((NTSTATUS)0xC0000061L)
#define STATUS_USER_MAPPED_FILE         ((NTSTATUS)0xC0000243L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_DEVICE_NOT_READY         ((NTSTATUS)0xC00000A3L)
#define STATUS_FILE_TOO_LARGE           ((NTSTATUS)0xC0000904L)
#define STATUS_VOLUME_DISMOUNTED        ((NTSTATUS)0xC000026EL)
#define STATUS_NOT_FOUND                ((NTSTATUS)0xC0000225L)
#define STATUS_ACCESS_VIOLATION         ((NTSTATUS)0xC0000005L)

struct sc { NTSTATUS st; int e; const char *name; };

static const struct sc status_table[] = {
	{ STATUS_SUCCESS, 0, "STATUS_SUCCESS" },
	{ STATUS_NO_MEMORY, ENOMEM, "STATUS_NO_MEMORY" },
	{ STATUS_INSUFFICIENT_RESOURCES, ENOMEM, "STATUS_INSUFFICIENT_RESOURCES" },
	{ STATUS_QUOTA_EXCEEDED, ENOMEM, "STATUS_QUOTA_EXCEEDED" },
	{ STATUS_INVALID_HANDLE, EBADF, "STATUS_INVALID_HANDLE" },
	{ STATUS_FILE_CLOSED, EBADF, "STATUS_FILE_CLOSED" },
	{ STATUS_OBJECT_TYPE_MISMATCH, EBADF, "STATUS_OBJECT_TYPE_MISMATCH" },
	{ STATUS_INVALID_PARAMETER, EINVAL, "STATUS_INVALID_PARAMETER" },
	{ STATUS_INVALID_INFO_CLASS, EINVAL, "STATUS_INVALID_INFO_CLASS" },
	{ STATUS_INFO_LENGTH_MISMATCH, EINVAL, "STATUS_INFO_LENGTH_MISMATCH" },
	{ STATUS_DATATYPE_MISALIGNMENT, EINVAL, "STATUS_DATATYPE_MISALIGNMENT" },
	{ STATUS_OBJECT_NAME_NOT_FOUND, ENOENT, "STATUS_OBJECT_NAME_NOT_FOUND" },
	{ STATUS_OBJECT_PATH_NOT_FOUND, ENOENT, "STATUS_OBJECT_PATH_NOT_FOUND" },
	{ STATUS_NO_SUCH_FILE, ENOENT, "STATUS_NO_SUCH_FILE" },
	{ STATUS_NO_SUCH_DEVICE, ENOENT, "STATUS_NO_SUCH_DEVICE" },
	{ STATUS_NOT_FOUND, ENOENT, "STATUS_NOT_FOUND" },
	{ STATUS_DLL_NOT_FOUND, ENOENT, "STATUS_DLL_NOT_FOUND" },
	{ STATUS_FILE_DELETED, ENOENT, "STATUS_FILE_DELETED" },
	{ STATUS_DELETE_PENDING, ENOENT, "STATUS_DELETE_PENDING" },
	{ STATUS_OBJECT_NAME_INVALID, ENOENT, "STATUS_OBJECT_NAME_INVALID" },
	{ STATUS_OBJECT_PATH_INVALID, ENOENT, "STATUS_OBJECT_PATH_INVALID" },
	{ STATUS_OBJECT_PATH_SYNTAX_BAD, ENOENT, "STATUS_OBJECT_PATH_SYNTAX_BAD" },
	{ STATUS_NAME_TOO_LONG, ENAMETOOLONG, "STATUS_NAME_TOO_LONG" },
	{ STATUS_ACCESS_DENIED, EACCES, "STATUS_ACCESS_DENIED" },
	{ STATUS_PRIVILEGE_NOT_HELD, EACCES, "STATUS_PRIVILEGE_NOT_HELD" },
	{ STATUS_CANNOT_DELETE, EACCES, "STATUS_CANNOT_DELETE" },
	{ STATUS_SHARING_VIOLATION, EBUSY, "STATUS_SHARING_VIOLATION" },
	{ STATUS_USER_MAPPED_FILE, EBUSY, "STATUS_USER_MAPPED_FILE" },
	{ STATUS_OBJECT_NAME_COLLISION, EEXIST, "STATUS_OBJECT_NAME_COLLISION" },
	{ STATUS_FILE_IS_A_DIRECTORY, EISDIR, "STATUS_FILE_IS_A_DIRECTORY" },
	{ STATUS_NOT_A_DIRECTORY, ENOTDIR, "STATUS_NOT_A_DIRECTORY" },
	{ STATUS_DIRECTORY_NOT_EMPTY, ENOTEMPTY, "STATUS_DIRECTORY_NOT_EMPTY" },
	{ STATUS_DISK_FULL, ENOSPC, "STATUS_DISK_FULL" },
	{ STATUS_TOO_MANY_OPENED_FILES, EMFILE, "STATUS_TOO_MANY_OPENED_FILES" },
	{ STATUS_PIPE_BROKEN, EPIPE, "STATUS_PIPE_BROKEN" },
	{ STATUS_PIPE_DISCONNECTED, EPIPE, "STATUS_PIPE_DISCONNECTED" },
	{ STATUS_PIPE_CLOSING, EPIPE, "STATUS_PIPE_CLOSING" },
	{ STATUS_PIPE_LISTENING, EPIPE, "STATUS_PIPE_LISTENING" },
	{ STATUS_PIPE_NOT_AVAILABLE, EPIPE, "STATUS_PIPE_NOT_AVAILABLE" },
	{ STATUS_PIPE_EMPTY, EAGAIN, "STATUS_PIPE_EMPTY" },
	{ STATUS_NOT_IMPLEMENTED, ENOSYS, "STATUS_NOT_IMPLEMENTED" },
	{ STATUS_NOT_SUPPORTED, ENOSYS, "STATUS_NOT_SUPPORTED" },
	{ STATUS_INVALID_DEVICE_REQUEST, ENOSYS, "STATUS_INVALID_DEVICE_REQUEST" },
	{ STATUS_END_OF_FILE, 0, "STATUS_END_OF_FILE" },
	{ STATUS_MEDIA_WRITE_PROTECTED, EROFS, "STATUS_MEDIA_WRITE_PROTECTED" },
	{ STATUS_NOT_SAME_DEVICE, EXDEV, "STATUS_NOT_SAME_DEVICE" },
	{ STATUS_IO_TIMEOUT, ETIMEDOUT, "STATUS_IO_TIMEOUT" },
	{ STATUS_CANCELLED, EINTR, "STATUS_CANCELLED" },
	{ STATUS_TOO_MANY_LINKS, EMLINK, "STATUS_TOO_MANY_LINKS" },
	{ STATUS_ACCESS_VIOLATION, EFAULT, "STATUS_ACCESS_VIOLATION" },
	{ STATUS_INVALID_IMAGE_FORMAT, ENOEXEC, "STATUS_INVALID_IMAGE_FORMAT" },
	{ STATUS_INVALID_IMAGE_NOT_MZ, ENOEXEC, "STATUS_INVALID_IMAGE_NOT_MZ" },
	{ STATUS_INVALID_IMAGE_PROTECT, ENOEXEC, "STATUS_INVALID_IMAGE_PROTECT" },
	{ STATUS_INVALID_IMAGE_WIN_32, ENOEXEC, "STATUS_INVALID_IMAGE_WIN_32" },
	{ STATUS_INVALID_IMAGE_WIN_64, ENOEXEC, "STATUS_INVALID_IMAGE_WIN_64" },
	{ STATUS_ENTRYPOINT_NOT_FOUND, ENOEXEC, "STATUS_ENTRYPOINT_NOT_FOUND" },
	{ STATUS_FILE_INVALID, ENOEXEC, "STATUS_FILE_INVALID" },
	{ STATUS_DEVICE_NOT_READY, ENXIO, "STATUS_DEVICE_NOT_READY" },
	{ STATUS_VOLUME_DISMOUNTED, ENXIO, "STATUS_VOLUME_DISMOUNTED" },
	{ STATUS_FILE_TOO_LARGE, EFBIG, "STATUS_FILE_TOO_LARGE" },
	{ STATUS_PROCESS_IS_TERMINATING, ESRCH, "STATUS_PROCESS_IS_TERMINATING" },
	{ STATUS_BUFFER_TOO_SMALL, ERANGE, "STATUS_BUFFER_TOO_SMALL" },
	{ STATUS_BUFFER_OVERFLOW, ERANGE, "STATUS_BUFFER_OVERFLOW" },
	{ STATUS_DATA_ERROR, EIO, "STATUS_DATA_ERROR" },
	{ STATUS_NOT_A_REPARSE_POINT, EINVAL, "STATUS_NOT_A_REPARSE_POINT" },
	{ STATUS_IO_REPARSE_TAG_NOT_HANDLED, EINVAL, "STATUS_IO_REPARSE_TAG_NOT_HANDLED" },
};

struct dc { unsigned e; int errno_val; const char *name; };

static const struct dc doserror_table[] = {
	{ 0, 0, "ERROR_SUCCESS" },
	{ 1, ENOSYS, "ERROR_INVALID_FUNCTION" },
	{ 2, ENOENT, "ERROR_FILE_NOT_FOUND" },
	{ 3, ENOENT, "ERROR_PATH_NOT_FOUND" },
	{ 4, EMFILE, "ERROR_TOO_MANY_OPEN_FILES" },
	{ 5, EACCES, "ERROR_ACCESS_DENIED" },
	{ 6, EBADF, "ERROR_INVALID_HANDLE" },
	{ 8, ENOMEM, "ERROR_NOT_ENOUGH_MEMORY" },
	{ 14, ENOMEM, "ERROR_OUTOFMEMORY" },
	{ 13, EINVAL, "ERROR_INVALID_DATA" },
	{ 15, ENODEV, "ERROR_INVALID_DRIVE" },
	{ 17, EXDEV, "ERROR_NOT_SAME_DEVICE" },
	{ 18, ENOENT, "ERROR_NO_MORE_FILES" },
	{ 19, EROFS, "ERROR_WRITE_PROTECT" },
	{ 21, ENXIO, "ERROR_NOT_READY" },
	{ 32, EBUSY, "ERROR_SHARING_VIOLATION" },
	{ 33, EBUSY, "ERROR_LOCK_VIOLATION" },
	{ 39, ENOSPC, "ERROR_DISK_FULL" },
	{ 112, ENOSPC, "ERROR_HANDLE_DISK_FULL" },
	{ 80, EEXIST, "ERROR_FILE_EXISTS" },
	{ 183, EEXIST, "ERROR_ALREADY_EXISTS" },
	{ 87, EINVAL, "ERROR_INVALID_PARAMETER" },
	{ 109, EPIPE, "ERROR_BROKEN_PIPE" },
	{ 110, EACCES, "ERROR_OPEN_FAILED" },
	{ 122, ERANGE, "ERROR_INSUFFICIENT_BUFFER" },
	{ 123, ENOENT, "ERROR_INVALID_NAME" },
	{ 145, ENOTEMPTY, "ERROR_DIR_NOT_EMPTY" },
	{ 206, ENAMETOOLONG, "ERROR_FILENAME_EXCED_RANGE" },
	{ 231, EPIPE, "ERROR_PIPE_BUSY" },
	{ 232, EPIPE, "ERROR_NO_DATA" },
	{ 233, EPIPE, "ERROR_PIPE_NOT_CONNECTED" },
	{ 267, ENOTDIR, "ERROR_DIRECTORY" },
	{ 1816, ENOMEM, "ERROR_NOT_ENOUGH_QUOTA" },
	{ 999999, EIO, "(unmapped -> default EIO)" },
};

/* ==================================================================
 * <errno.h> header content -- the 81 mandatory error macros.  Audit
 * group U (XBD header contents); see test/POSIX-COVERAGE.md "XBD
 * header contents (group U)".
 *
 * errno.h.html DESCRIPTION: "The <errno.h> header shall define the
 * following macros which shall expand to integer constant expressions
 * with type int, distinct positive values (except as noted below), and
 * which shall be suitable for use in #if preprocessing directives",
 * followed by a list of 81 names.  The list is unconditional -- no
 * option-group margin marker guards any of them -- so all 81 are
 * mandatory for a conforming <errno.h>.  EBADMSG, EMULTIHOP, ENETRESET,
 * ENOLINK and EPROTO were the five spicule did not define, and a
 * consumer met that as a compile error rather than a wrong answer:
 * gnulib's errno/strerror-override modules name four of the five
 * directly, but only after its configure probe has already decided
 * what the platform is.
 * ================================================================== */

static void test_errno_mandatory_macros(void)
{
	/* "distinct positive values" -- and distinct from every other
	 * error macro the same list mandates, which is what makes them
	 * usable as switch labels. */
	static const int mandatory[] = {
		EBADMSG, EMULTIHOP, ENETRESET, ENOLINK, EPROTO,
		/* the ones spicule already has, for the distinctness check */
		E2BIG, EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT,
		EALREADY, EBADF, EBUSY, ECANCELED, ECHILD, ECONNABORTED,
		ECONNREFUSED, ECONNRESET, EDEADLK, EDESTADDRREQ, EDOM,
		EDQUOT, EEXIST, EFAULT, EFBIG, EHOSTUNREACH, EIDRM, EILSEQ,
		EINPROGRESS, EINTR, EINVAL, EIO, EISCONN, EISDIR, ELOOP,
		EMFILE, EMLINK, EMSGSIZE, ENAMETOOLONG, ENETDOWN,
		ENETUNREACH, ENFILE, ENOBUFS, ENODATA, ENODEV, ENOENT,
		ENOEXEC, ENOLCK, ENOMEM, ENOMSG, ENOPROTOOPT, ENOSPC,
		ENOSR, ENOSTR, ENOSYS, ENOTCONN, ENOTDIR, ENOTEMPTY,
		ENOTRECOVERABLE, ENOTSOCK, ENOTTY, ENXIO, EOVERFLOW,
		EOWNERDEAD, EPERM, EPIPE, EPROTONOSUPPORT, EPROTOTYPE,
		ERANGE, EROFS, ESPIPE, ESRCH, ESTALE, ETIME, ETIMEDOUT,
		ETXTBSY, EXDEV,
	};
	size_t i, j;

	CHECK(EBADMSG > 0 && EMULTIHOP > 0 && ENETRESET > 0);
	CHECK(ENOLINK > 0 && EPROTO > 0);

	for (i = 0; i < sizeof mandatory / sizeof mandatory[0]; i++)
		for (j = i + 1; j < sizeof mandatory / sizeof mandatory[0]; j++)
			CHECK(mandatory[i] != mandatory[j]);

	/* "suitable for use in #if preprocessing directives" -- the five
	 * must be integer constant expressions the preprocessor can see,
	 * not enum constants or extern objects. */
#if EPROTO > 0 && EBADMSG > 0 && ENOLINK > 0 && EMULTIHOP > 0 && ENETRESET > 0
	CHECK(1);
#else
	CHECK(0);
#endif

	/* strerror.html RETURN VALUE: strerror() sets errno to [EINVAL]
	 * only "if errnum is not a valid error number"; a value <errno.h>
	 * itself mandates is valid, so closing this gap means a message
	 * for each, not just a #define. */
	{
		static const int five[] = { EBADMSG, EMULTIHOP, ENETRESET, ENOLINK, EPROTO };
		for (i = 0; i < 5; i++) {
			const char *m;
			errno = 0;
			m = strerror(five[i]);
			CHECK(m != NULL && m[0] != '\0' && errno == 0);
		}
	}
}

int main(void)
{
	size_t i;

	test_errno_mandatory_macros();

	for (i = 0; i < sizeof status_table / sizeof status_table[0]; i++) {
		int got = __errno_from_status(status_table[i].st);
		if (got != status_table[i].e)
			printf("FAIL %s:%d: __errno_from_status(%s) = %d, want %d\n",
			       __FILE__, __LINE__, status_table[i].name, got, status_table[i].e);
		fails += (got != status_table[i].e);
	}

	for (i = 0; i < sizeof doserror_table / sizeof doserror_table[0]; i++) {
		int got = __errno_from_doserror(doserror_table[i].e);
		if (got != doserror_table[i].errno_val)
			printf("FAIL %s:%d: __errno_from_doserror(%u) [%s] = %d, want %d\n",
			       __FILE__, __LINE__, doserror_table[i].e, doserror_table[i].name, got, doserror_table[i].errno_val);
		fails += (got != doserror_table[i].errno_val);
	}

	/* __set_errno_status: errno = map(st); return -1.  When the map
	 * yields 0 (STATUS_SUCCESS or STATUS_END_OF_FILE, neither of which
	 * a caller should feed to this "always report an error" helper),
	 * src/internal/errno.c substitutes EIO rather than leaving errno at
	 * 0, since 0 is not a valid error indicator. */
	errno = 0;
	CHECK(__set_errno_status(STATUS_ACCESS_DENIED) == -1 && errno == EACCES);
	errno = 0;
	CHECK(__set_errno_status(STATUS_END_OF_FILE) == -1 && errno == EIO);
	errno = 0;
	CHECK(__set_errno_status(STATUS_SUCCESS) == -1 && errno == EIO);

	if (!fails) printf("posix-errno: all tests passed\n");
	return fails != 0;
}
