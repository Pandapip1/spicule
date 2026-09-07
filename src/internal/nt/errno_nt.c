/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The NTSTATUS-to-errno mapping, moved out of src/internal/errno.c
 * (which keeps only __errno_location(), the one part every platform
 * needs identically) so a Linux build never links in a call to
 * RtlNtStatusToDosError() -- see errno.c's own banner for why that
 * mattered in practice, not just in principle.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include "libc.h"

int __errno_from_status(NTSTATUS st)
{
	switch (st) {
	case STATUS_SUCCESS: return 0;
	case STATUS_NO_MEMORY:
	case STATUS_INSUFFICIENT_RESOURCES:
	case STATUS_QUOTA_EXCEEDED: return ENOMEM;
	case STATUS_INVALID_HANDLE:
	case STATUS_FILE_CLOSED:
	case STATUS_OBJECT_TYPE_MISMATCH: return EBADF;
	case STATUS_INVALID_PARAMETER:
	case STATUS_INVALID_INFO_CLASS:
	case STATUS_INFO_LENGTH_MISMATCH:
	case STATUS_DATATYPE_MISALIGNMENT: return EINVAL;
	case STATUS_OBJECT_NAME_NOT_FOUND:
	case STATUS_OBJECT_PATH_NOT_FOUND:
	case STATUS_NO_SUCH_FILE:
	case STATUS_NO_SUCH_DEVICE:
	case STATUS_NOT_FOUND:
	case STATUS_DLL_NOT_FOUND:
	case STATUS_FILE_DELETED:
	case STATUS_DELETE_PENDING:
	case STATUS_OBJECT_NAME_INVALID:
	case STATUS_OBJECT_PATH_INVALID:
	case STATUS_OBJECT_PATH_SYNTAX_BAD: return ENOENT;
	case STATUS_NAME_TOO_LONG: return ENAMETOOLONG;
	case STATUS_ACCESS_DENIED:
	case STATUS_PRIVILEGE_NOT_HELD:
	case STATUS_CANNOT_DELETE: return EACCES;
	case STATUS_SHARING_VIOLATION:
	case STATUS_USER_MAPPED_FILE: return EBUSY;
	case STATUS_FILE_LOCK_CONFLICT:
	case STATUS_LOCK_NOT_GRANTED: return EWOULDBLOCK;
	case STATUS_OBJECT_NAME_COLLISION: return EEXIST;
	case STATUS_FILE_IS_A_DIRECTORY: return EISDIR;
	case STATUS_NOT_A_DIRECTORY: return ENOTDIR;
	case STATUS_DIRECTORY_NOT_EMPTY: return ENOTEMPTY;
	case STATUS_DISK_FULL: return ENOSPC;
	case STATUS_TOO_MANY_OPENED_FILES: return EMFILE;
	case STATUS_PIPE_BROKEN:
	case STATUS_PIPE_DISCONNECTED:
	case STATUS_PIPE_CLOSING:
	case STATUS_PIPE_LISTENING:
	case STATUS_PIPE_NOT_AVAILABLE: return EPIPE;
	case STATUS_PIPE_EMPTY: return EAGAIN;
	case STATUS_NOT_IMPLEMENTED:
	case STATUS_NOT_SUPPORTED:
	case STATUS_INVALID_DEVICE_REQUEST: return ENOSYS;
	case STATUS_END_OF_FILE: return 0;
	case STATUS_MEDIA_WRITE_PROTECTED: return EROFS;
	case STATUS_NOT_SAME_DEVICE: return EXDEV;
	case STATUS_IO_TIMEOUT: return ETIMEDOUT;
	case STATUS_CANCELLED: return EINTR;
	case STATUS_TOO_MANY_LINKS: return EMLINK;
	case STATUS_ACCESS_VIOLATION: return EFAULT;
	case STATUS_INVALID_IMAGE_FORMAT:
	case STATUS_INVALID_IMAGE_NOT_MZ:
	case STATUS_INVALID_IMAGE_PROTECT:
	case STATUS_INVALID_IMAGE_WIN_32:
	case STATUS_INVALID_IMAGE_WIN_64:
	case STATUS_ENTRYPOINT_NOT_FOUND:
	case STATUS_FILE_INVALID: return ENOEXEC;
	case STATUS_DEVICE_NOT_READY:
	case STATUS_VOLUME_DISMOUNTED: return ENXIO;
	case STATUS_FILE_TOO_LARGE: return EFBIG;
	case STATUS_PROCESS_IS_TERMINATING: return ESRCH;
	case STATUS_BUFFER_TOO_SMALL:
	case STATUS_BUFFER_OVERFLOW: return ERANGE;
	case STATUS_DATA_ERROR: return EIO;
	case STATUS_NOT_A_REPARSE_POINT:
	case STATUS_IO_REPARSE_TAG_NOT_HANDLED: return EINVAL;
	/* The object manager's own reparse-point resolution gives up on a
	 * chain that never bottoms out in a real file and answers this
	 * status; a symbolic link loop is exactly that case. Previously
	 * unmapped entirely, falling through to RtlNtStatusToDosError()'s
	 * default EIO -- indistinguishable from a real I/O error. */
	case STATUS_REPARSE_POINT_NOT_RESOLVED: return ELOOP;
	/* AFD (src/internal/afd.h, src/socket/): values confirmed against
	 * mingw-w64's vendored copy of Microsoft's own ntstatus.h. */
	case STATUS_CONNECTION_REFUSED: return ECONNREFUSED;
	case STATUS_CONNECTION_RESET: return ECONNRESET;
	case STATUS_CONNECTION_ABORTED: return ECONNABORTED;
	case STATUS_CONNECTION_DISCONNECTED:
	case STATUS_LOCAL_DISCONNECT:
	case STATUS_REMOTE_DISCONNECT:
	case STATUS_GRACEFUL_DISCONNECT: return ENOTCONN;
	case STATUS_CONNECTION_ACTIVE: return EISCONN;
	case STATUS_CONNECTION_INVALID: return ENOTCONN;
	case STATUS_ADDRESS_ALREADY_ASSOCIATED:
	case STATUS_ADDRESS_ALREADY_EXISTS: return EADDRINUSE;
	case STATUS_INVALID_ADDRESS:
	case STATUS_INVALID_ADDRESS_COMPONENT: return EADDRNOTAVAIL;
	case STATUS_NETWORK_UNREACHABLE: return ENETUNREACH;
	case STATUS_HOST_UNREACHABLE: return EHOSTUNREACH;
	case STATUS_PROTOCOL_UNREACHABLE: return ENOPROTOOPT;
	case STATUS_PORT_UNREACHABLE: return ECONNREFUSED;
	case STATUS_REQUEST_ABORTED: return ECONNABORTED;
	case STATUS_TOO_MANY_ADDRESSES: return EADDRNOTAVAIL;
	case STATUS_ADDRESS_CLOSED: return ENOTCONN;
	case STATUS_PROTOCOL_NOT_SUPPORTED: return EPROTONOSUPPORT;
	default:
		return __errno_from_doserror(RtlNtStatusToDosError(st));
	}
}

/* Win32 error codes the status table above does not already cover. */
int __errno_from_doserror(unsigned e)
{
	switch (e) {
	case 0: return 0;
	case 1: return ENOSYS;       /* ERROR_INVALID_FUNCTION */
	case 2: case 3: return ENOENT;
	case 4: return EMFILE;
	case 5: return EACCES;
	case 6: return EBADF;
	case 8: case 14: return ENOMEM;
	case 13: return EINVAL;
	case 15: return ENODEV;
	case 17: return EXDEV;
	case 18: return ENOENT;
	case 19: return EROFS;
	case 21: return ENXIO;
	case 32: case 33: return EBUSY;
	case 39: case 112: return ENOSPC;
	case 80: case 183: return EEXIST;
	case 87: return EINVAL;
	case 109: return EPIPE;
	case 110: return EACCES;
	case 122: return ERANGE;
	case 123: return ENOENT;
	case 145: return ENOTEMPTY;
	case 206: return ENAMETOOLONG;
	case 231: case 232: case 233: return EPIPE;
	case 267: return ENOTDIR;
	case 1816: return ENOMEM;
	default: return EIO;
	}
}

int __set_errno_status(NTSTATUS st)
{
	int e = __errno_from_status(st);
	errno = e ? e : EIO;
	return -1;
}

// NOLINTEND(misc-include-cleaner)
