/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include <errno.h>
#include <locale.h>
#include "libc.h"
#include "ownership_stubs.h"

/* Indexed by errno; the highest value in bits/errno.h is
 * ENOTRECOVERABLE (131). */
static const char *const __errmsgs[] = {
	[0] = "No error information",
	[EPERM] = "Operation not permitted",
	[ENOENT] = "No such file or directory",
	[ESRCH] = "No such process",
	[EINTR] = "Interrupted system call",
	[EIO] = "I/O error",
	[ENXIO] = "No such device or address",
	[E2BIG] = "Argument list too long",
	[ENOEXEC] = "Exec format error",
	[EBADF] = "Bad file descriptor",
	[ECHILD] = "No child process",
	[EAGAIN] = "Resource temporarily unavailable",
	[ENOMEM] = "Out of memory",
	[EACCES] = "Permission denied",
	[EFAULT] = "Bad address",
	[ENOTBLK] = "Block device required",
	[EBUSY] = "Resource busy",
	[EEXIST] = "File exists",
	[EXDEV] = "Cross-device link",
	[ENODEV] = "No such device",
	[ENOTDIR] = "Not a directory",
	[EISDIR] = "Is a directory",
	[EINVAL] = "Invalid argument",
	[ENFILE] = "Too many open files in system",
	[EMFILE] = "No file descriptors available",
	[ENOTTY] = "Not a tty",
	[ETXTBSY] = "Text file busy",
	[EFBIG] = "File too large",
	[ENOSPC] = "No space left on device",
	[ESPIPE] = "Invalid seek",
	[EROFS] = "Read-only file system",
	[EMLINK] = "Too many links",
	[EPIPE] = "Broken pipe",
	[EDOM] = "Domain error",
	[ERANGE] = "Result not representable",
	[EDEADLK] = "Resource deadlock would occur",
	[ENAMETOOLONG] = "Filename too long",
	[ENOLCK] = "No locks available",
	[ENOSYS] = "Function not implemented",
	[ENOTEMPTY] = "Directory not empty",
	[ELOOP] = "Symbolic link loop",
	[ENOMSG] = "No message of desired type",
	[EIDRM] = "Identifier removed",
	[ENOSTR] = "Device not a stream",
	[ENODATA] = "No data available",
	[ETIME] = "Device timeout",
	[ENOSR] = "Out of streams resources",
	[ENOLINK] = "Link has been severed",
	[EPROTO] = "Protocol error",
	[EMULTIHOP] = "Multihop attempted",
	[EBADMSG] = "Bad message",
	[EOVERFLOW] = "Value too large for data type",
	[EILSEQ] = "Illegal byte sequence",
	[ENOTSOCK] = "Not a socket",
	[EDESTADDRREQ] = "Destination address required",
	[EMSGSIZE] = "Message too large",
	[EPROTOTYPE] = "Protocol wrong type for socket",
	[ENOPROTOOPT] = "Protocol not available",
	[EPROTONOSUPPORT] = "Protocol not supported",
	[EOPNOTSUPP] = "Not supported",
	[EAFNOSUPPORT] = "Address family not supported by protocol",
	[EADDRINUSE] = "Address in use",
	[EADDRNOTAVAIL] = "Address not available",
	[ENETDOWN] = "Network is down",
	[ENETUNREACH] = "Network unreachable",
	[ENETRESET] = "Connection reset by network",
	[ECONNABORTED] = "Connection aborted",
	[ECONNRESET] = "Connection reset by peer",
	[ENOBUFS] = "No buffer space available",
	[EISCONN] = "Socket is connected",
	[ENOTCONN] = "Socket not connected",
	[ETIMEDOUT] = "Operation timed out",
	[ECONNREFUSED] = "Connection refused",
	[EHOSTUNREACH] = "Host is unreachable",
	[EALREADY] = "Operation already in progress",
	[EINPROGRESS] = "Operation in progress",
	[ESTALE] = "Stale file handle",
	[EDQUOT] = "Quota exceeded",
	[ECANCELED] = "Operation canceled",
	[EOWNERDEAD] = "Previous owner died",
	[ENOTRECOVERABLE] = "State not recoverable",
};

#define NERR (sizeof __errmsgs / sizeof *__errmsgs)

const char *__strerror_msg(int e)
{
	if (e < 0 || (size_t)e >= NERR || !__errmsgs[e]) return __errmsgs[0];
	return __errmsgs[e];
}

withtok(null_terminated)
char *strerror(int e)
{
	char *result = (char *)__strerror_msg(e);
	unsafe_assume_string_terminated(result);
	return result;
}

withtok(null_terminated)
char *strerror_l(int e, locale_t loc)
{
	(void)loc;
	return strerror(e);
}

// NOLINTEND(misc-include-cleaner)
