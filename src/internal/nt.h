/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The native NT interface spicule is built on: types, structures, constants
 * and prototypes for the ntdll routines used anywhere in the library.  This
 * is deliberately self-contained -- no windows.h, no winternl.h -- so that
 * the library builds with nothing but its own headers and tcc.
 *
 * Layouts are the documented/observed ones for both i386 and x86_64, and
 * are expressed with pointer-sized fields so that one definition serves
 * both.  Where a structure is only ever read at a few offsets, only the
 * leading fields up to the last one needed are declared, and a comment
 * says so.
 */
#ifndef _SPICULE_NT_H
#define _SPICULE_NT_H

#include <features.h>
#include <allocation_tokens.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __i386__
#define NTAPI __attribute__((stdcall))
#else
#define NTAPI
#endif

#define TRUE 1
#define FALSE 0

typedef int NTSTATUS;
typedef void *HANDLE, **PHANDLE;
typedef void *PVOID;
typedef unsigned char BOOLEAN, UCHAR;
typedef unsigned short USHORT, WCHAR, *PWSTR;
typedef const WCHAR *PCWSTR;
typedef uint32_t ULONG, *PULONG;
typedef int32_t LONG;
typedef unsigned long long ULONGLONG;
typedef long long LONGLONG;
typedef uintptr_t ULONG_PTR;
typedef intptr_t LONG_PTR;
typedef size_t SIZE_T;
typedef ULONG ACCESS_MASK;
typedef LONGLONG LARGE_INTEGER;
typedef ULONGLONG ULARGE_INTEGER;
typedef USHORT RTL_ATOM;

#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)

/* ---- security identifiers and access tokens ------------------------- */
typedef struct _SID_IDENTIFIER_AUTHORITY {
	UCHAR Value[6];
} SID_IDENTIFIER_AUTHORITY;

typedef struct _SID {
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[1];
} SID, *PSID;

typedef struct _SID_AND_ATTRIBUTES {
	PSID Sid;
	ULONG Attributes;
} SID_AND_ATTRIBUTES;

typedef struct _TOKEN_USER {
	SID_AND_ATTRIBUTES User;
} TOKEN_USER;

typedef enum _TOKEN_INFORMATION_CLASS {
	TokenUser = 1
} TOKEN_INFORMATION_CLASS;

#define SID_REVISION                 1
#define SID_MAX_SUB_AUTHORITIES     15
#define SECURITY_MAX_SID_SIZE       (8 + 4 * SID_MAX_SUB_AUTHORITIES)
#define TOKEN_QUERY             0x0008

/* ---- status codes ---------------------------------------------------- */
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_WAIT_0                   ((NTSTATUS)0x00000000L)
#define STATUS_USER_APC                 ((NTSTATUS)0x000000C0L)
#define STATUS_ALERTED                  ((NTSTATUS)0x00000101L)
#define STATUS_TIMEOUT                  ((NTSTATUS)0x00000102L)
#define STATUS_PENDING                  ((NTSTATUS)0x00000103L)
#define STATUS_OBJECT_NAME_EXISTS       ((NTSTATUS)0x40000000L)
#define STATUS_PROCESS_CLONED           ((NTSTATUS)0x00000129L)
#define STATUS_BUFFER_OVERFLOW          ((NTSTATUS)0x80000005L)
#define STATUS_NO_MORE_FILES            ((NTSTATUS)0x80000006L)
#define STATUS_DATATYPE_MISALIGNMENT    ((NTSTATUS)0x80000002L)
#define STATUS_UNSUCCESSFUL             ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED          ((NTSTATUS)0xC0000002L)
#define STATUS_INVALID_INFO_CLASS       ((NTSTATUS)0xC0000003L)
#define STATUS_INFO_LENGTH_MISMATCH     ((NTSTATUS)0xC0000004L)
#define STATUS_ACCESS_VIOLATION         ((NTSTATUS)0xC0000005L)
#define STATUS_INVALID_HANDLE           ((NTSTATUS)0xC0000008L)
#define STATUS_INVALID_PARAMETER        ((NTSTATUS)0xC000000DL)
#define STATUS_NO_SUCH_DEVICE           ((NTSTATUS)0xC000000EL)
#define STATUS_NO_SUCH_FILE             ((NTSTATUS)0xC000000FL)
#define STATUS_INVALID_DEVICE_REQUEST   ((NTSTATUS)0xC0000010L)
#define STATUS_END_OF_FILE              ((NTSTATUS)0xC0000011L)
#define STATUS_NO_MEMORY                ((NTSTATUS)0xC0000017L)
#define STATUS_INVALID_FILE_FOR_SECTION ((NTSTATUS)0xC0000020L)
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
#define STATUS_SEMAPHORE_LIMIT_EXCEEDED ((NTSTATUS)0xC0000047L)
#define STATUS_FILE_LOCK_CONFLICT       ((NTSTATUS)0xC0000054L)
#define STATUS_LOCK_NOT_GRANTED         ((NTSTATUS)0xC0000055L)
#define STATUS_RANGE_NOT_LOCKED         ((NTSTATUS)0xC000007EL)
#define STATUS_DELETE_PENDING           ((NTSTATUS)0xC0000056L)
#define STATUS_DISK_FULL                ((NTSTATUS)0xC000007FL)
#define STATUS_TOO_MANY_OPENED_FILES    ((NTSTATUS)0xC000011FL)
#define STATUS_FILE_IS_A_DIRECTORY      ((NTSTATUS)0xC00000BAL)
#define STATUS_NOT_SUPPORTED            ((NTSTATUS)0xC00000BBL)
#define STATUS_PIPE_BROKEN              ((NTSTATUS)0xC000014BL)
#define STATUS_PIPE_DISCONNECTED        ((NTSTATUS)0xC00000B0L)
#define STATUS_PIPE_EMPTY               ((NTSTATUS)0xC00000D9L)
#define STATUS_PIPE_CONNECTED           ((NTSTATUS)0xC00000B2L)
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
#define STATUS_REPARSE_POINT_NOT_RESOLVED ((NTSTATUS)0xC0000280L)
#define STATUS_PRIVILEGE_NOT_HELD       ((NTSTATUS)0xC0000061L)
#define STATUS_USER_MAPPED_FILE         ((NTSTATUS)0xC0000243L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_DEVICE_NOT_READY         ((NTSTATUS)0xC00000A3L)
#define STATUS_FILE_TOO_LARGE           ((NTSTATUS)0xC0000904L)
#define STATUS_VOLUME_DISMOUNTED        ((NTSTATUS)0xC000026EL)
#define STATUS_NOT_FOUND                ((NTSTATUS)0xC0000225L)
#define STATUS_CONTROL_C_EXIT           ((NTSTATUS)0xC000013AL)

/* AFD (src/socket/ (every .c there)); values confirmed against mingw-w64's vendored
 * copy of Microsoft's own ntstatus.h (see src/internal/afd.h's banner)
 * -- /usr/share/mingw-w64/include/ntstatus.h on the machine this was
 * written on, the same headers this project's cross toolchain ships. */
#define STATUS_LOCAL_DISCONNECT             ((NTSTATUS)0xC000013BL)
#define STATUS_REMOTE_DISCONNECT            ((NTSTATUS)0xC000013CL)
#define STATUS_INVALID_ADDRESS              ((NTSTATUS)0xC0000141L)
#define STATUS_INVALID_ADDRESS_COMPONENT    ((NTSTATUS)0xC0000207L)
#define STATUS_TOO_MANY_ADDRESSES           ((NTSTATUS)0xC0000209L)
#define STATUS_ADDRESS_ALREADY_EXISTS       ((NTSTATUS)0xC000020AL)
#define STATUS_ADDRESS_CLOSED               ((NTSTATUS)0xC000020BL)
#define STATUS_CONNECTION_DISCONNECTED      ((NTSTATUS)0xC000020CL)
#define STATUS_CONNECTION_RESET             ((NTSTATUS)0xC000020DL)
#define STATUS_CONNECTION_REFUSED           ((NTSTATUS)0xC0000236L)
#define STATUS_GRACEFUL_DISCONNECT          ((NTSTATUS)0xC0000237L)
#define STATUS_ADDRESS_ALREADY_ASSOCIATED   ((NTSTATUS)0xC0000238L)
#define STATUS_CONNECTION_INVALID           ((NTSTATUS)0xC000023AL)
#define STATUS_CONNECTION_ACTIVE            ((NTSTATUS)0xC000023BL)
#define STATUS_NETWORK_UNREACHABLE          ((NTSTATUS)0xC000023CL)
#define STATUS_HOST_UNREACHABLE             ((NTSTATUS)0xC000023DL)
#define STATUS_PROTOCOL_UNREACHABLE         ((NTSTATUS)0xC000023EL)
#define STATUS_PORT_UNREACHABLE             ((NTSTATUS)0xC000023FL)
#define STATUS_REQUEST_ABORTED              ((NTSTATUS)0xC0000240L)
#define STATUS_CONNECTION_ABORTED           ((NTSTATUS)0xC0000241L)
#define STATUS_PROTOCOL_NOT_SUPPORTED       ((NTSTATUS)0xC000A013L)

/* ---- basic structures ------------------------------------------------ */
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	char  *Buffer;
} STRING, ANSI_STRING, *PSTRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L

/* On an LLP64 target (x86_64: ULONG stays 4 bytes, HANDLE/PVOID become 8)
 * OBJECT_ATTRIBUTES has two real compiler-inserted padding gaps -- 4
 * bytes after the 4-byte Length before the pointer-sized RootDirectory,
 * and another 4 bytes after Attributes before SecurityDescriptor -- that
 * setting only the six named fields below, however completely, can never
 * reach.  Those bytes are genuinely uninitialized stack garbage, and
 * every one of this macro's call sites hands its address straight into a
 * real Nt (or Zw) syscall (NtCreateFile, NtOpenProcess, NtCreateEvent,
 * and every other NtCreate/NtOpen call in this tree): uninitialized
 * stack content crossing into the kernel on every OBJECT_ATTRIBUTES-
 * taking call this library makes.  The memset first proves the whole
 * object, padding included, before the named fields are set. */
#define InitializeObjectAttributes(p, n, a, r, s) do { \
	memset((p), 0, sizeof(*(p))); \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = (r); \
	(p)->Attributes = (a); \
	(p)->ObjectName = (n); \
	(p)->SecurityDescriptor = (s); \
	(p)->SecurityQualityOfService = NULL; \
} while (0)

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY *Flink;
	struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _CURDIR {
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32];
	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#define STARTF_USESTDHANDLES            0x00000100

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	/* more follows; not needed */
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/* The PEB, up to ProcessHeap; the rest is not used here.  Padding after
 * the four leading bytes falls out of natural alignment on both arches. */
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN BitField;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	ULONG CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID SharedData;
	PVOID *ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	SIZE_T HeapSegmentReserve;
	SIZE_T HeapSegmentCommit;
	SIZE_T HeapDeCommitTotalFreeThreshold;
	SIZE_T HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID *ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PVOID LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
} PEB, *PPEB;

typedef struct _NT_TIB {
	PVOID ExceptionList;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID SubSystemTib;
	PVOID FiberData;
	PVOID ArbitraryUserPointer;
	struct _NT_TIB *Self;
} NT_TIB;

typedef struct _TEB {
	NT_TIB NtTib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;
	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	ULONG CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	/* more follows; not needed */
} TEB, *PTEB;

/* ---- files ----------------------------------------------------------- */
#define FILE_READ_DATA            0x0001
#define FILE_LIST_DIRECTORY       0x0001
#define FILE_WRITE_DATA           0x0002
#define FILE_ADD_FILE             0x0002
#define FILE_APPEND_DATA          0x0004
#define FILE_ADD_SUBDIRECTORY     0x0004
#define FILE_READ_EA              0x0008
#define FILE_WRITE_EA             0x0010
#define FILE_EXECUTE              0x0020
#define FILE_TRAVERSE             0x0020
#define FILE_DELETE_CHILD         0x0040
#define FILE_READ_ATTRIBUTES      0x0080
#define FILE_WRITE_ATTRIBUTES     0x0100
#define DELETE                    0x00010000L
#define READ_CONTROL              0x00020000L
#define WRITE_DAC                 0x00040000L
#define WRITE_OWNER               0x00080000L
#define SYNCHRONIZE               0x00100000L
#define STANDARD_RIGHTS_REQUIRED  0x000F0000L
#define STANDARD_RIGHTS_READ      READ_CONTROL
#define STANDARD_RIGHTS_WRITE     READ_CONTROL
#define GENERIC_READ              0x80000000L
#define GENERIC_WRITE             0x40000000L
#define GENERIC_EXECUTE           0x20000000L
#define GENERIC_ALL               0x10000000L
#define FILE_GENERIC_READ  (STANDARD_RIGHTS_READ|FILE_READ_DATA|FILE_READ_ATTRIBUTES|FILE_READ_EA|SYNCHRONIZE)
#define FILE_GENERIC_WRITE (STANDARD_RIGHTS_WRITE|FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES|FILE_WRITE_EA|FILE_APPEND_DATA|SYNCHRONIZE)
#define FILE_GENERIC_EXECUTE (STANDARD_RIGHTS_READ|FILE_READ_ATTRIBUTES|FILE_EXECUTE|SYNCHRONIZE)

#define FILE_SHARE_READ           0x00000001
#define FILE_SHARE_WRITE          0x00000002
#define FILE_SHARE_DELETE         0x00000004
#define FILE_SHARE_VALID_FLAGS    0x00000007

#define FILE_ATTRIBUTE_READONLY             0x00000001
#define FILE_ATTRIBUTE_HIDDEN               0x00000002
#define FILE_ATTRIBUTE_SYSTEM               0x00000004
#define FILE_ATTRIBUTE_DIRECTORY            0x00000010
#define FILE_ATTRIBUTE_ARCHIVE              0x00000020
#define FILE_ATTRIBUTE_DEVICE               0x00000040
#define FILE_ATTRIBUTE_NORMAL               0x00000080
#define FILE_ATTRIBUTE_TEMPORARY            0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE          0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT        0x00000400
#define FILE_ATTRIBUTE_COMPRESSED           0x00000800
#define FILE_ATTRIBUTE_OFFLINE              0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED            0x00004000
/* Cloud-backed placeholders (OneDrive and other sync engines).  A file
 * carrying either of these has no local data: opening it, or reading a
 * byte of it, makes the provider fetch the whole thing over the network.
 * __is_program() (src/process/find_program.c) checks them so that a PATH
 * search never triggers a multi-megabyte download to look at two bytes. */
#define FILE_ATTRIBUTE_RECALL_ON_OPEN         0x00040000
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS  0x00400000

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005

#define FILE_DIRECTORY_FILE             0x00000001
#define FILE_WRITE_THROUGH              0x00000002
#define FILE_SEQUENTIAL_ONLY            0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING  0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT       0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020
#define FILE_NON_DIRECTORY_FILE         0x00000040
#define FILE_CREATE_TREE_CONNECTION     0x00000080
#define FILE_COMPLETE_IF_OPLOCKED       0x00000100
#define FILE_NO_EA_KNOWLEDGE            0x00000200
#define FILE_OPEN_REMOTE_INSTANCE       0x00000400
#define FILE_RANDOM_ACCESS              0x00000800
#define FILE_DELETE_ON_CLOSE            0x00001000
#define FILE_OPEN_BY_FILE_ID            0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT     0x00004000
#define FILE_NO_COMPRESSION             0x00008000
#define FILE_OPEN_REQUIRING_OPLOCK      0x00010000
#define FILE_RESERVE_OPFILTER           0x00100000
#define FILE_OPEN_REPARSE_POINT         0x00200000
#define FILE_OPEN_NO_RECALL             0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY  0x00800000

#define FILE_SUPERSEDED                 0x00000000
#define FILE_OPENED                     0x00000001
#define FILE_CREATED                    0x00000002
#define FILE_OVERWRITTEN                0x00000003
#define FILE_EXISTS                     0x00000004
#define FILE_DOES_NOT_EXIST             0x00000005

#define FILE_PIPE_BYTE_STREAM_TYPE      0x00000000
#define FILE_PIPE_MESSAGE_TYPE          0x00000001
#define FILE_PIPE_BYTE_STREAM_MODE      0x00000000
#define FILE_PIPE_MESSAGE_MODE          0x00000001
#define FILE_PIPE_QUEUE_OPERATION       0x00000000
#define FILE_PIPE_COMPLETE_OPERATION    0x00000001

#define FILE_WRITE_TO_END_OF_FILE       (-1LL)
#define FILE_USE_FILE_POINTER_POSITION  (-2LL)

#define FILE_DEVICE_BEEP                0x00000001
#define FILE_DEVICE_CD_ROM              0x00000002
#define FILE_DEVICE_CONSOLE             0x00000050
#define FILE_DEVICE_DISK                0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008
#define FILE_DEVICE_NAMED_PIPE          0x00000011
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NULL                0x00000015
#define FILE_DEVICE_SCREEN              0x0000001C
#define FILE_DEVICE_SERIAL_PORT         0x0000001B
#define FILE_DEVICE_UNKNOWN             0x00000022
#define FILE_DEVICE_VIRTUAL_DISK        0x00000024
#define FILE_DEVICE_MAILSLOT            0x0000000C
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003
#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020
#define FILE_DEVICE_FILE_SYSTEM         0x00000009

#define FILE_REMOVABLE_MEDIA            0x00000001
#define FILE_READ_ONLY_DEVICE           0x00000002
#define FILE_REMOTE_DEVICE              0x00000010
#define FILE_DEVICE_IS_MOUNTED          0x00000020

/* FILE_FS_ATTRIBUTE_INFORMATION.FileSystemAttributes; only the one bit
 * src/stat/statvfs.c needs.  The volume is mounted read-only. */
#define FILE_READ_ONLY_VOLUME           0x00080000

typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation,
	FileIoCompletionNotificationInformation,
	FileIoStatusBlockRangeInformation,
	FileIoPriorityHintInformation,
	FileSfioReserveInformation,
	FileSfioVolumeInformation,
	FileHardLinkInformation,
	FileProcessIdsUsingFileInformation,
	FileNormalizedNameInformation,
	FileNetworkPhysicalNameInformation,
	FileIdGlobalTxDirectoryInformation,
	FileIsRemoteDeviceInformation,
	FileUnusedInformation,
	FileNumaNodeInformation,
	FileStandardLinkInformation,
	FileRemoteProtocolInformation,
	FileRenameInformationBypassAccessCheck,
	FileLinkInformationBypassAccessCheck,
	FileVolumeNameInformation,
	FileIdInformation,
	FileIdExtdDirectoryInformation,
	FileReplaceCompletionInformation,
	FileHardLinkFullIdInformation,
	FileIdExtdBothDirectoryInformation,
	FileDispositionInformationEx,
	FileRenameInformationEx,
	FileRenameInformationExBypassAccessCheck,
	FileDesiredStorageClassInformation,
	FileStatInformation,
	FileMemoryPartitionInformation,
	FileStatLxInformation,
	FileCaseSensitiveInformation,
	FileLinkInformationEx,
	FileLinkInformationExBypassAccessCheck,
	FileStorageReserveIdInformation,
	FileCaseSensitiveInformationForceAccessCheck,
	FileMaximumInformation
} FILE_INFORMATION_CLASS;

typedef enum _FS_INFORMATION_CLASS {
	FileFsVolumeInformation = 1,
	FileFsLabelInformation,
	FileFsSizeInformation,
	FileFsDeviceInformation,
	FileFsAttributeInformation,
	FileFsControlInformation,
	FileFsFullSizeInformation,
	FileFsObjectIdInformation,
	FileFsDriverPathInformation,
	FileFsVolumeFlagsInformation,
	FileFsSectorSizeInformation,
	FileFsMaximumInformation
} FS_INFORMATION_CLASS;

typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG FileAttributes;
} FILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG NumberOfLinks;
	BOOLEAN DeletePending;
	BOOLEAN Directory;
} FILE_STANDARD_INFORMATION;

typedef struct _FILE_INTERNAL_INFORMATION {
	LARGE_INTEGER IndexNumber;
} FILE_INTERNAL_INFORMATION;

/* NtQueryObject's ObjectNameInformation, used by __fstat_handle (src/stat/stat.c)
 * as a fallback identity source for pipes/consoles/char devices, for which
 * FileInternalInformation is not universally supported (NPFS answers
 * STATUS_NOT_IMPLEMENTED for it -- confirmed both empirically and by
 * <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle>'s
 * "This handle should not be a pipe handle" for the kernel32 call built on
 * the same two NT queries). Layout and class value per
 * <https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject>. */
typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectNameInformation = 1,
	ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION;

/* ObjectBasicInformation.  Only GrantedAccess is used here (src/internal/
 * fd.c, to recover the access mode of a handle this process did not open),
 * but the whole structure has to be declared because NtQueryObject checks
 * the length it is given against the class's full size.  Layout per
 * <https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject>
 * and ntifs.h. */
typedef struct _OBJECT_BASIC_INFORMATION {
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG Reserved[3];
	ULONG NameInfoSize;
	ULONG TypeInfoSize;
	ULONG SecurityDescriptorSize;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION;

typedef struct _FILE_POSITION_INFORMATION {
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION;

typedef struct _FILE_END_OF_FILE_INFORMATION {
	LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION;

typedef struct _FILE_ALLOCATION_INFORMATION {
	LARGE_INTEGER AllocationSize;
} FILE_ALLOCATION_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION {
	BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION_EX {
	ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX;

#define FILE_DISPOSITION_DO_NOT_DELETE              0x00000000
#define FILE_DISPOSITION_DELETE                     0x00000001
#define FILE_DISPOSITION_POSIX_SEMANTICS            0x00000002
#define FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK  0x00000004
#define FILE_DISPOSITION_ON_CLOSE                   0x00000008
#define FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE  0x00000010

typedef struct _FILE_RENAME_INFORMATION {
	union {
		BOOLEAN ReplaceIfExists;
		ULONG Flags;
	};
	HANDLE RootDirectory;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_RENAME_INFORMATION;

#define FILE_RENAME_REPLACE_IF_EXISTS               0x00000001
#define FILE_RENAME_POSIX_SEMANTICS                 0x00000002

typedef struct _FILE_NAME_INFORMATION {
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_NAME_INFORMATION;

typedef struct _FILE_ATTRIBUTE_TAG_INFORMATION {
	ULONG FileAttributes;
	ULONG ReparseTag;
} FILE_ATTRIBUTE_TAG_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION;

typedef struct _FILE_MODE_INFORMATION {
	ULONG Mode;
} FILE_MODE_INFORMATION;

typedef struct _FILE_ACCESS_INFORMATION {
	ACCESS_MASK AccessFlags;
} FILE_ACCESS_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION {
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
	ULONG NextEntryOffset;
	ULONG FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG FileAttributes;
	ULONG FileNameLength;
	ULONG EaSize;
	char ShortNameLength;
	WCHAR ShortName[12];
	LARGE_INTEGER FileId;
	WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_FS_DEVICE_INFORMATION {
	ULONG DeviceType;
	ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION;

typedef struct _FILE_FS_VOLUME_INFORMATION {
	LARGE_INTEGER VolumeCreationTime;
	ULONG VolumeSerialNumber;
	ULONG VolumeLabelLength;
	BOOLEAN SupportsObjects;
	WCHAR VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION;

typedef struct _FILE_FS_SIZE_INFORMATION {
	LARGE_INTEGER TotalAllocationUnits;
	LARGE_INTEGER AvailableAllocationUnits;
	ULONG SectorsPerAllocationUnit;
	ULONG BytesPerSector;
} FILE_FS_SIZE_INFORMATION;

/* FileFsFullSizeInformation.  The distinction from FILE_FS_SIZE_INFORMATION
 * above is quota: CallerAvailableAllocationUnits is what *this* caller may
 * still allocate (quota applied), ActualAvailableAllocationUnits is what
 * is free on the volume regardless of quota.  That is exactly POSIX's
 * f_bavail/f_bfree split, which is why statvfs prefers this class. */
typedef struct _FILE_FS_FULL_SIZE_INFORMATION {
	LARGE_INTEGER TotalAllocationUnits;
	LARGE_INTEGER CallerAvailableAllocationUnits;
	LARGE_INTEGER ActualAvailableAllocationUnits;
	ULONG SectorsPerAllocationUnit;
	ULONG BytesPerSector;
} FILE_FS_FULL_SIZE_INFORMATION;

/* FileFsAttributeInformation.  FileSystemName is variable-length, so a
 * caller wanting it must over-allocate; src/stat/statvfs.c wants only
 * FileSystemAttributes and MaximumComponentNameLength, both fixed. */
typedef struct _FILE_FS_ATTRIBUTE_INFORMATION {
	ULONG FileSystemAttributes;
	LONG MaximumComponentNameLength;
	ULONG FileSystemNameLength;
	WCHAR FileSystemName[1];
} FILE_FS_ATTRIBUTE_INFORMATION;

typedef struct _FILE_PIPE_LOCAL_INFORMATION {
	ULONG NamedPipeType;
	ULONG NamedPipeConfiguration;
	ULONG MaximumInstances;
	ULONG CurrentInstances;
	ULONG InboundQuota;
	ULONG ReadDataAvailable;
	ULONG OutboundQuota;
	ULONG WriteQuotaAvailable;
	ULONG NamedPipeState;
	ULONG NamedPipeEnd;
} FILE_PIPE_LOCAL_INFORMATION;

#define FILE_PIPE_CONNECTED_STATE 3

typedef struct _REPARSE_DATA_BUFFER {
	ULONG ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG Flags;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR DataBuffer[1];
		} GenericReparseBuffer;
	};
} REPARSE_DATA_BUFFER;

#define IO_REPARSE_TAG_MOUNT_POINT  0xA0000003L
#define IO_REPARSE_TAG_SYMLINK      0xA000000CL
#define IO_REPARSE_TAG_LX_SYMLINK   0xA000001DL
#define SYMLINK_FLAG_RELATIVE       1
#define FSCTL_GET_REPARSE_POINT     0x000900A8
#define FSCTL_SET_REPARSE_POINT     0x000900A4
#define FSCTL_PIPE_PEEK             0x0011400C
/* FSCTL_PIPE_LISTEN: CTL_CODE(FILE_DEVICE_NAMED_PIPE=0x11, function=2,
 * METHOD_BUFFERED, FILE_ANY_ACCESS) -- confirmed against Wine's
 * include/winioctl.h (FSCTL_PIPE_PEEK above, function=3 with
 * FILE_READ_DATA access, computes to the same 0x0011400C already in
 * this file, so the derivation is the same one used for the constant
 * that was already trusted here). What it does, and why
 * src/signal/sigdelivery.c's server loop cannot skip it: a freshly
 * created (or freshly reconnected) named pipe server instance starts in
 * NPFS's "listening" state, not "connected" -- an NtReadFile against it
 * in that state fails immediately with STATUS_PIPE_LISTENING rather
 * than blocking (ReactOS's drivers/filesystems/npfs/read.c, which
 * checks NamedPipeState before ever queuing a read). FSCTL_PIPE_LISTEN
 * is the operation that blocks until a client actually connects and
 * moves the instance to "connected"; it is what kernel32's
 * ConnectNamedPipe wraps for the exact same reason. */
#define FSCTL_PIPE_LISTEN           0x00110008
#define MAXIMUM_REPARSE_DATA_BUFFER_SIZE 16384

typedef struct _FILE_PIPE_PEEK_BUFFER {
	ULONG NamedPipeState;
	ULONG ReadDataAvailable;
	ULONG NumberOfMessages;
	ULONG MessageLength;
	char Data[1];
} FILE_PIPE_PEEK_BUFFER;

/* ---- processes ------------------------------------------------------- */
typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessQuotaLimits = 1,
	ProcessIoCounters = 2,
	ProcessVmCounters = 3,
	ProcessTimes = 4,
	ProcessBasePriority = 5,
	ProcessRaisePriority = 6,
	ProcessDebugPort = 7,
	ProcessExceptionPort = 8,
	ProcessAccessToken = 9,
	ProcessLdtInformation = 10,
	ProcessLdtSize = 11,
	ProcessDefaultHardErrorMode = 12,
	ProcessIoPortHandlers = 13,
	ProcessPooledUsageAndLimits = 14,
	ProcessWorkingSetWatch = 15,
	ProcessUserModeIOPL = 16,
	ProcessEnableAlignmentFaultFixup = 17,
	ProcessPriorityClass = 18,
	ProcessWx86Information = 19,
	ProcessHandleCount = 20,
	ProcessAffinityMask = 21,
	ProcessPriorityBoost = 22,
	ProcessDeviceMap = 23,
	ProcessSessionInformation = 24,
	ProcessForegroundInformation = 25,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessLUIDDeviceMapsEnabled = 28,
	ProcessBreakOnTermination = 29,
	ProcessDebugObjectHandle = 30,
	ProcessDebugFlags = 31,
	ProcessHandleTracing = 32,
	ProcessIoPriority = 33,
	ProcessExecuteFlags = 34,
	ProcessImageFileNameWin32 = 43,
	ProcessCookie = 36,
	ProcessImageInformation = 37
} PROCESSINFOCLASS;

typedef struct _PROCESS_PRIORITY_CLASS {
	UCHAR Foreground;
	UCHAR PriorityClass;
} PROCESS_PRIORITY_CLASS;

#define PROCESS_PRIOCLASS_IDLE          1
#define PROCESS_PRIOCLASS_NORMAL        2
#define PROCESS_PRIOCLASS_HIGH          3
#define PROCESS_PRIOCLASS_REALTIME      4
#define PROCESS_PRIOCLASS_BELOW_NORMAL  5
#define PROCESS_PRIOCLASS_ABOVE_NORMAL  6

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _KERNEL_USER_TIMES {
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER ExitTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES;

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID TransferAddress;
	ULONG ZeroBits;
	SIZE_T MaximumStackSize;
	SIZE_T CommittedStackSize;
	ULONG SubSystemType;
	union {
		struct {
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	union {
		struct {
			USHORT MajorOperatingSystemVersion;
			USHORT MinorOperatingSystemVersion;
		};
		ULONG OperatingSystemVersion;
	};
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	BOOLEAN ImageContainsCode;
	union {
		UCHAR ImageFlags;
		struct {
			UCHAR ComPlusNativeReady : 1;
			UCHAR ComPlusILOnly : 1;
			UCHAR ImageDynamicallyRelocated : 1;
			UCHAR ImageMappedFlat : 1;
			UCHAR BaseBelow4gb : 1;
			UCHAR ComPlusPrefer32bit : 1;
			UCHAR Reserved : 2;
		};
	};
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
} SECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG Length;
	HANDLE Process;
	HANDLE Thread;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION;

#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED  0x00000001
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES   0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE    0x00000004

#define PROCESS_TERMINATE           0x0001
#define PROCESS_CREATE_THREAD       0x0002
#define PROCESS_VM_OPERATION        0x0008
#define PROCESS_VM_READ             0x0010
#define PROCESS_VM_WRITE            0x0020
#define PROCESS_DUP_HANDLE          0x0040
#define PROCESS_QUERY_INFORMATION   0x0400
#define PROCESS_SUSPEND_RESUME      0x0800
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define PROCESS_ALL_ACCESS          (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0xFFFF)

/* ---- job objects (src/misc/resource.c: setrlimit()'s NT analogue for
 * RLIMIT_NPROC/RLIMIT_CPU/RLIMIT_AS/RLIMIT_DATA; src/process/wait.c's
 * recursive-descendant CPU-time rollup for times()/wait3()/wait4(), see
 * JOBOBJECT_BASIC_ACCOUNTING_INFORMATION below) ----------------------------
 * Field/flag layout and JOBOBJECTINFOCLASS ordinals per winnt.h; this
 * library only ever uses JobObjectBasicAccountingInformation,
 * JobObjectBasicLimitInformation and JobObjectExtendedLimitInformation,
 * so nothing past those three is declared here. */
#define JOB_OBJECT_ASSIGN_PROCESS   0x0001
#define JOB_OBJECT_SET_ATTRIBUTES   0x0002
#define JOB_OBJECT_QUERY            0x0004
#define JOB_OBJECT_TERMINATE        0x0008
#define JOB_OBJECT_ALL_ACCESS       (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3f)

typedef enum _JOBOBJECTINFOCLASS {
	JobObjectBasicAccountingInformation = 1,
	JobObjectBasicLimitInformation = 2,
	JobObjectExtendedLimitInformation = 9
} JOBOBJECTINFOCLASS;

typedef struct _IO_COUNTERS {
	ULONGLONG ReadOperationCount;
	ULONGLONG WriteOperationCount;
	ULONGLONG OtherOperationCount;
	ULONGLONG ReadTransferCount;
	ULONGLONG WriteTransferCount;
	ULONGLONG OtherTransferCount;
} IO_COUNTERS;

typedef struct _JOBOBJECT_BASIC_LIMIT_INFORMATION {
	LARGE_INTEGER PerProcessUserTimeLimit;
	LARGE_INTEGER PerJobUserTimeLimit;
	ULONG LimitFlags;
	SIZE_T MinimumWorkingSetSize;
	SIZE_T MaximumWorkingSetSize;
	ULONG ActiveProcessLimit;
	ULONG_PTR Affinity;
	ULONG PriorityClass;
	ULONG SchedulingClass;
} JOBOBJECT_BASIC_LIMIT_INFORMATION;

typedef struct _JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
	JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
	IO_COUNTERS IoInfo;
	SIZE_T ProcessMemoryLimit;
	SIZE_T JobMemoryLimit;
	SIZE_T PeakProcessMemoryUsed;
	SIZE_T PeakJobMemoryUsed;
} JOBOBJECT_EXTENDED_LIMIT_INFORMATION;

/* JobObjectBasicAccountingInformation (class 1): the kernel's own
 * running total of CPU time for every process ever assigned to a job,
 * including ones that have since terminated -- it survives past the
 * member process's own death for as long as this process keeps the job
 * handle open. src/process/wait.c's fill_child_rusage() reads
 * TotalUserTime/TotalKernelTime here instead of a bare
 * NtQueryInformationProcess(ProcessTimes) precisely because a spawned
 * child's own descendants (this process's grandchildren) automatically
 * become members of the same job their creator belongs to -- ordinary,
 * non-nested job membership inheritance, not a new mechanism -- so this
 * one query already folds in CPU time this library's own per-process
 * children_ktime100ns/children_utime100ns accumulator (src/process/
 * wait.c) has no way to read out of another process's address space.
 * No pointer-sized members, so this is 48 bytes on every arch. */
typedef struct _JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
	LARGE_INTEGER TotalUserTime;
	LARGE_INTEGER TotalKernelTime;
	LARGE_INTEGER ThisPeriodTotalUserTime;
	LARGE_INTEGER ThisPeriodTotalKernelTime;
	ULONG TotalPageFaultCount;
	ULONG TotalProcesses;
	ULONG ActiveProcesses;
	ULONG TotalTerminatedProcesses;
} JOBOBJECT_BASIC_ACCOUNTING_INFORMATION;

#define JOB_OBJECT_LIMIT_PROCESS_TIME    0x00000002
#define JOB_OBJECT_LIMIT_ACTIVE_PROCESS  0x00000008
#define JOB_OBJECT_LIMIT_PROCESS_MEMORY  0x00000100

#define DUPLICATE_CLOSE_SOURCE      0x00000001
#define DUPLICATE_SAME_ACCESS       0x00000002
#define DUPLICATE_SAME_ATTRIBUTES   0x00000004

#define MEM_COMMIT                  0x00001000
#define MEM_RESERVE                 0x00002000
#define MEM_DECOMMIT                0x00004000
#define MEM_RELEASE                 0x00008000
#define MEM_FREE                    0x00010000
#define MEM_TOP_DOWN                0x00100000
#define PAGE_NOACCESS               0x01
#define PAGE_READONLY               0x02
#define PAGE_READWRITE              0x04
#define PAGE_EXECUTE                0x10
#define PAGE_EXECUTE_READ           0x20
#define PAGE_EXECUTE_READWRITE      0x40
#define PAGE_WRITECOPY              0x08
#define PAGE_EXECUTE_WRITECOPY      0x80

/* Section objects (src/mman/mman.c's file-backed mmap()).  SEC_COMMIT is
 * the only allocation attribute used: it means the whole section is
 * backed by the file and committed up front, as opposed to SEC_RESERVE
 * (demand-commit, only meaningful for a pagefile-backed section) or
 * SEC_IMAGE (PE loading, src/process/exec.c's territory, a different
 * NtCreateSection call entirely). SECTION_MAP_* are the DesiredAccess
 * bits NtCreateSection/NtMapViewOfSection actually check; ALL_ACCESS is
 * broad on purpose because the section handle is closed immediately
 * after the view is mapped (the view keeps its own reference), so there
 * is no lingering handle whose rights matter later. */
#define SEC_COMMIT                   0x08000000
#define SECTION_QUERY                0x0001
#define SECTION_MAP_WRITE            0x0002
#define SECTION_MAP_READ             0x0004
#define SECTION_MAP_EXECUTE          0x0008
#define SECTION_EXTEND_SIZE          0x0010
#define SECTION_ALL_ACCESS           (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE| \
                                       SECTION_QUERY|SECTION_MAP_WRITE| \
                                       SECTION_MAP_READ|SECTION_MAP_EXECUTE| \
                                       SECTION_EXTEND_SIZE)
typedef enum _SECTION_INHERIT { ViewShare = 1, ViewUnmap = 2 } SECTION_INHERIT;

/* NtQueryVirtualMemory()'s MemoryBasicInformation class (used by
 * src/signal/signal.c to tell SEGV_MAPERR from SEGV_ACCERR after an
 * access violation: State == MEM_FREE/MEM_RESERVE means nothing was
 * ever mapped there, State == MEM_COMMIT means a real page exists and
 * Protect is what actually denied the access). Field layout matches
 * winnt.h's MEMORY_BASIC_INFORMATION exactly (verified against
 * mingw-w64 and Wine's copies) -- BaseAddress/AllocationBase are
 * pointer-sized and RegionSize is SIZE_T, so this struct is naturally
 * 28 bytes on a 32-bit build and 48 bytes on a 64-bit one (4 bytes of
 * compiler-inserted padding before RegionSize, to keep it 8-byte
 * aligned) without needing an explicit padding member either way --
 * the same convention every other PVOID/SIZE_T-mixing struct in this
 * file already relies on (e.g. JOBOBJECT_BASIC_LIMIT_INFORMATION
 * above). */
typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation = 0
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_BASIC_INFORMATION {
	PVOID BaseAddress;
	PVOID AllocationBase;
	ULONG AllocationProtect;
	SIZE_T RegionSize;
	ULONG State;
	ULONG Protect;
	ULONG Type;
} MEMORY_BASIC_INFORMATION;

#define HEAP_NO_SERIALIZE           0x00000001
#define HEAP_GROWABLE               0x00000002
#define HEAP_GENERATE_EXCEPTIONS    0x00000004
#define HEAP_ZERO_MEMORY            0x00000008
#define HEAP_REALLOC_IN_PLACE_ONLY  0x00000010

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION {
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	ULONG_PTR ActiveProcessorsAffinityMask;
	char NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
	LARGE_INTEGER BootTime;
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER TimeZoneBias;
	ULONG TimeZoneId;
	ULONG Reserved;
	ULONGLONG BootTimeBias;
	ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION;

typedef struct _TIME_FIELDS {
	short Year;
	short Month;
	short Day;
	short Hour;
	short Minute;
	short Second;
	short Milliseconds;
	short Weekday;
} TIME_FIELDS;

typedef struct _RTL_TIME_ZONE_INFORMATION {
	LONG Bias;
	WCHAR StandardName[32];
	TIME_FIELDS StandardDate;
	LONG StandardBias;
	WCHAR DaylightName[32];
	TIME_FIELDS DaylightDate;
	LONG DaylightBias;
} RTL_TIME_ZONE_INFORMATION;

typedef struct _RTL_OSVERSIONINFOW {
	ULONG dwOSVersionInfoSize;
	ULONG dwMajorVersion;
	ULONG dwMinorVersion;
	ULONG dwBuildNumber;
	ULONG dwPlatformId;
	WCHAR szCSDVersion[128];
} RTL_OSVERSIONINFOW;

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation = 0,
	ThreadTimes = 1,
	ThreadPriority = 2,
	ThreadBasePriority = 3,
	ThreadAffinityMask = 4,
	ThreadImpersonationToken = 5,
	ThreadDescriptorTableEntry = 6,
	ThreadEnableAlignmentFaultFixup = 7,
	ThreadEventPair = 8,
	ThreadQuerySetWin32StartAddress = 9,
	ThreadZeroTlsCell = 10,
	ThreadPerformanceCount = 11,
	ThreadAmILastThread = 12,
	ThreadIdealProcessor = 13,
	ThreadPriorityBoost = 14,
	ThreadSetTlsArrayAddress = 15,
	ThreadIsIoPending = 16,
	ThreadHideFromDebugger = 17
} THREADINFOCLASS;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION;

/* Exceptions */
typedef struct _EXCEPTION_RECORD {
	ULONG ExceptionCode;
	ULONG ExceptionFlags;
	struct _EXCEPTION_RECORD *ExceptionRecord;
	PVOID ExceptionAddress;
	ULONG NumberParameters;
	ULONG_PTR ExceptionInformation[15];
} EXCEPTION_RECORD;

typedef struct _EXCEPTION_POINTERS {
	EXCEPTION_RECORD *ExceptionRecord;
	PVOID ContextRecord;
} EXCEPTION_POINTERS;

typedef LONG (NTAPI *PVECTORED_EXCEPTION_HANDLER)(EXCEPTION_POINTERS *);
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#define EXCEPTION_CONTINUE_SEARCH 0
#define EXCEPTION_EXECUTE_HANDLER 1

#define EXCEPTION_ACCESS_VIOLATION          0xC0000005
#define EXCEPTION_ILLEGAL_INSTRUCTION       0xC000001D
#define EXCEPTION_INT_DIVIDE_BY_ZERO        0xC0000094
#define EXCEPTION_INT_OVERFLOW              0xC0000095
#define EXCEPTION_FLT_DIVIDE_BY_ZERO        0xC000008E
#define EXCEPTION_FLT_INVALID_OPERATION     0xC0000090
#define EXCEPTION_FLT_OVERFLOW              0xC0000091
#define EXCEPTION_STACK_OVERFLOW            0xC00000FD
#define EXCEPTION_BREAKPOINT                0x80000003
#define EXCEPTION_PRIV_INSTRUCTION          0xC0000096
#define EXCEPTION_IN_PAGE_ERROR             0xC0000006
#define EXCEPTION_DATATYPE_MISALIGNMENT     0x80000002
/* Values per winnt.h's STATUS_FLOAT_* (verified against mingw-w64 and
 * Wine's copies); EXCEPTION_FLT_DIVIDE_BY_ZERO/INVALID_OPERATION/
 * OVERFLOW above are the same family, just already present. */
#define EXCEPTION_FLT_DENORMAL_OPERAND      0xC000008D
#define EXCEPTION_FLT_INEXACT_RESULT        0xC000008F
#define EXCEPTION_FLT_UNDERFLOW             0xC0000093

/* The #BR fault: a BOUND instruction whose index was outside the bounds
 * pair it was checked against (winnt.h's STATUS_ARRAY_BOUNDS_EXCEEDED,
 * numerically just below the float family above). Reachable only on
 * i386 -- BOUND is not an instruction in long mode -- but the status is
 * defined for both, since exception_handler() dispatches on the code
 * rather than on the architecture. */
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED     0xC000008C

/* Not an access violation (0xC0000005): raised on touching a page an
 * explicit PAGE_GUARD protection was set on (winnt.h's
 * STATUS_GUARD_PAGE_VIOLATION), most commonly by something outside
 * spicule probing a thread stack's guard region -- this library never
 * sets PAGE_GUARD itself, there is no PAGE_GUARD bit among the PAGE_*
 * constants above. src/signal/signal.c's exception_handler() names
 * this explicitly so it is provably not folded into the
 * EXCEPTION_ACCESS_VIOLATION case despite the similar shape. */
#define STATUS_GUARD_PAGE_VIOLATION         0x80000001
#define DBG_CONTROL_C                       0x40010005
#define DBG_CONTROL_BREAK                   0x40010008

typedef void (NTAPI *PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, ULONG);

/* NtQueryEaFile/NtSetEaFile wire records.  EaNameLength excludes the
 * terminating NUL; EaValueLength does not.  The value starts immediately
 * after EaName[EaNameLength + 1], and non-final records are ULONG-aligned. */
typedef struct __nt_file_full_ea_information {
	ULONG NextEntryOffset;
	UCHAR Flags;
	UCHAR EaNameLength;
	USHORT EaValueLength;
	char EaName[1];
} __NT_FILE_FULL_EA_INFORMATION;

typedef struct __nt_file_get_ea_information {
	ULONG NextEntryOffset;
	UCHAR EaNameLength;
	char EaName[1];
} __NT_FILE_GET_EA_INFORMATION;

/* ---- registry (src/misc/uname.c's node-name lookup) ------------------
 * KEY_QUERY_VALUE: the one access right this tree ever asks a registry
 * key for -- ntdll's own winnt.h numbering, not invented here.
 * KeyValuePartialInformation: the NtQueryValueKey information class
 * whose payload is "the value's raw data, with a leading TitleIndex/
 * Type/DataLength header" -- the shape every caller wants when it
 * already knows the value's type (REG_SZ here) and just wants the
 * bytes. Both are genuine ntdll exports, not stubs: real Windows and
 * Wine both depend on registry access working for essentially
 * everything, unlike the adjacent NtLockRegistryKey this file's own
 * NtCreateSection comment already flags as a Wine stub -- see this
 * project's own WHOEVER-IMPLEMENTS-THIS note in test/posix-sysinfo.c's
 * uname() fence for the one thing that note could not verify from this
 * tree alone (confirm on the actual Wine/Windows leg, not by more
 * reading here). */
#define KEY_QUERY_VALUE 0x0001

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataLength;
	UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

/* ---- prototypes ------------------------------------------------------ */
NTSTATUS NTAPI NtClose(HANDLE);
NTSTATUS NTAPI NtOpenKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NtQueryValueKey(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, LARGE_INTEGER *, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
NTSTATUS NTAPI NtReadFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, LARGE_INTEGER *, PULONG);
NTSTATUS NTAPI NtWriteFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, const void *, ULONG, LARGE_INTEGER *, PULONG);
NTSTATUS NTAPI NtQueryInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
NTSTATUS NTAPI NtSetInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
NTSTATUS NTAPI NtQueryEaFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, BOOLEAN, PVOID, ULONG, PULONG, BOOLEAN);
NTSTATUS NTAPI NtSetEaFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG);
NTSTATUS NTAPI NtQueryVolumeInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FS_INFORMATION_CLASS);
NTSTATUS NTAPI NtQueryObject(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);
NTSTATUS NTAPI NtQueryFullAttributesFile(POBJECT_ATTRIBUTES, FILE_NETWORK_OPEN_INFORMATION *);
NTSTATUS NTAPI NtQueryAttributesFile(POBJECT_ATTRIBUTES, FILE_BASIC_INFORMATION *);
NTSTATUS NTAPI NtDeleteFile(POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NtFlushBuffersFile(HANDLE, PIO_STATUS_BLOCK);
NTSTATUS NTAPI NtFlushVirtualMemory(HANDLE, const void **, SIZE_T *, PIO_STATUS_BLOCK);
NTSTATUS NTAPI NtFsControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtCreateNamedPipeFile(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, LARGE_INTEGER *);
NTSTATUS NTAPI NtLockFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, LARGE_INTEGER *, LARGE_INTEGER *, PULONG, BOOLEAN, BOOLEAN);
NTSTATUS NTAPI NtUnlockFile(HANDLE, PIO_STATUS_BLOCK, LARGE_INTEGER *, LARGE_INTEGER *, PULONG);
NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
NTSTATUS NTAPI NtTerminateThread(HANDLE, NTSTATUS);
NTSTATUS NTAPI NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
NTSTATUS NTAPI NtOpenProcessToken(HANDLE, ACCESS_MASK, PHANDLE);
NTSTATUS NTAPI NtQueryInformationToken(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtOpenSymbolicLinkObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NtQuerySymbolicLinkObject(HANDLE, PUNICODE_STRING, PULONG);
NTSTATUS NTAPI NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtSetInformationProcess(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
NTSTATUS NTAPI NtQueryInformationThread(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtWaitForSingleObject(HANDLE, BOOLEAN, LARGE_INTEGER *);
NTSTATUS NTAPI NtWaitForMultipleObjects(ULONG, HANDLE *, ULONG, BOOLEAN, LARGE_INTEGER *);
NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
NTSTATUS NTAPI NtSuspendThread(HANDLE, PULONG);
typedef void (NTAPI *PKNORMAL_ROUTINE)(PVOID, PVOID, PVOID);
NTSTATUS NTAPI NtQueueApcThread(HANDLE, PKNORMAL_ROUTINE, PVOID, PVOID, PVOID);

/* Whole-process suspend and resume, the primitive kill(pid, SIGSTOP)
 * and kill(pid, SIGCONT) are built on (src/signal/signal.c).  Each
 * keeps a per-process count and applies it to every thread the target
 * has, including ones it creates while suspended -- which is what makes
 * them usable as job control, where walking the target's thread list
 * with NtSuspendThread would race a child that spawns a thread mid-stop
 * and leave it running.  Undocumented by Microsoft but exported by
 * ntdll on every NT since XP, and implemented by Wine as a real syscall
 * (dlls/ntdll/ntdll.spec, dlls/ntdll/unix/process.c).  Both want
 * PROCESS_SUSPEND_RESUME on the handle. */
NTSTATUS NTAPI NtSuspendProcess(HANDLE);
NTSTATUS NTAPI NtResumeProcess(HANDLE);
NTSTATUS NTAPI NtGetContextThread(HANDLE, PVOID);
NTSTATUS NTAPI NtSetContextThread(HANDLE, PVOID);
NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, SIZE_T *);
NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, const void *, SIZE_T, SIZE_T *);
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, SIZE_T *, ULONG, ULONG);
NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);
NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG, PULONG);
/* File-backed mmap() (src/mman/mman.c).  Real, ordinary ntdll exports on
 * both NT and Wine -- unlike the SEC_IMAGE call src/process/exec.c uses
 * for PE loading, this is the everyday data-mapping path every mapped
 * file goes through. MaximumSize is passed NULL to mean "the file's
 * current size", which is why mmap() never has to query it itself. */
NTSTATUS NTAPI NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LARGE_INTEGER *, ULONG, ULONG, HANDLE);
NTSTATUS NTAPI NtMapViewOfSection(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, LARGE_INTEGER *, SIZE_T *, SECTION_INHERIT, ULONG, ULONG);
NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
/* Real, non-stub exports, and implemented in Wine as well as on NT:
 * dlls/ntdll/ntdll.spec:272 is a genuine `stdcall -syscall` thunk (the
 * adjacent NtLockProductActivationKeys/NtLockRegistryKey are commented-out
 * `# @ stub`, which is the contrast), and dlls/ntdll/unix/virtual.c:6254
 * calls the host's mlock(2) for NtCurrentProcess() rather than returning
 * STATUS_NOT_IMPLEMENTED.  Both measured at wine 855d92781.
 *
 * Neither takes a structure, so the layout-assertion block below needs
 * nothing new for them -- worth saying, because "adds prototypes but no
 * assertions" otherwise reads as an oversight rather than a fact about
 * these two signatures.  Used by mlock()/munlock() (src/mman/mman.c). */
NTSTATUS NTAPI NtLockVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);
NTSTATUS NTAPI NtUnlockVirtualMemory(HANDLE, PVOID *, SIZE_T *, ULONG);
NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, SIZE_T *);
NTSTATUS NTAPI NtQuerySystemTime(LARGE_INTEGER *);
NTSTATUS NTAPI NtSetSystemTime(LARGE_INTEGER *, LARGE_INTEGER *);
NTSTATUS NTAPI NtQueryPerformanceCounter(LARGE_INTEGER *, LARGE_INTEGER *);
NTSTATUS NTAPI NtDelayExecution(BOOLEAN, LARGE_INTEGER *);
NTSTATUS NTAPI NtYieldExecution(void);
NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
/* A NotificationEvent stays signalled once set, until something
 * explicitly resets it; a SynchronizationEvent auto-resets the instant
 * one waiter is released by it -- the same NotificationTimer/
 * SynchronizationTimer distinction TIMER_TYPE below makes, and for the
 * same reason: src/signal/sigdelivery.c wants auto-reset for both its
 * mutex-over-an-event (each acquirer's wait must consume the "free"
 * signal so the next acquirer blocks) and its "a packet arrived" wakeup
 * for select() (one wakeup must not persist past the pass that consumes
 * it). */
typedef enum _EVENT_TYPE {
	NotificationEvent,
	SynchronizationEvent
} EVENT_TYPE;
#define EVENT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)
NTSTATUS NTAPI NtCreateEvent(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, BOOLEAN);
NTSTATUS NTAPI NtSetEvent(HANDLE, LONG *);

#define MUTANT_QUERY_STATE 0x0001
#define MUTANT_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|MUTANT_QUERY_STATE)
NTSTATUS NTAPI NtCreateMutant(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN);
NTSTATUS NTAPI NtReleaseMutant(HANDLE, LONG *);

typedef enum _SEMAPHORE_INFORMATION_CLASS {
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS;
typedef struct _SEMAPHORE_BASIC_INFORMATION {
	LONG CurrentCount;
	LONG MaximumCount;
} SEMAPHORE_BASIC_INFORMATION;
#define SEMAPHORE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)
NTSTATUS NTAPI NtCreateSemaphore(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LONG, LONG);
NTSTATUS NTAPI NtOpenSemaphore(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NtQuerySemaphore(HANDLE, SEMAPHORE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtReleaseSemaphore(HANDLE, LONG, LONG *);

/* THREAD_ALL_ACCESS: same STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0xFFFF
 * shape as PROCESS_ALL_ACCESS above -- the classic (pre-Vista-widened)
 * value, which is all src/signal/sigdelivery.c needs for a handle it
 * only ever hands to NtClose(). */
#define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0xFFFF)
/* NtCreateThreadEx: introduced NTDLL 6.0 (Vista) --
 * https://www.geoffchappell.com/studies/windows/win32/ntdll/history/names60.htm
 * -- below this library's Windows-7 floor (tools/ntdll.def), so adding
 * it does not raise that floor. The AttributeList parameter (a
 * PS_ATTRIBUTE_LIST*) is declared PVOID here rather than defining that
 * struct: src/signal/sigdelivery.c, the only caller, always passes NULL
 * for it, which the API treats as "no extended attributes". */
NTSTATUS NTAPI NtCreateThreadEx(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
                                 PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

/* Waitable timers.  A NotificationTimer stays signalled once it expires
 * (a SynchronizationTimer auto-resets on the first waiter); alarm()
 * wants the one-shot, so it uses the former.  The APC handed to
 * NtSetTimer is queued to the thread that called it and runs only when
 * that thread enters an alertable wait -- see src/unistd/sleep.c. */
typedef enum _TIMER_TYPE {
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE;
typedef void (NTAPI *PTIMER_APC_ROUTINE)(PVOID, ULONG, LONG);
#define TIMER_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3)
NTSTATUS NTAPI NtCreateTimer(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, TIMER_TYPE);
NTSTATUS NTAPI NtSetTimer(HANDLE, LARGE_INTEGER *, PTIMER_APC_ROUTINE, PVOID, BOOLEAN, LONG, BOOLEAN *);
NTSTATUS NTAPI NtCancelTimer(HANDLE, BOOLEAN *);
NTSTATUS NTAPI NtRaiseHardError(NTSTATUS, ULONG, ULONG, ULONG_PTR *, ULONG, PULONG);
NTSTATUS NTAPI NtCreateJobObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NtAssignProcessToJobObject(HANDLE, HANDLE);
NTSTATUS NTAPI NtSetInformationJobObject(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG);
NTSTATUS NTAPI NtQueryInformationJobObject(HANDLE, JOBOBJECTINFOCLASS, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtWow64QueryInformationProcess64(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
NTSTATUS NTAPI NtWow64ReadVirtualMemory64(HANDLE, ULONGLONG, PVOID, ULONGLONG, ULONGLONG *);

withtok(rtl_heap_allocated)
PVOID    NTAPI RtlAllocateHeap(PVOID, ULONG, SIZE_T);
BOOLEAN  NTAPI RtlFreeHeap(PVOID, ULONG, PVOID consume(rtl_heap_allocated));
withtok(rtl_heap_allocated)
PVOID    NTAPI RtlReAllocateHeap(PVOID, ULONG, PVOID consume_if_nonnull_return(rtl_heap_allocated), SIZE_T);
SIZE_T   NTAPI RtlSizeHeap(PVOID, ULONG, PVOID);
PVOID    NTAPI RtlCreateHeap(ULONG, PVOID, SIZE_T, SIZE_T, PVOID, PVOID);
PPEB     NTAPI RtlGetCurrentPeb(void);
BOOLEAN  NTAPI RtlDosPathNameToNtPathName_U(PCWSTR, PUNICODE_STRING, PCWSTR *, PVOID);
NTSTATUS NTAPI RtlDosPathNameToNtPathName_U_WithStatus(PCWSTR, PUNICODE_STRING, PCWSTR *, PVOID);
void     NTAPI RtlFreeUnicodeString(PUNICODE_STRING);
void     NTAPI RtlInitUnicodeString(PUNICODE_STRING, PCWSTR);
ULONG    NTAPI RtlGetCurrentDirectory_U(ULONG, PWSTR);
NTSTATUS NTAPI RtlSetCurrentDirectory_U(PUNICODE_STRING);
ULONG    NTAPI RtlGetFullPathName_U(PCWSTR, ULONG, PWSTR, PWSTR *);
ULONG    NTAPI RtlDetermineDosPathNameType_U(PCWSTR);
ULONG    NTAPI RtlIsDosDeviceName_U(PCWSTR);
ULONG    NTAPI RtlNtStatusToDosError(NTSTATUS);
NTSTATUS NTAPI RtlUTF8ToUnicodeN(PWSTR, ULONG, PULONG, const char *, ULONG);
NTSTATUS NTAPI RtlUnicodeToUTF8N(char *, ULONG, PULONG, PCWSTR, ULONG);
NTSTATUS NTAPI RtlCreateProcessParameters(PRTL_USER_PROCESS_PARAMETERS *, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING);
NTSTATUS NTAPI RtlCreateProcessParametersEx(PRTL_USER_PROCESS_PARAMETERS *, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PVOID, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, PUNICODE_STRING, ULONG);
NTSTATUS NTAPI RtlDestroyProcessParameters(PRTL_USER_PROCESS_PARAMETERS);
NTSTATUS NTAPI RtlCreateUserProcess(PUNICODE_STRING, ULONG, PRTL_USER_PROCESS_PARAMETERS, PVOID, PVOID, HANDLE, BOOLEAN, HANDLE, HANDLE, RTL_USER_PROCESS_INFORMATION *);
NTSTATUS NTAPI RtlCloneUserProcess(ULONG, PVOID, PVOID, HANDLE, RTL_USER_PROCESS_INFORMATION *);
NTSTATUS NTAPI RtlQueryTimeZoneInformation(RTL_TIME_ZONE_INFORMATION *);
void     NTAPI RtlTimeToTimeFields(LARGE_INTEGER *, TIME_FIELDS *);
BOOLEAN  NTAPI RtlTimeFieldsToTime(TIME_FIELDS *, LARGE_INTEGER *);
NTSTATUS NTAPI RtlGetVersion(RTL_OSVERSIONINFOW *);
ULONG    NTAPI RtlRandomEx(PULONG);
PVOID    NTAPI RtlAddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
ULONG    NTAPI RtlRemoveVectoredExceptionHandler(PVOID);
void     NTAPI RtlRaiseStatus(NTSTATUS);
NTSTATUS NTAPI RtlQueryEnvironmentVariable_U(PVOID, PUNICODE_STRING, PUNICODE_STRING);
NTSTATUS NTAPI RtlCreateEnvironment(BOOLEAN, PVOID *);
NTSTATUS NTAPI RtlDestroyEnvironment(PVOID);
NTSTATUS NTAPI RtlSetEnvironmentVariable(PVOID *, PUNICODE_STRING, PUNICODE_STRING);
ULONG    NTAPI RtlDosSearchPath_U(PCWSTR, PCWSTR, PCWSTR, ULONG, PWSTR, PWSTR *);
NTSTATUS NTAPI LdrGetDllHandle(PWSTR, PVOID, PUNICODE_STRING, PVOID *);
NTSTATUS NTAPI LdrGetProcedureAddress(PVOID, PSTRING, ULONG, PVOID *);
NTSTATUS NTAPI LdrLoadDll(PWSTR, PULONG, PUNICODE_STRING, PVOID *);
NTSTATUS NTAPI LdrUnloadDll(PVOID);
void     NTAPI RtlAcquirePebLock(void);
void     NTAPI RtlReleasePebLock(void);

/* ---- layout assertions ----------------------------------------------
 *
 * Every structure above is an ABI boundary: it is either passed to or
 * returned from an Nt... or Rtl... call, or its bytes go on the wire to a
 * driver.  Nothing in this header is a private spicule structure whose
 * layout is ours to choose -- the kernel picks it, and a declaration
 * that disagrees is not a compile error, it is a silent wrong-offset
 * read or a heap overflow.  That has cost real bugs: symlinkat() had a
 * one-byte heap overflow (src/unistd/link.c, fixed in a54b53a) because
 * an allocation used the on-the-wire REPARSE_DATA_BUFFER header sizes
 * while the writes went through the C struct, and AFD_CONNECT_INFO's
 * TAAddressCount offset was wrong for as long as it existed -- the tell,
 * in hindsight, being that it was the one structure in its header with
 * no layout assertion against it.
 *
 * So the section below is EXHAUSTIVE over the structures declared above,
 * in the order they are declared.  That is the point: a structure with no
 * entry here is visible by scanning for the gap, which is precisely the
 * signal that was missing when AFD_CONNECT_INFO was wrong.  Add to this
 * section when you add a structure.
 *
 * Why _Static_assert and not a negative-sized-array typedef: this tree is
 * -std=c99, where _Static_assert is formally a C11 extension, but both
 * compilers that build it accept it there without a diagnostic (tcc for
 * i386-win32 and x86_64-win32; clang for the native ASan build) and the
 * message it prints names the structure and the field.  The array idiom
 * compiles everywhere but tcc reports it as "invalid array size" and
 * nothing else, which is a worse safety net.  No -pedantic is used by any
 * gate stage.
 *
 * Why one expression serves i386, x86_64 and the native ASan build:
 * every size and offset in this header is exactly `c + m * sizeof(void*)`
 * for integer c, m -- verified mechanically across all 418 sizes and
 * offsets, with zero exceptions -- because pointer width is the only
 * thing that differs between the two target ABIs.  NT_PTR spells that
 * out, so an assertion holds on both arches without an #if, and a
 * structure that is genuinely pointer-free gets a plain constant that
 * can be read straight off phnt or the ntifs.h documentation.
 *
 * This is only sound because ULONG is now exactly 32 bits (see the
 * typedef block at the top).  It used to be `unsigned long`, which is 32
 * bits under LLP64 and 64 under the LP64 of the native ASan build, and
 * that difference alone gave 33 of the 56 structures here two different
 * layouts -- REPARSE_DATA_BUFFER's PathBuffer sat at +20 on the target
 * and +32 under ASan.  The ASan build was therefore sanitising struct
 * layouts that do not exist on any Windows, which is the opposite of what
 * an oracle is for.
 */
#define NT_PTR ((size_t)sizeof(void *))
#if defined(__linux__)
/* This whole section verifies that spicule's own local redeclarations of
 * real Windows ABI structures (PEB, UNICODE_STRING, OBJECT_ATTRIBUTES,
 * ...) match the REAL Windows PE ABI's own field layout -- see this
 * section's own banner above ("catching AFD_CONNECT_INFO-class bugs").
 * That check is meaningless noise on a non-NT platform build: nothing
 * on Linux ever constructs, receives, or interprets a Windows PEB, and
 * i386-linux-gnu was found (empirically, bringing up crt/linux/i386/
 * start.S) to disagree with this section's own `c + m*NT_PTR` formula
 * for several PEB fields -- a real, pre-existing gap in this project's
 * i386-NT layout data, entirely unrelated to anything this Linux port
 * touches, and explicitly out of this pass's own scope to chase down
 * (the task's own brief: "don't touch the NT side at all"). Disabling
 * just these two macros (not any struct/type declaration, not any NT
 * runtime code, not the i386-win32/x86_64-win32/native-ASan builds
 * this section still verifies exactly as before -- __linux__ is never
 * defined for any of those) unblocks compiling this shared header for
 * a Linux target without touching, silently or otherwise, anything
 * this section exists to catch on the platform it actually matters for. */
#define NT_LAYOUT_SIZE(T, n) _Static_assert(1, "NT layout check disabled for this platform")
#define NT_LAYOUT_OFFSET(T, F, n) _Static_assert(1, "NT layout check disabled for this platform")
#else
#define NT_LAYOUT_SIZE(T, n) \
	_Static_assert(sizeof(T) == (n), \
	               "NT layout: sizeof(" #T ") is not " #n)
#define NT_LAYOUT_OFFSET(T, F, n) \
	_Static_assert(offsetof(T, F) == (n), \
	               "NT layout: " #T "." #F " is not at +" #n)
#endif

/* UNICODE_STRING */
NT_LAYOUT_SIZE(UNICODE_STRING, 2*NT_PTR);
NT_LAYOUT_OFFSET(UNICODE_STRING, Length, 0);
NT_LAYOUT_OFFSET(UNICODE_STRING, MaximumLength, 2);
NT_LAYOUT_OFFSET(UNICODE_STRING, Buffer, NT_PTR);

/* STRING */
NT_LAYOUT_SIZE(STRING, 2*NT_PTR);
NT_LAYOUT_OFFSET(STRING, Length, 0);
NT_LAYOUT_OFFSET(STRING, MaximumLength, 2);
NT_LAYOUT_OFFSET(STRING, Buffer, NT_PTR);

/* OBJECT_ATTRIBUTES */
NT_LAYOUT_SIZE(OBJECT_ATTRIBUTES, 6*NT_PTR);
NT_LAYOUT_OFFSET(OBJECT_ATTRIBUTES, Length, 0);
NT_LAYOUT_OFFSET(OBJECT_ATTRIBUTES, RootDirectory, NT_PTR);
NT_LAYOUT_OFFSET(OBJECT_ATTRIBUTES, ObjectName, 2*NT_PTR);
NT_LAYOUT_OFFSET(OBJECT_ATTRIBUTES, Attributes, 3*NT_PTR);
NT_LAYOUT_OFFSET(OBJECT_ATTRIBUTES, SecurityDescriptor, 4*NT_PTR);
NT_LAYOUT_OFFSET(OBJECT_ATTRIBUTES, SecurityQualityOfService, 5*NT_PTR);

/* IO_STATUS_BLOCK */
NT_LAYOUT_SIZE(IO_STATUS_BLOCK, 2*NT_PTR);
NT_LAYOUT_OFFSET(IO_STATUS_BLOCK, Status, 0);
NT_LAYOUT_OFFSET(IO_STATUS_BLOCK, Pointer, 0);
NT_LAYOUT_OFFSET(IO_STATUS_BLOCK, Information, NT_PTR);

/* CLIENT_ID */
NT_LAYOUT_SIZE(CLIENT_ID, 2*NT_PTR);
NT_LAYOUT_OFFSET(CLIENT_ID, UniqueProcess, 0);
NT_LAYOUT_OFFSET(CLIENT_ID, UniqueThread, NT_PTR);

/* SID / TOKEN_USER */
NT_LAYOUT_SIZE(SID_IDENTIFIER_AUTHORITY, 6);
NT_LAYOUT_SIZE(SID, 12);
NT_LAYOUT_OFFSET(SID, Revision, 0);
NT_LAYOUT_OFFSET(SID, SubAuthorityCount, 1);
NT_LAYOUT_OFFSET(SID, IdentifierAuthority, 2);
NT_LAYOUT_OFFSET(SID, SubAuthority, 8);
NT_LAYOUT_SIZE(SID_AND_ATTRIBUTES, 2*NT_PTR);
NT_LAYOUT_OFFSET(SID_AND_ATTRIBUTES, Sid, 0);
NT_LAYOUT_OFFSET(SID_AND_ATTRIBUTES, Attributes, NT_PTR);
NT_LAYOUT_SIZE(TOKEN_USER, 2*NT_PTR);

/* LIST_ENTRY */
NT_LAYOUT_SIZE(LIST_ENTRY, 2*NT_PTR);
NT_LAYOUT_OFFSET(LIST_ENTRY, Flink, 0);
NT_LAYOUT_OFFSET(LIST_ENTRY, Blink, NT_PTR);

/* CURDIR */
NT_LAYOUT_SIZE(CURDIR, 3*NT_PTR);
NT_LAYOUT_OFFSET(CURDIR, DosPath, 0);
NT_LAYOUT_OFFSET(CURDIR, Handle, 2*NT_PTR);

/* RTL_DRIVE_LETTER_CURDIR */
NT_LAYOUT_SIZE(RTL_DRIVE_LETTER_CURDIR, 8 + 2*NT_PTR);
NT_LAYOUT_OFFSET(RTL_DRIVE_LETTER_CURDIR, Flags, 0);
NT_LAYOUT_OFFSET(RTL_DRIVE_LETTER_CURDIR, Length, 2);
NT_LAYOUT_OFFSET(RTL_DRIVE_LETTER_CURDIR, TimeStamp, 4);
NT_LAYOUT_OFFSET(RTL_DRIVE_LETTER_CURDIR, DosPath, 8);

/* RTL_USER_PROCESS_PARAMETERS */
/* sizeof deliberately NOT asserted: this declaration is a leading
 * prefix of the real NT structure and stops where spicule stops
 * reading, so its size is ours, not NT's.  Pinning it would assert
 * a number no Windows agrees with and would fight any future
 * extension of the prefix.  The offsets below are the real ABI. */
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, MaximumLength, 0);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, Length, 4);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, Flags, 8);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, DebugFlags, 12);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, ConsoleHandle, 16);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, ConsoleFlags, 16 + NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, StandardInput, 16 + 2*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, StandardOutput, 16 + 3*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, StandardError, 16 + 4*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, CurrentDirectory, 16 + 5*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, DllPath, 16 + 8*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, ImagePathName, 16 + 10*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, CommandLine, 16 + 12*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, Environment, 16 + 14*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, StartingX, 16 + 15*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, StartingY, 20 + 15*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, CountX, 24 + 15*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, CountY, 28 + 15*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, CountCharsX, 32 + 15*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, CountCharsY, 36 + 15*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, FillAttribute, 40 + 15*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, WindowFlags, 44 + 15*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, ShowWindowFlags, 48 + 15*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, WindowTitle, 48 + 16*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, DesktopInfo, 48 + 18*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, ShellInfo, 48 + 20*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, RuntimeData, 48 + 22*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, CurrentDirectories, 48 + 24*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, EnvironmentSize, 304 + 88*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, EnvironmentVersion, 304 + 89*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, PackageDependencyData, 304 + 90*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, ProcessGroupId, 304 + 91*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_PARAMETERS, LoaderThreads, 308 + 91*NT_PTR);

/* PEB_LDR_DATA */
/* sizeof deliberately NOT asserted: this declaration is a leading
 * prefix of the real NT structure and stops where spicule stops
 * reading, so its size is ours, not NT's.  Pinning it would assert
 * a number no Windows agrees with and would fight any future
 * extension of the prefix.  The offsets below are the real ABI. */
NT_LAYOUT_OFFSET(PEB_LDR_DATA, Length, 0);
NT_LAYOUT_OFFSET(PEB_LDR_DATA, Initialized, 4);
NT_LAYOUT_OFFSET(PEB_LDR_DATA, SsHandle, 8);
NT_LAYOUT_OFFSET(PEB_LDR_DATA, InLoadOrderModuleList, 8 + NT_PTR);
NT_LAYOUT_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList, 8 + 3*NT_PTR);
NT_LAYOUT_OFFSET(PEB_LDR_DATA, InInitializationOrderModuleList, 8 + 5*NT_PTR);
NT_LAYOUT_OFFSET(PEB_LDR_DATA, EntryInProgress, 8 + 7*NT_PTR);

/* LDR_DATA_TABLE_ENTRY */
/* sizeof deliberately NOT asserted: this declaration is a leading
 * prefix of the real NT structure and stops where spicule stops
 * reading, so its size is ours, not NT's.  Pinning it would assert
 * a number no Windows agrees with and would fight any future
 * extension of the prefix.  The offsets below are the real ABI. */
NT_LAYOUT_OFFSET(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks, 0);
NT_LAYOUT_OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks, 2*NT_PTR);
NT_LAYOUT_OFFSET(LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks, 4*NT_PTR);
NT_LAYOUT_OFFSET(LDR_DATA_TABLE_ENTRY, DllBase, 6*NT_PTR);
NT_LAYOUT_OFFSET(LDR_DATA_TABLE_ENTRY, EntryPoint, 7*NT_PTR);
NT_LAYOUT_OFFSET(LDR_DATA_TABLE_ENTRY, SizeOfImage, 8*NT_PTR);
NT_LAYOUT_OFFSET(LDR_DATA_TABLE_ENTRY, FullDllName, 9*NT_PTR);
NT_LAYOUT_OFFSET(LDR_DATA_TABLE_ENTRY, BaseDllName, 11*NT_PTR);

/* PEB */
/* sizeof deliberately NOT asserted: this declaration is a leading
 * prefix of the real NT structure and stops where spicule stops
 * reading, so its size is ours, not NT's.  Pinning it would assert
 * a number no Windows agrees with and would fight any future
 * extension of the prefix.  The offsets below are the real ABI. */
NT_LAYOUT_OFFSET(PEB, InheritedAddressSpace, 0);
NT_LAYOUT_OFFSET(PEB, ReadImageFileExecOptions, 1);
NT_LAYOUT_OFFSET(PEB, BeingDebugged, 2);
NT_LAYOUT_OFFSET(PEB, BitField, 3);
NT_LAYOUT_OFFSET(PEB, Mutant, NT_PTR);
NT_LAYOUT_OFFSET(PEB, ImageBaseAddress, 2*NT_PTR);
NT_LAYOUT_OFFSET(PEB, Ldr, 3*NT_PTR);
NT_LAYOUT_OFFSET(PEB, ProcessParameters, 4*NT_PTR);
NT_LAYOUT_OFFSET(PEB, SubSystemData, 5*NT_PTR);
NT_LAYOUT_OFFSET(PEB, ProcessHeap, 6*NT_PTR);
NT_LAYOUT_OFFSET(PEB, FastPebLock, 7*NT_PTR);
NT_LAYOUT_OFFSET(PEB, AtlThunkSListPtr, 8*NT_PTR);
NT_LAYOUT_OFFSET(PEB, IFEOKey, 9*NT_PTR);
NT_LAYOUT_OFFSET(PEB, CrossProcessFlags, 10*NT_PTR);
NT_LAYOUT_OFFSET(PEB, KernelCallbackTable, 11*NT_PTR);
NT_LAYOUT_OFFSET(PEB, SystemReserved, 12*NT_PTR);
NT_LAYOUT_OFFSET(PEB, AtlThunkSListPtr32, 4 + 12*NT_PTR);
NT_LAYOUT_OFFSET(PEB, ApiSetMap, 8 + 12*NT_PTR);
NT_LAYOUT_OFFSET(PEB, TlsExpansionCounter, 8 + 13*NT_PTR);
NT_LAYOUT_OFFSET(PEB, TlsBitmap, 8 + 14*NT_PTR);
NT_LAYOUT_OFFSET(PEB, TlsBitmapBits, 8 + 15*NT_PTR);
NT_LAYOUT_OFFSET(PEB, ReadOnlySharedMemoryBase, 16 + 15*NT_PTR);
NT_LAYOUT_OFFSET(PEB, SharedData, 16 + 16*NT_PTR);
NT_LAYOUT_OFFSET(PEB, ReadOnlyStaticServerData, 16 + 17*NT_PTR);
NT_LAYOUT_OFFSET(PEB, AnsiCodePageData, 16 + 18*NT_PTR);
NT_LAYOUT_OFFSET(PEB, OemCodePageData, 16 + 19*NT_PTR);
NT_LAYOUT_OFFSET(PEB, UnicodeCaseTableData, 16 + 20*NT_PTR);
NT_LAYOUT_OFFSET(PEB, NumberOfProcessors, 16 + 21*NT_PTR);
NT_LAYOUT_OFFSET(PEB, NtGlobalFlag, 20 + 21*NT_PTR);
NT_LAYOUT_OFFSET(PEB, CriticalSectionTimeout, 32 + 20*NT_PTR);
NT_LAYOUT_OFFSET(PEB, HeapSegmentReserve, 40 + 20*NT_PTR);
NT_LAYOUT_OFFSET(PEB, HeapSegmentCommit, 40 + 21*NT_PTR);
NT_LAYOUT_OFFSET(PEB, HeapDeCommitTotalFreeThreshold, 40 + 22*NT_PTR);
NT_LAYOUT_OFFSET(PEB, HeapDeCommitFreeBlockThreshold, 40 + 23*NT_PTR);
NT_LAYOUT_OFFSET(PEB, NumberOfHeaps, 40 + 24*NT_PTR);
NT_LAYOUT_OFFSET(PEB, MaximumNumberOfHeaps, 44 + 24*NT_PTR);
NT_LAYOUT_OFFSET(PEB, ProcessHeaps, 48 + 24*NT_PTR);
NT_LAYOUT_OFFSET(PEB, GdiSharedHandleTable, 48 + 25*NT_PTR);
NT_LAYOUT_OFFSET(PEB, ProcessStarterHelper, 48 + 26*NT_PTR);
NT_LAYOUT_OFFSET(PEB, GdiDCAttributeList, 48 + 27*NT_PTR);
NT_LAYOUT_OFFSET(PEB, LoaderLock, 48 + 28*NT_PTR);
NT_LAYOUT_OFFSET(PEB, OSMajorVersion, 48 + 29*NT_PTR);
NT_LAYOUT_OFFSET(PEB, OSMinorVersion, 52 + 29*NT_PTR);
NT_LAYOUT_OFFSET(PEB, OSBuildNumber, 56 + 29*NT_PTR);
NT_LAYOUT_OFFSET(PEB, OSCSDVersion, 58 + 29*NT_PTR);
NT_LAYOUT_OFFSET(PEB, OSPlatformId, 60 + 29*NT_PTR);
NT_LAYOUT_OFFSET(PEB, ImageSubsystem, 64 + 29*NT_PTR);
NT_LAYOUT_OFFSET(PEB, ImageSubsystemMajorVersion, 68 + 29*NT_PTR);
NT_LAYOUT_OFFSET(PEB, ImageSubsystemMinorVersion, 72 + 29*NT_PTR);

/* NT_TIB */
NT_LAYOUT_SIZE(NT_TIB, 7*NT_PTR);
NT_LAYOUT_OFFSET(NT_TIB, ExceptionList, 0);
NT_LAYOUT_OFFSET(NT_TIB, StackBase, NT_PTR);
NT_LAYOUT_OFFSET(NT_TIB, StackLimit, 2*NT_PTR);
NT_LAYOUT_OFFSET(NT_TIB, SubSystemTib, 3*NT_PTR);
NT_LAYOUT_OFFSET(NT_TIB, FiberData, 4*NT_PTR);
NT_LAYOUT_OFFSET(NT_TIB, ArbitraryUserPointer, 5*NT_PTR);
NT_LAYOUT_OFFSET(NT_TIB, Self, 6*NT_PTR);

/* TEB */
/* sizeof deliberately NOT asserted: this declaration is a leading
 * prefix of the real NT structure and stops where spicule stops
 * reading, so its size is ours, not NT's.  Pinning it would assert
 * a number no Windows agrees with and would fight any future
 * extension of the prefix.  The offsets below are the real ABI. */
NT_LAYOUT_OFFSET(TEB, NtTib, 0);
NT_LAYOUT_OFFSET(TEB, EnvironmentPointer, 7*NT_PTR);
NT_LAYOUT_OFFSET(TEB, ClientId, 8*NT_PTR);
NT_LAYOUT_OFFSET(TEB, ActiveRpcHandle, 10*NT_PTR);
NT_LAYOUT_OFFSET(TEB, ThreadLocalStoragePointer, 11*NT_PTR);
NT_LAYOUT_OFFSET(TEB, ProcessEnvironmentBlock, 12*NT_PTR);
NT_LAYOUT_OFFSET(TEB, LastErrorValue, 13*NT_PTR);
NT_LAYOUT_OFFSET(TEB, CountOfOwnedCriticalSections, 4 + 13*NT_PTR);
NT_LAYOUT_OFFSET(TEB, CsrClientThread, 8 + 13*NT_PTR);
NT_LAYOUT_OFFSET(TEB, Win32ThreadInfo, 8 + 14*NT_PTR);
NT_LAYOUT_OFFSET(TEB, User32Reserved, 8 + 15*NT_PTR);
NT_LAYOUT_OFFSET(TEB, UserReserved, 112 + 15*NT_PTR);
NT_LAYOUT_OFFSET(TEB, WOW32Reserved, 128 + 16*NT_PTR);
NT_LAYOUT_OFFSET(TEB, CurrentLocale, 128 + 17*NT_PTR);
NT_LAYOUT_OFFSET(TEB, FpSoftwareStatusRegister, 132 + 17*NT_PTR);

/* FILE_BASIC_INFORMATION */
NT_LAYOUT_SIZE(FILE_BASIC_INFORMATION, 40);
NT_LAYOUT_OFFSET(FILE_BASIC_INFORMATION, CreationTime, 0);
NT_LAYOUT_OFFSET(FILE_BASIC_INFORMATION, LastAccessTime, 8);
NT_LAYOUT_OFFSET(FILE_BASIC_INFORMATION, LastWriteTime, 16);
NT_LAYOUT_OFFSET(FILE_BASIC_INFORMATION, ChangeTime, 24);
NT_LAYOUT_OFFSET(FILE_BASIC_INFORMATION, FileAttributes, 32);

/* FILE_STANDARD_INFORMATION */
NT_LAYOUT_SIZE(FILE_STANDARD_INFORMATION, 24);
NT_LAYOUT_OFFSET(FILE_STANDARD_INFORMATION, AllocationSize, 0);
NT_LAYOUT_OFFSET(FILE_STANDARD_INFORMATION, EndOfFile, 8);
NT_LAYOUT_OFFSET(FILE_STANDARD_INFORMATION, NumberOfLinks, 16);
NT_LAYOUT_OFFSET(FILE_STANDARD_INFORMATION, DeletePending, 20);
NT_LAYOUT_OFFSET(FILE_STANDARD_INFORMATION, Directory, 21);

/* FILE_INTERNAL_INFORMATION */
NT_LAYOUT_SIZE(FILE_INTERNAL_INFORMATION, 8);
NT_LAYOUT_OFFSET(FILE_INTERNAL_INFORMATION, IndexNumber, 0);

/* OBJECT_NAME_INFORMATION */
NT_LAYOUT_SIZE(OBJECT_NAME_INFORMATION, 2*NT_PTR);
NT_LAYOUT_OFFSET(OBJECT_NAME_INFORMATION, Name, 0);

/* FILE_POSITION_INFORMATION */
NT_LAYOUT_SIZE(FILE_POSITION_INFORMATION, 8);
NT_LAYOUT_OFFSET(FILE_POSITION_INFORMATION, CurrentByteOffset, 0);

/* FILE_END_OF_FILE_INFORMATION */
NT_LAYOUT_SIZE(FILE_END_OF_FILE_INFORMATION, 8);
NT_LAYOUT_OFFSET(FILE_END_OF_FILE_INFORMATION, EndOfFile, 0);

/* FILE_ALLOCATION_INFORMATION */
NT_LAYOUT_SIZE(FILE_ALLOCATION_INFORMATION, 8);
NT_LAYOUT_OFFSET(FILE_ALLOCATION_INFORMATION, AllocationSize, 0);

/* FILE_DISPOSITION_INFORMATION */
NT_LAYOUT_SIZE(FILE_DISPOSITION_INFORMATION, 1);
NT_LAYOUT_OFFSET(FILE_DISPOSITION_INFORMATION, DeleteFile, 0);

/* FILE_DISPOSITION_INFORMATION_EX */
NT_LAYOUT_SIZE(FILE_DISPOSITION_INFORMATION_EX, 4);
NT_LAYOUT_OFFSET(FILE_DISPOSITION_INFORMATION_EX, Flags, 0);

/* FILE_RENAME_INFORMATION */
NT_LAYOUT_SIZE(FILE_RENAME_INFORMATION, 8 + 2*NT_PTR);
NT_LAYOUT_OFFSET(FILE_RENAME_INFORMATION, RootDirectory, NT_PTR);
NT_LAYOUT_OFFSET(FILE_RENAME_INFORMATION, FileNameLength, 2*NT_PTR);
NT_LAYOUT_OFFSET(FILE_RENAME_INFORMATION, FileName, 4 + 2*NT_PTR);

/* FILE_NAME_INFORMATION */
NT_LAYOUT_SIZE(FILE_NAME_INFORMATION, 8);
NT_LAYOUT_OFFSET(FILE_NAME_INFORMATION, FileNameLength, 0);
NT_LAYOUT_OFFSET(FILE_NAME_INFORMATION, FileName, 4);

/* FILE_ATTRIBUTE_TAG_INFORMATION */
NT_LAYOUT_SIZE(FILE_ATTRIBUTE_TAG_INFORMATION, 8);
NT_LAYOUT_OFFSET(FILE_ATTRIBUTE_TAG_INFORMATION, FileAttributes, 0);
NT_LAYOUT_OFFSET(FILE_ATTRIBUTE_TAG_INFORMATION, ReparseTag, 4);

/* FILE_NETWORK_OPEN_INFORMATION */
NT_LAYOUT_SIZE(FILE_NETWORK_OPEN_INFORMATION, 56);
NT_LAYOUT_OFFSET(FILE_NETWORK_OPEN_INFORMATION, CreationTime, 0);
NT_LAYOUT_OFFSET(FILE_NETWORK_OPEN_INFORMATION, LastAccessTime, 8);
NT_LAYOUT_OFFSET(FILE_NETWORK_OPEN_INFORMATION, LastWriteTime, 16);
NT_LAYOUT_OFFSET(FILE_NETWORK_OPEN_INFORMATION, ChangeTime, 24);
NT_LAYOUT_OFFSET(FILE_NETWORK_OPEN_INFORMATION, AllocationSize, 32);
NT_LAYOUT_OFFSET(FILE_NETWORK_OPEN_INFORMATION, EndOfFile, 40);
NT_LAYOUT_OFFSET(FILE_NETWORK_OPEN_INFORMATION, FileAttributes, 48);

/* FILE_MODE_INFORMATION */
NT_LAYOUT_SIZE(FILE_MODE_INFORMATION, 4);
NT_LAYOUT_OFFSET(FILE_MODE_INFORMATION, Mode, 0);

/* FILE_ACCESS_INFORMATION */
NT_LAYOUT_SIZE(FILE_ACCESS_INFORMATION, 4);
NT_LAYOUT_OFFSET(FILE_ACCESS_INFORMATION, AccessFlags, 0);

/* FILE_DIRECTORY_INFORMATION */
NT_LAYOUT_SIZE(FILE_DIRECTORY_INFORMATION, 72);
NT_LAYOUT_OFFSET(FILE_DIRECTORY_INFORMATION, NextEntryOffset, 0);
NT_LAYOUT_OFFSET(FILE_DIRECTORY_INFORMATION, FileIndex, 4);
NT_LAYOUT_OFFSET(FILE_DIRECTORY_INFORMATION, CreationTime, 8);
NT_LAYOUT_OFFSET(FILE_DIRECTORY_INFORMATION, LastAccessTime, 16);
NT_LAYOUT_OFFSET(FILE_DIRECTORY_INFORMATION, LastWriteTime, 24);
NT_LAYOUT_OFFSET(FILE_DIRECTORY_INFORMATION, ChangeTime, 32);
NT_LAYOUT_OFFSET(FILE_DIRECTORY_INFORMATION, EndOfFile, 40);
NT_LAYOUT_OFFSET(FILE_DIRECTORY_INFORMATION, AllocationSize, 48);
NT_LAYOUT_OFFSET(FILE_DIRECTORY_INFORMATION, FileAttributes, 56);
NT_LAYOUT_OFFSET(FILE_DIRECTORY_INFORMATION, FileNameLength, 60);
NT_LAYOUT_OFFSET(FILE_DIRECTORY_INFORMATION, FileName, 64);

/* FILE_ID_BOTH_DIR_INFORMATION */
NT_LAYOUT_SIZE(FILE_ID_BOTH_DIR_INFORMATION, 112);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, NextEntryOffset, 0);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileIndex, 4);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, CreationTime, 8);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, LastAccessTime, 16);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, LastWriteTime, 24);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, ChangeTime, 32);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, EndOfFile, 40);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, AllocationSize, 48);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileAttributes, 56);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileNameLength, 60);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, EaSize, 64);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, ShortNameLength, 68);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, ShortName, 70);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileId, 96);
NT_LAYOUT_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName, 104);

/* FILE_FS_DEVICE_INFORMATION */
NT_LAYOUT_SIZE(FILE_FS_DEVICE_INFORMATION, 8);
NT_LAYOUT_OFFSET(FILE_FS_DEVICE_INFORMATION, DeviceType, 0);
NT_LAYOUT_OFFSET(FILE_FS_DEVICE_INFORMATION, Characteristics, 4);

/* FILE_FS_VOLUME_INFORMATION */
NT_LAYOUT_SIZE(FILE_FS_VOLUME_INFORMATION, 24);
NT_LAYOUT_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeCreationTime, 0);
NT_LAYOUT_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeSerialNumber, 8);
NT_LAYOUT_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabelLength, 12);
NT_LAYOUT_OFFSET(FILE_FS_VOLUME_INFORMATION, SupportsObjects, 16);
NT_LAYOUT_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel, 18);

/* FILE_FS_SIZE_INFORMATION */
NT_LAYOUT_SIZE(FILE_FS_SIZE_INFORMATION, 24);
NT_LAYOUT_OFFSET(FILE_FS_SIZE_INFORMATION, TotalAllocationUnits, 0);
NT_LAYOUT_OFFSET(FILE_FS_SIZE_INFORMATION, AvailableAllocationUnits, 8);
NT_LAYOUT_OFFSET(FILE_FS_SIZE_INFORMATION, SectorsPerAllocationUnit, 16);
NT_LAYOUT_OFFSET(FILE_FS_SIZE_INFORMATION, BytesPerSector, 20);

/* FILE_FS_FULL_SIZE_INFORMATION */
NT_LAYOUT_SIZE(FILE_FS_FULL_SIZE_INFORMATION, 32);
NT_LAYOUT_OFFSET(FILE_FS_FULL_SIZE_INFORMATION, TotalAllocationUnits, 0);
NT_LAYOUT_OFFSET(FILE_FS_FULL_SIZE_INFORMATION, CallerAvailableAllocationUnits, 8);
NT_LAYOUT_OFFSET(FILE_FS_FULL_SIZE_INFORMATION, ActualAvailableAllocationUnits, 16);
NT_LAYOUT_OFFSET(FILE_FS_FULL_SIZE_INFORMATION, SectorsPerAllocationUnit, 24);
NT_LAYOUT_OFFSET(FILE_FS_FULL_SIZE_INFORMATION, BytesPerSector, 28);

/* FILE_FS_ATTRIBUTE_INFORMATION */
NT_LAYOUT_SIZE(FILE_FS_ATTRIBUTE_INFORMATION, 16);
NT_LAYOUT_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemAttributes, 0);
NT_LAYOUT_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, MaximumComponentNameLength, 4);
NT_LAYOUT_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemNameLength, 8);
NT_LAYOUT_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName, 12);

/* FILE_PIPE_LOCAL_INFORMATION */
NT_LAYOUT_SIZE(FILE_PIPE_LOCAL_INFORMATION, 40);
NT_LAYOUT_OFFSET(FILE_PIPE_LOCAL_INFORMATION, NamedPipeType, 0);
NT_LAYOUT_OFFSET(FILE_PIPE_LOCAL_INFORMATION, NamedPipeConfiguration, 4);
NT_LAYOUT_OFFSET(FILE_PIPE_LOCAL_INFORMATION, MaximumInstances, 8);
NT_LAYOUT_OFFSET(FILE_PIPE_LOCAL_INFORMATION, CurrentInstances, 12);
NT_LAYOUT_OFFSET(FILE_PIPE_LOCAL_INFORMATION, InboundQuota, 16);
NT_LAYOUT_OFFSET(FILE_PIPE_LOCAL_INFORMATION, ReadDataAvailable, 20);
NT_LAYOUT_OFFSET(FILE_PIPE_LOCAL_INFORMATION, OutboundQuota, 24);
NT_LAYOUT_OFFSET(FILE_PIPE_LOCAL_INFORMATION, WriteQuotaAvailable, 28);
NT_LAYOUT_OFFSET(FILE_PIPE_LOCAL_INFORMATION, NamedPipeState, 32);
NT_LAYOUT_OFFSET(FILE_PIPE_LOCAL_INFORMATION, NamedPipeEnd, 36);

/* REPARSE_DATA_BUFFER */
NT_LAYOUT_SIZE(REPARSE_DATA_BUFFER, 24);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, ReparseTag, 0);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, ReparseDataLength, 4);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, Reserved, 6);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer, 8);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.SubstituteNameOffset, 8);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.SubstituteNameLength, 10);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PrintNameOffset, 12);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PrintNameLength, 14);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.Flags, 16);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, SymbolicLinkReparseBuffer.PathBuffer, 20);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer, 8);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.SubstituteNameOffset, 8);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer, 16);
NT_LAYOUT_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer, 8);

/* FILE_PIPE_PEEK_BUFFER */
NT_LAYOUT_SIZE(FILE_PIPE_PEEK_BUFFER, 20);
NT_LAYOUT_OFFSET(FILE_PIPE_PEEK_BUFFER, NamedPipeState, 0);
NT_LAYOUT_OFFSET(FILE_PIPE_PEEK_BUFFER, ReadDataAvailable, 4);
NT_LAYOUT_OFFSET(FILE_PIPE_PEEK_BUFFER, NumberOfMessages, 8);
NT_LAYOUT_OFFSET(FILE_PIPE_PEEK_BUFFER, MessageLength, 12);
NT_LAYOUT_OFFSET(FILE_PIPE_PEEK_BUFFER, Data, 16);

/* PROCESS_PRIORITY_CLASS */
NT_LAYOUT_SIZE(PROCESS_PRIORITY_CLASS, 2);
NT_LAYOUT_OFFSET(PROCESS_PRIORITY_CLASS, Foreground, 0);
NT_LAYOUT_OFFSET(PROCESS_PRIORITY_CLASS, PriorityClass, 1);

/* PROCESS_BASIC_INFORMATION */
NT_LAYOUT_SIZE(PROCESS_BASIC_INFORMATION, 6*NT_PTR);
NT_LAYOUT_OFFSET(PROCESS_BASIC_INFORMATION, ExitStatus, 0);
NT_LAYOUT_OFFSET(PROCESS_BASIC_INFORMATION, PebBaseAddress, NT_PTR);
NT_LAYOUT_OFFSET(PROCESS_BASIC_INFORMATION, AffinityMask, 2*NT_PTR);
NT_LAYOUT_OFFSET(PROCESS_BASIC_INFORMATION, BasePriority, 3*NT_PTR);
NT_LAYOUT_OFFSET(PROCESS_BASIC_INFORMATION, UniqueProcessId, 4*NT_PTR);
NT_LAYOUT_OFFSET(PROCESS_BASIC_INFORMATION, InheritedFromUniqueProcessId, 5*NT_PTR);

/* KERNEL_USER_TIMES */
NT_LAYOUT_SIZE(KERNEL_USER_TIMES, 32);
NT_LAYOUT_OFFSET(KERNEL_USER_TIMES, CreateTime, 0);
NT_LAYOUT_OFFSET(KERNEL_USER_TIMES, ExitTime, 8);
NT_LAYOUT_OFFSET(KERNEL_USER_TIMES, KernelTime, 16);
NT_LAYOUT_OFFSET(KERNEL_USER_TIMES, UserTime, 24);

/* SECTION_IMAGE_INFORMATION */
NT_LAYOUT_SIZE(SECTION_IMAGE_INFORMATION, 32 + 4*NT_PTR);
NT_LAYOUT_OFFSET(SECTION_IMAGE_INFORMATION, TransferAddress, 0);
NT_LAYOUT_OFFSET(SECTION_IMAGE_INFORMATION, ZeroBits, NT_PTR);
NT_LAYOUT_OFFSET(SECTION_IMAGE_INFORMATION, MaximumStackSize, 2*NT_PTR);
NT_LAYOUT_OFFSET(SECTION_IMAGE_INFORMATION, CommittedStackSize, 3*NT_PTR);
NT_LAYOUT_OFFSET(SECTION_IMAGE_INFORMATION, SubSystemType, 4*NT_PTR);
NT_LAYOUT_OFFSET(SECTION_IMAGE_INFORMATION, ImageCharacteristics, 12 + 4*NT_PTR);
NT_LAYOUT_OFFSET(SECTION_IMAGE_INFORMATION, DllCharacteristics, 14 + 4*NT_PTR);
NT_LAYOUT_OFFSET(SECTION_IMAGE_INFORMATION, Machine, 16 + 4*NT_PTR);
NT_LAYOUT_OFFSET(SECTION_IMAGE_INFORMATION, ImageContainsCode, 18 + 4*NT_PTR);
NT_LAYOUT_OFFSET(SECTION_IMAGE_INFORMATION, LoaderFlags, 20 + 4*NT_PTR);
NT_LAYOUT_OFFSET(SECTION_IMAGE_INFORMATION, ImageFileSize, 24 + 4*NT_PTR);
NT_LAYOUT_OFFSET(SECTION_IMAGE_INFORMATION, CheckSum, 28 + 4*NT_PTR);

/* RTL_USER_PROCESS_INFORMATION */
NT_LAYOUT_SIZE(RTL_USER_PROCESS_INFORMATION, 32 + 9*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_INFORMATION, Length, 0);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_INFORMATION, Process, NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_INFORMATION, Thread, 2*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_INFORMATION, ClientId, 3*NT_PTR);
NT_LAYOUT_OFFSET(RTL_USER_PROCESS_INFORMATION, ImageInformation, 5*NT_PTR);

/* IO_COUNTERS */
NT_LAYOUT_SIZE(IO_COUNTERS, 48);
NT_LAYOUT_OFFSET(IO_COUNTERS, ReadOperationCount, 0);
NT_LAYOUT_OFFSET(IO_COUNTERS, WriteOperationCount, 8);
NT_LAYOUT_OFFSET(IO_COUNTERS, OtherOperationCount, 16);
NT_LAYOUT_OFFSET(IO_COUNTERS, ReadTransferCount, 24);
NT_LAYOUT_OFFSET(IO_COUNTERS, WriteTransferCount, 32);
NT_LAYOUT_OFFSET(IO_COUNTERS, OtherTransferCount, 40);

/* JOBOBJECT_BASIC_ACCOUNTING_INFORMATION -- no pointer-sized members,
 * so the size is the same 48 bytes on every arch. */
NT_LAYOUT_SIZE(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, 48);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, TotalUserTime, 0);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, TotalKernelTime, 8);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, ThisPeriodTotalUserTime, 16);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, ThisPeriodTotalKernelTime, 24);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, TotalPageFaultCount, 32);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, TotalProcesses, 36);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, ActiveProcesses, 40);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, TotalTerminatedProcesses, 44);

/* JOBOBJECT_BASIC_LIMIT_INFORMATION */
NT_LAYOUT_SIZE(JOBOBJECT_BASIC_LIMIT_INFORMATION, 32 + 4*NT_PTR);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, PerProcessUserTimeLimit, 0);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, PerJobUserTimeLimit, 8);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, LimitFlags, 16);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, MinimumWorkingSetSize, 16 + NT_PTR);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, MaximumWorkingSetSize, 16 + 2*NT_PTR);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, ActiveProcessLimit, 16 + 3*NT_PTR);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, Affinity, 16 + 4*NT_PTR);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, PriorityClass, 16 + 5*NT_PTR);
NT_LAYOUT_OFFSET(JOBOBJECT_BASIC_LIMIT_INFORMATION, SchedulingClass, 20 + 5*NT_PTR);

/* JOBOBJECT_EXTENDED_LIMIT_INFORMATION */
NT_LAYOUT_SIZE(JOBOBJECT_EXTENDED_LIMIT_INFORMATION, 80 + 8*NT_PTR);
NT_LAYOUT_OFFSET(JOBOBJECT_EXTENDED_LIMIT_INFORMATION, BasicLimitInformation, 0);
NT_LAYOUT_OFFSET(JOBOBJECT_EXTENDED_LIMIT_INFORMATION, IoInfo, 32 + 4*NT_PTR);
NT_LAYOUT_OFFSET(JOBOBJECT_EXTENDED_LIMIT_INFORMATION, ProcessMemoryLimit, 80 + 4*NT_PTR);
NT_LAYOUT_OFFSET(JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobMemoryLimit, 80 + 5*NT_PTR);
NT_LAYOUT_OFFSET(JOBOBJECT_EXTENDED_LIMIT_INFORMATION, PeakProcessMemoryUsed, 80 + 6*NT_PTR);
NT_LAYOUT_OFFSET(JOBOBJECT_EXTENDED_LIMIT_INFORMATION, PeakJobMemoryUsed, 80 + 7*NT_PTR);

/* MEMORY_BASIC_INFORMATION */
NT_LAYOUT_SIZE(MEMORY_BASIC_INFORMATION, 8 + 5*NT_PTR);
NT_LAYOUT_OFFSET(MEMORY_BASIC_INFORMATION, BaseAddress, 0);
NT_LAYOUT_OFFSET(MEMORY_BASIC_INFORMATION, AllocationBase, NT_PTR);
NT_LAYOUT_OFFSET(MEMORY_BASIC_INFORMATION, AllocationProtect, 2*NT_PTR);
NT_LAYOUT_OFFSET(MEMORY_BASIC_INFORMATION, RegionSize, 3*NT_PTR);
NT_LAYOUT_OFFSET(MEMORY_BASIC_INFORMATION, State, 4*NT_PTR);
NT_LAYOUT_OFFSET(MEMORY_BASIC_INFORMATION, Protect, 4 + 4*NT_PTR);
NT_LAYOUT_OFFSET(MEMORY_BASIC_INFORMATION, Type, 8 + 4*NT_PTR);

/* SYSTEM_BASIC_INFORMATION */
NT_LAYOUT_SIZE(SYSTEM_BASIC_INFORMATION, 24 + 5*NT_PTR);
NT_LAYOUT_OFFSET(SYSTEM_BASIC_INFORMATION, Reserved, 0);
NT_LAYOUT_OFFSET(SYSTEM_BASIC_INFORMATION, TimerResolution, 4);
NT_LAYOUT_OFFSET(SYSTEM_BASIC_INFORMATION, PageSize, 8);
NT_LAYOUT_OFFSET(SYSTEM_BASIC_INFORMATION, NumberOfPhysicalPages, 12);
NT_LAYOUT_OFFSET(SYSTEM_BASIC_INFORMATION, LowestPhysicalPageNumber, 16);
NT_LAYOUT_OFFSET(SYSTEM_BASIC_INFORMATION, HighestPhysicalPageNumber, 20);
NT_LAYOUT_OFFSET(SYSTEM_BASIC_INFORMATION, AllocationGranularity, 24);
NT_LAYOUT_OFFSET(SYSTEM_BASIC_INFORMATION, MinimumUserModeAddress, 24 + NT_PTR);
NT_LAYOUT_OFFSET(SYSTEM_BASIC_INFORMATION, MaximumUserModeAddress, 24 + 2*NT_PTR);
NT_LAYOUT_OFFSET(SYSTEM_BASIC_INFORMATION, ActiveProcessorsAffinityMask, 24 + 3*NT_PTR);
NT_LAYOUT_OFFSET(SYSTEM_BASIC_INFORMATION, NumberOfProcessors, 24 + 4*NT_PTR);

/* SYSTEM_TIMEOFDAY_INFORMATION */
NT_LAYOUT_SIZE(SYSTEM_TIMEOFDAY_INFORMATION, 48);
NT_LAYOUT_OFFSET(SYSTEM_TIMEOFDAY_INFORMATION, BootTime, 0);
NT_LAYOUT_OFFSET(SYSTEM_TIMEOFDAY_INFORMATION, CurrentTime, 8);
NT_LAYOUT_OFFSET(SYSTEM_TIMEOFDAY_INFORMATION, TimeZoneBias, 16);
NT_LAYOUT_OFFSET(SYSTEM_TIMEOFDAY_INFORMATION, TimeZoneId, 24);
NT_LAYOUT_OFFSET(SYSTEM_TIMEOFDAY_INFORMATION, Reserved, 28);
NT_LAYOUT_OFFSET(SYSTEM_TIMEOFDAY_INFORMATION, BootTimeBias, 32);
NT_LAYOUT_OFFSET(SYSTEM_TIMEOFDAY_INFORMATION, SleepTimeBias, 40);

/* TIME_FIELDS */
NT_LAYOUT_SIZE(TIME_FIELDS, 16);
NT_LAYOUT_OFFSET(TIME_FIELDS, Year, 0);
NT_LAYOUT_OFFSET(TIME_FIELDS, Month, 2);
NT_LAYOUT_OFFSET(TIME_FIELDS, Day, 4);
NT_LAYOUT_OFFSET(TIME_FIELDS, Hour, 6);
NT_LAYOUT_OFFSET(TIME_FIELDS, Minute, 8);
NT_LAYOUT_OFFSET(TIME_FIELDS, Second, 10);
NT_LAYOUT_OFFSET(TIME_FIELDS, Milliseconds, 12);
NT_LAYOUT_OFFSET(TIME_FIELDS, Weekday, 14);

/* RTL_TIME_ZONE_INFORMATION */
NT_LAYOUT_SIZE(RTL_TIME_ZONE_INFORMATION, 172);
NT_LAYOUT_OFFSET(RTL_TIME_ZONE_INFORMATION, Bias, 0);
NT_LAYOUT_OFFSET(RTL_TIME_ZONE_INFORMATION, StandardName, 4);
NT_LAYOUT_OFFSET(RTL_TIME_ZONE_INFORMATION, StandardDate, 68);
NT_LAYOUT_OFFSET(RTL_TIME_ZONE_INFORMATION, StandardBias, 84);
NT_LAYOUT_OFFSET(RTL_TIME_ZONE_INFORMATION, DaylightName, 88);
NT_LAYOUT_OFFSET(RTL_TIME_ZONE_INFORMATION, DaylightDate, 152);
NT_LAYOUT_OFFSET(RTL_TIME_ZONE_INFORMATION, DaylightBias, 168);

/* RTL_OSVERSIONINFOW */
NT_LAYOUT_SIZE(RTL_OSVERSIONINFOW, 276);
NT_LAYOUT_OFFSET(RTL_OSVERSIONINFOW, dwOSVersionInfoSize, 0);
NT_LAYOUT_OFFSET(RTL_OSVERSIONINFOW, dwMajorVersion, 4);
NT_LAYOUT_OFFSET(RTL_OSVERSIONINFOW, dwMinorVersion, 8);
NT_LAYOUT_OFFSET(RTL_OSVERSIONINFOW, dwBuildNumber, 12);
NT_LAYOUT_OFFSET(RTL_OSVERSIONINFOW, dwPlatformId, 16);
NT_LAYOUT_OFFSET(RTL_OSVERSIONINFOW, szCSDVersion, 20);

/* THREAD_BASIC_INFORMATION */
NT_LAYOUT_SIZE(THREAD_BASIC_INFORMATION, 8 + 5*NT_PTR);
NT_LAYOUT_OFFSET(THREAD_BASIC_INFORMATION, ExitStatus, 0);
NT_LAYOUT_OFFSET(THREAD_BASIC_INFORMATION, TebBaseAddress, NT_PTR);
NT_LAYOUT_OFFSET(THREAD_BASIC_INFORMATION, ClientId, 2*NT_PTR);
NT_LAYOUT_OFFSET(THREAD_BASIC_INFORMATION, AffinityMask, 4*NT_PTR);
NT_LAYOUT_OFFSET(THREAD_BASIC_INFORMATION, Priority, 5*NT_PTR);
NT_LAYOUT_OFFSET(THREAD_BASIC_INFORMATION, BasePriority, 4 + 5*NT_PTR);

/* EXCEPTION_RECORD */
NT_LAYOUT_SIZE(EXCEPTION_RECORD, 8 + 18*NT_PTR);
NT_LAYOUT_OFFSET(EXCEPTION_RECORD, ExceptionCode, 0);
NT_LAYOUT_OFFSET(EXCEPTION_RECORD, ExceptionFlags, 4);
NT_LAYOUT_OFFSET(EXCEPTION_RECORD, ExceptionRecord, 8);
NT_LAYOUT_OFFSET(EXCEPTION_RECORD, ExceptionAddress, 8 + NT_PTR);
NT_LAYOUT_OFFSET(EXCEPTION_RECORD, NumberParameters, 8 + 2*NT_PTR);
NT_LAYOUT_OFFSET(EXCEPTION_RECORD, ExceptionInformation, 8 + 3*NT_PTR);

/* EXCEPTION_POINTERS */
NT_LAYOUT_SIZE(EXCEPTION_POINTERS, 2*NT_PTR);
NT_LAYOUT_OFFSET(EXCEPTION_POINTERS, ExceptionRecord, 0);
NT_LAYOUT_OFFSET(EXCEPTION_POINTERS, ContextRecord, NT_PTR);

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
