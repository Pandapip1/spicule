/* C library internals and platform ABI fields intentionally use the
 * implementation-reserved namespace so they cannot collide with users.
 */
// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The `\Device\Afd` wire protocol: ioctl codes and request/reply
 * structures for AF_INET/SOCK_STREAM and AF_INET/SOCK_DGRAM sockets,
 * driven directly through NtCreateFile/NtDeviceIoControlFile per
 * test/networking-audit.md sec 1 ("Decision: drive AFD directly through
 * ntdll").
 *
 * None of this is documented by Microsoft.  It is cross-checked against
 * two independent sources that agree on it, per the audit:
 *
 *   - ReactOS's own AFD client (dll/win32/msafd/misc/{dllmain,sndrcv,
 *     helpers}.c) and the ioctl-code/structure header its driver and
 *     client share (sdk/include/reactos/drivers/afd/shared.h) -- both
 *     read directly from a checkout at /tmp/claude/repos/reactos while
 *     writing this file.  This is the *primary* source: it is real,
 *     compilable, driver-and-client-agreeing code, and it is what
 *     test/networking-audit.md and CONTRIBUTING.md's task both point at
 *     for "how Windows itself does it" (NtCreateFile + an EA buffer, as
 *     opposed to Wine's invented IOCTL_AFD_WINE_* codes).
 *   - mingw-w64's vendored copies of Microsoft's own DDK headers,
 *     ntstatus.h and tdi.h (found on this machine under
 *     /usr/share/mingw-w64/include/ -- the same headers this project's
 *     cross toolchain ships), for TRANSPORT_ADDRESS/TA_ADDRESS/
 *     TDI_ADDRESS_IP's exact field layout and the TDI_RECEIVE_* flags.
 *     ReactOS's own client code uses these types but does not vendor a
 *     copy of tdi.h itself; mingw-w64's is the SDK original.
 *
 * The ioctl code arithmetic is independently confirmed a third way:
 * test/networking-audit.md sec 1 shows Wine's IOCTL_AFD_BIND/LISTEN/
 * RECV/POLL (CTL_CODE(FILE_DEVICE_BEEP, 0x800+op, method,
 * FILE_ANY_ACCESS)) numerically equal ReactOS's
 * _AFD_CONTROL_CODE(op, method) for the same operations -- two
 * independent reverse-engineering efforts landed on the same numbers.
 *
 * Only what AF_INET/SOCK_STREAM and AF_INET/SOCK_DGRAM (this project's
 * declared scope; see <sys/socket.h>'s banner) need is transcribed:
 * bind, connect, listen (SOCK_STREAM only -- refused for SOCK_DGRAM by
 * the front door before either backend is reached, see
 * src/socket/listen.c), accept (wait-for-listen + accept, SOCK_STREAM
 * only for the same reason), send, recv, select/poll, disconnect, and
 * socket creation itself, now parametrized by socket type (the
 * AFD_TRANSPORT_TCP/AFD_TRANSPORT_UDP pair below).  AF_UNIX-only and
 * multipoint-only pieces of the real structures are still left out: an
 * anonymous AF_UNIX/SOCK_DGRAM socket (src/socket/socket.c,
 * src/socket/socketpair.c) is one of the two AF_INET transports above
 * wearing a different sa_family at the front door, not a third wire
 * shape here.
 */
#ifndef _SPICULE_AFD_H
#define _SPICULE_AFD_H

#include <stdint.h>
#include "nt.h"

/* ---- ioctl code generation (shared.h: FSCTL_AFD_BASE/_AFD_CONTROL_CODE,
 * confirmed against Wine's independently-derived numbers -- see the file
 * banner) ------------------------------------------------------------- */
#define AFD_FILE_DEVICE_NETWORK 0x00000012UL
#define _AFD_CONTROL_CODE(op, method) ((AFD_FILE_DEVICE_NETWORK) << 12 | ((op) << 2) | (method))

#define METHOD_BUFFERED_  0
#define METHOD_NEITHER_   3

#define AFD_BIND                    0
#define AFD_CONNECT                 1
#define AFD_START_LISTEN            2
#define AFD_WAIT_FOR_LISTEN         3
#define AFD_ACCEPT                  4
#define AFD_RECV                    5
#define AFD_SEND                    7
#define AFD_SELECT                  9
#define AFD_DISCONNECT              10
#define AFD_GET_SOCK_NAME           11
#define AFD_GET_PEER_NAME           12

#define IOCTL_AFD_BIND               _AFD_CONTROL_CODE(AFD_BIND, METHOD_NEITHER_)
#define IOCTL_AFD_CONNECT            _AFD_CONTROL_CODE(AFD_CONNECT, METHOD_NEITHER_)
#define IOCTL_AFD_START_LISTEN       _AFD_CONTROL_CODE(AFD_START_LISTEN, METHOD_NEITHER_)
#define IOCTL_AFD_WAIT_FOR_LISTEN    _AFD_CONTROL_CODE(AFD_WAIT_FOR_LISTEN, METHOD_BUFFERED_)
#define IOCTL_AFD_ACCEPT             _AFD_CONTROL_CODE(AFD_ACCEPT, METHOD_BUFFERED_)
#define IOCTL_AFD_RECV               _AFD_CONTROL_CODE(AFD_RECV, METHOD_NEITHER_)
#define IOCTL_AFD_SEND               _AFD_CONTROL_CODE(AFD_SEND, METHOD_NEITHER_)
#define IOCTL_AFD_SELECT             _AFD_CONTROL_CODE(AFD_SELECT, METHOD_BUFFERED_)
#define IOCTL_AFD_DISCONNECT         _AFD_CONTROL_CODE(AFD_DISCONNECT, METHOD_NEITHER_)
/* 0x1202F / 0x12033.  The first has the same third-way confirmation the
 * codes above do: Wine's independently-derived IOCTL_AFD_GETSOCKNAME
 * (include/wine/afd.h, CTL_CODE(FILE_DEVICE_BEEP, 0x80b, METHOD_NEITHER,
 * FILE_ANY_ACCESS)) is numerically 0x1202F too.  The second has only the
 * one source: Wine's ws2_32 answers getpeername out of its own cached
 * connect()/accept() state and never issues an ioctl for it, so there is
 * no second derivation of 0x12033 to check against.  spicule now follows
 * that cached-state design too; the peer ioctl definitions remain here
 * as documented reverse-engineering and for their structural tests, not
 * as a production dependency. */
#define IOCTL_AFD_GET_SOCK_NAME      _AFD_CONTROL_CODE(AFD_GET_SOCK_NAME, METHOD_NEITHER_)
#define IOCTL_AFD_GET_PEER_NAME      _AFD_CONTROL_CODE(AFD_GET_PEER_NAME, METHOD_NEITHER_)

/* Every wire-format struct below spells a 32-bit field as `uint32_t`
 * (and TAAddressCount as `int32_t`, matching TDI's own LONG), not
 * src/internal/nt.h's `ULONG` (`unsigned long`).  On the real target
 * (mingw's LLP64 ABI) the two are identical, always 4 bytes; but this
 * header is also compiled natively for `make asan` (fuzz/ntstubs.c),
 * where the host's LP64 ABI makes `unsigned long` 8 bytes.  These
 * structs are built with hand-computed byte offsets (__afd_open()'s EA
 * buffer, in particular), not sizeof()/member access alone, so a wider
 * ULONG there silently shifts every offset after it and misaligns the
 * next struct -- confirmed the hard way, as a real UBSan misaligned-
 * access finding under `make asan` before this fix. */
/* ---- TDI address structures (tdi.h) ---------------------------------
 *
 * tdi.h declares TA_ADDRESS and TRANSPORT_ADDRESS at default alignment:
 *
 *      typedef struct _TA_ADDRESS {
 *        USHORT AddressLength;   +0
 *        USHORT AddressType;     +2
 *        UCHAR  Address[1];      +4
 *      } TA_ADDRESS;
 *      typedef struct _TRANSPORT_ADDRESS {
 *        LONG       TAAddressCount;  +0
 *        TA_ADDRESS Address[1];      +4
 *      } TRANSPORT_ADDRESS;
 *
 * so the address bytes of the first (and here only) TA_ADDRESS begin at
 * +12 of an AFD_BIND_DATA and are TDI_ADDRESS_LENGTH_IP long.
 *
 * *** TDI_ADDRESS_IP is deliberately NOT declared as a struct here. ***
 *
 * In tdi.h it sits inside `#include "pshpack1.h"` ... `#include
 * "poppack.h"` -- /usr/share/mingw-w64/include/tdi.h lines 388 and 582
 * bracket it -- so it is packed to 1 and
 * TDI_ADDRESS_LENGTH_IP == sizeof(TDI_ADDRESS_IP) == 14:
 *
 *      USHORT sin_port;     +0
 *      ULONG  in_addr;      +2   <- unaligned; only pack(1) puts it here
 *      UCHAR  sin_zero[8];  +6
 *
 * Transcribing those three fields as an ordinary C struct (which this
 * header did until this commit) makes the compiler insert two bytes of
 * padding after sin_port to align in_addr, giving in_addr at +4,
 * sin_zero at +8 and sizeof() == 16.  Every byte from +2 on is then
 * wrong on the wire, and AddressLength is declared as 16 rather than
 * 14.  That is the same defect class as the 12-vs-24-byte open packet
 * this header carried one commit ago, and it is what bind() was
 * tripping over -- see the AFD_BIND_DATA banner below.
 *
 * Rather than re-introduce the struct with an __attribute__((packed))
 * that four different compilers (mingw gcc, tcc, and the native gcc and
 * clang of `make lint`/`make asan`) would each have to honour, the
 * address payload is written and read through named byte offsets, the
 * way this header already handles the EA buffer.  That is also what
 * both reference clients do: neither ReactOS's WSPBind
 * (dll/win32/msafd/misc/dllmain.c) nor the layout phnt documents ever
 * instantiates a TDI_ADDRESS_IP -- they copy the 14 bytes of
 * `sockaddr.sa_data` verbatim.
 *
 * The rule they both encode, and which the offsets below implement:
 * TA_ADDRESS.AddressType overlays sockaddr.sa_family and
 * TA_ADDRESS.Address overlays sockaddr.sa_data, so
 *
 *      AddressLength == sockaddr length - sizeof(sa_family) == 14
 *
 * for a sockaddr_in.  Sources, in agreement for once:
 *
 *   - ReactOS dll/win32/msafd/misc/dllmain.c, WSPBind():
 *       BindData->Address.Address[0].AddressLength =
 *           SocketAddressLength - sizeof(SocketAddress->sa_family);
 *       BindData->Address.Address[0].AddressType = SocketAddress->sa_family;
 *       RtlCopyMemory(BindData->Address.Address[0].Address,
 *                     SocketAddress->sa_data, ...);
 *   - System Informer phnt, ntafd.h, the AFD_ADDRESS union: its
 *     `TdiAddressUnpacked` arm is `UCHAR Padding[10]` followed by a
 *     SOCKADDR_STORAGE, with the comment
 *     "RTL_SIZEOF_THROUGH_FIELD(TDI_ADDRESS_INFO, Address.Address[0].AddressLength)"
 *     and an ASCII diagram showing SOCKADDR's sa_family sitting exactly
 *     on TA_ADDRESS's AddressType.  10 == 4 (ActivityCount) + 4
 *     (TAAddressCount) + 2 (AddressLength), i.e. the embedded sockaddr
 *     starts at AddressType.
 *   - mingw-w64 tdi.h, for the pack(1) that makes the count 14.
 */
#define TDI_ADDRESS_TYPE_IP 2

/* sizeof(TDI_ADDRESS_IP) with tdi.h's pack(1) in force, which is what
 * TA_ADDRESS.AddressLength must carry for an AF_INET address -- and,
 * equivalently, sizeof(struct sockaddr_in) - sizeof(sa_family_t). */
#define TDI_ADDRESS_LENGTH_IP 14

/* Field offsets within those 14 bytes.  Network byte order throughout;
 * they are copied out of sockaddr_in unchanged. */
#define TDI_IP_OFF_PORT 0
#define TDI_IP_OFF_ADDR 2
#define TDI_IP_OFF_ZERO 6
#define TDI_IP_ZERO_LEN 8

typedef struct _TA_ADDRESS {
	unsigned short AddressLength;
	unsigned short AddressType;
	unsigned char Address[TDI_ADDRESS_LENGTH_IP]; /* exactly one packed TDI_ADDRESS_IP */
} TA_ADDRESS;

typedef struct _TRANSPORT_ADDRESS {
	int32_t TAAddressCount;
	TA_ADDRESS Address[1];
} TRANSPORT_ADDRESS;

/* TDI_ADDRESS_INFO (tdi.h): what IOCTL_AFD_BIND writes *back* in TDI
 * mode -- a ULONG ActivityCount followed by a TRANSPORT_ADDRESS.  For
 * one AF_INET address that is 4 + 4 + 2 + 2 + 14 == 26 bytes, which is
 * two bytes *more* than sizeof(AFD_BIND_DATA)'s TRANSPORT_ADDRESS
 * payload, so the reply cannot be read back into the request buffer the
 * way ReactOS does it (its
 * FIELD_OFFSET(AFD_BIND_DATA, Address.Address[SocketAddressLength])
 * indexes the TA_ADDRESS *array*, wildly over-allocating and hiding the
 * question).  src/socket/bind.c gives the reply its own buffer. */
#define AFD_TDI_ADDRESS_INFO_SIZE_IP (4 + 4 + 2 + 2 + TDI_ADDRESS_LENGTH_IP)

/* ---- the EA buffer NtCreateFile takes (a generic NT structure, not
 * AFD-specific, but this is the only place spicule needs it -- field
 * layout confirmed by ReactOS's WSPSocket use of EaName/EaNameLength/
 * EaValueLength, dllmain.c around line 256). ------------------------- */
typedef struct _FILE_FULL_EA_INFORMATION {
	uint32_t NextEntryOffset;
	unsigned char Flags;
	unsigned char EaNameLength;
	unsigned short EaValueLength;
	char EaName[1]; /* EaNameLength bytes + a NUL, then EaValueLength bytes of value */
} FILE_FULL_EA_INFORMATION;

/* The header size that matters on the wire is offsetof(..., EaName) == 8,
 * *not* sizeof(FILE_FULL_EA_INFORMATION).  sizeof() is 12: it counts the
 * EaName[1] placeholder byte and then rounds the whole thing up to the
 * 4-byte alignment NextEntryOffset forces.  Sizing a buffer with sizeof()
 * therefore overstates the entry by 3 bytes and leaves the declared total
 * length 4-misaligned -- see __afd_open()'s comment and
 * test/posix-socket-ea.c, which asserts the exact-fit arithmetic.
 *
 * The invariants NT's own validator (ReactOS ntoskrnl/io/iomgr/util.c,
 * IoCheckEaBufferValidity(), an @implemented reimplementation of the
 * kernel's) enforces on this buffer, transcribed here because
 * test/posix-socket-ea.c checks each one by name:
 *
 *   ComputedLength = EaValueLength + EaNameLength
 *                    + FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + 1
 *
 *   - EaLength must be >= FIELD_OFFSET(..., EaName), and >= ComputedLength;
 *   - EaName[EaNameLength] must be ANSI_NULL -- so EaNameLength excludes
 *     the terminator but the terminator must still be in the buffer;
 *   - for a non-final entry, NextEntryOffset must equal
 *     ALIGN_UP_BY(ComputedLength, sizeof(ULONG));
 *   - for the final entry, NextEntryOffset must be 0. */
#define AFD_EA_HEADER_SIZE 8 /* offsetof(FILE_FULL_EA_INFORMATION, EaName) */

/* ---- socket creation (shared.h: AFD_CREATE_PACKET, AfdCommand;
 * dllmain.c's WSPSocket around ReactOS's own line 243/347 for the
 * NtCreateFile/EA recipe) ---------------------------------------------
 *
 * The transport device name for AF_INET/SOCK_STREAM: "\Device\Tcp".
 * Confirmed independently of ReactOS by Mateusz Lewczak's "Under the
 * Hood of AFD.sys" reverse-engineering series
 * (https://leftarcode.com/posts/afd-reverse-engineering-part1/, which
 * also confirms the "\Device\Afd\Endpoint" open path and the
 * "AfdOpenPacketXX" EA name below).
 *
 * *** The two sources disagree on the EA value's own layout, and only
 * one of them describes the driver CI actually runs against. ***
 *
 * ReactOS's client (dll/win32/msafd/misc/dllmain.c) fills an
 * AFD_CREATE_PACKET (sdk/include/reactos/drivers/afd/shared.h):
 *
 *      +0  DWORD EndpointFlags
 *      +4  DWORD GroupID
 *      +8  DWORD SizeOfTransportName
 *     +12  WCHAR TransportName[]
 *
 * -- a 12-byte header, no address-family/type/protocol fields, because
 * ReactOS's *own* afd.sys (drivers/network/afd/afd/main.c,
 * AfdCreateSocket()) reads only those three fields back out.  That is
 * the NT4/2000-era shape, and it is self-consistent for ReactOS.
 *
 * (The header offset is 12, taken from the *member* TransportName, not
 * from sizeof(AFD_CREATE_PACKET), which is 16 -- it counts the
 * TransportName[1] placeholder and pads to 4.  The driver copies from
 * `ConnectInfo->TransportName`, i.e. +12; the `EaInfoValue` it computes
 * at +sizeof() is used for a debug print and nothing else.  ReactOS's
 * own apitest agrees, sizing with FIELD_OFFSET(.., TransportName).)
 *
 * Since Vista the EA value is instead an AFD_OPEN_PACKET with a
 * *24-byte* header carrying three extra LONGs between GroupID and the
 * name length:
 *
 *      +0  ULONG EndpointFlags          (AFD_ENDPOINT_FLAGS)
 *      +4  ULONG GroupID                (GROUP)
 *      +8  LONG  AddressFamily          AF_*
 *     +12  LONG  SocketType             SOCK_*
 *     +16  LONG  Protocol               IPPROTO_*
 *     +20  ULONG TransportDeviceNameLength   -- in BYTES, not characters
 *     +24  WCHAR TransportDeviceName[]  UTF-16, not NUL-counted
 *
 * Two independent reverse-engineering efforts agree on that 24-byte
 * shape, against ReactOS's 12:
 *
 *   - System Informer's phnt headers, ntafd.h: `AFD_OPEN_PACKET` and
 *     the `AFD_OPEN_PACKET_FULL_EA` convenience wrapper right below it
 *     (which also pins EaName to `CHAR EaName[sizeof(AfdOpenPacket)]`,
 *     i.e. 16 bytes -- 15 plus the NUL -- putting the value at +24 of
 *     the EA entry).  `TransportDeviceNameLength` is annotated
 *     `_Field_size_bytes_opt_()`, which is what settles bytes-vs-chars.
 *   - Lewczak's series (part 1, "AFD_OPEN_PACKET_EA"), which lists
 *     endpointFlags, groupID, addressFamily, socketType, protocol,
 *     sizeOfTransportName in exactly that order after a 0x10-byte
 *     eaName.
 *
 * *** Both shapes are wrong somewhere, and the buffer cannot say which
 * one it is. ***
 *
 * Using ReactOS's 12-byte layout against real Windows puts the UTF-16
 * device name where afd.sys expects SocketType/Protocol/
 * TransportDeviceNameLength.  afd.sys then reads a *name length* out of
 * the middle of the name text -- for "\Device\Tcp" the WCHARs at +20
 * are 'i','c', so the length reads back as 0x00630069 == 6488169
 * (~6.2 MB) -- and walks that far past the end of a 67-byte buffer
 * (observed directly: reintroducing the old layout makes
 * test/posix-socket-ea.c print exactly that number).  That is the
 * STATUS_ACCESS_VIOLATION (-> EFAULT) socket() returned on the CI
 * windows-test legs while this header carried the ReactOS shape.  Wine
 * cannot see it: Wine's AFD is its own implementation and never parses
 * this packet.
 *
 * The mirror-image failure is quieter and therefore worse.  Sending the
 * 24-byte layout to ReactOS's driver has AfdCreateSocket() read our
 * AddressFamily (AF_INET == 2) as SizeOfTransportName, so
 * FCB->TdiDeviceName becomes two bytes copied out of our SocketType
 * field: the one-character string L"\1".  *NtCreateFile returns
 * STATUS_SUCCESS.*  socket() succeeds and hands back a corrupt
 * endpoint.
 *
 * *** That much is measured, not reasoned. ***  Booting ReactOS with an
 * instrumented afd.sys (DebugTraceLevel raised from MIN_TRACE to
 * MID_TRACE at drivers/network/afd/afd/main.c:21 -- DBG was already on,
 * so AFD_DbgPrint compiles in and only the runtime level suppressed it;
 * `ninja afd` and copying the driver onto the VM is the whole cost) and
 * running an spicule socket() program produced, from AfdCreateSocket()'s
 * success path:
 *
 *     (/drivers/network/afd/afd/main.c:438)(AfdCreateSocket)
 *         Success: AfdOpenPacketXX \x01
 *
 * -- the name text being exactly one character, U+0001, on the wire:
 *
 *     53 75 63 63 65 73 73 3a 20 41 66 64 4f 70 65 6e
 *     50 61 63 6b 65 74 58 58 20 01 0d 0a
 *
 * Both halves of that fall out of the mechanism independently, which is
 * what makes it hard to get by coincidence: the length is 2 bytes
 * because our AddressFamily is AF_INET == 2, and the character is
 * 0x0001 because it is the low half of our SocketType == SOCK_STREAM.
 * And it is printed from the *success* path, so the corruption is
 * silent at its source.
 *
 * The control that makes that a finding rather than an anecdote: on the
 * same boot, through the same instrumented driver, native ws2_32
 * callers printed `Success: AfdOpenPacketXX \Device\Udp`.  A tracer too
 * broken to print a device name would have produced a blank or garbled
 * line indistinguishable from the result above; this rules that out.
 *
 * What happens *after* the corrupt endpoint is created is still read
 * from source, not observed: WarmSocketForBind()'s
 * `!FCB->TdiDeviceName.Length` guard does not fire (the length is 2,
 * not 0), TdiOpenAddressFile() hands the one-character name to
 * ZwCreateFile, and the object-name failure comes back as ENOENT from a
 * call that never touched a transport name.  bind()'s actual status was
 * not captured on that boot -- the test program reported over COM2,
 * which had no driver -- so the ENOENT chain is inferred, anchored at a
 * measured origin rather than free-floating.
 *
 * The corrected path was subsequently measured on that instrumented
 * ReactOS system.  test/posix-socket-shape.c reported NT 5.2 from the
 * PEB, selected AFD_SHAPE_NT4, passed all 31 checks (including socket(),
 * bind(), listen() and close()), and the driver printed `Success:
 * AfdOpenPacketXX \Device\Tcp`.  Thus both the 12-byte packet image and
 * the endpoint it creates have a positive result; the test remains the
 * regression assertion for that result.
 *
 * That is why the choice below is made from the OS version rather than
 * by probing.  A probe needs a failure to learn from; the wrong guess
 * here *succeeds* in both directions, and by the time an error appears
 * the endpoint has already been created.  There is no version field,
 * no length, and no other discriminator in the EA bytes -- ReactOS's
 * own apitest (modules/rostests/apitests/afd/AfdHelpers.c) picks
 * between the identical pair of layouts with
 * `LOBYTE(LOWORD(GetVersion())) >= 6` for exactly this reason.  See
 * src/internal/ntversion.c for the three tests a divergence must meet
 * before it is allowed to be version-gated; this one is the reason that
 * file exists, and is not a licence to gate anything else.
 *
 * phnt notes that leaving TransportDeviceNameLength at 0 (no device
 * name) selects "TLI" transport mode, in which AFD's bind/connect/
 * accept ioctls take SOCKADDR rather than the TDI_ADDRESS_INFO /
 * TRANSPORT_ADDRESS structures the rest of this header is built on.
 * This code therefore keeps naming "\Device\Tcp", which selects TDI
 * (or hybrid) mode and keeps the structures below correct.  If Server
 * 2025 has finally retired the \Device\Tcp TDI stub, the open will
 * fail with a name-lookup status (ENOENT) rather than EFAULT -- a
 * distinguishable next signal, and the point at which converting the
 * whole file to the _TL structures becomes the fix. */
/* Spelled as WCHAR-array initializer lists, not L"..." literals: a wide
 * string literal's element type is the compiler's native wchar_t,
 * which is a 32-bit int on a non-Windows-targeting compiler (confirmed
 * against this project's own `make lint` native-gcc/clang pass, which
 * is not a Windows-targeting compiler on purpose -- src/internal/nt.h's
 * WCHAR is `unsigned short`, so `static const WCHAR x[] = L"..."` is a
 * real array-element type mismatch there, not just a lint nit).  This
 * project's few existing L"..." uses (src/signal/signal.c etc.) all
 * hand a wide literal straight to RtlInitUnicodeString()/similar as a
 * pointer, which only warns on the pointee-type mismatch; this file
 * needs an actual WCHAR[], so it sidesteps the literal instead. */
#define AFD_TRANSPORT_TCP { '\\','D','e','v','i','c','e','\\','T','c','p', 0 }
/* The transport device name for AF_INET/SOCK_DGRAM: "\Device\Udp",
 * added for SOCK_DGRAM (2026-09-01).  Not independently reverse
 * engineered the way \Device\Tcp was (this header's socket-creation
 * banner) -- but it does not need to be.  Two of the three facts that
 * banner spent its length establishing about \Device\Tcp are facts
 * about AFD's *open-packet mechanism*, not about TCP specifically, and
 * apply to any transport device name AFD is handed: which 12-vs-24-byte
 * packet shape a given afd.sys reads (__afd_open_shape(), decided from
 * the OS version, not the name), and that a wrong shape corrupts
 * silently rather than failing loudly.  Both are already handled by
 * reusing the exact same __afd_build_open_ea_for() codepath \Device\Tcp
 * goes through, just with a different name and AddressFamily/
 * SocketType/Protocol -- no new mechanism, so no new blind spot.
 *
 * The name itself rests on two things that *are* independently
 * confirmed, both already recorded in that banner rather than repeated
 * here: real Windows ws2_32 driving the same instrumented ReactOS
 * afd.sys this project's own \Device\Tcp finding came from printed
 * `Success: AfdOpenPacketXX \Device\Udp` for a UDP socket (the control
 * that ruled out a broken tracer), and it is the name every public
 * Windows AFD reverse-engineering source (ReactOS's own afd.sys driver,
 * which implements \Device\Udp identically to \Device\Tcp as a TDI
 * transport; Lewczak's "Under the Hood of AFD.sys" series) gives for
 * UDP.  What is NOT independently confirmed, unlike \Device\Tcp, is a
 * clean bind()/connect()/send()/recv() run through it observed on an
 * instrumented driver -- this project has no runnable x86_64 Wine in
 * its own CI/dev sandbox (see this repo's own tooling notes) to supply
 * that the way test/posix-socket-shape.c's \Device\Tcp run was
 * supplied, so this is inference from the mechanism plus the name, not
 * a repeat of that measurement.  socketpair(AF_UNIX, SOCK_DGRAM, ...)'s
 * NT backend (src/socket/socketpair.c) is the one real consumer of this
 * device name; its own comment says the same thing in POSIX terms. */
#define AFD_TRANSPORT_UDP { '\\','D','e','v','i','c','e','\\','U','d','p', 0 }
#define AFD_ENDPOINT_DEVICE { '\\','D','e','v','i','c','e','\\','A','f','d','\\','E','n','d','p','o','i','n','t', 0 }

#define AFD_EA_NAME "AfdOpenPacketXX"
#define AFD_EA_NAME_LEN 15 /* strlen(AFD_EA_NAME), not counting the NUL EaName itself is stored with */

/* Every field spelled as a fixed-width type, for the LP64-vs-LLP64
 * reason in this header's banner: `make asan` compiles it natively. */
typedef struct _AFD_OPEN_PACKET {
	uint32_t EndpointFlags;
	uint32_t GroupID;
	int32_t AddressFamily;
	int32_t SocketType;
	int32_t Protocol;
	uint32_t TransportDeviceNameLength; /* bytes, excluding any NUL */
	WCHAR TransportDeviceName[1];
} AFD_OPEN_PACKET;

/* offsetof(AFD_OPEN_PACKET, TransportDeviceName).  Named separately for
 * the same reason AFD_EA_HEADER_SIZE is: sizeof(AFD_OPEN_PACKET) is 28,
 * not 24 -- it counts the TransportDeviceName[1] placeholder and rounds
 * up -- so sizeof() would overstate the value by 4 bytes. */
#define AFD_OPEN_PACKET_HEADER_SIZE 24

/* The NT4/NT5 shape, transcribed from ReactOS's shared.h with the same
 * fixed-width types and for the same LP64 reason as above.  Kept as a
 * declared structure rather than a run of offsets so the two layouts
 * can be read side by side: the whole defect is that they differ only
 * by three fields nobody can see on the wire. */
typedef struct _AFD_CREATE_PACKET {
	uint32_t EndpointFlags;
	uint32_t GroupID;
	uint32_t SizeOfTransportName; /* bytes, excluding any NUL */
	WCHAR TransportName[1];
} AFD_CREATE_PACKET;

/* offsetof(AFD_CREATE_PACKET, TransportName).  NOT
 * sizeof(AFD_CREATE_PACKET), which is 16 -- see the banner. */
#define AFD_CREATE_PACKET_HEADER_SIZE 12

/* Which of the two the driver on the other end is going to read.
 * __afd_open_shape() picks one per platform; the _for() builders below
 * take it explicitly so a test can construct either shape's byte image
 * on any host. */
#define AFD_SHAPE_NT4 0 /* 12-byte AFD_CREATE_PACKET: NT 4 .. NT 5.2, ReactOS */
#define AFD_SHAPE_NT6 1 /* 24-byte AFD_OPEN_PACKET:   NT 6.0+, real Windows, Wine */

/* ---- bind (shared.h: AFD_BIND_DATA, AFD_SHARE_*) --------------------- */
#define AFD_SHARE_UNIQUE    0
#define AFD_SHARE_REUSE     1
#define AFD_SHARE_WILDCARD  2
#define AFD_SHARE_EXCLUSIVE 3

typedef struct _AFD_BIND_DATA {
	uint32_t ShareType;
	TRANSPORT_ADDRESS Address;
} AFD_BIND_DATA;

/* The IOCTL_AFD_BIND *request* as it appears on the wire, by offset.
 * Named separately from AFD_BIND_DATA for the same reason
 * AFD_EA_HEADER_SIZE is named separately from
 * sizeof(FILE_FULL_EA_INFORMATION): sizeof(AFD_BIND_DATA) is 28, two
 * bytes more than the 26 the request actually occupies, because
 * TAAddressCount's 4-byte alignment rounds the tail up.  Declaring 28
 * would declare two bytes the request does not describe.
 *
 *      +0   ULONG  ShareType         AFD_SHARE_*
 *      +4   LONG   TAAddressCount    == 1
 *      +8   USHORT AddressLength     == TDI_ADDRESS_LENGTH_IP == 14
 *      +10  USHORT AddressType       == TDI_ADDRESS_TYPE_IP == AF_INET == 2
 *      +12  USHORT sin_port          network order
 *      +14  ULONG  in_addr           network order  <- NOT +16; see the
 *      +18  UCHAR  sin_zero[8]                         TDI banner above
 *      == 26
 *
 * Note +10 onwards is byte-for-byte a `struct sockaddr_in`: AddressType
 * is its sa_family and the 14 address bytes are its sa_data.  That is
 * the invariant phnt's AFD_ADDRESS diagram draws and the one
 * test/posix-socket-bind.c asserts.
 *
 * IOCTL_AFD_BIND is METHOD_NEITHER (phnt ntafd.h: 0x12003), so afd.sys
 * sees the caller's buffer and its declared length directly; the length
 * is the only thing bounding how much of the address it reads. */
#define AFD_BIND_REQ_OFF_SHARE_TYPE   0
#define AFD_BIND_REQ_OFF_ADDR_COUNT   4
#define AFD_BIND_REQ_OFF_ADDR_LENGTH  8
#define AFD_BIND_REQ_OFF_ADDR_TYPE   10
#define AFD_BIND_REQ_OFF_ADDR        12
#define AFD_BIND_REQ_SIZE (AFD_BIND_REQ_OFF_ADDR + TDI_ADDRESS_LENGTH_IP)

/* ---- listen / accept -------------------------------------------------- */
typedef struct _AFD_LISTEN_DATA {
	unsigned char UseSAN;
	uint32_t Backlog;
	unsigned char UseDelayedAcceptance;
} AFD_LISTEN_DATA;

typedef struct _AFD_RECEIVED_ACCEPT_DATA {
	uint32_t SequenceNumber;
	TRANSPORT_ADDRESS Address;
} AFD_RECEIVED_ACCEPT_DATA;

/* The IOCTL_AFD_WAIT_FOR_LISTEN *reply* as it appears on the wire, by
 * offset -- the same TRANSPORT_ADDRESS shape as the bind request above,
 * behind a ULONG sequence number instead of a ULONG share type:
 *
 *      +0   ULONG  SequenceNumber
 *      +4   LONG   TAAddressCount    == 1 for the one peer address
 *      +8   USHORT AddressLength     == TDI_ADDRESS_LENGTH_IP == 14
 *      +10  USHORT AddressType       == TDI_ADDRESS_TYPE_IP == AF_INET == 2
 *      +12  UCHAR  Address[14]       packed TDI_ADDRESS_IP; see the TDI banner
 *      == 26
 *
 * Named separately from sizeof(AFD_RECEIVED_ACCEPT_DATA) for the reason
 * AFD_BIND_REQ_SIZE is: the sizeof() is 28, two bytes more than the 26
 * the reply occupies, because TAAddressCount's alignment rounds the tail
 * up.  As with bind, everything from +10 on is byte-for-byte a
 * `struct sockaddr_in`.
 *
 * 26 is also exactly what the driver declares written.  AfdWaitForListen()
 * (the AFD driver's own listen.c, Copyright (c) 1989 Microsoft
 * Corporation) completes with
 *
 *     Irp->IoStatus.Information =
 *         sizeof(*listenResponse) - sizeof(TRANSPORT_ADDRESS) +
 *             connection->RemoteAddressLength;
 *
 * i.e. sizeof(SequenceNumber) plus however many bytes of TDI address the
 * transport handed it -- 4 + 22 for one AF_INET address.  It moves in
 * exactly RemoteAddressLength bytes and nothing else.
 *
 * *** IOCTL_AFD_WAIT_FOR_LISTEN is METHOD_BUFFERED, and unlike
 * IOCTL_AFD_SELECT its buffer is out-only. ***
 *
 * The I/O manager copies back exactly Information bytes and does not
 * touch the rest of the caller's buffer.  For the aliased SELECT buffer
 * an unwritten tail read back as the caller's own request (see
 * __afd_poll_events_for()); here there is no request to read back, so an
 * unwritten tail is whatever the caller left there -- uninitialised
 * stack, handed out as a peer address.  The reply buffer is therefore
 * zeroed before the call and interpreted only through
 * __afd_accept_reply_addr(), never by indexing Address[0] directly. */
#define AFD_ACCEPT_RSP_OFF_SEQUENCE    ((size_t)0)
#define AFD_ACCEPT_RSP_OFF_ADDR_COUNT  ((size_t)4)
#define AFD_ACCEPT_RSP_OFF_ADDR_LENGTH ((size_t)8)
#define AFD_ACCEPT_RSP_OFF_ADDR_TYPE   ((size_t)10)
#define AFD_ACCEPT_RSP_OFF_ADDR        ((size_t)12)
#define AFD_ACCEPT_RSP_SIZE (AFD_ACCEPT_RSP_OFF_ADDR + TDI_ADDRESS_LENGTH_IP)

typedef struct _AFD_ACCEPT_DATA {
	uint32_t UseSAN;
	uint32_t SequenceNumber;
	HANDLE ListenHandle; /* the *new* socket handle the connection lands on */
} AFD_ACCEPT_DATA;

/* ---- connect ---------------------------------------------------------
 *
 * *** The two sources disagree, and only on 64-bit. ***
 *
 * ReactOS sdk/include/reactos/drivers/afd/shared.h, AFD_CONNECT_INFO:
 *
 *      BOOLEAN           UseSAN;
 *      ULONG             Root;
 *      ULONG             Unknown;
 *      TRANSPORT_ADDRESS RemoteAddress;
 *
 * System Informer phnt, ntafd.h, AFD_CONNECT_JOIN_INFO (the structure
 * its AFD_CONNECT comment names: "in: AFD_CONNECT_JOIN_INFO_TL or
 * AFD_CONNECT_JOIN_INFO (depending on transport mode)"):
 *
 *      BOOLEAN           SanActive;
 *      HANDLE            RootEndpoint;
 *      HANDLE            ConnectEndpoint;
 *      TRANSPORT_ADDRESS RemoteAddress;
 *
 * The first field agrees.  The middle two do not: ReactOS has two
 * ULONGs where phnt has two HANDLEs.  On i386 a HANDLE is 4 bytes and
 * the two layouts are byte-for-byte identical -- RemoteAddress at +12
 * either way.  On x86_64 a HANDLE is 8 and carries 8-byte alignment,
 * so phnt puts RootEndpoint at +8, ConnectEndpoint at +16 and
 * RemoteAddress at +24, where ReactOS puts RemoteAddress at +12.
 * Measured, not assumed: both declarations compiled for both ABIs.
 *
 * phnt is followed here, for the same reason (and with the same
 * evidence shape) as the 24-byte AFD_OPEN_PACKET above:
 *
 *   - ReactOS's structure is what ReactOS's *own* afd.sys parses.  It
 *     is self-consistent for ReactOS and says nothing about the driver
 *     Windows ships; this project has now found four places where the
 *     two differ (sub-page SectionAlignment, the open packet, a
 *     FileBasicInformation access rule, and afd.sys's create-packet
 *     parsing), and in every case real-Windows CI sided against
 *     ReactOS.
 *   - phnt's names are the giveaway: `RootEndpoint` and
 *     `ConnectEndpoint` are endpoint *handles* -- the multipoint
 *     root/leaf handles WSAJoinLeaf passes, which is why the same
 *     structure serves AFD_CONNECT and AFD_JOIN_LEAF (phnt ntafd.h,
 *     opcodes 1 and 46).  A handle cannot be a ULONG on Win64.
 *     ReactOS's own field names -- `Root` and a literal `Unknown` --
 *     record that its authors did not know what the fields were.
 *   - The failing leg is x86_64, which is exactly and only where the
 *     two layouts differ; i386, where they agree, gets past connect().
 *
 * With ReactOS's layout on x86_64 the whole TRANSPORT_ADDRESS lands 12
 * bytes early, so afd.sys reads TAAddressCount out of the tail of
 * ConnectEndpoint and the address out of the middle of the caller's
 * TAAddressCount/AddressLength/AddressType.
 *
 * The request is therefore written through named byte offsets, exactly
 * as the bind request above is, so that no compiler's padding rules
 * enter into it.  Unlike bind's, these offsets are pointer-sized
 * rather than absolute -- that is the whole point of the disagreement
 * -- so they are expressed in terms of sizeof(HANDLE):
 *
 *  i386 (HANDLE == 4)                x86_64 (HANDLE == 8)
 *      +0   BOOLEAN SanActive            +0   BOOLEAN SanActive
 *      +4   HANDLE  RootEndpoint         +8   HANDLE  RootEndpoint
 *      +8   HANDLE  ConnectEndpoint     +16   HANDLE  ConnectEndpoint
 *     +12   LONG    TAAddressCount      +24   LONG    TAAddressCount
 *     +16   USHORT  AddressLength       +28   USHORT  AddressLength
 *     +18   USHORT  AddressType         +30   USHORT  AddressType
 *     +20   UCHAR   Address[14]         +32   UCHAR   Address[14]
 *     == 34                             == 46
 *
 * As with bind, everything from AddressType on is byte-for-byte a
 * `struct sockaddr_in` (phnt's AFD_ADDRESS diagram), and the 14
 * address bytes are the packed TDI_ADDRESS_IP of the TDI banner above.
 *
 * IOCTL_AFD_CONNECT is METHOD_NEITHER (phnt ntafd.h: 0x12007), so the
 * declared input length is the only bound afd.sys has on how far into
 * the buffer it reads -- hence __afd_connect_request_size() rather
 * than sizeof(AFD_CONNECT_INFO), which rounds up for alignment. */
typedef struct _AFD_CONNECT_INFO {
	unsigned char SanActive;
	HANDLE RootEndpoint;
	HANDLE ConnectEndpoint;
	TRANSPORT_ADDRESS RemoteAddress;
} AFD_CONNECT_INFO;

/* Spelled with sizeof(HANDLE), not a literal, because the value
 * legitimately differs between this project's two target ABIs; see the
 * table above.  Not usable in #if, and deliberately not needed there. */
/* Spelled in size_t, not unsigned long: under LLP64 `unsigned long` is 32
 * bits while size_t is 64, so `3UL * sizeof(HANDLE)` would multiply in 32
 * bits and only then widen for the pointer arithmetic it feeds.  Nothing
 * here comes near overflowing -- the largest product is 3*8 -- but doing
 * the arithmetic in the type the result is used as makes that true by
 * construction rather than by the values happening to be small.  clang-tidy
 * 18's bugprone-implicit-widening-of-multiplication-result flags the other
 * spelling in the pinned lint stage, and it is right to. */
#define AFD_CONNECT_REQ_OFF_SAN_ACTIVE  ((size_t)0)
#define AFD_CONNECT_REQ_OFF_ROOT_EP     (sizeof(HANDLE))
#define AFD_CONNECT_REQ_OFF_CONNECT_EP  ((size_t)2 * sizeof(HANDLE))
#define AFD_CONNECT_REQ_OFF_ADDR_COUNT  ((size_t)3 * sizeof(HANDLE))
#define AFD_CONNECT_REQ_OFF_ADDR_LENGTH (AFD_CONNECT_REQ_OFF_ADDR_COUNT + 4)
#define AFD_CONNECT_REQ_OFF_ADDR_TYPE   (AFD_CONNECT_REQ_OFF_ADDR_COUNT + 6)
#define AFD_CONNECT_REQ_OFF_ADDR        (AFD_CONNECT_REQ_OFF_ADDR_COUNT + 8)
#define AFD_CONNECT_REQ_SIZE            (AFD_CONNECT_REQ_OFF_ADDR + TDI_ADDRESS_LENGTH_IP)

/* ---- send / recv (shared.h: AFD_WSABUF, AFD_RECV_INFO, AFD_SEND_INFO,
 * AFD_SKIP_FIO/AFD_OVERLAPPED/AFD_IMMEDIATE; tdi.h: TDI_RECEIVE_*) ----- */
typedef struct _AFD_WSABUF {
	unsigned int len;
	char *buf;
} AFD_WSABUF;

#define AFD_IMMEDIATE 0x4UL

#define TDI_RECEIVE_PARTIAL   0x00000010UL
#define TDI_RECEIVE_NORMAL    0x00000020UL
#define TDI_RECEIVE_EXPEDITED 0x00000040UL
#define TDI_RECEIVE_PEEK      0x00000080UL
#define TDI_SEND_EXPEDITED    0x00000020UL

typedef struct _AFD_RECV_INFO {
	AFD_WSABUF *BufferArray;
	uint32_t BufferCount;
	uint32_t AfdFlags;
	uint32_t TdiFlags;
} AFD_RECV_INFO;

typedef struct _AFD_SEND_INFO {
	AFD_WSABUF *BufferArray;
	uint32_t BufferCount;
	uint32_t AfdFlags;
	uint32_t TdiFlags;
} AFD_SEND_INFO;

/* ---- disconnect (shutdown()) ------------------------------------------ */
#define AFD_DISCONNECT_SEND 0x01UL
#define AFD_DISCONNECT_RECV 0x02UL
#define AFD_DISCONNECT_ABORT 0x04UL

typedef struct _AFD_DISCONNECT_INFO {
	uint32_t DisconnectType;
	LARGE_INTEGER Timeout;
} AFD_DISCONNECT_INFO;

/* ---- select/poll (shared.h: AFD_POLL_INFO/AFD_HANDLE, AFD_EVENT_*;
 * dllmain.c's WSPSelect for the fd_set-bit -> AFD_EVENT_* mapping this
 * project's __fd_probe()/select()/poll() reuse) ------------------------ */
#define AFD_EVENT_RECEIVE      0x0001UL
#define AFD_EVENT_OOB_RECEIVE  0x0002UL
#define AFD_EVENT_SEND         0x0004UL
#define AFD_EVENT_DISCONNECT   0x0008UL
#define AFD_EVENT_ABORT        0x0010UL
#define AFD_EVENT_CLOSE        0x0020UL
#define AFD_EVENT_CONNECT      0x0040UL
#define AFD_EVENT_ACCEPT       0x0080UL
#define AFD_EVENT_CONNECT_FAIL 0x0100UL

/* readfds: a read, a hangup or a pending accept would all not block. */
#define AFD_POLL_READ_BITS (AFD_EVENT_RECEIVE | AFD_EVENT_DISCONNECT | AFD_EVENT_ABORT | AFD_EVENT_CLOSE | AFD_EVENT_ACCEPT)
/* writefds: a send, or an in-progress connect() finishing, would not block. */
#define AFD_POLL_WRITE_BITS (AFD_EVENT_SEND | AFD_EVENT_CONNECT | AFD_EVENT_CONNECT_FAIL)

/* *** The same disagreement as AFD_CONNECT_INFO above, in the same
 * place, and again only on x86_64 -- but this one is settled by
 * Microsoft's own source for the driver that parses it. ***
 *
 * ReactOS sdk/include/reactos/drivers/afd/shared.h, AFD_POLL_INFO:
 *
 *      LARGE_INTEGER Timeout;
 *      ULONG         HandleCount;
 *      ULONG_PTR     Exclusive;      <- pointer-sized
 *      AFD_HANDLE    Handles[1];
 *
 * which puts Handles at +24 on x86_64 (at +16 on i386, where
 * ULONG_PTR is four bytes and every source below agrees anyway).
 * spicule followed it.  It is wrong: the field is not pointer-sized.
 *
 *   - The AFD driver's own source, afd.h, "Structures for
 *     IOCTL_AFD_POLL" (Copyright (c) 1992 Microsoft Corporation;
 *     sources.inc MAJORCOMP=ntos MINORCOMP=afd):
 *
 *         typedef struct _AFD_POLL_INFO {
 *             LARGE_INTEGER Timeout;
 *             ULONG NumberOfHandles;
 *             BOOLEAN Unique;
 *             AFD_POLL_HANDLE_INFO Handles[1];
 *         } AFD_POLL_INFO, *PAFD_POLL_INFO;
 *
 *     This is first-party source for the very code that reads this
 *     buffer: poll.c's AfdPoll() dereferences ->Unique, ->Timeout,
 *     ->NumberOfHandles and ->Handles straight out of
 *     Irp->AssociatedIrp.SystemBuffer.  Its IOCTL_AFD_POLL is
 *     _AFD_CONTROL_CODE(AFD_POLL = 9, METHOD_BUFFERED) -- this
 *     header's IOCTL_AFD_SELECT, 0x12024, exactly.
 *   - System Informer phnt, ntafd.h, AFD_POLL_INFO: character for
 *     character the same declaration, BOOLEAN Unique included.  That
 *     is now the fifth place on this project where phnt has matched
 *     real Windows and ReactOS has not.
 *   - wepoll (github.com/piscisaureus/wepoll, wepoll.c) and libuv
 *     (include/uv/win.h, _AFD_POLL_INFO) both put `ULONG Exclusive`
 *     in that slot instead, and spell the ioctl as the literal
 *     0x00012024.  These two are not transcriptions of a header: they
 *     are working code driving the shipping afd.sys on x86 *and* x64
 *     at enormous volume (libuv is Node.js's event loop).  A Handles
 *     array 8 bytes out of place on x64 would not survive that.
 *
 * The NT 4.0 source is taken as decisive here, which it is not for
 * every AFD structure -- the open packet demonstrably changed shape
 * after it (see the AFD_OPEN_PACKET_HEADER_SIZE banner above).  Here
 * it does not stand alone: three later, independent, x64-era sources
 * put Handles at that same +16, and only ReactOS dissents.
 *
 * Those sources do disagree with each other about the field's *type*
 * -- BOOLEAN Unique (Microsoft, phnt) versus ULONG Exclusive (wepoll,
 * libuv) -- and this header does not resolve that, because it need
 * not: all of them put four bytes at +12 ahead of an 8-aligned
 * Handles, and this project always sends zero there, which is the same
 * four zero bytes either way (a BOOLEAN at +12 leaves +13..+15 as
 * padding the caller must still zero, which is what a ULONG at +12
 * amounts to).  The disagreement is recorded, not hidden.
 *
 * Zero there is not just "the value we happen to send": AfdPoll()
 * reads that field as Unique, and a non-zero Unique makes the incoming
 * poll supersede any existing unique poll on the same first file
 * object, cancelling that other IRP with STATUS_CANCELLED.  A probe
 * that set it would silently cancel another thread's concurrent
 * select()/poll() on the same socket.  Whatever the field is called,
 * this project must keep sending zero.
 *
 * Unlike connect's, these header offsets are the *same* on both ABIs;
 * it is the element size of the Handles array that is pointer-sized
 * (AFD_HANDLE: HANDLE, then two 32-bit fields -- 16 bytes on x86_64,
 * 12 on i386).
 *
 *      +0   LARGE_INTEGER Timeout        (both ABIs)
 *      +8   ULONG         HandleCount    (phnt: NumberOfHandles)
 *     +12   four bytes, zero             (Unique / Exclusive) <- NOT ULONG_PTR
 *     +16   AFD_HANDLE    Handles[]
 *
 * IOCTL_AFD_SELECT is METHOD_BUFFERED (0x12024), so afd.sys reads a
 * kernel copy of this buffer and writes the results back into it --
 * which is why there are readers below as well as builders.
 *
 * Reach, stated exactly: src/select/select.c's __fd_probe() has a
 * __FD_SOCKET case that sends this request, and both callers
 * (poll_pass() in the same file and the loop in src/select/poll.c) now
 * route sockets to it.  They did not always: each once called
 * __fd_probe() only for f->type == __FD_PIPE and treated every other
 * type, sockets included, as unconditionally ready -- which is why the
 * layout defect below was latent rather than observed, and why the
 * wire format was worth getting right before the routing landed on it.
 *
 * Observed, not merely reasoned: issuing this ioctl on a real AFD
 * endpoint with Handles at +24 returns STATUS_INVALID_HANDLE
 * (0xC0000008) -- the driver reads the handle from the wrong offset
 * and finds the zero bytes the caller left there -- where the same
 * request with Handles at +16 returns STATUS_SUCCESS.  __fd_probe()
 * maps a failed ioctl to "ready, and hung up" (never-ready would let
 * an unprobeable socket hang an infinite-timeout select()), so the
 * symptom of getting this layout wrong is a socket that select() and
 * poll() report ready when it is not, with no error surfaced anywhere
 * -- caught by test/posix-select-socket.c, whose idle-socket
 * assertions reject exactly that, and by test/posix-socket-poll.c,
 * which asserts this layout with no device at all. */
typedef struct _AFD_HANDLE {
	HANDLE Handle;
	uint32_t Events;
	NTSTATUS Status;
} AFD_HANDLE;

/* Storage only -- large enough and correctly aligned for a one-handle
 * request on both ABIs, exactly as AFD_CONNECT_INFO above is for a
 * connect request.  Nothing is written or read through its members;
 * that goes through the offsets below.  The Exclusive field is spelled
 * as the four bytes every source but ReactOS agrees on, so that the
 * declaration cannot quietly disagree with them again. */
typedef struct _AFD_POLL_INFO {
	LARGE_INTEGER Timeout;
	uint32_t HandleCount;
	uint32_t Exclusive; /* four bytes, not ULONG_PTR -- see above */
	AFD_HANDLE Handles[1];
} AFD_POLL_INFO;

/* Spelled in size_t for the same LLP64 reason the connect offsets
 * above are (f77ceaa): `unsigned long` is 32 bits on this target while
 * a pointer is 64, so a product computed in unsigned long would be
 * truncated before it widened for the pointer arithmetic below.  These
 * are the first offsets multiplied by a *variable* count, which is
 * where clang-tidy's bugprone-implicit-widening-of-multiplication-result
 * bites; sizeof already yields size_t, so every expression here is
 * 64-bit throughout. */
#define AFD_POLL_REQ_OFF_TIMEOUT      ((size_t)0)
#define AFD_POLL_REQ_OFF_HANDLE_COUNT ((size_t)8)
#define AFD_POLL_REQ_OFF_EXCLUSIVE    ((size_t)12)
#define AFD_POLL_REQ_OFF_HANDLES      ((size_t)16)
/* One AFD_HANDLE on the wire: HANDLE, ULONG Events, NTSTATUS Status --
 * 16 bytes on x86_64, 12 on i386.  This is the only part of the
 * request whose size depends on the ABI. */
#define AFD_POLL_H_OFF_HANDLE ((size_t)0)
#define AFD_POLL_H_OFF_EVENTS (sizeof(HANDLE))
#define AFD_POLL_H_OFF_STATUS (sizeof(HANDLE) + 4)
#define AFD_POLL_H_SIZE       (sizeof(HANDLE) + 8)
#define AFD_POLL_REQ_SIZE(n)  (AFD_POLL_REQ_OFF_HANDLES + (size_t)(n) * AFD_POLL_H_SIZE)

/* ---- getsockname / getpeername replies, by offset --------------------
 *
 * Both ioctls take no input at all and write one TRANSPORT_ADDRESS-
 * shaped reply.  *** The two replies are NOT the same shape. ***  That
 * is the single fact this section exists to record, because nothing
 * about the two function names suggests it and reading the second reply
 * with the first's offsets yields a plausible-looking address four
 * bytes out of place:
 *
 *   - IOCTL_AFD_GET_SOCK_NAME answers with a TDI_ADDRESS_INFO -- a
 *     ULONG ActivityCount and *then* the TRANSPORT_ADDRESS, 26 bytes for
 *     one AF_INET address (AFD_TDI_ADDRESS_INFO_SIZE_IP, the same reply
 *     IOCTL_AFD_BIND already returns).  It is not AFD's own structure:
 *     the driver hands the request straight to the transport as a TDI
 *     TDI_QUERY_INFORMATION/TDI_QUERY_ADDRESS_INFO over an MDL of the
 *     caller's buffer (ReactOS drivers/network/afd/afd/info.c,
 *     AfdGetSockName()), and TDI_ADDRESS_INFO is what that query is
 *     defined to return.  ReactOS's client agrees: WSPGetSockName
 *     (dll/win32/msafd/misc/dllmain.c) declares its buffer
 *     PTDI_ADDRESS_INFO and reads the address out of `&TdiAddress->Address`.
 *   - IOCTL_AFD_GET_PEER_NAME answers with a bare TRANSPORT_ADDRESS, 22
 *     bytes, no ActivityCount.  AFD does not consult the transport for
 *     this one at all -- AfdGetPeerName() RtlCopyMemory's the
 *     FCB->RemoteAddress it recorded at connect/accept time straight
 *     into the caller's buffer -- and WSPGetPeerName declares its buffer
 *     PTRANSPORT_ADDRESS, not PTDI_ADDRESS_INFO, to match.
 *
 * Both are METHOD_NEITHER, so afd.sys writes through Irp->UserBuffer
 * with OutputBufferLength as its only bound and there is no
 * Information-bounded copy-back to reason about (AfdGetPeerName()
 * completes with Information 0 outright).  The reply buffer is still
 * zeroed before the call and still interpreted only through
 * __afd_transport_addr_out(), for the reason the accept banner above
 * gives: over a zeroed buffer, a reply that stopped short of the
 * address leaves AddressLength zero, and rejecting zero rejects that
 * reply without any second source of truth about how big it "should"
 * have been. */
#define AFD_SOCKNAME_RSP_OFF_ACTIVITY    ((size_t)0)
#define AFD_SOCKNAME_RSP_OFF_ADDR        ((size_t)4) /* the TRANSPORT_ADDRESS */
#define AFD_SOCKNAME_RSP_SIZE            ((size_t)AFD_TDI_ADDRESS_INFO_SIZE_IP)

#define AFD_PEERNAME_RSP_OFF_ADDR        ((size_t)0)
#define AFD_PEERNAME_RSP_SIZE            ((size_t)(4 + 2 + 2 + TDI_ADDRESS_LENGTH_IP))

/* ---- helpers shared by src/socket/ (every .c there) (src/socket/afdsupport.c) ------ */
/* socklen_t is `unsigned` (include/alltypes.h.in) -- spelled that way
 * here, not with <sys/socket.h>'s typedef, so this header (pulled into
 * src/select/select.c, which has no reason to include <sys/socket.h>)
 * stays self-contained. */
struct sockaddr;
/* Open a fresh AFD endpoint handle: the guts of socket() and of the new
 * handle accept() installs for an incoming connection.  `socktype` is
 * the plain <sys/socket.h> SOCK_STREAM/SOCK_DGRAM value, selecting
 * \Device\Tcp/IPPROTO_TCP or \Device\Udp/IPPROTO_UDP (see
 * AFD_TRANSPORT_TCP/AFD_TRANSPORT_UDP above) -- added for SOCK_DGRAM
 * (2026-09-01); every existing call site passed (implicitly)
 * SOCK_STREAM before this parameter existed, since AF_INET/SOCK_STREAM
 * was this project's only transport.  Returns 0, or -1 with errno. */
int __afd_open(HANDLE *out, int socktype);
/* The AfdOpenPacketXX EA buffer __afd_open() hands NtCreateFile, split
 * out so it can be inspected without a device: __afd_open_ea_size()
 * returns the exact byte count (no slack -- see AFD_EA_HEADER_SIZE),
 * and __afd_build_open_ea() fills that many bytes at `buf`, always for
 * the AF_INET/SOCK_STREAM/IPPROTO_TCP transport (the only one that
 * existed when these two no-argument convenience wrappers were
 * written; test/posix-socket-shape.c relies on that fixed choice).  buf
 * must be at least 4-byte aligned, which is what NT's own EA validator
 * requires of the whole entry.  test/posix-socket-ea.c re-parses the
 * result and asserts every invariant NT checks; it is the only reason
 * these are separate functions, and it runs on hosts with no working
 * \Device\Afd at all. */
unsigned long __afd_open_ea_size(void);
void __afd_build_open_ea(void *buf);
/* The same build function, with the packet shape AND the socket type
 * named rather than detected/fixed: AFD_SHAPE_NT4 or AFD_SHAPE_NT6,
 * SOCK_STREAM or SOCK_DGRAM.  These exist so that a test can build and
 * check *any* combination on any host, including ones the host it runs
 * on would never choose -- otherwise the legacy layout, or the
 * SOCK_DGRAM/UDP fields, would be unasserted everywhere CI can reach.
 * Library code should call __afd_open() and let it thread
 * __afd_open_shape() and its own `socktype` argument through.
 *
 * __afd_open_ea_size_for() does NOT take a socktype: "\Device\Tcp" and
 * "\Device\Udp" are both 11 characters, so the two transports produce
 * byte-identical packet sizes -- only __afd_build_open_ea_for()'s
 * *contents* (the name text itself, and the NT6 shape's AddressFamily/
 * SocketType/Protocol fields) depend on which one is being built. */
unsigned long __afd_open_ea_size_for(int shape);
void __afd_build_open_ea_for(int shape, int socktype, void *buf);
/* Which shape this platform's afd.sys reads: AFD_SHAPE_NT6 on NT 6.0
 * and later (real Windows, Wine), AFD_SHAPE_NT4 below that (ReactOS,
 * which targets NT 5.2).  Decided from PEB.OSMajorVersion via
 * __nt_version_at_least(); see this header's socket-creation banner for
 * why this one decision is version-gated instead of probed, and
 * src/internal/ntversion.c for when that is ever allowed again. */
int __afd_open_shape(void);
/* The IOCTL_AFD_BIND request body, split out for exactly the same
 * reason and inspected exactly the same way: __afd_bind_request_size()
 * returns the byte count the ioctl declares (26, not
 * sizeof(AFD_BIND_DATA)), and __afd_build_bind_request() fills that
 * many bytes at `buf` from a sockaddr, returning 0, or -1 with
 * errno=EINVAL/EAFNOSUPPORT for an address this project cannot express.
 * buf must be 4-byte aligned and at least sizeof(AFD_BIND_DATA) bytes
 * (the two bytes of tail slack are not written).
 * test/posix-socket-bind.c re-parses the result by offset with no
 * reference to this header, and runs with no \Device\Afd at all. */
unsigned long __afd_bind_request_size(void);
/* buf required: cast to AFD_BIND_DATA * and written through
 * unconditionally (`bd->Address`/`bd->ShareType`), with no NULL check
 * anywhere in src/socket/afdsupport.c's own body. Its one real call
 * site (src/socket/nt/plat_socket.c) always passes `&bd`, the address
 * of its own local AFD_BIND_DATA. addr is NOT required here: it is only
 * ever forwarded into __afd_addr_from_sockaddr(), which already carries
 * its own real `if (!addr || ...)` check -- addr is genuinely optional
 * at that function's own contract, matching bind()'s/connect()'s shared
 * validation shape. */
int __afd_build_bind_request(void *buf, unsigned long share_type,
                             const struct sockaddr *addr, unsigned len)
    __attribute__((nonnull(1)));
/* The IOCTL_AFD_CONNECT request body, split out and inspected exactly
 * the same way, and for a sharper reason: its layout is the one place
 * ReactOS and phnt disagree, and they disagree only on x86_64, so no
 * amount of i386 testing can catch a regression here.
 * __afd_connect_request_size() returns the byte count the ioctl
 * declares (46 on x86_64, 34 on i386 -- not sizeof(AFD_CONNECT_INFO),
 * which rounds up), and __afd_build_connect_request() fills that many
 * bytes at `buf` from a sockaddr, returning 0, or -1 with
 * errno=EINVAL/EAFNOSUPPORT.  buf must be pointer-aligned and at least
 * sizeof(AFD_CONNECT_INFO) bytes.  test/posix-socket-connect.c
 * re-parses the result by offset with no reference to this header, and
 * runs with no \Device\Afd at all. */
unsigned long __afd_connect_request_size(void);
int __afd_build_connect_request(void *buf, const struct sockaddr *addr, unsigned len);
/* The IOCTL_AFD_SELECT request body, built and read back through the
 * AFD_POLL_REQ_OFF_* and AFD_POLL_H_OFF_* offsets for the reason that
 * header section gives: ReactOS's ULONG_PTR Exclusive puts Handles at
 * +24 on x86_64, where Microsoft's own AFD source, phnt, wepoll and
 * libuv all put it at +16.  __afd_poll_request_size(n) is the byte
 * count for n handles; __afd_build_poll_request() zeroes that many
 * bytes at `buf` and fills Timeout/HandleCount/Exclusive;
 * __afd_poll_set_handle() fills one array element;
 * __afd_poll_get_events()/__afd_poll_get_status() read array slot i
 * back raw, and __afd_poll_get_handle_count() reads the reply's own
 * NumberOfHandles.  `buf` must be pointer-aligned and at least
 * __afd_poll_request_size(n) bytes.
 * test/posix-socket-poll.c re-parses the result by offset with no
 * reference to this header, and runs with no \Device\Afd at all.
 *
 * *** Reading the reply: use __afd_poll_events_for(), not
 * __afd_poll_get_events(0). ***
 *
 * The raw slot accessors are for the layout test.  A caller
 * interpreting an actual reply must go through
 * __afd_poll_events_for(), which reads NumberOfHandles first and only
 * looks at slots the driver says it wrote, matching on the handle.
 * Two separate properties of AfdPoll() make the indexed read wrong:
 *
 *   - It reports *nothing* by writing nothing.  poll.c sets
 *     `pollInfo->NumberOfHandles = 0;` before its readiness scan and
 *     completes with `Irp->IoStatus.Information = (ULONG)pollHandleInfo
 *     - (ULONG)pollInfo;`, which on a zero-event poll is the 16 bytes
 *     of header alone.  IOCTL_AFD_SELECT is METHOD_BUFFERED, so the
 *     I/O manager copies back exactly those Information bytes -- the
 *     caller's Handles[] is never overwritten and still holds whatever
 *     the caller put there.  If input and output are the same buffer,
 *     that is the *requested* event mask, and reading it back as a
 *     result reports every requested bit as fired.  An idle socket then
 *     looks readable and writable, on the success path, forever.
 *
 *     The obvious check gives the wrong answer here, so read it
 *     carefully: AfdPoll() *does* clear the field.  At the top of
 *     every iteration of its scan, before any event is tested, it
 *     does `pollHandleInfo->PollEvents = 0;` and
 *     `pollHandleInfo->Status = STATUS_SUCCESS;`, and for a
 *     one-handle poll pollHandleInfo is still pollInfo->Handles.
 *     "The driver leaves the field alone" is therefore false at
 *     the driver level, and an auditor who checks only that would
 *     clear this code.  The clear is real -- it just happens in
 *     the kernel's Irp->AssociatedIrp.SystemBuffer and does not
 *     survive the Information-bounded copy-back into the caller's
 *     buffer (ReactOS ntoskrnl/io/iomgr/irp.c: RtlCopyMemory of
 *     IoStatus.Information bytes into Irp->UserBuffer).
 *   - It compacts what it does write: the output pointer advances only
 *     for endpoints that fired, so output slot i is not request slot i.
 *
 * Both are read off the AFD driver's own poll.c (Copyright (c) 1992
 * Microsoft Corporation).  Every working consumer bounds by the count
 * the same way -- Wine's ws2_32 loops to params->count, wepoll and
 * libuv both reject NumberOfHandles < 1.
 *
 * Callers should also hand the ioctl a *separate*, zeroed output
 * buffer rather than aliasing the request, so that a reply the driver
 * declines to write reads back as zero rather than as the request; see
 * src/select/select.c's __FD_SOCKET case. */
unsigned long __afd_poll_request_size(unsigned long nhandles);
void __afd_build_poll_request(void *buf, long long timeout, unsigned long nhandles);
void __afd_poll_set_handle(void *buf, unsigned long i, HANDLE h, uint32_t events);
uint32_t __afd_poll_get_events(const void *buf, unsigned long i);
NTSTATUS __afd_poll_get_status(const void *buf, unsigned long i);
uint32_t __afd_poll_get_handle_count(const void *buf);
uint32_t __afd_poll_events_for(const void *buf, unsigned long nrequested, HANDLE h);
/* Issue one AFD ioctl on socket handle h and wait for it to finish --
 * every AFD request (src/socket/ (every .c there)) goes through this.  STATUS_PENDING
 * is waited out on the handle itself (see __afd_open()'s comment on why
 * that works here instead of ReactOS's per-call NtCreateEvent).
 * *io_out, if not NULL, receives the final IO_STATUS_BLOCK (its
 * Information field is what bind()'s TdiAddressHandle-style results and
 * recv()/send()'s byte counts come from). */
NTSTATUS __afd_ioctl(HANDLE h, ULONG code, void *in, ULONG inlen, void *out, ULONG outlen, IO_STATUS_BLOCK *io_out);
/* sockaddr_in -> TRANSPORT_ADDRESS, validating family/length.  Returns
 * 0, or -1 with errno=EINVAL/EAFNOSUPPORT.
 *
 * out required: written unconditionally (`out->TAAddressCount`, ...)
 * once past the two early-return validation checks, with no NULL check
 * of out itself anywhere. Both real call sites (src/socket/afdsupport.c's
 * own __afd_build_bind_request()/__afd_build_connect_request()) pass
 * &bd->Address/&ta, never NULL. addr is NOT required: this function's
 * own `if (!addr || len < ...) { errno = EINVAL; return -1; }` is real
 * and load-bearing, not decoration -- it is what makes addr genuinely
 * optional at every one of ITS OWN callers' contracts (bind()/
 * connect()'s shared validation shape) too. */
int __afd_addr_from_sockaddr(const struct sockaddr *restrict addr, unsigned len, TRANSPORT_ADDRESS *restrict out)
    __attribute__((nonnull(3)));
/* TA_ADDRESS (as embedded in a TRANSPORT_ADDRESS) -> sockaddr_in,
 * truncating into *addr and *len the way accept()/recvfrom() are specified
 * to. */
void __afd_addr_to_sockaddr(const TA_ADDRESS *ta, struct sockaddr *addr, unsigned *len);
/* Interpret an IOCTL_AFD_WAIT_FOR_LISTEN reply: check that it actually
 * carries a peer address, and, if addr is not NULL, convert it in.
 * Returns 0, or -1 for a reply that does not describe one address --
 * which, over a buffer zeroed before the ioctl, is also what a
 * short Information-bounded copy-back looks like.  Reads the reply
 * through AFD_ACCEPT_RSP_OFF_*, so it takes the raw buffer rather than
 * an AFD_RECEIVED_ACCEPT_DATA and needs no particular alignment.
 * Sets no errno; the caller decides what the failure means. */
int __afd_accept_reply_addr(const void *reply, struct sockaddr *addr, unsigned *len);
/* The same interpretation, over a TRANSPORT_ADDRESS image on its own:
 * `ta` points at TAAddressCount, not at the enclosing reply.  Three
 * ioctls answer with one of these behind three different headers -- a
 * ULONG SequenceNumber (wait-for-listen), a ULONG ActivityCount
 * (get-sock-name), nothing at all (get-peer-name) -- so the header is
 * the caller's business and the address is this function's.  Checks
 * TAAddressCount >= 1 and AddressLength >= TDI_ADDRESS_LENGTH_IP before
 * reading anything, converts into *addr and *len with accept.html's
 * truncation rule when addr is not NULL, and returns 0, or -1 for a
 * reply that describes no address.  Sets no errno.  Reads exactly
 * 4 + 2 + 2 + TDI_ADDRESS_LENGTH_IP bytes and needs no alignment. */
int __afd_transport_addr_out(const void *ta, struct sockaddr *addr, unsigned *len);
/* The IOCTL_AFD_GET_SOCK_NAME and IOCTL_AFD_GET_PEER_NAME replies:
 * __afd_*_reply_size() is the exact byte count each ioctl's output
 * buffer declares for one AF_INET address (26 and 22 -- see the
 * getsockname/getpeername banner above for why they differ), and
 * __afd_*_reply_addr() interprets a buffer of that size, with
 * __afd_transport_addr_out()'s contract and return value.  Split out
 * like the bind/connect request builders and for the same reason:
 * test/posix-socket-getname.c re-parses both by offset with no
 * reference to this header, and runs with no \Device\Afd at all -- the
 * only place the +4-versus-+0 difference can be caught here. */
unsigned long __afd_sockname_reply_size(void);
int __afd_sockname_reply_addr(const void *reply, struct sockaddr *addr, unsigned *len);
unsigned long __afd_peername_reply_size(void);
int __afd_peername_reply_addr(const void *reply, struct sockaddr *addr, unsigned *len);

/* Per-socket state bits, stashed in struct __fd's otherwise-unused `pad`
 * byte for __FD_SOCKET descriptors only (test/networking-audit.md sec 2:
 * "dirflag and pos are meaningless for a socket and can stay zero/-1" --
 * true of pos, but bind()/listen()/connect() do need to remember a
 * little state across calls, and pad is the other field that sits
 * unused for every non-directory type already). */
#define AFD_ST_BOUND      0x01
#define AFD_ST_LISTENING  0x02
#define AFD_ST_CONNECTED  0x04
#define AFD_ST_REUSEADDR  0x08
/* SOCK_DGRAM, not SOCK_STREAM.  Numerically identical to
 * src/internal/plat_socket.h's own __SOCK_ST_DGRAM -- see that header's
 * banner for why the two definitions must never drift apart. */
#define AFD_ST_DGRAM      0x10

#endif

// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
