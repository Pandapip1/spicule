/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The WOW64-only repair fork() needs after RtlCloneUserProcess, for the
 * two ways a cloned thread comes back broken under WOW64 -- a 32-bit
 * spicule process on a 64-bit kernel -- that fork.c's own header comment
 * describes at a high level. Prior art: M2libc's x86/windows/process.c
 * calls this technique "heaven's gate" surgery.
 *
 * Everything here runs in the *parent*, operating on the clone's still-
 * CREATE_SUSPENDED process and thread handles, before fork.c ever calls
 * NtResumeThread -- the child never executes a single instruction in
 * its broken state; there is nothing for it to repair itself.
 *
 * ---- the FS-base problem ------------------------------------------------
 * A legitimately new WOW64 thread starts in 64-bit ntdll's
 * LdrInitializeThunk, which walks down through Wow64LdrpInitialize into
 * wow64cpu!BTCpuSimulate -- the loop that actually executes 32-bit code
 * one translated block at a time -- and it is *that* bring-up, not
 * anything the kernel does directly, which programs the thread's FS
 * descriptor to point at its 32-bit TEB.  A cloned thread skips all of
 * this: the context the kernel hands it looks like it is resuming
 * partway through the 32-bit ZwCreateUserProcess syscall stub, having
 * never gone through BTCpuSimulate at all, so FS is never programmed
 * and fs:0x18 (what __teb() depends on) faults the instant anything
 * touches it.
 *
 * The fix has two parts. First, the thread's *native* (64-bit) register
 * state is forced to look like it is only just entering BTCpuSimulate --
 * Rip at its entry point, Rsp still the thread's own stack, the segment
 * and flags registers a fresh 64-bit thread would have -- instead of
 * wherever the kernel actually left it.  Second, wow64cpu's context-
 * setting code (BTCpuSetContext), which runs from inside that loop the
 * first time it is entered, is told this is a cloned thread so it does
 * the FS reprogramming BTCpuSimulate would otherwise assume had already
 * happened at thread creation.  That signal is carried the same way a
 * real STATUS_PROCESS_CLONED return from RtlCloneUserProcess would be:
 * as the value of Eax in the thread's 32-bit (WOW64 CPU-area) context.
 *
 * ---- the SRW lock problem -----------------------------------------------
 * RtlCloneUserProcess -- the 32-bit one, in the 32-bit ntdll.dll every
 * WOW64 process has mapped, the same one fork.c calls directly -- holds
 * two internal SRW locks around the underlying clone syscall, and only
 * its own post-syscall code releases them: one unconditionally, the
 * other via RtlAcquireReleaseSRWLockExclusive, an acquire-then-release
 * used purely as a memory barrier.  The clone's address space is a
 * snapshot taken while both locks are held, and nothing in the child
 * will ever run the parent's release, so that barrier call deadlocks
 * forever on the way out of the very call this file is patching around.
 *
 * There is no exported symbol for that second lock -- it is a private
 * ntdll global -- so the only way to find it is a *measured* offset
 * from RtlCloneUserProcess's own address (which, being exported, is
 * stable and resolved normally).  This is exactly the offset fork.c's
 * own header comment already anticipated needing.  It is measured
 * against one Windows 11 build -- the same one M2libc's own notes are
 * against -- and nothing guarantees it holds on every build; there is
 * no documented, version-independent way to locate this lock, which is
 * the entire reason this technique exists instead of a supported API.
 * Writing zero over it is safe here specifically because the child is
 * still suspended and has not executed a single instruction since the
 * clone: nothing has raced on it, and the only thing that will ever
 * touch it is the one barrier call this unsticks.
 *
 * ---- how the native side is reached from 32-bit code --------------------
 * A WOW64 process's own 64-bit half -- native ntdll, wow64cpu.dll, and
 * the real (64-bit) NtGetContextThread/NtSetContextThread -- is not
 * something 32-bit code can just call.  NtWow64QueryInformationProcess64
 * and NtWow64ReadVirtualMemory64 (both already used elsewhere for
 * reading a WOW64 parent's 64-bit state) can *read* it, which is enough
 * to walk the 64-bit PEB's loaded-module list and each module's export
 * directory by hand and resolve real function addresses -- no offsets
 * needed for any of that, just the documented PE and LDR layouts, which
 * are stable across Windows versions unlike the raw RVAs above.
 *
 * Calling into that 64-bit code, though, needs an actual CPU mode
 * switch: a small stub, allocated once as an executable page in this
 * process, that far-calls into a 64-bit code segment (selector 0x33),
 * runs a native call with the resolved address, and far-returns back to
 * 32-bit code (selector 0x23) via retf.  That is the classic "heaven's
 * gate" idiom this file's header comment and M2libc's both refer to by
 * that name; gate_call() below is the whole of it.
 */

/* This translation unit implements spicule's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <string.h>
#include "libc.h"

/* ---- measured, WOW64-ntdll-build-specific offsets ----------------------
 * See this file's header comment: there is no exported symbol for
 * ntdll's clone-path SRW lock, so its address can only be found relative
 * to RtlCloneUserProcess's own (exported, stable) address by a fixed
 * offset measured on one real build.  If fork() is ever seen to hang in
 * a WOW64 child on some other build, this is the first thing to
 * re-measure. */
#define WOW64_RTLCLONEUSERPROCESS_RVA 0xbaa60
#define WOW64_STUCK_SRWLOCK_RVA       0x12d52c

/* CONTEXT_AMD64 flag values (CONTEXT_AMD64 tag 0x100000 | fields). */
#define CTX64_CONTROL                 0x100001   /* Rip,Rsp,SegCs,SegSs,EFlags */
#define CTX64_CONTROL_INTEGER_SEGMENTS 0x100007   /* + the integer and segment regs */
/* CONTEXT_i386 flag value: CONTEXT_FULL (control|integer|segments). */
#define CTX32_FULL                    0x10007

static void *align16(void *p)
{
	return (void *)(((ULONG)p + 15) & ~(ULONG)15);
}

/* ---- reading this process's own 64-bit half ----------------------------
 * All of these read via NtWow64ReadVirtualMemory64 against
 * NtCurrentProcess(): the addresses are 64-bit because they live above
 * the 4GB this 32-bit process can address directly, but they are still
 * this same process's own memory. */

static int wow64_read64(ULONGLONG addr, void *buf, ULONG len)
{
	ULONGLONG got = 0;
	NTSTATUS st = NtWow64ReadVirtualMemory64(NtCurrentProcess(), addr, buf, len, &got);
	return (NT_SUCCESS(st) && got == len) ? 0 : -1;
}

/* Read a NUL-terminated string in small chunks, stopping as soon as the
 * terminator is seen, so a name near the end of a mapped region is not
 * read past what is actually there. */
static int wow64_read_cstr(ULONGLONG addr, char *buf, unsigned max)
{
	unsigned i;
	for (i = 0; i < max; i += 16) {
		unsigned n = max - i < 16 ? max - i : 16;
		unsigned k;
		if (wow64_read64(addr + i, buf + i, n)) return -1;
		for (k = 0; k < n; k++) if (buf[i + k] == 0) return 0;
	}
	buf[max - 1] = 0;
	return 0;
}

/* Find a loaded 64-bit module by base name, walking PEB64.Ldr's
 * InLoadOrderModuleList the same way __teb()/__peb's own callers walk
 * the 32-bit one, just at 64-bit offsets (stable across Windows
 * versions: this is the documented LDR_DATA_TABLE_ENTRY/PEB shape, not
 * a measured offset). */
static int wow64_module_base(ULONGLONG peb64, const char *name, ULONGLONG *base_out)
{
	ULONGLONG ldr, head, cur;
	int guard;

	if (wow64_read64(peb64 + 0x18, &ldr, 8)) return -1;      /* PEB64.Ldr */
	head = ldr + 0x10;                                       /* InLoadOrderModuleList */
	if (wow64_read64(head, &cur, 8)) return -1;              /* head.Flink */

	for (guard = 0; cur != head && guard < 512; guard++) {
		ULONGLONG dllbase, namebuf_addr, next;
		USHORT namelen;
		char namebuf[64];
		unsigned i;

		if (wow64_read64(cur + 0x30, &dllbase, 8)) return -1;       /* DllBase */
		if (wow64_read64(cur + 0x58, &namelen, 2)) return -1;       /* BaseDllName.Length */
		if (wow64_read64(cur + 0x60, &namebuf_addr, 8)) return -1;  /* BaseDllName.Buffer */

		if (namelen >= sizeof namebuf * 2) namelen = sizeof(namebuf) * 2 - 2;
		{
			/* BaseDllName is UTF-16; name is a plain ASCII literal, so
			 * just read every other byte and compare case-insensitively. */
			unsigned char wide[128];
			if (wow64_read64(namebuf_addr, wide, namelen)) return -1;
			for (i = 0; i * 2 < namelen; i++) namebuf[i] = (char)wide[i * 2];
			namebuf[i] = 0;
		}
		for (i = 0; name[i] && namebuf[i]; i++) {
			char a = name[i], b = namebuf[i];
			if (a >= 'A' && a <= 'Z') a += 32;
			if (b >= 'A' && b <= 'Z') b += 32;
			if (a != b) break;
		}
		if (!name[i] && !namebuf[i]) { *base_out = dllbase; return 0; }

		if (wow64_read64(cur, &next, 8)) return -1;   /* entry.InLoadOrderLinks.Flink */
		cur = next;
	}
	return -1;
}

/* Resolve one exported function's address in a 64-bit module by walking
 * its PE32+ export directory -- the documented layout, not a measured
 * offset. */
static int wow64_export(ULONGLONG dllbase, const char *name, ULONGLONG *addr_out)
{
	ULONG e_lfanew, export_rva, n_names, addr_names, addr_ords, addr_funcs;
	unsigned i;

	if (wow64_read64(dllbase + 0x3C, &e_lfanew, 4)) return -1;         /* IMAGE_DOS_HEADER.e_lfanew */
	if (wow64_read64(dllbase + e_lfanew + 0x88, &export_rva, 4)) return -1; /* NT header + FileHeader(20) + OptHdr64 DataDirectory[0].VA */
	if (wow64_read64(dllbase + export_rva + 0x18, &n_names, 4)) return -1;   /* IMAGE_EXPORT_DIRECTORY.NumberOfNames */
	if (wow64_read64(dllbase + export_rva + 0x20, &addr_names, 4)) return -1; /* .AddressOfNames */
	if (wow64_read64(dllbase + export_rva + 0x24, &addr_ords, 4)) return -1;  /* .AddressOfNameOrdinals */
	if (wow64_read64(dllbase + export_rva + 0x1C, &addr_funcs, 4)) return -1; /* .AddressOfFunctions */

	for (i = 0; i < n_names; i++) {
		ULONG name_rva, func_rva;
		USHORT ord;
		char namebuf[64];
		unsigned j;

		if (wow64_read64(dllbase + addr_names + (ULONGLONG)i * 4, &name_rva, 4)) return -1;
		if (wow64_read_cstr(dllbase + name_rva, namebuf, sizeof namebuf)) return -1;
		for (j = 0; name[j] && namebuf[j] == name[j]; j++) ;
		if (name[j] || namebuf[j]) continue;

		if (wow64_read64(dllbase + addr_ords + (ULONGLONG)i * 2, &ord, 2)) return -1;
		if (wow64_read64(dllbase + addr_funcs + (ULONGLONG)ord * 4, &func_rva, 4)) return -1;
		*addr_out = dllbase + func_rva;
		return 0;
	}
	return -1;
}

/* ---- the heaven's gate itself -------------------------------------------
 * One executable page, allocated the first time it is needed and kept
 * for the lifetime of the process.  Its first 0x40 bytes are the fixed
 * 32-bit entry stub built once, below; its next bytes are a 64-bit call
 * stub rewritten before every gate_call() (only the target address
 * differs between calls -- NtGetContextThread64 once, then
 * NtSetContextThread64 -- so only that needs patching each time). */
static unsigned char *gate_page;
static volatile ULONG gate_arg1, gate_arg2, gate_result;

static int gate_init(void)
{
	PVOID addr = 0;
	SIZE_T sz = 4096;
	NTSTATUS st;
	unsigned char code[0x40];
	ULONG a1 = (ULONG)&gate_arg1, a2 = (ULONG)&gate_arg2, rs = (ULONG)&gate_result, g64;

	if (gate_page) return 0;

	st = NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &sz,
	                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(st)) return -1;
	gate_page = addr;
	g64 = (ULONG)(gate_page + 0x40);

	memset(code, 0x90, sizeof code);
	/* mov ecx, [&gate_arg1] ; mov edx, [&gate_arg2] -- these become the
	 * 64-bit call's rcx/rdx: writing a 32-bit register always zero-
	 * extends its 64-bit half, in every mode, so by the time the far
	 * call below lands in 64-bit code rcx/rdx already hold the correct
	 * (small, <4GB) values with no further work. */
	code[0x00] = 0x8B; code[0x01] = 0x0D; memcpy(code + 0x02, &a1, 4);
	code[0x06] = 0x8B; code[0x07] = 0x15; memcpy(code + 0x08, &a2, 4);
	/* push 0x33 ; push <64-bit stub offset> ; call fword ptr [esp] --
	 * the classic 32-to-64 "heaven's gate" transition: a far call whose
	 * operand (the far pointer we just pushed) points at 64-bit code,
	 * so control resumes there with CS reloaded to the 64-bit selector,
	 * while the call's own far return address (CS=0x23 here, EIP just
	 * past this instruction) sits on the stack for the far side's retf
	 * to come back to. */
	code[0x0C] = 0x6A; code[0x0D] = 0x33;
	code[0x0E] = 0x68; memcpy(code + 0x0F, &g64, 4);
	code[0x13] = 0xFF; code[0x14] = 0x1C; code[0x15] = 0x24;
	/* add esp, 8 -- discards the far-call operand pushed above, which
	 * "call fword ptr [esp]" reads but does not itself pop. */
	code[0x16] = 0x83; code[0x17] = 0xC4; code[0x18] = 0x08;
	/* mov [&gate_result], eax ; ret */
	code[0x19] = 0xA3; memcpy(code + 0x1A, &rs, 4);
	code[0x1E] = 0xC3;

	{
		size_t i;
		for (i = 0; i < sizeof code; i++) gate_page[i] = code[i];
	}
	return 0;
}

/* Call a native 64-bit function of two pointer-sized arguments, from
 * this WOW64 process's own thread, no other threads involved, and
 * return its result truncated to 32 bits (every status this file cares
 * about fits in 32 bits regardless of RAX's full width). */
static ULONG gate_call(ULONGLONG target, ULONG arg1, ULONG arg2) // NOLINT(bugprone-easily-swappable-parameters) -- target and argument slots have fixed gate-call roles
{
	unsigned char blob[] = {
		0x49, 0x89, 0xE4,                         /* mov r12, rsp        -- save, so the far return's stack position doesn't depend on incoming alignment */
		0x48, 0x83, 0xE4, 0xF0,                   /* and rsp, -16        -- Win64 ABI requires rsp 16-aligned before `call` */
		0x48, 0x83, 0xEC, 0x20,                   /* sub rsp, 0x20       -- 32 bytes of shadow space for the callee */
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,        /* mov rax, imm64      -- target address, patched below */
		0xFF, 0xD0,                                 /* call rax */
		0x4C, 0x89, 0xE4,                            /* mov rsp, r12        -- restore, so retf finds the far-call's own return frame */
		0xCB,                                          /* retf                -- back to 32-bit code (CS=0x23) */
	};

	if (gate_init()) return (ULONG)-1;
	memcpy(blob + 13, &target, 8);
	{
		size_t i;
		for (i = 0; i < sizeof blob; i++) gate_page[0x40 + i] = blob[i];
	}
	gate_arg1 = arg1;
	gate_arg2 = arg2;
	__asm__ __volatile__("call *%0" : : "r"(gate_page) : "eax", "ecx", "edx", "memory");
	return gate_result;
}

void __wow64_fixup_clone(HANDLE process, HANDLE thread) // NOLINT(bugprone-easily-swappable-parameters) -- fixed platform-backend contract; process and thread handles have distinct roles
{
	unsigned char pbi[48];
	ULONGLONG peb64, ntdll64, wow64cpu64;
	ULONGLONG nt_get_context64, nt_set_context64, btcpu_simulate64;
	ULONGLONG rsp;

	{
		ULONG ret_len = 0;
		NTSTATUS st = NtWow64QueryInformationProcess64(NtCurrentProcess(), ProcessBasicInformation,
		                                                pbi, sizeof pbi, &ret_len);
		if (!NT_SUCCESS(st)) return;
	}
	memcpy(&peb64, pbi + 8, 8);   /* PROCESS_BASIC_INFORMATION64.PebBaseAddress */

	if (wow64_module_base(peb64, "ntdll.dll", &ntdll64)) return;
	if (wow64_module_base(peb64, "wow64cpu.dll", &wow64cpu64)) return;
	if (wow64_export(ntdll64, "NtGetContextThread", &nt_get_context64)) return;
	if (wow64_export(ntdll64, "NtSetContextThread", &nt_set_context64)) return;
	if (wow64_export(wow64cpu64, "BTCpuSimulate", &btcpu_simulate64)) return;

	/* Step 1: read the clone's own native Rsp -- BTCpuSimulate is going
	 * to be entered as if fresh, on the thread's own existing stack, not
	 * a new one. */
	{
		unsigned char raw[0x4D0 + 16], *ctx = align16(raw);
		ULONG flags = CTX64_CONTROL_INTEGER_SEGMENTS;
		size_t i;
		for (i = 0; i < 0x4D0; i++) ctx[i] = 0;
		memcpy(ctx + 0x30, &flags, 4);                        /* ContextFlags */
		if (gate_call(nt_get_context64, (ULONG)thread, (ULONG)ctx)) return;
		memcpy(&rsp, ctx + 0x98, 8);                           /* Rsp */
	}

	/* Step 2: redirect the clone's native context to BTCpuSimulate's own
	 * entry point, on that same stack, with fresh 64-bit-mode segment
	 * and flags registers -- i.e. exactly the state a legitimately new
	 * WOW64 thread has just before its own FS-base bring-up runs, which
	 * is the state this clone was never given. */
	{
		unsigned char raw[0x4D0 + 16], *ctx = align16(raw);
		ULONG flags = CTX64_CONTROL, eflags = 0x202;
		USHORT cs = 0x33, ss = 0x2B;
		size_t i;
		for (i = 0; i < 0x4D0; i++) ctx[i] = 0;
		memcpy(ctx + 0x30, &flags, 4);                         /* ContextFlags */
		memcpy(ctx + 0x38, &cs, 2);                            /* SegCs */
		memcpy(ctx + 0x42, &ss, 2);                            /* SegSs */
		memcpy(ctx + 0x44, &eflags, 4);                        /* EFlags */
		memcpy(ctx + 0x98, &rsp, 8);                           /* Rsp */
		memcpy(ctx + 0xF8, &btcpu_simulate64, 8);              /* Rip */
		if (gate_call(nt_set_context64, (ULONG)thread, (ULONG)ctx)) return;
	}

	/* Step 3: mark the clone as STATUS_PROCESS_CLONED in its own 32-bit
	 * (WOW64 CPU-area) context's Eax -- the same flag a real clone
	 * return from RtlCloneUserProcess carries, which is what tells
	 * BTCpuSetContext, the first time it runs for this thread, to
	 * reprogram FS instead of assuming it already happened.  This half
	 * of the context is already thunked for 32-bit callers, so it needs
	 * no gate. */
	{
		unsigned char raw[0x2CC + 16], *ctx = align16(raw);
		ULONG flags = CTX32_FULL, eax = STATUS_PROCESS_CLONED;
		NTSTATUS st;
		size_t i;
		for (i = 0; i < 0x2CC; i++) ctx[i] = 0;
		memcpy(ctx, &flags, 4);                                /* ContextFlags */
		st = NtGetContextThread(thread, ctx);
		if (!NT_SUCCESS(st)) return;
		memcpy(ctx + 0xB0, &eax, 4);                           /* Eax */
		NtSetContextThread(thread, ctx);
	}

	/* Step 4: zero the stuck SRW lock in the child -- see this file's
	 * header comment on why this offset, not an export, is the only way
	 * to find it, and why zeroing it here is safe.  Best-effort: if this
	 * write fails there is nothing else to try, and leaving the clone as
	 * it is no worse than not having attempted the repair at all. */
	{
		unsigned char zero[4] = { 0, 0, 0, 0 };
		SIZE_T written;
		// NOLINTNEXTLINE(bugprone-casting-through-void) -- WOW64 repair computes an object address from the ABI function entry address
		unsigned char *lock = (unsigned char *)(void *)RtlCloneUserProcess
		                     - WOW64_RTLCLONEUSERPROCESS_RVA + WOW64_STUCK_SRWLOCK_RVA;
		NtWriteVirtualMemory(process, lock, zero, 4, &written);
	}
}

// NOLINTEND(misc-include-cleaner)
