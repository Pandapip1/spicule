/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * The console input line discipline.
 *
 * A POSIX terminal has a line discipline between the device and read():
 * it is what turns the interrupt character into SIGINT instead of data.
 * On NT that job belongs to conhost, and it only does it while
 * ENABLE_PROCESSED_INPUT is set -- at which point Ctrl-C never reaches
 * the input stream at all, and the resulting console control event is
 * delivered by injecting a thread into this process through user32
 * (microsoft/terminal, doc/ConsoleCtrlEvent.md: "conhost requests that
 * user32 injects a thread into the attached console application ...
 * ntuser's exitwin.c CreateCtrlThread"), which is why catching it needs
 * kernel32's SetConsoleCtrlHandler and has no ntdll equivalent.
 *
 * So this library does the other half itself.  Once a program leaves
 * canonical mode (src/termios/termios.c, tcsetattr() clearing ICANON),
 * ENABLE_PROCESSED_INPUT goes off with ENABLE_LINE_INPUT and conhost
 * starts delivering Ctrl-C as a plain 0x03 byte -- Microsoft's own
 * conhost makes that conditional explicit, src/host/input.cpp's
 * HandleGenericKeyEvent only raising a control event for 'C' `&&
 * IsInProcessedInputMode()` and otherwise letting the key event fall
 * through into the input buffer.  From then on the thread below is the
 * sole reader of the handle and does the discipline's job in software:
 * 0x03 becomes SIGINT and is consumed rather than delivered, exactly as
 * a tty driver does for VINTR when ISIG is set, and every other byte is
 * queued for the application.
 *
 * Why a dedicated thread rather than doing it inside read(): the
 * interrupt has to be noticed when the key is pressed, not when some
 * thread happens to call read().  NtReadFile on a console handle blocks
 * on a real event (conhost's inputBuffer.cpp only SetEvent()s when
 * records are written; nothing spins), so a thread parked in it costs
 * nothing until a key arrives.
 *
 * Why canonical mode is left alone: with ENABLE_LINE_INPUT still set,
 * conhost holds the line in its own editor and hands it over only at
 * Enter, so an interrupt character would be seen a whole line late --
 * worse than the console's own handling, not better.  Taking that case
 * over honestly would mean reimplementing line editing here.  So a
 * program that never leaves canonical mode is untouched: same console
 * mode, same reads, same Ctrl-C behavior it had before this file
 * existed.
 *
 * Ctrl-Break is a documented residual gap, not an oversight.  conhost
 * handles VK_CANCEL unconditionally -- src/host/input.cpp raises
 * CTRL_BREAK_EVENT and flushes the input buffer without consulting
 * IsInProcessedInputMode() at all -- so a Ctrl-Break keystroke can
 * never appear in the byte stream this thread reads, in any console
 * mode.  There is nothing here to scan for.  The kernel32 build still
 * catches it through SetConsoleCtrlHandler (src/signal/signal.c); the
 * ntdll-only build cannot, and does not pretend to.
 */

/* This translation unit implements ntlibc's freestanding -nostdinc
 * public-header contract; transitive ABI declarations are intentional,
 * so hosted include ownership and unused-include advice do not apply. */
// NOLINTBEGIN(misc-include-cleaner)
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include "libc.h"
#include "conin.h"
#include "plat_signal.h"
#include "plat_thread.h"

#define CONIN_QUEUE 4096
#define CONIN_CHUNK 256
#define CHAR_INTR 0x03

static struct {
	__plat_handle_t h;          /* the console input handle, once owned */
	__plat_handle_t arrival;    /* auto-reset; set on every arrival */
	__plat_handle_t lock;       /* auto-reset, created signalled: a mutex */
	/* Written once by the reader thread and read unlocked by every
	 * other one: an aligned int either reads as 0 or as the real tid,
	 * and both answers route __conin_read() somewhere correct. */
	pid_t owner;                /* the reader thread's own tid */
	int soft_isig;              /* this thread owes the application SIGINT */
	int ended;                  /* the handle stopped producing input */
	unsigned head, tail;        /* head == tail means empty */
	unsigned char q[CONIN_QUEUE];
} conin;

static void conin_lock(void) { NtWaitForSingleObject(conin.lock, FALSE, 0); }
static void conin_unlock(void) { NtSetEvent(conin.lock, 0); }

static unsigned queued(void) { return conin.head - conin.tail; }

/* Bytes that do not fit are dropped, the same thing a real terminal does
 * to a full input queue. */
static void queue_push(unsigned char c)
{
	if (queued() >= CONIN_QUEUE) return;
	conin.q[conin.head % CONIN_QUEUE] = c;
	conin.head++;
}

/* One pass over what NtReadFile just produced, splitting it into the
 * interrupt character (consumed, raised) and everything else (queued).
 * Returns nonzero if an interrupt was seen, so the caller can raise it
 * with no lock of this file's held. */
static int consume_chunk(const unsigned char *p, unsigned n)
{
	int intr = 0;
	unsigned i;

	conin_lock();
	for (i = 0; i < n; i++) {
		if (p[i] == CHAR_INTR && conin.soft_isig) intr = 1;
		else queue_push(p[i]);
	}
	conin_unlock();
	return intr;
}

/* The sole reader of the console input handle for the rest of this
 * process's life.  Runs detached, like every other thread this library
 * creates. */
static ULONG NTAPI conin_thread(PVOID arg)
{
	unsigned char chunk[CONIN_CHUNK];

	(void)arg;
	conin.owner = gettid();
	for (;;) {
		IO_STATUS_BLOCK io;
		NTSTATUS st;
		int intr;

		io.Status = 0;
		io.Information = 0;
		st = NtReadFile(conin.h, 0, 0, 0, &io, chunk, (ULONG)sizeof chunk, 0, 0);
		if (st == STATUS_PENDING) {
			NtWaitForSingleObject(conin.h, FALSE, 0);
			st = io.Status;
		}
		if (!NT_SUCCESS(st) || io.Information == 0) {
			/* End of input, or a console that has gone away:
			 * publish it once and stop.  Readers see a
			 * permanent end-of-file rather than a hang. */
			conin_lock();
			conin.ended = 1;
			conin_unlock();
			__plat_event_set(conin.arrival);
			return 0;
		}

		intr = consume_chunk(chunk, (unsigned)io.Information);
		__plat_event_set(conin.arrival);

		if (intr) {
			/* Same discipline src/signal/signal.c's kernel32
			 * ctrl_handler() uses, on the same kind of thread:
			 * the disposition runs here, and a thread blocked in
			 * __conin_read() below notices through
			 * __sig_caught_count() and returns EINTR. */
			__sig_lock();
			__raise_internal(SIGINT);
			__sig_unlock();
			__sig_notify_delivery();
			__plat_event_set(conin.arrival);
		}
	}
}

int __conin_takeover(__plat_handle_t h)
{
	__plat_handle_t thr;

	if (conin.h) return conin.h == h ? 0 : -1;

	conin.lock = __plat_sigevent_create(1);
	if (!conin.lock) return -1;
	conin.arrival = __plat_sigevent_create(0);
	if (!conin.arrival) { __plat_close(conin.lock); conin.lock = 0; return -1; }

	/* Published before the thread starts, since the thread reads it
	 * first thing; nothing else looks at conin.h until the takeover
	 * has been declared successful. */
	conin.h = h;
	if (__plat_thread_start((void *)conin_thread, 0, &thr) < 0) {
		conin.h = 0;
		__plat_close(conin.arrival);
		__plat_close(conin.lock);
		conin.arrival = conin.lock = 0;
		return -1;
	}
	__plat_close(thr);   /* detached, like sigdelivery.c's own */
	return 0;
}

void __conin_set_isig(int on)
{
	if (!conin.h) return;
	conin_lock();
	conin.soft_isig = on;
	conin_unlock();
}

int __conin_owns(__plat_handle_t h) { return conin.h != 0 && conin.h == h; }

int __conin_pending(void)
{
	int ready;

	if (!conin.h) return 0;
	conin_lock();
	ready = queued() != 0 || conin.ended;
	conin_unlock();
	return ready;
}

__plat_handle_t __conin_event(void) { return conin.arrival; }

ssize_t __conin_read(void *buf, size_t count)
{
	unsigned char *out = buf;

	/* A signal disposition runs on the thread that raised it, so a
	 * SIGINT handler that reads the console is running on the reader
	 * thread itself -- the one thread that must never wait for the
	 * reader thread. It reads the device directly instead, which is
	 * safe precisely because that thread is here rather than in its
	 * own NtReadFile. */
	if (conin.owner && gettid() == conin.owner) {
		IO_STATUS_BLOCK io;
		NTSTATUS st;

		io.Status = 0;
		io.Information = 0;
		st = NtReadFile(conin.h, 0, 0, 0, &io, buf, (ULONG)count, 0, 0);
		if (st == STATUS_PENDING) {
			NtWaitForSingleObject(conin.h, FALSE, 0);
			st = io.Status;
		}
		if (st == STATUS_END_OF_FILE) return 0;
		if (!NT_SUCCESS(st)) return __set_errno_status(st);
		return (ssize_t)io.Information;
	}

	for (;;) {
		unsigned long caught;
		unsigned available, left_behind;
		size_t took = 0;
		int ended;

		conin_lock();
		available = queued();
		ended = conin.ended;
		while (took < count && took < available) {
			out[took] = conin.q[conin.tail % CONIN_QUEUE];
			conin.tail++;
			took++;
		}
		left_behind = queued();
		conin_unlock();

		if (took) {
			/* Re-arm for any other waiter: the arrival event is
			 * auto-reset, so the wakeup this reader consumed
			 * would otherwise be lost to a second one. */
			if (left_behind) __plat_event_set(conin.arrival);
			return (ssize_t)took;
		}
		if (ended) return 0;

		/* Nothing queued: sleep until an arrival or a signal. The
		 * caught-count baseline is select()'s own EINTR test
		 * (src/select/select.c): a signal that was actually caught
		 * during the wait interrupts the read, a merely pending one
		 * does not. */
		caught = __sig_caught_count();
		{
			__plat_handle_t waitset[2];
			int n = 0;
			__plat_handle_t sigev = __sig_delivery_event();

			waitset[n++] = conin.arrival;
			if (sigev) waitset[n++] = sigev;
			__plat_wait_any(waitset, (unsigned)n, TRUE, 0, 0);
		}
		if (__sig_caught_count() != caught) { errno = EINTR; return -1; }
	}
}

void __conin_reinit_after_fork(void)
{
	__plat_handle_t h = conin.h;

	if (!h) return;
	/* Only the calling thread was cloned, so the reader thread is gone
	 * and the two event handles name nothing live in this process.
	 * Forget all of it -- never NtClose()'d, for the reason
	 * sigdelivery.c's own reinit gives -- and take the handle over
	 * again from scratch, queue included. */
	conin.h = 0;
	conin.arrival = 0;
	conin.lock = 0;
	conin.owner = 0;
	conin.ended = 0;
	conin.head = conin.tail = 0;
	__conin_takeover(h);
}
// NOLINTEND(misc-include-cleaner)
