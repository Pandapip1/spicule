# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later
#
# libFuzzer harnesses for spicule.  See ../CONTRIBUTING.md.
#
#   make -C fuzz            build every harness
#   make -C fuzz run        build and run each for $(FUZZ_TIME) seconds
#   make -C fuzz clean
#
# or, from the top: `make fuzz` / `tools/fuzz.sh`.
#
# Every harness links the *real* src/*.c.  Nothing here is a copy of
# library code, and nothing here may become one: a harness that tests a
# transcription of printf.c stops testing printf.c the moment somebody
# edits printf.c.
#
# The library objects are built by ../tools/asan-build.sh, the same script
# `make asan` uses, so both are built from one mechanically derived file
# list.  They are rebuilt here rather than reused because libFuzzer needs
# the library itself instrumented for coverage (-fsanitize=fuzzer-no-link);
# without that the fuzzer gets no feedback from the code under test and is
# little better than random input.

srcdir  = ..
CC      = clang
ARCH   ?= x86_64
LIBDIR  = $(srcdir)/obj/fuzzlib$(MODESUF)
OUT     = $(srcdir)/obj/fuzz$(MODESUF)
FUZZ_TIME ?= 60

# ENGINE picks which fuzzing driver a harness is linked against.  Every
# fuzz_*.c file defines LLVMFuzzerTestOneInput() and nothing else on
# purpose: that is the portable seam both engines drive, so switching
# ENGINE never touches a harness source file.
#
#   libfuzzer  (default) linked against clang's built-in libFuzzer via
#              -fsanitize=fuzzer[-no-link], as everything below this
#              comment historically assumed.  ../tools/fuzz.sh drives it.
#
#   afl        linked against AFL++'s aflpp_driver -- a libFuzzer-driver
#              work-alike that supplies main(), and, when the binary is
#              built by afl-clang-fast, AFL++'s shared-memory persistent
#              loop (__afl_persistent_loop over __afl_fuzz_ptr /
#              __afl_fuzz_len) -- instead of clang's libFuzzer runtime.
#              Coverage feedback comes from afl-clang-fast's own LLVM
#              pass, not SanitizerCoverage, so -fsanitize=fuzzer is never
#              added in this mode: linking both would put two competing
#              edge-coverage instrumentations in one binary for no gain,
#              since afl-clang-fast does not need SanitizerCoverage to
#              begin with.  ../tools/afl-fuzz.sh drives this engine.
#              `apt-get install afl++` provides afl-clang-fast and the
#              driver archive; see that script for the checks it runs
#              before starting a campaign.
ENGINE ?= libfuzzer
ifeq ($(ENGINE),afl)
CC := afl-clang-fast
# The archive providing main() and ExecuteFilesOnyByOne() -- AFL++'s own
# driver, deliberately kept rather than replaced with a smaller one that
# would dodge the persistent-mode/forkserver path: that path is the one
# that actually drives spicule's fork() and signal delivery under load,
# and a harness that avoided it would stop testing that part of the ntdll
# shim rather than fixing what was wrong with it.  See fuzz/aflshim.c for
# what "wrong with it" turned out to mean and how it is fixed.
# The *system* archive AFL_DRIVER (below) is patched from.  Overridable
# because /usr/lib/afl is a Debian/Ubuntu packaging path; a source build
# of AFL++ puts it under the checkout's own directory instead.
AFL_DRIVER_SYS ?= /usr/lib/afl/libAFLDriver.a
# Where afl-clang-fast finds its *system* runtime -- the directory
# AFL_RTDIR (below) is patched from.  Overridable for the same reason
# AFL_DRIVER_SYS is.
AFL_SYSDIR ?= /usr/lib/afl
ENGINESUF   = -afl
# AFL++'s runtime -- afl-compiler-rt.o, linked into every harness
# automatically, and libAFLDriver.a's aflpp_driver.o, linked explicitly
# below as AFL_DRIVER -- calls open()/read()/write()/close()/shmat()/
# shmdt()/getenv()/fork()/waitpid()/sigaction()/signal()/fcntl() to talk
# to afl-fuzz and to run the persistent-mode fast path (fork a fresh
# child per test case, in this very process, rather than paying
# execve() each time).  Every one of those names is also a strong
# symbol in spicule, which wins the link -- the same class of bug, and
# the same fix, STATRENAME already applies to stat().  See
# fuzz/aflshim.c for which of them actually needed it (measured, not
# assumed: several of AFL++'s own calls tolerate spicule's versions well
# enough to still work) and what each fix cost.  AFL_RTDIR is a local
# copy of $(AFL_SYSDIR) with those symbols in afl-compiler-rt*.o (and,
# separately, in a patched copy of aflpp_driver.o repackaged as
# AFL_DRIVER, since it is a different object entirely and ships in its
# own archive rather than under AFL_SYSDIR) renamed to the __real_*
# names fuzz/aflshim.c defines; AFL_PATH -- an AFL++ option since
# classic AFL, meant for exactly this, relocating its runtime directory
# -- is exported for the whole recipe so afl-clang-fast's own link step
# picks the patched copy over its compiled-in default instead of
# $(AFL_SYSDIR).
AFL_DRIVER = $(AFL_RTDIR)/libAFLDriver.a
AFL_RTDIR := $(abspath $(srcdir)/obj/afl-rt)
export AFL_PATH := $(AFL_RTDIR)
# The library build (below) is told to instrument for libFuzzer's
# SanitizerCoverage via SPICULE_ASAN_EXTRA; afl-clang-fast instruments
# every object it compiles on its own; this flag is unneeded for it
# and unrelated to it, so it is empty in this engine.
LIBCOV_EXTRA =
else ifeq ($(ENGINE),libfuzzer)
ENGINESUF   =
LIBCOV_EXTRA = -fsanitize=fuzzer-no-link
else
$(error ENGINE must be libfuzzer or afl, not $(ENGINE))
endif

# SAN_MODE: WHICH SANITIZER, AND WHY THERE IS A CHOICE.
#
#   asan   (default) ASan + UBSan.  The only mode whose runs are evidence
#          about memory safety, and the mode CI runs.
#
#   ubsan  UBSan alone.  Not an optimisation and not a preference: on a
#          host with vm.overcommit_memory=2 it is the only mode that
#          starts.  ASan reserves its ~15 TB shadow with MAP_NORESERVE,
#          and Linux's do_mmap() honours that flag only when
#          sysctl_overcommit_memory != OVERCOMMIT_NEVER; under strict
#          overcommit the reservation is charged against CommitLimit and
#          refused, so every ASan-linked binary here dies before main()
#          with "failed to allocate 0xdfff0001000 bytes".  See the long
#          comment above SAN_MODE in ../tools/asan-build.sh, which
#          carries the full mechanism and the list of what this mode
#          stops detecting.
#
# THE SHORT VERSION OF THAT LIST, because it changes how a harness in
# this directory has to be written: UBSan has no shadow memory, so in
# this mode there is NO heap-buffer-overflow, use-after-free,
# double-free or leak detection.  A harness that wants an out-of-bounds
# write noticed here must bring its own check -- fuzz_pathname.c writes
# an eight-byte 0xAB guard past the string it hands basename()/dirname()
# and verifies it afterwards, which works in both modes.  A harness that
# relies on ASan alone still compiles and runs here; it just stops
# asserting what it was written to assert, silently.  Write for both.
#
#   make -C fuzz                    asan (default)
#   make -C fuzz ub                 build every harness in ubsan mode
#   make -C fuzz ubrun              ... and fuzz them
#   make -C fuzz ubcoverage         ... and report their coverage
#
# The two modes use disjoint object and corpus trees ($(MODESUF)), so
# neither invalidates the other's stamp and a mode switch never relinks
# against the other mode's objects.
# NOTHING IN THIS DIRECTORY MAY INVOKE WINE, AND IF THAT EVER CHANGES IT
# MUST SET THE CRASH-DIALOG OVERRIDE ITSELF.
#
# Everything here is native ELF: the harnesses are clang-built, and
# fuzz/ntstubs.c exists precisely so the NT surface is answered in-process
# rather than by an NT runtime.  Verified rather than assumed -- an
# `strace -f -e trace=execve` over a parse, a build, an ubrun and the
# asan-unavailable path executes only sh, make, find, sort, mkdir, ls,
# wc, clang and the harness itself.
#
# The reason this is written down instead of left obvious: the natural
# next feature here is replaying a crash artefact against a PE build
# under Wine, and that would be the first Wine invocation in this
# directory.  Without
#
#     WINEDEBUG=-all WINEDLLOVERRIDES=winedbg.exe=d
#
# an unhandled exception -- OR AN UNIMPLEMENTED-FUNCTION STUB -- makes
# Wine launch `winedbg --auto`, which opens a GUI window on the
# developer's real desktop and blocks for input, so the run hangs rather
# than fails.  A fuzz harness exists to provoke crashes, so here that is
# not an occasional popup but one per finding: a fuzzer having a good
# night becomes a popup storm on somebody's desktop.
#
# These must be set BY the new invocation, not inherited.  The Python
# suites set them for themselves (tools/run-tests.py, posix-opts.py,
# test-policy.py) and tools/gate.sh only mentions them in comments while
# relying on those tools -- so there is no ambient guarantee for a make
# recipe to lean on.
SAN_MODE ?= asan
ifeq ($(SAN_MODE),asan)
ifeq ($(ENGINE),afl)
# No -fsanitize=fuzzer: see the ENGINE comment above.  afl-clang-fast
# still honours -fsanitize=address,undefined exactly as plain clang does
# -- AFL++'s instrumentation pass and ASan/UBSan's are independent, and
# this is the same flag set the libfuzzer+asan combination below uses.
SAN        = -fsanitize=address,undefined -fno-sanitize-recover=undefined
FUZZER_LIB = $(AFL_DRIVER)
else
SAN       = -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined
# The driver's own -fsanitize=fuzzer supplies libFuzzer here.
FUZZER_LIB =
endif
SAN_RT    = libclang_rt.asan-$(ARCH).so
SAN_LINK  = -shared-libasan
CFLAGS_ORACLE = -fsanitize=address,undefined -g -O1 -w
# ntstubs.c's __interceptor_malloc and friends ARE the ASan runtime's in
# this mode; a local definition would collide with it.
SHIM_SRC  =
RUNFLAGS  =
MODESUF   = $(ENGINESUF)
else ifeq ($(SAN_MODE),ubsan)
# -fsanitize=fuzzer-no-link, and libFuzzer named explicitly below,
# rather than -fsanitize=fuzzer.  WITHOUT AddressSanitizer the driver
# adds libclang_rt.fuzzer_interceptors, which carries its own
# definitions of strcmp/strncmp/strstr for comparison feedback -- and
# spicule defines all three in this same link, so the link fails with
# "multiple definition of `strncmp'".  Naming libclang_rt.fuzzer
# directly gets libFuzzer without the interceptors and the collision
# does not arise.  The alternative, -Wl,--allow-multiple-definition,
# was tried first and is worse for a reason that is easy to miss: it
# links, but it silently decides which strcmp the whole binary uses,
# and in a library whose own strcmp is under test that is exactly the
# thing not to leave to link order.  libFuzzer loses its string-compare
# feedback in this mode; that is a fuzzing-efficiency cost, not a
# correctness one.
ifeq ($(ENGINE),afl)
# No -fsanitize=fuzzer-no-link here either, and so no interceptor
# collision to route around: this mode links AFL++'s driver archive, not
# a libFuzzer runtime, and the archive defines no strcmp/strncmp/strstr
# of its own (confirmed with `nm` -- it references them as undefined,
# same as any other caller of spicule).
SAN        = -fsanitize=undefined -fno-sanitize-recover=undefined
FUZZER_LIB = $(AFL_DRIVER)
else
SAN       = -fsanitize=fuzzer-no-link,undefined -fno-sanitize-recover=undefined
FUZZER_LIB = $(dir $(SAN_SO))libclang_rt.fuzzer-$(ARCH).a -lstdc++
endif
SAN_RT    = libclang_rt.ubsan_standalone-$(ARCH).so
# -shared-libsan is not optional.  With the static UBSan runtime, its
# start-up call to sysconf(_SC_SIGSTKSZ) binds at link time to spicule's
# sysconf, which answers 0, and the runtime dies in
# SetAlternateSignalStack before the program starts.  Same failure, same
# cause, as the -shared-libasan note in ../tools/asan-build.sh.
SAN_LINK  = -shared-libsan
CFLAGS_ORACLE = -fsanitize=undefined -g -O1 -w
# ...and here they are undefined, so ubsanshim.c supplies them.  See the
# file itself for what that costs.
SHIM_SRC  = ubsanshim.c
# libFuzzer's -detect_leaks defaults to 1 and drives its own leak
# heuristic plus __lsan_do_recoverable_leak_check.  There is no
# LeakSanitizer behind that here (ubsanshim.c's __lsan_* are no-ops), so
# leave it off rather than let it report a "leak" it cannot confirm.
# Meaningless to the afl engine too (it does not read libFuzzer flags at
# all), but harmless to leave set.
RUNFLAGS  = -detect_leaks=0
MODESUF   = -ubsan$(ENGINESUF)
else
$(error SAN_MODE must be asan or ubsan, not $(SAN_MODE))
endif

INC  = -I$(srcdir)/src/internal -I$(srcdir)/obj/include -I$(srcdir)/include \
       -I$(srcdir)/arch/$(ARCH) -I$(srcdir)/arch/generic
CFLAGS_HARNESS = $(SAN) -g -O1 -std=c99 -nostdinc -fno-builtin -w \
                 -D_XOPEN_SOURCE=700 -D_SPICULE_INTERNAL $(INC)
# host_oracle.c and ubsanshim.c are the two files built against the host
# headers; CFLAGS_ORACLE is set per mode above.
SAN_SO  = $(shell $(CC) -print-file-name=$(SAN_RT))
RPATH   = -Wl,-rpath,$(dir $(SAN_SO))
# libFuzzer calls stat() to decide whether the corpus path is a directory,
# and it was compiled against the host's struct stat, which is not spicule's.
# See fuzz/statshim.h -- without the seam every corpus directory looks absent.
#
# The seam used to be -Wl,--wrap=stat.  It is not any more, and the reason
# is a measured defect, not a preference: --wrap is a LINK-WIDE rename.  It
# redirects every undefined reference named `stat` in the link, and spicule's
# own objects are in that link -- src/glob/glob.c calls stat() at four
# sites, src/ftw/ftw.c and src/stdlib/mktemp.c at one each.  Each was being
# handed a 144-byte host `struct stat` in the 120-byte spicule one it had on
# its stack: a 24-byte overrun, with st_mode and st_nlink transposed, so
# glob() silently stopped recognising directories.  fuzz_glob reported it as
# "stack-buffer-overflow ... WRITE of size 144" on its first run; no harness
# had ever reached an internal stat() before, which is why a reviewed,
# reasoned-about shim had been wrong since it was written.
#
# STATRENAME fixes the cause instead.  objcopy renames `stat` to
# __real_stat throughout the *library* objects only -- the definition in
# src/stat/stat.o and every internal reference to it move together, so
# spicule's callers reach spicule's stat() directly and no rename can come
# between them.  The compiler runtime's objects are untouched, so
# libFuzzer's `stat` still binds to the host-layout shim ntstubs.c defines
# under that name.
#
# ONE RULE FOR HARNESS AUTHORS, because this cannot be enforced by the
# build: a harness is compiled against spicule's headers but is NOT part of
# the renamed set, so a plain stat() call from fuzz_*.c reaches the
# host-layout shim and overruns the caller's buffer exactly as glob did.
# Call __real_stat() instead; fuzz/fuzz_glob.c declares it and says so.
STATRENAME = stat=__real_stat
# $(SAN_SO) is named explicitly, and first: the shared ASan runtime has to
# be the first entry in the executable's library list or it refuses to
# start ("ASan runtime does not come first in initial library list").  The
# driver appends it after -ldl/-lm, which is too late.

HARNESSES = strtod printf scanf utf path strptime strtol strftime \
            fnmatch regex glob wordexp \
            shparse inet string search getopt env time pathname getdate \
            iconv strfmon catgets m4 sed ed awk grep expr \
            resolv nsswitch patch pax ar \
            util_printf tr find xargs cut \
            sort csplit od uudecode uuencode test \
            modeparse crontime attime \
            diff cmp dd \
            tput stty
EXES = $(HARNESSES:%=$(OUT)/fuzz_%)
SHIM_OBJ = $(SHIM_SRC:%.c=$(OUT)/%.o)
COVSHIM_OBJ = $(SHIM_SRC:%.c=$(COVOUT)/%.o)
# fuzz/aflshim.c, and the local patched runtime copy it pairs with (see
# the ENGINE=afl comment above): both are specific to that engine, so
# both are empty and pull nothing into a libfuzzer-engine link.
AFLSHIM_OBJ = $(if $(filter afl,$(ENGINE)),$(OUT)/aflshim.o,)
AFLRT_DEP   = $(if $(filter afl,$(ENGINE)),$(AFL_RTDIR)/.built,)

# What the instrumented library is built from.  Derived with find, never
# written out by hand: a hand-listed prerequisite set stops mentioning the
# file somebody adds tomorrow, and the harness would then be fuzzing a
# library that no longer matches src/.  The header sweep is deliberately
# coarse -- every header the sanitized build can see, not the ones a given
# .c happens to include -- because asan-build.sh is all-or-nothing anyway
# (it starts with `rm -rf $OBJ`), so a finer set would buy nothing.
LIBSRC := $(shell find $(srcdir)/src -name '*.c' 2>/dev/null | sort)
LIBHDR := $(shell find $(srcdir)/src $(srcdir)/include $(srcdir)/arch \
                       $(srcdir)/obj/include -name '*.h' 2>/dev/null | sort)
LIBDEP  = $(LIBSRC) $(LIBHDR) $(srcdir)/tools/asan-build.sh ntstubs.c

all: $(EXES)

# The stamp, not compiled.txt, is the target.  compiled.txt is written
# line by line as the loop compiles, so a run that dies in the middle
# leaves one behind that is newer than every source and describes only
# half a library -- exactly the newer-but-wrong file that defeats an mtime
# rule (see the comment above `kaem:` in the top-level Makefile).  The
# stamp is touched only after the script exits 0, and asan-build.sh's own
# `rm -rf $OBJ` removes the previous one before anything else, so a failed
# or interrupted build leaves no stamp and the next make rebuilds.
#
# The rebuild is all 202 objects, because that is the granularity the
# script offers; it costs about 7s (and 2s more to relink the four
# harnesses), and happens only when a source, a header or the script
# itself has actually changed.  An unconditional rebuild would be
# defensible at that price, but it is not needed: unlike `make kaem`
# there is no committed artefact here that a newer-but-wrong file could
# corrupt -- the inputs are the same files the script itself reads, and
# the only way to fool the stamp is to `touch` it by hand.
$(LIBDIR)/.built: $(LIBDEP)
	SPICULE_CC=$(CC) \
	SPICULE_SAN_MODE=$(SAN_MODE) \
	SPICULE_ASAN_OBJ=$(abspath $(LIBDIR)) \
	SPICULE_ASAN_EXTRA=$(LIBCOV_EXTRA) \
	$(srcdir)/tools/asan-build.sh --objects-only
	for o in $(LIBDIR)/obj/*.o; do objcopy --redefine-sym $(STATRENAME) "$$o"; done
	touch $@

$(OUT):
	mkdir -p $(OUT)

$(OUT)/host_oracle.o: host_oracle.c statshim.h | $(OUT)
	$(CC) $(CFLAGS_ORACLE) -c $< -o $@

# Built only in ubsan mode ($(SHIM_SRC) is empty otherwise, so this rule
# has nothing to make).  Against the host headers, like host_oracle.c.
$(OUT)/ubsanshim.o: ubsanshim.c | $(OUT)
	$(CC) $(CFLAGS_ORACLE) -c $< -o $@

# Built only for ENGINE=afl.  Against the host headers, like
# host_oracle.c -- see the file itself for what it does and why.
$(OUT)/aflshim.o: aflshim.c | $(OUT)
	$(CC) $(CFLAGS_ORACLE) -c $< -o $@

# A local, patched copy of AFL++'s runtime directory: everything under
# $(AFL_SYSDIR) is symlinked through unchanged except afl-compiler-rt*.o,
# which is copied and then has the symbols fuzz/aflshim.c defines
# redirected to it -- see that file for which ones and why.  The same
# treatment is given to a copy of libAFLDriver.a's one member,
# aflpp_driver.o, repackaged as $(AFL_DRIVER): that object ships in its
# own archive rather than under $(AFL_SYSDIR), so it cannot be patched
# by the loop below, but it needs the same getenv()/fcntl() redirects
# for the reason fuzz/aflshim.c's banner gives (its own is-this-AFL-fuzz
# detection, LLVMFuzzerRunDriver()'s `in_afl`, calls getenv() and
# fcntl(FORKSRV_FD, F_GETFD) directly -- and the getenv() short-circuits
# the fcntl() out of ever running at all when it, too, is unpatched).
# Not keyed to MODESUF: this
# content depends only on the installed AFL++ version, so the asan and
# ubsan engine=afl builds share one copy.
#
# No dependency on the system files' mtimes: an `apt upgrade` of afl++
# between builds is not a case this tree tries to detect on its own,
# same as it does not re-run tools/asan-build.sh because /usr/bin/clang
# changed underneath it.  `rm -rf obj/afl-rt` forces a refresh.
$(AFL_RTDIR)/.built:
	rm -rf "$(AFL_RTDIR)"
	mkdir -p "$(AFL_RTDIR)"
	for f in "$(AFL_SYSDIR)"/*; do \
	  b=$$(basename "$$f"); \
	  case "$$b" in \
	    afl-compiler-rt*.o) \
	      cp "$$f" "$(AFL_RTDIR)/$$b"; \
	      objcopy \
	        --redefine-sym open=__real_open \
	        --redefine-sym read=__real_read \
	        --redefine-sym write=__real_write \
	        --redefine-sym close=__real_close \
	        --redefine-sym shmat=__real_shmat \
	        --redefine-sym shmdt=__real_shmdt \
	        --redefine-sym getenv=__real_getenv \
	        --redefine-sym fork=__real_fork \
	        --redefine-sym waitpid=__real_waitpid \
	        --redefine-sym sigaction=__real_sigaction \
	        --redefine-sym signal=__real_signal \
	        --redefine-sym fcntl=__real_fcntl \
	        --redefine-sym raise=__real_raise \
	        --redefine-sym kill=__real_kill \
	        "$(AFL_RTDIR)/$$b" ;; \
	    libAFLDriver.a) ;; \
	    *) ln -s "$$f" "$(AFL_RTDIR)/$$b" ;; \
	  esac; \
	done
	cd "$(AFL_RTDIR)" && ar x "$(abspath $(AFL_DRIVER_SYS))" aflpp_driver.o
	objcopy \
	  --redefine-sym fcntl=__real_fcntl \
	  --redefine-sym getenv=__real_getenv \
	  "$(AFL_RTDIR)/aflpp_driver.o"
	ar rcs "$(AFL_RTDIR)/libAFLDriver.a" "$(AFL_RTDIR)/aflpp_driver.o"
	touch $@

# -DSPICULE_FUZZ_STATWRAP turns on the struct stat seam (fuzz/statshim.h).
# Only here: tools/asan-build.sh compiles its own copy of ntstubs.c for the
# test binaries, and those must keep seeing spicule's stat() as it is.
$(OUT)/ntstubs.o: ntstubs.c statshim.h $(LIBHDR) $(LIBDIR)/.built | $(OUT)
	$(CC) $(CFLAGS_HARNESS) -DSPICULE_FUZZ_STATWRAP -c $< -o $@

# The library objects are globbed by the shell, at recipe time.  $(wildcard)
# would be expanded by make against a directory it may have cached before
# the stamp rule refilled it, and an empty expansion links a harness with
# no spicule in it at all.
$(OUT)/fuzz_%: fuzz_%.c $(LIBHDR) $(OUT)/host_oracle.o $(SHIM_OBJ) $(AFLSHIM_OBJ) $(OUT)/ntstubs.o $(LIBDIR)/.built | $(OUT) $(AFLRT_DEP)
	$(CC) $(CFLAGS_HARNESS) $(SAN_LINK) $(RPATH) \
	  $(SAN_SO) $< $(OUT)/ntstubs.o $(OUT)/host_oracle.o $(SHIM_OBJ) $(AFLSHIM_OBJ) \
	  $(LIBDIR)/obj/*.o $(FUZZER_LIB) -ldl -lm -o $@

# fuzz_nsswitch: src/netdb/linux/ is not part of $(LIBDIR) -- every file
# under any src/*/linux/ directory is deliberately skipped by
# ../tools/asan-build.sh (see the comment above its `linux)` case: this
# native harness exercises the NT backend through ntstubs.c, and that
# directory has no nt/ counterpart standing in for it the way every
# other platform-split module does). __nsswitch_order() itself has no
# NT dependency at all -- fopen/fgets/fclose/strchr/strncmp/tolower,
# every one of them already in $(LIBDIR) -- so rather than widen that
# script's file selection for every harness, the real nsswitch.c is
# compiled here, once, straight from the source tree, and linked into
# this harness alone. Nothing in nsswitch.c changes: __nsswitch_order()
# was already non-static and already declared in src/internal/
# nsswitch.h, so this is a build-graph addition, not a source change.
# See fuzz/fuzz_nsswitch.c's own banner for the fuller reasoning, and
# fuzz/fuzz_resolv.c's for why resolv.c takes a different route
# (#include, not a linked object) to reach a `static` function this
# approach cannot expose.
$(OUT)/nsswitch.o: $(srcdir)/src/netdb/linux/nsswitch.c $(LIBHDR) | $(OUT)
	$(CC) $(CFLAGS_HARNESS) -c $< -o $@

$(OUT)/fuzz_nsswitch: fuzz_nsswitch.c $(LIBHDR) $(OUT)/host_oracle.o $(SHIM_OBJ) $(AFLSHIM_OBJ) $(OUT)/ntstubs.o $(OUT)/nsswitch.o $(LIBDIR)/.built | $(OUT) $(AFLRT_DEP)
	$(CC) $(CFLAGS_HARNESS) $(SAN_LINK) $(RPATH) \
	  $(SAN_SO) $< $(OUT)/ntstubs.o $(OUT)/host_oracle.o $(SHIM_OBJ) $(AFLSHIM_OBJ) $(OUT)/nsswitch.o \
	  $(LIBDIR)/obj/*.o $(FUZZER_LIB) -ldl -lm -o $@

# Leak detection on; see tools/asan-build.sh for why it can be trusted here.
# handle_abort=1 is what makes a differential mismatch produce a crash
# artefact rather than only three lines of stderr -- see tools/fuzz.sh,
# which explains it at length.
LEAKS ?= 1

# Where a run's findings live between runs.  One subtree per harness:
#
#   $(CORPUS)/<h>/corpus    libFuzzer's minimized corpus, re-read next run
#   $(CORPUS)/<h>/crashes   crash-<sha1> / leak-<sha1>, feedable to --repro
#
# SPICULE_FUZZ_MIRROR makes that subtree, and only that subtree, visible in
# ntstubs.c's simulated volume, so libFuzzer's own file I/O -- which goes
# through spicule, not the host -- can see and add to it.  See the block
# comment above mirror_init() in ntstubs.c.  Point CORPUS somewhere
# persistent (or let CI cache it) and each night resumes where the last
# one stopped instead of starting from random bytes.
CORPUS ?= $(abspath $(srcdir)/obj/fuzzcorpus$(MODESUF))

# ---------------------------------- can ASan start on this host at all?
#
# The same question tools/asan-build.sh asks, asked by the same script,
# so the two cannot drift into disagreeing.  See tools/asan-available.sh
# for the mechanism (MAP_NORESERVE is honoured only when overcommit is
# not OVERCOMMIT_NEVER), for why the answer is `unavailable` rather than
# `error`, and for the exit-77 convention.
#
# Without this, `make -C fuzz run` on a strict-overcommit host prints
# "AddressSanitizer failed to allocate 0xdfff0001000 bytes" once per
# harness and exits non-zero, which reads as a corrupt toolchain.  It has
# been read that way.
#
# TEST_PROFILE is not repeated here: the top-level Makefile holds the one
# default and this asks it for it.  In ubsan mode the check is skipped
# outright -- there is no shadow to reserve, so there is nothing for the
# profile to declare unavailable.
TEST_PROFILE ?= $(shell $(MAKE) -s -C $(srcdir) print-test-profile 2>/dev/null)
ifeq ($(SAN_MODE),asan)
CHECK_SAN = SPICULE_TEST_PROFILE="$(TEST_PROFILE)" $(srcdir)/tools/asan-available.sh || exit $$?;
else
CHECK_SAN = :;
endif

# DEBUGINFOD_URLS= : see the long comment in ../tools/fuzz.sh.  With it set
# -- Ubuntu exports it from /etc/profile.d/debuginfod.sh -- llvm-symbolizer
# makes a doomed HTTPS request for the harness's build-id before reading the
# DWARF that is already in the harness, and ASan's blocking read() on the
# symbolizer pipe hangs with it.
run: all
	@$(CHECK_SAN) \
	 rc=0; \
	for h in $(HARNESSES); do \
	   mkdir -p $(CORPUS)/$$h/corpus $(CORPUS)/$$h/crashes; \
	   before=$$(ls -1 $(CORPUS)/$$h/corpus | wc -l); \
	   echo "== fuzz_$$h ($(FUZZ_TIME)s, corpus $$before)"; \
	   SPICULE_FUZZ_MIRROR=$(CORPUS)/$$h DEBUGINFOD_URLS= \
	   LD_PRELOAD=$(SAN_SO) ASAN_OPTIONS=detect_leaks=$(LEAKS):handle_abort=1 \
	   UBSAN_OPTIONS=print_stacktrace=1 \
	   $(OUT)/fuzz_$$h $(RUNFLAGS) -max_total_time=$(FUZZ_TIME) -max_len=256 \
	     -print_funcs=0 -print_final_stats=1 \
	     -artifact_prefix=$(CORPUS)/$$h/crashes/ \
	     $(CORPUS)/$$h/corpus \
	   || { echo "   fuzz_$$h FOUND SOMETHING"; rc=1; }; \
	   echo "   corpus $$before -> $$(ls -1 $(CORPUS)/$$h/corpus | wc -l)"; \
	 done; exit $$rc

# ------------------------------------------------------------- coverage
#
#   make -C fuzz coverage                 every harness, per-file table
#   make -C fuzz coverage HARNESSES=path  one harness
#   make -C fuzz coverage FUNCS=1         per-function, not per-file
#   make -C fuzz coverage MODULE=src/regex  restrict to one module
#   make -C fuzz coverage ALL=1           list the 0.00% files too
#
# What this answers: "which src/*.c did harness X actually enter?"  A
# harness that compiles, runs and reports no crashes without ever
# reaching the module it names is a vacuous pass, and until this target
# existed there was no way to tell one from a real one.
#
# Why a second library build rather than adding the flags to the fuzzing
# one: -fprofile-instr-generate on the hot path costs throughput, and
# `make run` is a throughput job.  The two object trees are independent
# (COVLIB vs LIBDIR), so neither invalidates the other's stamp.
#
# THE PART THAT IS NOT OBVIOUS -- why a bare -fprofile-instr-generate
# writes nothing here, measured rather than assumed:
#
#   1. LLVM's profile runtime picks its output path in an .init_array
#      constructor, from getenv("LLVM_PROFILE_FILE").  getenv() in this
#      link is *spicule's*, reading spicule's `environ`, which ntstubs.c's
#      own constructor deliberately replaces with an empty one (see the
#      comment above that loop: a native test must not inherit the
#      harness's real environment).  So LLVM_PROFILE_FILE is invisible
#      no matter how it is set, and the runtime falls back to its
#      built-in default name, "default.profraw".
#   2. It then opens that name with fopen() -- again spicule's, which
#      goes to NtCreateFile in ntstubs.c, i.e. into the *simulated*
#      volume, which is ordinary process memory and evaporates on exit.
#      The profile is written every time; it is written into a file
#      system that does not outlive the process.
#
# Both are fixed here without touching src/ or the harnesses:
#
#   -fprofile-instr-generate=<path> bakes the output path into the
#   binary (__llvm_profile_filename), so no getenv is needed; and the
#   path is put inside SPICULE_FUZZ_MIRROR, the seam ntstubs.c already
#   provides for exactly this -- one host directory made visible in the
#   simulated volume so libFuzzer's own file I/O can reach the host.
#
# What this deliberately does NOT do: it does not stop the harness
# linking src/exit/exit.c, and does not intercept NtTerminateProcess.
# spicule's exit() is entered (measured: libFuzzer's FuzzerDriver calls
# exit(0), not _Exit()), runs __funcs_on_exit(), and the profile
# runtime's atexit handler fires from there.  exit(), atexit() and
# __stdio_exit() stay under test, unchanged, in the coverage build as
# in the fuzzing one.
COVLIB   = $(srcdir)/obj/fuzzcovlib$(MODESUF)
COVOUT   = $(srcdir)/obj/fuzzcov$(MODESUF)
COVDATA  = $(srcdir)/obj/fuzzcovdata$(MODESUF)
COV_TIME ?= 20
PROF      = -fprofile-instr-generate -fcoverage-mapping
COVEXES   = $(HARNESSES:%=$(COVOUT)/fuzz_%)

$(COVLIB)/.built: $(LIBDEP)
	SPICULE_SAN_MODE=$(SAN_MODE) \
	SPICULE_ASAN_OBJ=$(abspath $(COVLIB)) \
	SPICULE_ASAN_EXTRA='-fsanitize=fuzzer-no-link $(PROF)' \
	$(srcdir)/tools/asan-build.sh --objects-only
	for o in $(COVLIB)/obj/*.o; do objcopy --redefine-sym $(STATRENAME) "$$o"; done
	touch $@

$(COVOUT):
	mkdir -p $(COVOUT)

$(COVOUT)/host_oracle.o: host_oracle.c statshim.h | $(COVOUT)
	$(CC) $(CFLAGS_ORACLE) -c $< -o $@

$(COVOUT)/ubsanshim.o: ubsanshim.c | $(COVOUT)
	$(CC) $(CFLAGS_ORACLE) $(PROF) -c $< -o $@

$(COVOUT)/ntstubs.o: ntstubs.c statshim.h $(LIBHDR) $(COVLIB)/.built | $(COVOUT)
	$(CC) $(CFLAGS_HARNESS) $(PROF) -DSPICULE_FUZZ_STATWRAP -c $< -o $@

# The baked-in profile path is per harness and lives under COVDATA/<h>,
# which coverage.sh hands to SPICULE_FUZZ_MIRROR as that run's mirror
# root.  A per-harness subdirectory, not one shared one: ntstubs.c
# imports the whole mirror directory into the volume at start-up, so a
# shared one would make every run slurp in every other run's profraw.
$(COVOUT)/fuzz_%: fuzz_%.c $(LIBHDR) $(COVOUT)/host_oracle.o $(COVSHIM_OBJ) $(COVOUT)/ntstubs.o $(COVLIB)/.built | $(COVOUT)
	$(CC) $(CFLAGS_HARNESS) $(PROF) \
	  -fprofile-instr-generate=$(abspath $(COVDATA))/$*/fuzz_$*.profraw \
	  $(SAN_LINK) $(RPATH) \
	  $(SAN_SO) $< $(COVOUT)/ntstubs.o $(COVOUT)/host_oracle.o $(COVSHIM_OBJ) \
	  $(COVLIB)/obj/*.o $(FUZZER_LIB) -ldl -lm -o $@

# fuzz_nsswitch's coverage-tree twin of the $(OUT)/nsswitch.o rule above:
# same reason (src/netdb/linux/ is not part of $(COVLIB) either, for the
# identical asan-build.sh skip), same fix, just instrumented with $(PROF)
# like every other file under $(COVOUT) so `make -C fuzz coverage` can
# report this harness's per-file coverage the same way it does for
# everything else in $(HARNESSES).
$(COVOUT)/nsswitch.o: $(srcdir)/src/netdb/linux/nsswitch.c $(LIBHDR) | $(COVOUT)
	$(CC) $(CFLAGS_HARNESS) $(PROF) -c $< -o $@

$(COVOUT)/fuzz_nsswitch: fuzz_nsswitch.c $(LIBHDR) $(COVOUT)/host_oracle.o $(COVSHIM_OBJ) $(COVOUT)/ntstubs.o $(COVOUT)/nsswitch.o $(COVLIB)/.built | $(COVOUT)
	$(CC) $(CFLAGS_HARNESS) $(PROF) \
	  -fprofile-instr-generate=$(abspath $(COVDATA))/nsswitch/fuzz_nsswitch.profraw \
	  $(SAN_LINK) $(RPATH) \
	  $(SAN_SO) $< $(COVOUT)/ntstubs.o $(COVOUT)/host_oracle.o $(COVSHIM_OBJ) $(COVOUT)/nsswitch.o \
	  $(COVLIB)/obj/*.o $(FUZZER_LIB) -ldl -lm -o $@

coverage: $(COVEXES)
	@$(CHECK_SAN) \
	 COV_TIME=$(COV_TIME) FUNCS=$(FUNCS) MODULE=$(MODULE) ALL=$(ALL) \
	 SAN_SO=$(SAN_SO) COVOUT=$(abspath $(COVOUT)) \
	 COVDATA=$(abspath $(COVDATA)) SRCDIR=$(abspath $(srcdir)) \
	 ./coverage.sh $(HARNESSES)

# ------------------------------------------------------------ ubsan mode
#
# Thin recursions, so there is one set of rules and not two.  Everything
# they build lands in the -ubsan trees, so `make -C fuzz` and
# `make -C fuzz ub` can both be up to date at once.
ub:
	@$(MAKE) SAN_MODE=ubsan all

ubrun:
	@$(MAKE) SAN_MODE=ubsan run

ubcoverage:
	@$(MAKE) SAN_MODE=ubsan coverage

# The AFL++ engine, both sanitizer modes.  Thin recursions, exactly like
# ub/ubrun above: one set of build rules, and MODESUF (via ENGINESUF)
# keeps every combination's objects in its own tree, so `make -C fuzz
# all` and `make -C fuzz afl` can both be up to date at once.  There is
# no `aflfuzz` analogue of `run`: afl-fuzz is a separate binary with its
# own flags (-i/-o/-V, not libFuzzer's -max_total_time/-artifact_prefix),
# so campaigns are driven by ../tools/afl-fuzz.sh, not by this Makefile.
afl:
	@$(MAKE) ENGINE=afl all

aflub:
	@$(MAKE) ENGINE=afl SAN_MODE=ubsan all

# Both modes' trees, whichever mode this invocation is in: a `clean` that
# left the other mode's objects behind would be a `clean` that has to be
# run twice, and nobody would.
clean:
	rm -rf $(srcdir)/obj/fuzz $(srcdir)/obj/fuzzlib \
	       $(srcdir)/obj/fuzzcov $(srcdir)/obj/fuzzcovlib $(srcdir)/obj/fuzzcovdata \
	       $(srcdir)/obj/fuzz-ubsan $(srcdir)/obj/fuzzlib-ubsan \
	       $(srcdir)/obj/fuzzcov-ubsan $(srcdir)/obj/fuzzcovlib-ubsan \
	       $(srcdir)/obj/fuzzcovdata-ubsan \
	       $(srcdir)/obj/fuzz-afl $(srcdir)/obj/fuzzlib-afl \
	       $(srcdir)/obj/fuzz-ubsan-afl $(srcdir)/obj/fuzzlib-ubsan-afl \
	       $(srcdir)/obj/afl-rt

.PHONY: all run clean coverage ub ubrun ubcoverage afl aflub

# A half-written object or executable left behind by a failed compile is
# newer than its sources, so make would consider it up to date next time.
.DELETE_ON_ERROR:
