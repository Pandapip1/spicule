# SPDX-FileCopyrightText: (C) 2026 Gavin John
# SPDX-License-Identifier: GPL-3.0-or-later

#
# Makefile for spicule (requires GNU make)
#
# This is the same shape as musl's Makefile: the library is a single
# static archive built from every source file under src/, plus a crt1.o
# and a handful of per-arch files under arch/$(ARCH)/.  Sources in
# arch/$(ARCH)/src/ override sources of the same name under src/.
#
# A second, independent axis selects the OS-level backend a module's
# front door calls into (see src/internal/plat_handle.h/plat_mem.h/
# plat_fd.h): src/<module>/$(PLATFORM)/*.c, additive the same way
# arch/$(ARCH)/src/ is.  Only PLATFORM=nt (the default, and today the
# only accepted value -- see configure) is implemented.
#
# Targets:
#   all       build lib/libc.a, lib/crt1.o, lib/ntdll.def (and the wrapper),
#             plus obj/sh/sh.exe, the sh(1p) binary over the shell engine
#   install   install headers, libraries and the wrapper under $(prefix)
#   check     build test/*.c against the result and run them under wine
#   linkcheck prove every publicly declared function actually links
#   asan      build src/*.c natively under ASan+UBSan and run what applies
#   cfi       like asan, plus -fsanitize=cfi-icall (own target: -flto cost)
#   hwasan    build src/*.c natively under HWAddressSanitizer (arm64-only
#             runtime; reports "not applicable" elsewhere -- see the target)
#   tsan      opt-in ThreadSanitizer probe (see tools/tsan-probe.sh)
#   fuzz      build and run the libFuzzer harnesses in fuzz/
#   clean     remove build output
#
# Configuration is read from config.mak, written by ./configure.
#

srcdir = .
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
libdir = $(prefix)/lib
includedir = $(prefix)/include

SRC_DIRS = $(wildcard $(addprefix $(srcdir)/,src/* crt))
BASE_GLOBS = $(addsuffix /*.c,$(SRC_DIRS))
ARCH_GLOBS = $(addsuffix /$(ARCH)/*.[csS],$(SRC_DIRS)) $(srcdir)/arch/$(ARCH)/src/*.[csS]
# PLAT_GLOBS is the platform axis's own additive glob, the same shape as
# ARCH_GLOBS but keyed on PLATFORM (which OS-level backend, e.g.
# src/mman/nt/plat_mem.c) rather than ARCH (CPU width).  The two axes are
# independent -- see src/internal/plat_handle.h and the headers it
# backs (plat_mem.h, plat_fd.h) for what crosses this seam and why.
# Like ARCH_GLOBS's per-module override half, no basename collision is
# intended (a front-door file and its backend are always different
# filenames), so this never actually replaces anything today, but
# REPLACED_OBJS is extended symmetrically so the machinery would do the
# right thing if one ever existed.
# PLAT_GLOBS matches .[csS], not just .c: a platform backend can need real
# assembly the way arch/$(ARCH)/src/ already does (e.g. clone(2)'s
# trampoline, src/thread/linux/$(ARCH)/clone.S below -- see its own
# header for why that one specifically cannot be plain C).
PLAT_GLOBS = $(addsuffix /$(PLATFORM)/*.[csS],$(SRC_DIRS))
# PLAT_ARCH_GLOBS is a third, innermost axis for a file that is specific
# to BOTH the platform and the arch at once (crt/linux/aarch64/start.S:
# the raw ELF entry point, whose calling convention and register set are
# as arch-specific as clone(2)'s trampoline, but only exist under
# PLATFORM=linux at all -- NT has no equivalent, the loader hands crt1.c
# an already-built PEB). Same additive-override shape one level deeper;
# REPLACED_OBJS' subst below strips both the PLATFORM and ARCH path
# components so a file here can, symmetrically with the other two axes,
# override a same-named base file (nothing does today).
PLAT_ARCH_GLOBS = $(addsuffix /$(PLATFORM)/$(ARCH)/*.[csS],$(SRC_DIRS))
BASE_SRCS = $(sort $(wildcard $(BASE_GLOBS)))
ARCH_SRCS = $(sort $(wildcard $(ARCH_GLOBS)))
PLAT_SRCS = $(sort $(wildcard $(PLAT_GLOBS)))
PLAT_ARCH_SRCS = $(sort $(wildcard $(PLAT_ARCH_GLOBS)))
BASE_OBJS = $(patsubst $(srcdir)/%,%.o,$(basename $(BASE_SRCS)))
ARCH_OBJS = $(patsubst $(srcdir)/%,%.o,$(basename $(ARCH_SRCS)))
PLAT_OBJS = $(patsubst $(srcdir)/%,%.o,$(basename $(PLAT_SRCS)))
PLAT_ARCH_OBJS = $(patsubst $(srcdir)/%,%.o,$(basename $(PLAT_ARCH_SRCS)))
REPLACED_OBJS = $(sort $(subst /$(ARCH)/,/,$(filter-out arch/%,$(ARCH_OBJS))) \
                       $(subst /$(PLATFORM)/,/,$(PLAT_OBJS)) \
                       $(subst /$(PLATFORM)/$(ARCH)/,/,$(PLAT_ARCH_OBJS)))
ALL_OBJS = $(addprefix obj/, $(filter-out $(REPLACED_OBJS), $(sort $(BASE_OBJS) $(ARCH_OBJS) $(PLAT_OBJS) $(PLAT_ARCH_OBJS))))

LIBC_OBJS = $(filter obj/src/%,$(ALL_OBJS)) $(filter obj/arch/%,$(ALL_OBJS))
CRT_OBJS = $(filter obj/crt/%,$(ALL_OBJS))

AOBJS = $(LIBC_OBJS)
GENH = obj/include/bits/alltypes.h
IMPH = $(addprefix $(srcdir)/, src/internal/libc.h src/internal/nt.h src/internal/rtlib.h)

CFLAGS_ALL = $(CFLAGS_C99FSE)
# _ALL_SOURCE (features.h turns it into _GNU_SOURCE) is for the library
# itself, not for programs: without it a TU implementing a GNU/BSD
# extension never sees its own public declaration, so a mismatch between
# the header and the definition is silent instead of a compile error.
CFLAGS_ALL += -D_XOPEN_SOURCE=700 -D_ALL_SOURCE -D_SPICULE_INTERNAL
CFLAGS_ALL += -I$(srcdir)/arch/$(ARCH) -I$(srcdir)/arch/generic -Iobj/include -I$(srcdir)/include -I$(srcdir)/src/internal
CFLAGS_ALL += $(CPPFLAGS) $(CFLAGS_AUTO) $(CFLAGS)
# KERNEL32 comes from config.mak, included below; deferred (not `ifeq`,
# which is resolved at parse time, before that include runs) so it still
# sees the real value.
CFLAGS_ALL += $(if $(filter yes,$(KERNEL32)),-DSPICULE_USE_KERNEL32)

AR      = $(CC) -ar
RANLIB  = true
INSTALL = $(srcdir)/tools/install.sh

ARCH_INCLUDES = $(wildcard $(srcdir)/arch/$(ARCH)/bits/*.h)
GENERIC_INCLUDES = $(wildcard $(srcdir)/arch/generic/bits/*.h)
INCLUDES = $(wildcard $(srcdir)/include/*.h $(srcdir)/include/*/*.h)
ALL_INCLUDES = $(sort $(INCLUDES:$(srcdir)/%=%) $(GENH:obj/%=%) $(ARCH_INCLUDES:$(srcdir)/arch/$(ARCH)/%=include/%) $(GENERIC_INCLUDES:$(srcdir)/arch/generic/%=include/%))

EMPTY_LIB_NAMES = m rt pthread crypt util xnet resolv dl
EMPTY_LIBS = $(EMPTY_LIB_NAMES:%=lib/lib%.a)
STATIC_LIBS = lib/libc.a
DEF_FILES = lib/ntdll.def
CRT_LIBS = $(addprefix lib/,$(notdir $(CRT_OBJS)))

# sh(1p): a PE program, not part of libc.a.  Its sources live in the
# top-level sh/ directory rather than under src/ -- test/sh-design.md's
# "Placement and gates" ("its own source directory and binary -- rather
# than blurring into src/") and CONTRIBUTING.md's "Why a shell lives in a
# libc repo" both say so, and SRC_DIRS above is the mechanical reason it
# has to be true: src/* is a wildcard, so a main() under src/ would be
# archived into libc.a and fight with the main() of every program that
# links it.  The command *language* stays in src/sh/ (an internal part
# of the library, which is how wordexp/system/popen will reach it); only
# the entry point is out here.
SH_SRCS = $(sort $(wildcard $(srcdir)/sh/*.c))
SH_EXE = obj/sh/sh.exe

# POSIX standard utilities (XCU): same shape as sh/ above and for the same
# reason -- each is a real PE program, not part of libc.a, so it cannot
# live under src/*'s wildcard.  Unlike sh/, this is *one file per
# program* rather than one directory per program: bin/cp.c is the whole
# of obj/bin/cp.exe, a thin main() over __util_cp_main() (src/util/cp.c,
# declared in src/internal/util.h), the same "entry point out here, logic
# in the library" split sh/main.c uses for __sh_main().  Each utility's
# logic is also reachable in-process as a shell builtin (src/sh/builtin.c)
# without going through this .exe at all -- see that file's own comment
# for why both forms exist.
BIN_SRCS = $(sort $(wildcard $(srcdir)/bin/*.c))
BIN_EXES = $(patsubst $(srcdir)/bin/%.c,obj/bin/%.exe,$(BIN_SRCS))

WRAPCC_TCC = $(CC)

-include config.mak

# ntdll.def only means anything for the NT platform (it lists ntdll's own
# exports, for -lntdll to link against) -- a platform=linux `all` has no
# use for it and no NT spicule-tcc wrapper either (ALL_TOOLS wraps a
# win32-targeting tcc specifically).  `all`'s own recipe list below still
# only chases $(SH_EXE)/$(BIN_EXES) on PLATFORM=nt: not because they fail
# to link there any more (PROG_LIBS/PROG_CRT, further down, make both
# link cleanly against a real PLATFORM=linux libc.a too -- see that
# variable's own comment), but because `all`'s PLATFORM=nt branch also
# chases install-check's wine-only tooling, which platform=linux simply
# has no equivalent of yet.
#
# Must come after -include config.mak, not before: ifeq is a parse-time
# directive, evaluated against whatever $(PLATFORM) is AT THAT LINE, and
# config.mak (not a default anywhere above) is the only thing that ever
# sets it away from empty -- an ifeq placed before the include always
# saw PLATFORM as empty and silently took the "else" branch, even when
# actually building nt. Caught by an actual nt build failing to find
# lib/ntdll.def's consumer, -lntdll, not by inspection.
ifeq ($(PLATFORM),nt)
ALL_LIBS = $(CRT_LIBS) $(STATIC_LIBS) $(EMPTY_LIBS) $(DEF_FILES)
ALL_TOOLS = obj/spicule-tcc
else
# obj/test/%.exe's own generic recipe further down links -lntdll
# unconditionally (it has exactly one shape, shared by both platforms)
# -- fine on PLATFORM=nt, where lib/ntdll.def satisfies it, but with
# nothing at all named lib/libntdll.a on PLATFORM=linux until now, so
# `make obj/test/<name>.exe` (this project's own documented native-
# Linux verification path -- see configure's Wine-detection comment:
# platform=linux "runs its own binaries natively" with no `check`/
# `linkcheck` equivalent, but individual test executables are still
# meant to build and run directly) failed at the link step for every
# single test, not just this pass's own new ones. A real Linux binary
# has no NTDLL to import from at all, so an EMPTY archive is exactly
# as correct an answer to `-lntdll` here as the existing EMPTY_LIBS
# stubs (-lm/-lrt/-lpthread/...) already are for THEIR own symbols --
# spicule bakes the real implementations directly into lib/libc.a on
# every platform; these -lX flags exist for source compatibility with
# programs that historically link them explicitly, not because any of
# them ever contribute real archive members here. lib/libntdll.a is
# kept OUT of EMPTY_LIBS itself (rather than just appending "ntdll" to
# EMPTY_LIB_NAMES) so this stays scoped to platform=linux's own ALL_LIBS
# line and never touches the nt branch above at all -- tcc's own -lntdll
# resolution there consumes lib/ntdll.def directly (a real .def
# import-table search, not an ar archive), and an empty lib/libntdll.a
# sitting in the same -L path could plausibly shadow that lookup if it
# were built on PLATFORM=nt too; it deliberately never is.
ALL_LIBS = $(CRT_LIBS) $(STATIC_LIBS) $(EMPTY_LIBS) lib/libntdll.a
ALL_TOOLS =
endif

ifeq ($(WRAPPER),yes)
ALL_TOOLS_BUILT = $(ALL_TOOLS)
endif

# A recipe that fails *after* it has already written part of its target
# leaves that partial file behind, and make then treats it as up to date
# for ever after -- the file is newer than its prerequisites, so nothing
# ever rebuilds it, and every later `make` says "up to date" about a
# corrupt artefact.  That is not hypothetical here: it is exactly how
# `make check` comes to report `FAIL rpath.exe (rc=6)` on run after run
# (rc=6 is 0xE0DE0006 truncated to a POSIX exit status -- abort() out of
# spicule_rpath_fail(), i.e. the delay-loaded rpath-plugin.dll would not
# map), while every other test still passes and a fresh tree passes too.
# GNU make already removes a target whose recipe was killed by a signal;
# .DELETE_ON_ERROR extends that to a recipe that merely exits non-zero,
# which is the case it does not handle by default.  See also the atomic
# rename on the two plugin DLLs below, for the one route this cannot
# cover: make itself being SIGKILLed (a cgroup OOM kill takes the whole
# process group, so make never runs its own cleanup).
.DELETE_ON_ERROR:

# sh(1p), the test binaries and install-check all build against a real
# program link now (PROG_LIBS/PROG_CRT link cleanly under PLATFORM=linux
# too -- `make obj/sh/sh.exe` works there directly), but install-check
# itself still probes wine/PE-only tooling that platform=linux has no
# equivalent of, so `all` only chases the whole group on PLATFORM=nt;
# platform=linux's `all` stops at the library + crt objects themselves
# (ALL_LIBS above already omits DEF_FILES/ALL_TOOLS the same way) --
# see the Makefile PLAT_GLOBS comment and configure's --platform flag.
ifeq ($(PLATFORM),nt)
all: $(ALL_LIBS) $(ALL_TOOLS_BUILT) $(SH_EXE) $(BIN_EXES)
else
all: $(ALL_LIBS)
endif

OBJ_DIRS = $(sort $(patsubst %/,%,$(dir $(ALL_LIBS) $(ALL_TOOLS) $(ALL_OBJS) $(GENH))) obj/include)

$(ALL_LIBS) $(ALL_TOOLS) $(ALL_OBJS) $(ALL_OBJS:%.o=%.lo) $(GENH): | $(OBJ_DIRS)

$(OBJ_DIRS):
	mkdir -p $@

# bits/alltypes.h is the per-arch half followed by the generic half.  Both
# halves are written in the compact TYPEDEF/STRUCT/UNION DSL in their .h.in
# form and are expanded through tools/mkalltypes.sed by
# tools/gen-alltypes.sh, at development time, into committed .h.gen files
# (`make alltypes`).  This build therefore only has to concatenate them.
#
# That split exists for the kaem bootstrap path: boot/kaem/ has to build
# this same header with nothing but mescc-tools-extra's tools, which
# include no sed and nothing else that can do mkalltypes.sed's capture-group
# rewrite -- but do include `catm`, which concatenates.  Keeping the normal
# build on the same pre-expanded files means one expansion and one source of
# truth, not sed-for-make and catm-for-kaem.  See tools/gen-alltypes.sh.
obj/include/bits/%.h: $(srcdir)/arch/$(ARCH)/bits/%.h.gen $(srcdir)/include/%.h.gen
	cat $(srcdir)/arch/$(ARCH)/bits/$(*F).h.gen $(srcdir)/include/$(*F).h.gen > $@

$(ALL_OBJS): $(GENH) $(IMPH)

# Beyond libc.h/nt.h (listed above, since every object depends on them),
# per-module private headers (dirent_internal.h, stdio_impl.h, and the
# like) are picked up automatically here rather than hand-listed: tcc's
# -MMD emits one obj/%.d per object recording the headers it actually
# included, and the -include below feeds them back in.  Without this, an
# edit to a private header used only by, say, dirent's .c files would not
# force those .o's to rebuild, and a stale .o built against the old
# struct layout would link without complaint -- silently wrong at
# runtime rather than a build error.
DEPFLAGS = -MMD -MF $(@:.o=.d)

obj/%.o: $(srcdir)/%.c
	$(CC) $(CFLAGS_ALL) $(DEPFLAGS) -c -o $@ $<

obj/%.o: $(srcdir)/%.S
	$(CC) $(CFLAGS_ALL) $(DEPFLAGS) -c -o $@ $<

obj/%.o: $(srcdir)/%.s
	$(CC) $(CFLAGS_ALL) -c -o $@ $<

lib/libc.a: $(AOBJS)
	rm -f $@
	$(AR) rcs $@ $(AOBJS)

$(EMPTY_LIBS):
	rm -f $@
	$(AR) rcs $@

# lib/libntdll.a: PLATFORM=linux only (see this file's ALL_LIBS comment
# above for why) -- same empty-archive shape as $(EMPTY_LIBS) above,
# kept as its own rule rather than folded into EMPTY_LIB_NAMES so it is
# never built, even accidentally, on PLATFORM=nt.
lib/libntdll.a:
	rm -f $@
	$(AR) rcs $@

# Not a plain `lib/%.o: obj/crt/%.o` pattern rule: that stem-matches on
# the TARGET's basename alone, so for a crt object that lives in a
# subdirectory of obj/crt/ (crt/linux/crt1.c, crt/linux/$(ARCH)/start.S
# -- PLAT_GLOBS/PLAT_ARCH_GLOBS both nest one or two levels under crt/,
# unlike crt/crt1.c's own unprefixed NT original) the pattern rule would
# go looking for a same-named object directly under obj/crt/ that was
# never built, rather than the real one PLAT_GLOBS/PLAT_ARCH_GLOBS's
# override actually produced -- confirmed by hand-tracing CRT_OBJS for
# PLATFORM=linux before this was caught, not hypothetical. An explicit
# per-object rule, generated from CRT_OBJS' own already-correct full
# paths, has no stem to guess wrong.
define CRT_LIB_RULE
lib/$(notdir $(1)): $(1)
	cp $$< $$@
endef
$(foreach o,$(CRT_OBJS),$(eval $(call CRT_LIB_RULE,$(o))))

lib/ntdll.def: $(srcdir)/tools/ntdll.def
	cp $< $@

obj/spicule-tcc: $(srcdir)/tools/spicule-tcc.in config.mak
	sed -e 's!@CC@!$(WRAPCC_TCC)!g' -e 's!@PREFIX@!$(prefix)!g' -e 's!@INCDIR@!$(includedir)!g' -e 's!@LIBDIR@!$(libdir)!g' $< > $@
	chmod +x $@

$(DESTDIR)$(bindir)/%: obj/%
	$(INSTALL) -D $< $@

$(DESTDIR)$(bindir)/%: obj/sh/%
	$(INSTALL) -D $< $@

$(DESTDIR)$(bindir)/%: obj/bin/%
	$(INSTALL) -D $< $@

$(DESTDIR)$(libdir)/%: lib/%
	$(INSTALL) -D -m 644 $< $@

$(DESTDIR)$(includedir)/bits/%: $(srcdir)/arch/$(ARCH)/bits/%
	$(INSTALL) -D -m 644 $< $@

$(DESTDIR)$(includedir)/bits/%: $(srcdir)/arch/generic/bits/%
	$(INSTALL) -D -m 644 $< $@

$(DESTDIR)$(includedir)/bits/%: obj/include/bits/%
	$(INSTALL) -D -m 644 $< $@

$(DESTDIR)$(includedir)/%: $(srcdir)/include/%
	$(INSTALL) -D -m 644 $< $@

install-libs: $(ALL_LIBS:lib/%=$(DESTDIR)$(libdir)/%)

install-headers: $(ALL_INCLUDES:include/%=$(DESTDIR)$(includedir)/%)

install-tools: $(ALL_TOOLS_BUILT:obj/%=$(DESTDIR)$(bindir)/%)

install-progs: $(DESTDIR)$(bindir)/$(notdir $(SH_EXE)) $(BIN_EXES:obj/bin/%=$(DESTDIR)$(bindir)/%)

install: install-libs install-headers install-tools install-progs

#
# kaem: regenerate the kaem-only bootstrap build script from this
# Makefile's own build recipe (tools/gen-kaem.sh runs `make -n -B
# lib/libc.a lib/crt1.o [lib/start.o]` and rewrites the dry-run output into
# kaem syntax), so boot/kaem/build-*.kaem can never silently drift out of
# sync with this Makefile as source files are added, removed, or renamed.
# See CONTRIBUTING.md for what boot/kaem/ is for.
#
# Each invocation regenerates *every* arch's script for its --platform, not
# just $(ARCH)'s, so a new source file cannot land in one and miss the
# others (CI only runs this on one matrix leg). Both platforms this
# generator knows are regenerated here, not just the default (nt): a real
# platform=linux kaem leg exists now (boot/kaem/build-linux-aarch64.kaem)
# and needs the same drift protection nt's legs already have, or an edit
# under crt/linux/ or src/*/linux/ could silently go stale there forever.
# This costs nothing extra on a runner with no real Linux toolchain: both
# calls are `make -n` dry runs that never invoke $(CC), so gen-kaem.sh's
# own PLATFORM/ARCH/CC/AR/CFLAGS overrides (see its header) make this a
# pure function of the source tree regardless of what config.mak's own CC
# is or whether clang is even installed -- confirmed by regenerating
# build-linux-aarch64.kaem against an nt-configured config.mak (and again
# with no clang on PATH at all) and diffing byte-for-byte against the same
# file generated from a real `./configure --platform=linux CC=clang`: identical.
#
# Deliberately unconditional rather than a file target with prerequisites:
# an mtime rule is defeated by a script that is newer than the sources but
# wrong -- e.g. one git has just written with conflict markers in it -- and
# both this target and the pre-commit hook that calls it would then quietly
# do nothing and report success.
kaem:
	./tools/gen-kaem.sh
	./tools/gen-kaem.sh --platform=linux

#
# alltypes: re-expand every bits/*.h.in through tools/mkalltypes.sed into
# the committed *.h.gen files that both this Makefile and the kaem
# bootstrap consume.  Same deal as `kaem` above: generated, committed, and
# regenerated unconditionally rather than on mtimes.
#
alltypes:
	./tools/gen-alltypes.sh

#
# generated: everything that is generated *and* committed, which is what
# .githooks/pre-commit and CI regenerate before checking for drift.  One
# recipe rather than two prerequisites so the order is fixed even under
# `make -j`: gen-kaem.sh dry-runs this Makefile, whose alltypes.h rule
# names the very files gen-alltypes.sh writes.
#
generated:
	./tools/gen-alltypes.sh
	./tools/gen-kaem.sh
	./tools/gen-kaem.sh --platform=linux

.PHONY: kaem alltypes generated

#
# sh: link the shell binary against this arch's freshly built crt1.o +
# libc.a + ntdll.def, exactly the way a test PE (or any other program) is
# linked -- there is nothing special about it, which is the point: the
# engine it calls is already in libc.a for every caller, and this adds
# only a main().  Built as one link straight from source (one file today)
# rather than through obj/%.o: the generic object rule above compiles with
# CFLAGS_ALL, i.e. -D_ALL_SOURCE -D_SPICULE_INTERNAL -Isrc/internal, which
# is deliberately the *library's* compile environment and not a program's
# (see CFLAGS_ALL's own comment).  sh/ is a program and must build with
# what any other program gets.
#
# `sh` is .PHONY for a reason that bites otherwise: a directory named sh/
# exists, so without it make considers the target already up to date and
# does nothing.
# obj/sh gets its own order-only directory target rather than joining
# OBJ_DIRS: OBJ_DIRS is walked by the kaem bootstrap generator (it
# dry-runs `make -B lib/libc.a lib/crt1.o`, whose mkdir lines come from
# there), and boot/kaem/ builds the *library*, not this program -- an
# obj/sh in those scripts would be a directory nothing there ever writes
# into.  Same shape as obj/test below, for the same reason.
obj/sh:
	mkdir -p $@

# SH_EXTRA_LIBS (defined further down, alongside PROG_LIBS/PROG_CRT):
# the same narrowly-scoped fix test/aio-leak-helper.exe's own rule
# already carries (see that rule's comment for the full bisected story
# -- fork()/wait()/exec(), src/process/{fork,wait,exec}.c, pull in this
# library's own long-double math objects, whose 128-bit soft-float
# intrinsics -nostdlib never supplies on its own). sh(1p) is a real
# shell -- it calls exec()/fork()/wait() for every external command it
# runs -- so it hits the identical gap on PLATFORM=linux, confirmed
# while building obj/sh/sh.exe to verify nm(1p)'s shell built-in
# (src/sh/builtin.c's bi_nm()) for real against a live sh.exe rather
# than by inspection alone. A no-op on PLATFORM=nt (SH_EXTRA_LIBS is
# empty there) -- see that variable's own comment for why this is
# $(SH_EXE)-specific rather than folded into PROG_LIBS project-wide.
$(SH_EXE): $(SH_SRCS) $(srcdir)/src/sh/sh.h $(ALL_LIBS) | obj/sh
	$(CC) $(CFLAGS_C99FSE) $(CFLAGS_AUTO) -I$(srcdir)/arch/$(ARCH) -I$(srcdir)/arch/generic -Iobj/include -I$(srcdir)/include -nostdlib -o $@ $(PROG_CRT) $(SH_SRCS) -Llib $(PROG_LIBS) $(SH_EXTRA_LIBS)

sh: $(SH_EXE)

# obj/bin gets its own order-only directory target for the same reason
# obj/sh does, immediately above: it is a program directory the kaem
# bootstrap generator's dry run of `lib/libc.a`/`lib/crt1.o` never writes
# into, so it does not belong in OBJ_DIRS.
obj/bin:
	mkdir -p $@

# One file, one program: unlike $(SH_EXE) above (one link from several
# sh/*.c), each bin/*.c is already the complete source of its own .exe,
# so this is a pattern rule, the same shape as obj/test/%.exe further
# down -- and links the same way for the same reason (a real PE program
# gets the *library's* consumer environment, not CFLAGS_ALL's
# -D_SPICULE_INTERNAL -Isrc/internal one; see that rule's own comment).
obj/bin/%.exe: $(srcdir)/bin/%.c $(ALL_LIBS) | obj/bin
	$(CC) $(CFLAGS_C99FSE) $(CFLAGS_AUTO) -I$(srcdir)/arch/$(ARCH) -I$(srcdir)/arch/generic -Iobj/include -I$(srcdir)/include -nostdlib -o $@ $(PROG_CRT) $< -Llib $(PROG_LIBS)

.PHONY: sh install-progs

#
# Tests: every test/*.c is built into a PE and run under wine.  A test
# passes if it exits 0.  tests named *-win.c are built but not run: they
# need something wine does not implement (RtlCloneUserProcess, say).
#
# test/delayall.c needs a different recipe (-Wl,--delay-all, plus
# lib/delayload2.o -- see crt/delayload2.c's header comment for why
# that object is not just part of -lc) and only builds at all when
# $(CC) has the flag (DELAY_ALL, from configure's probe): excluded from
# the generic glob/pattern-rule pair below for the same reason
# rpath-plugin.c is kept out of it (see the comment by
# obj/test/rpath-plugin.dll), even though delayall.c, unlike that file,
# does have a main and is otherwise an ordinary test.
TEST_SRCS = $(filter-out $(srcdir)/test/delayall.c,$(sort $(wildcard $(srcdir)/test/*.c)))
ifeq ($(ARCH),aarch64)
# These three tests exercise compiler facilities the arm64 TinyCC target does
# not provide yet: stack alloca, x87 inline assembly, and float-to-int runtime
# helpers. Keep the rest of the native Windows ARM suite buildable and visible.
TEST_SRCS := $(filter-out $(srcdir)/test/alloca.c $(srcdir)/test/posix-math.c $(srcdir)/test/rtlib.c,$(TEST_SRCS))
endif
TEST_EXES = $(patsubst $(srcdir)/test/%.c,obj/test/%.exe,$(TEST_SRCS))
TEST_RUN = $(filter-out %-win.exe,$(TEST_EXES))

# Capability terms for test/test-profiles.tsv's profile selectors.
#
# WHY THIS HAS A DEFAULT AT ALL.  These are *declarations*, not
# measurements: tools/testlib.py's Rule.matches() only ever compares a
# selector against the terms passed in with --profile, and nothing in
# this tree probes for a symlink or a console.  So a rule written
# `capability.console=no` applies exactly when someone says so, and
# never otherwise.
#
# Until this default existed, the terms lived only in .github/workflows/
# ci.yml, which meant a plain local `make check-pedantic` passed none of
# them, the exempting rules could not match, and the base disposition got
# probed instead.  That is not an environment difference or a flake --
# it made two cases report STALE deterministically, for every local run,
# for everyone.  Measured back to back on one tree:
#
#     without:  52 BUG, 45 NA, 2 policy failure(s)
#     with:     50 BUG, 47 NA, 0 policy failure(s)
#
# exactly the two cases the rules name, moving as the rules specify.
#
# WHAT WOULD FALSIFY EACH, since nothing here checks:
#   capability.symlink=no  a runner where symlink()/symlinkat() can
#                          build a loop -- i.e. real Windows with
#                          SeCreateSymbolicLinkPrivilege, or Developer
#                          Mode.  Wine's is not that.
#   capability.console=no  a runner whose stdin is a real console input
#                          queue rather than a pipe or NUL, so that
#                          tcflush(TCIFLUSH) has a queue to discard.
#                          Any interactive run is that.
#
# So this default describes a headless CI-shaped runner, which is what
# both this project's Wine legs and its windows-test legs are.  Override
# it on the command line if yours is not:
#     make check-pedantic TEST_PROFILE="capability.console=yes"
# check-pedantic prints any capability term the rules use and the
# profile leaves unset, so a third term added later cannot go missing
# the way these two did.
#
# capability.overcommit=no is the third term, and it is not like the other
# two: it does not exempt a test case, and no rule in
# test/test-profiles.tsv selects on it.  It says whether ASan can start at
# all on this host -- see tools/asan-available.sh -- and it is carried
# here because this is already the channel by which a runner's facts reach
# the tools, and a second channel for the same kind of fact is a second
# place to disagree.  A host with vm.overcommit_memory=2 cannot run any
# ASan-linked binary; this default says so, and tools/asan-available.sh
# refuses to act on it unless the kernel agrees.
TEST_PROFILE ?= capability.symlink=no capability.console=no capability.overcommit=no

# TEST_DEPFLAGS is the same mechanism DEPFLAGS provides for library
# objects, applied to the test binaries -- which compile and link in one
# step, so the depfile is named from the .exe rather than from a .o.
#
# Without it a test binary depended on its own .c file and the libraries
# and on NOTHING ELSE: not <tar.h>, not <stdio.h>, not the generated
# obj/include/bits/alltypes.h.  Editing a header and re-running `make
# obj/test/foo.exe` rebuilt nothing and silently ran the previous
# binary.  That is the same class of defect the DEPFLAGS comment above
# describes for private headers -- "a stale .o ... would link without
# complaint" -- and it bit for real: two mutation runs against
# include/tar.h came back falsely clean because the mutated header was
# never compiled in.
#
# It matters most for exactly the work that touches headers, where the
# alternative is remembering to delete the target by hand every time.
TEST_DEPFLAGS = -MMD -MF $(@:.exe=.d)

# -lntdll is an NT-only import library (see ALL_LIBS' own PLATFORM=nt/
# else split above -- nothing ever builds a PLATFORM=linux lib/
# libntdll.a). Every real-program link in this Makefile (this pattern
# rule, $(SH_EXE), obj/bin/%.exe) was, until test/posix-dl-linux.c and
# this getcwd()/sh.exe fix, always built under PLATFORM=nt and run
# under Wine (`check`'s and `test-exes`' own TEST_EXES, both driven by
# TEST_SRCS -- see the PLATFORM=nt-only branch of `all`, above, for the
# same asymmetry), so their hardcoded -lntdll was never exercised on
# any other platform before now. PROG_LIBS/PROG_CRT thread that same
# PLATFORM split through every real-program link, minimally, rather
# than hardcoding an NT-only import library into rules a Linux build
# now also needs to match cleanly (an explicit unknown-library link
# error, not a silent skip, is exactly what would happen without this:
# `make obj/test/posix-dl-linux.exe` or `make obj/sh/sh.exe` under
# PLATFORM=linux would fail with "cannot find -lntdll" otherwise).
ifeq ($(PLATFORM),nt)
PROG_LIBS = -lc -lntdll
PROG_CRT = lib/crt1.o
else
# -lgcc: this clang/binutils PLATFORM=linux `-nostdlib` link never
# supplies its own definitions for the 128-bit soft-float compiler-rt
# symbols (__eqtf2/__subtf3/__extendsftf2/...) that aarch64's ABI
# demands wherever long-double arithmetic is reachable from an object
# file that actually gets pulled into the link. src/math/{exp,log,pow,
# trig,floor,sqrt}.c each define their double- and long-double-suffixed
# functions (e.g. exp()/expl()) in the same translation unit, so linking
# in the double-precision one (needed by sh's builtin awk, or by fork/
# wait/exec per posix-realtime-linux.exe's own -lgcc, added first,
# narrowly, just below) drags in the unused long-double sibling and its
# unresolved quad-arithmetic references too. Originally fixed narrowly,
# for two test binaries only (see the -lgcc override rules below); by
# the time `obj/sh/sh.exe` and the whole test/util-*.c tier were first
# actually built+run on native Linux, the same gap showed up project-
# wide (any PLATFORM=linux program linking those math objects at all),
# so it now lives here instead, covering every real-program link
# (PROG_LIBS/TESTPROG_LIBS are the same value -- see the aliasing
# comment below). NT/tcc is unaffected (tcc supplies no such compiler-rt
# split, and the ifeq above already keeps this out of that branch
# entirely), so this is added only in this PLATFORM=linux else-branch.
PROG_LIBS = -lc -lgcc
# PLATFORM=linux's own crt is two objects, not one: crt/linux/$(ARCH)/
# start.S's real _start (sets up the stack, finds argc/argv/envp/auxv,
# calls __linux_start_main) is a SEPARATE object from crt/linux/crt1.c's
# __linux_start_main itself (see that file's own header comment) --
# unlike NT's crt/crt1.c, which is both halves in one object. Omitting
# lib/start.o here is exactly the failure this comment exists to head
# off: a link that "succeeds" with `ld: warning: cannot find entry
# symbol _start; defaulting to 0x...` and produces a binary that
# segfaults or runs garbage the instant it's executed, not a build
# error -- caught here, not by inspection, the first time this pattern
# rule was ever actually exercised under PLATFORM=linux (test/posix-dl-
# linux.c). Matches tools/linux-build-dlfcn.sh's own link line exactly.
PROG_CRT = lib/start.o lib/crt1.o
endif
# SH_EXTRA_LIBS: PLATFORM=linux only -- see $(SH_EXE)'s own recipe
# comment, further down, for why sh(1p) specifically needs a bare
# -lgcc there (the same gap test/aio-leak-helper.exe's rule already
# documents for fork()/exec()'s long-double math fallout). Kept out of
# PROG_LIBS itself: PROG_LIBS is shared by obj/bin/%.exe's pattern rule
# too, and not every standalone utility touches fork/exec, so widening
# PROG_LIBS itself is the same "real, disclosed follow-up work of its
# own" scope call the aio-leak-helper.exe comment already makes -- this
# variable stays $(SH_EXE)-only, and empty (never referenced at all) on
# PLATFORM=nt, where tcc has no libgcc.a to find in the first place.
ifeq ($(PLATFORM),linux)
SH_EXTRA_LIBS = -lgcc
else
SH_EXTRA_LIBS =
endif
# Old names, kept as aliases: some comments/tooling elsewhere in this
# tree still say "TESTPROG_*"; PROG_LIBS/PROG_CRT is the same value,
# just no longer test-only now that $(SH_EXE)/obj/bin/%.exe use it too.
TESTPROG_LIBS = $(PROG_LIBS)
TESTPROG_CRT = $(PROG_CRT)

obj/test/%.exe: $(srcdir)/test/%.c $(ALL_LIBS) | obj/test
	$(CC) $(CFLAGS_C99FSE) $(CFLAGS_AUTO) $(TEST_DEPFLAGS) -I$(srcdir)/arch/$(ARCH) -I$(srcdir)/arch/generic -Iobj/include -I$(srcdir)/include -nostdlib -o $@ $(TESTPROG_CRT) $< -Llib $(TESTPROG_LIBS)

# test/rpath.c delay-loads this DLL from its own directory ($ORIGIN)
# to exercise the real resolution path -- it links against nothing of
# spicule's, so it is built directly with $(CC), no crt1.o/libc.a
# involved, same as any other freestanding DLL. Kept as a plain
# prerequisite of the one test that needs it, not folded into TEST_EXES:
# it is not itself a test (no main), so test/*.c's generic pattern rule
# above must never see it -- that's also why its source lives one level
# down, in test/rpath-plugin-src/, out of the test/*.c glob entirely.
#
# Written to a temporary and renamed into place, not straight to $@.
# rename(2) is atomic, so nothing can ever observe a half-written DLL:
# not a `make check` running rpath.exe out of the same obj/ while this
# link is in flight, and -- the case .DELETE_ON_ERROR above cannot cover
# -- not a later run either, after a cgroup OOM kill SIGKILLs the whole
# process group and make never gets to delete its own partial output.
# This file earns the extra care the other build outputs do not: it is
# the only one consumed at *run* time, by the NT loader inside another
# program, so a corrupt one is not caught by a link that follows.  It
# surfaces only as `FAIL rpath.exe (rc=6)` -- abort() out of
# spicule_rpath_fail() -- on every subsequent run, with make insisting
# the DLL is up to date the whole time.  Same for delayall-plugin.dll.
obj/test/rpath-plugin.dll: $(srcdir)/test/rpath-plugin-src/rpath-plugin.c | obj/test
	$(CC) -shared -o $@.tmp $< && mv -f $@.tmp $@

obj/test/rpath.exe: obj/test/rpath-plugin.dll

# test/sh-main.c is the black-box test of the sh binary: it spawns
# obj/sh/sh.exe as a real process (test/sh-engine.c, by contrast, links the
# engine directly and never involves a second image).  It finds the exe
# by walking up from its own argv[0] -- see that file's header -- so the
# only wiring needed here is making sure the exe exists before the test
# runs.
obj/test/sh-main.exe: $(SH_EXE)

# test/util-trivial.c is the same idea as test/sh-main.c immediately
# above, but for the first tier of POSIX standard utilities: it spawns
# obj/bin/true.exe, obj/bin/false.exe and obj/bin/test.exe (and, to
# check the shell built-in agrees, obj/sh/sh.exe) as real processes, so
# all four need to exist first.
obj/test/util-trivial.exe: obj/bin/true.exe obj/bin/false.exe obj/bin/test.exe $(SH_EXE)

# test/util-pathnames.c is the same idea, one tier up: basename, dirname,
# pathchk, pwd, readlink and realpath (and, again, obj/sh/sh.exe to check
# the shell built-ins agree), all spawned as real processes.
obj/test/util-pathnames.exe: obj/bin/basename.exe obj/bin/dirname.exe obj/bin/pathchk.exe obj/bin/pwd.exe obj/bin/readlink.exe obj/bin/realpath.exe $(SH_EXE)

# test/util-fileops.c is the same idea, one tier up: rm/cp/mv actually
# touch the filesystem, so it spawns obj/bin/rm.exe, obj/bin/cp.exe and
# obj/bin/mv.exe (plus obj/sh/sh.exe for the builtin-agreement checks)
# as real processes and needs all four to exist first.
obj/test/util-fileops.exe: obj/bin/rm.exe obj/bin/cp.exe obj/bin/mv.exe $(SH_EXE)

# test/util-fsops.c is the same idea, for the filesystem-mutating tier:
# mkdir(1p)/rmdir(1p)/mkfifo(1p)/ln(1p)/chmod(1p)/touch(1p), each spawned
# as obj/bin/<name>.exe and exercised as a shell built-in via
# obj/sh/sh.exe -c, so all six .exes plus the shell need to exist first.
obj/test/util-fsops.exe: obj/bin/mkdir.exe obj/bin/rmdir.exe obj/bin/mkfifo.exe obj/bin/ln.exe obj/bin/chmod.exe obj/bin/touch.exe $(SH_EXE)

# test/util-textio.c is the same idea, one tier up again: the first batch
# of text I/O utilities -- cat(1p)/echo(1p)/tee(1p)/wc(1p)/head(1p)/
# tail(1p) -- each spawned as obj/bin/<name>.exe and exercised as a shell
# built-in via obj/sh/sh.exe -c, so all six .exes plus the shell need to
# exist first.
obj/test/util-textio.exe: obj/bin/cat.exe obj/bin/echo.exe obj/bin/tee.exe obj/bin/wc.exe obj/bin/head.exe obj/bin/tail.exe $(SH_EXE)

# test/util-datacopy.c is the same idea, one tier up: dd(1p)/df(1p)/
# du(1p)/cksum(1p)/uuencode(1p)/uudecode(1p), each spawned as
# obj/bin/<name>.exe and exercised as a shell built-in via obj/sh/sh.exe
# -c, so all six .exes plus the shell need to exist first.
obj/test/util-datacopy.exe: obj/bin/dd.exe obj/bin/df.exe obj/bin/du.exe obj/bin/cksum.exe obj/bin/uuencode.exe obj/bin/uudecode.exe $(SH_EXE)

# test/util-format.c is the same idea, one tier up: printf(1p)/od(1p)/
# pr(1p)/tabs(1p)/split(1p)/csplit(1p), each spawned as obj/bin/<name>.exe
# and exercised as a shell built-in via obj/sh/sh.exe -c, so all six
# .exes plus the shell need to exist first.
obj/test/util-format.exe: obj/bin/printf.exe obj/bin/od.exe obj/bin/pr.exe obj/bin/tabs.exe obj/bin/split.exe obj/bin/csplit.exe $(SH_EXE)

# test/util-sortset.c is the same idea, one tier up: sort(1p)/uniq(1p)/
# comm(1p)/join(1p)/tsort(1p), each spawned as obj/bin/<name>.exe and
# exercised as a shell built-in via obj/sh/sh.exe -c, so all five .exes
# plus the shell need to exist first.
obj/test/util-sortset.exe: obj/bin/sort.exe obj/bin/uniq.exe obj/bin/comm.exe obj/bin/join.exe obj/bin/tsort.exe $(SH_EXE)

# test/util-textfmt.c is the same idea, one tier up: cut(1p)/paste(1p)/
# tr(1p)/expand(1p)/unexpand(1p)/fold(1p), each spawned as
# obj/bin/<name>.exe and exercised as a shell built-in via
# obj/sh/sh.exe -c, so all six .exes plus the shell need to exist first.
obj/test/util-textfmt.exe: obj/bin/cut.exe obj/bin/paste.exe obj/bin/tr.exe obj/bin/expand.exe obj/bin/unexpand.exe obj/bin/fold.exe $(SH_EXE)

# test/util-patch.c is the same idea, one tier up: the first Tier-4
# "bigger engine" utility, patch(1p), spawned as obj/bin/patch.exe and
# exercised as a shell built-in via obj/sh/sh.exe -c, so both need to
# exist first.
obj/test/util-patch.exe: obj/bin/patch.exe $(SH_EXE)

# test/util-sed.c is the same idea, one tier up again: sed(1p), Tier 4's
# second "bigger engine" utility, spawned as obj/bin/sed.exe and exercised
# as a shell built-in via obj/sh/sh.exe -c, so that .exe plus the shell
# need to exist first.
obj/test/util-sed.exe: obj/bin/sed.exe $(SH_EXE)

# test/util-grep.c is the same idea, one tier up again: grep(1p),
# Tier 4's third "bigger engine" utility, spawned as obj/bin/grep.exe and
# exercised as a shell built-in via obj/sh/sh.exe -c, so both need to
# exist first.
obj/test/util-grep.exe: obj/bin/grep.exe $(SH_EXE)

# test/util-archive.c is the same idea, one tier up again: the Tier 4
# archive/content-format utilities -- pax(1p)/ar(1p)/file(1p), each
# spawned as obj/bin/<name>.exe and exercised as a shell built-in via
# obj/sh/sh.exe -c, so all three .exes plus the shell need to exist
# first.
obj/test/util-archive.exe: obj/bin/pax.exe obj/bin/file.exe obj/bin/ar.exe $(SH_EXE)

# test/util-findls.c is the same idea, one tier up again: find(1p)/
# xargs(1p)/expr(1p)/ls(1p), each spawned as obj/bin/<name>.exe and
# exercised as a shell built-in via obj/sh/sh.exe -c, so all four .exes
# plus the shell need to exist first. It also spawns obj/bin/echo.exe
# and obj/bin/false.exe directly as xargs(1p) targets.
obj/test/util-findls.exe: obj/bin/find.exe obj/bin/xargs.exe obj/bin/expr.exe obj/bin/ls.exe obj/bin/echo.exe obj/bin/false.exe $(SH_EXE)

# test/util-awk.c is the same idea, one tier up again: awk(1p), spawned
# as obj/bin/awk.exe and exercised as a shell built-in via obj/sh/sh.exe
# -c, so both the .exe and the shell need to exist first.
obj/test/util-awk.exe: obj/bin/awk.exe $(SH_EXE)

# test/util-edm4.c is the same idea, one tier up again: Tier 4's two
# other "bigger engines" -- ed(1p)/m4(1p) -- each spawned as
# obj/bin/<name>.exe and exercised as a shell built-in via
# obj/sh/sh.exe -c, so both .exes plus the shell need to exist first.
obj/test/util-edm4.exe: obj/bin/ed.exe obj/bin/m4.exe $(SH_EXE)

# test/util-diffcmp.c is the same idea, one tier up again:
# diff(1p)/cmp(1p), each spawned as obj/bin/<name>.exe and exercised as
# a shell built-in via obj/sh/sh.exe -c, so both .exes plus the shell
# need to exist first.
obj/test/util-diffcmp.exe: obj/bin/diff.exe obj/bin/cmp.exe $(SH_EXE)

# test/util-timeutil.c is the same idea, one tier up again: the first
# Tier-5 "process/environment" utilities, time(1p) and timeout, each
# spawned as obj/bin/<name>.exe and exercised as a shell built-in via
# obj/sh/sh.exe -c, so both .exes plus the shell need to exist first. It
# also spawns obj/bin/true.exe and obj/bin/false.exe directly as the
# child commands under test.
obj/test/util-timeutil.exe: obj/bin/time.exe obj/bin/timeout.exe obj/bin/true.exe obj/bin/false.exe $(SH_EXE)

# test/util-ttyctl.c is the same idea, one tier up again: the
# terminal-control utilities stty(1p)/tty(1p), each spawned as
# obj/bin/<name>.exe and exercised as a shell built-in via
# obj/sh/sh.exe -c, so both .exes plus the shell need to exist first.
obj/test/util-ttyctl.exe: obj/bin/stty.exe obj/bin/tty.exe $(SH_EXE)

# test/util-tput.c: Tier 8's tput(1p) (see src/internal/util.h's own
# comment on why this tier exists and what was deferred to get here),
# spawned as obj/bin/tput.exe and exercised as a shell built-in via
# obj/sh/sh.exe -c, so both need to exist first.
obj/test/util-tput.exe: obj/bin/tput.exe $(SH_EXE)

# test/util-sccs.c: Tier 9's SCCS tooling, admin(1p) and enough of
# get(1p) to round-trip it (see src/internal/util.h's own comment on
# what was deferred to get here, and src/util/get.c's own header
# comment on why delta(1p) specifically is not part of that round
# trip), each spawned as obj/bin/<name>.exe and exercised as a shell
# built-in via obj/sh/sh.exe -c, so both .exes plus the shell need to
# exist first.
obj/test/util-sccs.exe: obj/bin/admin.exe obj/bin/get.exe $(SH_EXE)

# test/util-mesg.c is the same idea, one tier up again: Tier 6's
# terminal-messaging utilities, mesg(1p) and write(1p), each spawned as
# obj/bin/<name>.exe and exercised as a shell built-in via
# obj/sh/sh.exe -c, so both .exes plus the shell need to exist first.
obj/test/util-mesg.exe: obj/bin/mesg.exe obj/bin/write.exe $(SH_EXE)

# test/util-atcron.c: at(1p)/batch(1p)/crontab(1p) plus their two
# scheduling daemons, atd and crond (src/util/atd.c, src/util/crond.c --
# not shell builtins, see those files' own headers, so obj/bin/atd.exe
# and obj/bin/crond.exe are this pair's *only* callers). This test
# spawns obj/sh/sh.exe indirectly too (atd/crond both resolve `sh` via
# PATH to run a job/crontab command -- see their own headers), so it
# is a prerequisite here for the same reason it is everywhere else in
# this file, even though no argv here ever names sh.exe directly.
obj/test/util-atcron.exe: obj/bin/at.exe obj/bin/batch.exe obj/bin/crontab.exe obj/bin/atd.exe obj/bin/crond.exe $(SH_EXE)

# test/util-mail.c is mailx(1p) -- originally deferred by this project's
# own POSIX-utilities plan as needing infrastructure that plan didn't
# build, now implemented for real (src/util/mailx.c's own header has
# the full writeup): spawned as obj/bin/mailx.exe (including two real
# concurrent child processes appending to the same mbox at once, to
# prove flock()-based locking actually serializes them) and exercised
# as a shell built-in via obj/sh/sh.exe -c, so both the .exe and the
# shell need to exist first.
obj/test/util-mail.exe: obj/bin/mailx.exe $(SH_EXE)

# test/util-man.c: man(1p), spawned as obj/bin/man.exe and exercised as
# a shell built-in via obj/sh/sh.exe -c, against fixture pages it writes
# itself into a scratch $MANPATH (this project's own established
# "write_file() into a private scratch dir" test idiom -- see
# test/util-textio.c) -- both real man/man1/*.1 pages in this checkout
# and a real, unmodified excerpt of GNU grep's own grep.1.
obj/test/util-man.exe: obj/bin/man.exe $(SH_EXE)

# test/util-strip.c: Tier 7 (Software Development option tier)'s
# strip(1p), spawned as obj/bin/strip.exe and exercised as a shell
# built-in via obj/sh/sh.exe -c. Its core assertion is behavioral, not
# a smoke test: it copies a real, already-built obj/bin/*.exe, strips
# the copy, and spawns the STRIPPED copy to confirm it still runs and
# produces correct output -- see src/util/strip.c's own header banner
# for why that is this utility's real acceptance test, not just "the
# file got smaller" -- so obj/bin/cat.exe (a small, simple real
# fixture) is a prerequisite here too, alongside strip.exe and sh.exe.
obj/test/util-strip.exe: obj/bin/strip.exe obj/bin/cat.exe $(SH_EXE)

# test/nmfix-src/nmfix.c: a tiny, deliberately unlinked object-file
# fixture for test/util-nm.c -- compiled (not linked, `-c`, no crt1.o/
# libc.a involved) with the real $(CC), so it is a genuine ELF64 object
# on PLATFORM=linux with known, predictable symbols (a genuine COFF
# object under the NT/tcc cross build, where it exists only so the
# build compiles cleanly -- Wine is broken in this sandbox so that leg
# is never actually run here; test/util-nm.c's own header comment
# explains how it degrades gracefully if it ever is).
obj/test/nmfix.o: $(srcdir)/test/nmfix-src/nmfix.c | obj/test
	$(CC) $(CFLAGS_C99FSE) $(CFLAGS_AUTO) -I$(srcdir)/arch/$(ARCH) -I$(srcdir)/arch/generic -Iobj/include -I$(srcdir)/include -c -o $@ $<

# test/util-nm.c: nm(1p) (Software Development option tier, this
# project's own plan's final tier), spawned as obj/bin/nm.exe and
# exercised as a shell built-in via obj/sh/sh.exe -c, against the real
# ELF64 object fixture above.
obj/test/util-nm.exe: obj/bin/nm.exe obj/test/nmfix.o $(SH_EXE)

# test/delayall.c and its plugin DLL: proof that an *unmodified* program
# (plain extern, ordinary call, no spicule-specific macro at the call
# site) gets $ORIGIN delay loading through -Wl,--delay-all and
# __delayLoadHelper2 (crt/delayload2.c) rather than through
# include/spicule/delayload.h's hand-authored stubs. Only defined/built
# when DELAY_ALL is yes -- see the "delayall (skipped)" branch of
# `check` below for what happens otherwise, and configure's "checking
# whether linker accepts -Wl,--delay-all" for the probe that sets it.
ifeq ($(DELAY_ALL),yes)
obj/test/delayall-plugin.dll: $(srcdir)/test/delayall-plugin-src/delayall-plugin.c | obj/test
	$(CC) -shared -o $@.tmp $< && mv -f $@.tmp $@

# delayload2.o must come *before* -lc/-lntdll on the command line, not
# after: tcc resolves each archive's undefined symbols in a single pass
# as it reaches that archive on the command line, so an object placed
# after -lc that itself needs symbols out of libc.a (delayload2.o needs
# spicule_rpath_load()/_fail() and spicule_pe_find_export()/_dll_range())
# would already be too late (confirmed empirically -- swapping the
# order is what turns "unresolved reference to spicule_rpath_load" etc.
# into a clean link).
obj/test/delayall.exe: $(srcdir)/test/delayall.c $(ALL_LIBS) obj/test/delayall-plugin.dll | obj/test
	$(CC) $(CFLAGS_C99FSE) $(CFLAGS_AUTO) $(TEST_DEPFLAGS) -Wl,--delay-all -I$(srcdir)/arch/$(ARCH) -I$(srcdir)/arch/generic -Iobj/include -I$(srcdir)/include -nostdlib -o $@ lib/crt1.o $< obj/test/delayall-plugin.dll lib/delayload2.o -Llib -lc -lntdll

TEST_EXES += obj/test/delayall.exe
# TEST_RUN is a recursively-expanded (`=`) variable, so it re-reads
# TEST_EXES -- now including delayall.exe -- every time it is expanded;
# no separate `+=` needed here, and one would double it up.
endif

# test/posix-dl-linux.c: real Linux dlopen() coverage against src/dlfcn/
# linux/plat_dlfcn.c (see that test's own header comment for why it is a
# separate file from test/posix-dl.c's NT-only clause audit). Excluded
# from the generic TEST_SRCS glob above unconditionally -- its own
# dlopen() calls name real Linux .so fixtures this build only knows how
# to produce, and only means anything at all, on PLATFORM=linux; an NT/
# Wine build would either fail to build the fixtures below (wrong
# target triple for -shared -fPIC ELF output) or, if it somehow did,
# have nothing meaningful to test against (plat_dlfcn.c has an entirely
# separate NT sibling, src/dlfcn/nt/plat_dlfcn.c, with its own already-
# covered feature set) -- so this test is re-added, and its fixture .so
# build rules only defined at all, under PLATFORM=linux, mirroring
# test/delayall.c's own DELAY_ALL-gated inclusion just above.
TEST_SRCS := $(filter-out $(srcdir)/test/posix-dl-linux.c,$(TEST_SRCS))
ifeq ($(PLATFORM),linux)
TEST_SRCS += $(srcdir)/test/posix-dl-linux.c
TEST_EXES := $(patsubst $(srcdir)/test/%.c,obj/test/%.exe,$(TEST_SRCS))
# TEST_RUN is recursively expanded (see delayall.exe's own comment
# above) so it picks this up too with no separate `+=` needed.

# Every dlfix_*.so fixture below is built the same way test/rpath-
# plugin.dll is -- see that rule's own comment for the atomic temp-
# then-rename reasoning, which applies identically here -- except with
# real ELF-.so-shaped flags (-fPIC -nostdlib -Wl,--hash-style=sysv: see
# tools/linux-build-dlfcn.sh's own identical build line and comment;
# plat_dlfcn.c's own banner explains why DT_HASH, not GNU-hash-only,
# is required) in place of rpath-plugin.dll's bare `-shared`. Built
# directly with $(CC) -- for PLATFORM=linux this IS a native Linux
# compiler already (the same one the rest of this build uses to
# produce lib/libc.a/lib/crt1.o), not a second cross toolchain. Kept in
# one shared test/dl-linux-fixtures/ directory rather than test/rpath-
# plugin.dll's one-subdirectory-per-fixture convention: four small,
# related fixtures for one test file, not four unrelated ones each
# needing their own naming scheme -- still out of the test/*.c glob
# entirely either way, which is the property that convention actually
# protects.
obj/test/dlfix_dep.so: $(srcdir)/test/dl-linux-fixtures/dlfix_dep.c | obj/test
	$(CC) -shared -fPIC -nostdlib -Wl,--hash-style=sysv -Wl,-soname,dlfix_dep.so -o $@.tmp $< && mv -f $@.tmp $@

# Linked directly against dlfix_dep.so (not just compiled alongside
# it): that is what makes the linker resolve dep_answer() against it
# and emit a real DT_NEEDED entry naming it, rather than leaving
# dep_answer() a plain unresolved symbol -- see dlfix_needs.c's own
# comment.
obj/test/dlfix_needs.so: $(srcdir)/test/dl-linux-fixtures/dlfix_needs.c obj/test/dlfix_dep.so | obj/test
	$(CC) -shared -fPIC -nostdlib -Wl,--hash-style=sysv -Wl,-soname,dlfix_needs.so -o $@.tmp $< obj/test/dlfix_dep.so && mv -f $@.tmp $@

obj/test/dlfix_ctor.so: $(srcdir)/test/dl-linux-fixtures/dlfix_ctor.c | obj/test
	$(CC) -shared -fPIC -nostdlib -Wl,--hash-style=sysv -Wl,-soname,dlfix_ctor.so -o $@.tmp $< && mv -f $@.tmp $@

obj/test/dlfix_tls.so: $(srcdir)/test/dl-linux-fixtures/dlfix_tls.c | obj/test
	$(CC) -shared -fPIC -nostdlib -Wl,--hash-style=sysv -Wl,-soname,dlfix_tls.so -o $@.tmp $< && mv -f $@.tmp $@

obj/test/dlfix_ifunc.so: $(srcdir)/test/dl-linux-fixtures/dlfix_ifunc.c | obj/test
	$(CC) -shared -fPIC -nostdlib -Wl,--hash-style=sysv -Wl,-soname,dlfix_ifunc.so -o $@.tmp $< && mv -f $@.tmp $@

obj/test/posix-dl-linux.exe: obj/test/dlfix_dep.so obj/test/dlfix_needs.so obj/test/dlfix_ctor.so obj/test/dlfix_tls.so obj/test/dlfix_ifunc.so
endif

# test/posix-realtime-linux.c: regression coverage for the AIO
# worker-process leak this file's own header comment documents in full
# (src/thread/aio.c's worker never checked for shutdown, and
# src/thread/linux/plat_thread.c's own __plat_thread_spawn() clones
# without CLONE_THREAD, so exit_group(2) never swept it). Gated exactly
# like test/posix-dl-linux.c just above -- fork()/waitpid()/a real
# /proc scan only mean anything against this native Linux backend, not
# an NT/Wine target with no /proc and no such worker-vs-thread split at
# all (NtTerminateProcess already tears every thread down together
# there, so there is nothing this test could observe leaking).
TEST_SRCS := $(filter-out $(srcdir)/test/posix-realtime-linux.c,$(TEST_SRCS))
ifeq ($(PLATFORM),linux)
TEST_SRCS += $(srcdir)/test/posix-realtime-linux.c
TEST_EXES := $(patsubst $(srcdir)/test/%.c,obj/test/%.exe,$(TEST_SRCS))

# test/aio-leak-helper-src/aio-leak-helper.c: the standalone helper
# process posix-realtime-linux.exe execve()s -- see that helper's own
# header comment for why it is a separate program rather than AIO calls
# made straight in a fork()'d child. Kept in its own subdirectory, out
# of the flat test/*.c glob entirely, the same reason test/dl-linux-
# fixtures/ is (a plain "does argv[1] exist" helper, not a self-
# contained pass/fail test TEST_RUN could run on its own).
#
# Both this rule and posix-realtime-linux.exe's own override just below
# originally added a bare `-lgcc` this pass's own testing surfaced as
# newly necessary: fork()/wait()/exec() (src/process/{fork,wait,exec}.c)
# pull in this object's own long-double math object files (src/math/
# {trig,exp,log,pow,floor}.c -- confirmed by bisection, not guessed: a
# two-line probe using only fork()+execv()+waitpid(), nothing math-
# related at all, hits the identical undefined __eqtf2/__subtf3/
# __extendsftf2/... symbols), whose 128-bit soft-float code these clang/
# binutils' own `-nostdlib` link never supplies a definition for on its
# own. `make obj/sh/sh.exe` -- this Makefile's own already-documented
# PLATFORM=linux claim (see the ALL_LIBS comment above) -- was RE-
# CONFIRMED BROKEN by this same probe before adding this: a real, pre-
# existing gap this pass's own fork()+exec() regression test is the
# first thing in this tree to actually trip on PLATFORM=linux, not
# something introduced here. Originally fixed narrowly, for these two
# test binaries only, pending the broader project-wide question (does
# every PLATFORM=linux program that touches fork/exec need it? does
# `-lgcc`'s own libgcc.a interact safely with sh.exe's or spicule-tcc's
# other dependencies?) -- that follow-up has since landed (PROG_LIBS/
# TESTPROG_LIBS's own PLATFORM=linux branch above now carries `-lgcc`
# for every real-program link, sh.exe included), so these two rules no
# longer need their own explicit `-lgcc`; kept as explicit override
# rules anyway (rather than falling back to the generic obj/test/%.exe
# pattern rule) only because aio-leak-helper.exe's own recipe already
# differs from that pattern rule in other ways (no $(TEST_DEPFLAGS), an
# extra prerequisite) that have nothing to do with `-lgcc`.
obj/test/aio-leak-helper.exe: $(srcdir)/test/aio-leak-helper-src/aio-leak-helper.c $(ALL_LIBS) | obj/test
	$(CC) $(CFLAGS_C99FSE) $(CFLAGS_AUTO) -I$(srcdir)/arch/$(ARCH) -I$(srcdir)/arch/generic -Iobj/include -I$(srcdir)/include -nostdlib -o $@ $(TESTPROG_CRT) $< -Llib $(TESTPROG_LIBS)

# Overrides the generic obj/test/%.exe pattern rule (a more specific,
# explicit rule always wins over a pattern rule in GNU make) purely to
# add the extra aio-leak-helper.exe prerequisite -- see that rule's own
# comment just above for the `-lgcc` history (now carried by
# TESTPROG_LIBS itself, not this recipe). Otherwise byte-identical to
# that generic recipe.
obj/test/posix-realtime-linux.exe: $(srcdir)/test/posix-realtime-linux.c $(ALL_LIBS) obj/test/aio-leak-helper.exe | obj/test
	$(CC) $(CFLAGS_C99FSE) $(CFLAGS_AUTO) $(TEST_DEPFLAGS) -I$(srcdir)/arch/$(ARCH) -I$(srcdir)/arch/generic -Iobj/include -I$(srcdir)/include -nostdlib -o $@ $(TESTPROG_CRT) $< -Llib $(TESTPROG_LIBS)
endif

# test/posix-signal-fault-linux.c: real hardware-fault (SIGSEGV/SIGILL/
# SIGFPE) coverage for src/signal/linux/plat_signal.c's
# __plat_sig_install_fault_handlers() -- see that test's own header
# comment for the full story. Gated exactly like test/posix-dl-linux.c
# and test/posix-realtime-linux.c just above, and for the closely
# related reason: a real hardware fault reaching this library's own
# rt_sigaction(2)-installed handler only means anything to test against
# this native Linux backend, which is the only platform that handler
# exists on at all (see __signal_init(), src/signal/signal.c) -- an NT/
# Wine build already has its own, entirely different fault path
# (RtlAddVectoredExceptionHandler(), same function) and no rt_sigaction()
# of any kind to test here.
TEST_SRCS := $(filter-out $(srcdir)/test/posix-signal-fault-linux.c,$(TEST_SRCS))
ifeq ($(PLATFORM),linux)
TEST_SRCS += $(srcdir)/test/posix-signal-fault-linux.c
TEST_EXES := $(patsubst $(srcdir)/test/%.c,obj/test/%.exe,$(TEST_SRCS))
endif

obj/test:
	mkdir -p $@

# test-exes: build every test PE, run none of them.  Same prerequisite
# list `check` has, minus the running -- so it also drags in the plugin
# DLLs (obj/test/rpath-plugin.dll, and delayall-plugin.dll where
# DELAY_ALL is yes), which are prerequisites of the .exe that loads
# them rather than members of TEST_EXES.
#
# Exists for CI: .github/workflows/ci.yml's `build-test-exes` job
# produces the binaries that both the Wine leg and the real-Windows leg
# consume, and must not run anything itself (it has no Wine installed,
# and the point of the split is that the real-Windows leg stops waiting
# on the Wine run).  Nothing stops a developer using it to check that
# every test still *compiles* without sitting through the run.
test-exes: $(TEST_EXES)

.PHONY: test-exes

check: $(TEST_EXES)
ifneq ($(DELAY_ALL),yes)
	@echo "NA delayall.exe (this \$$(CC) has no -Wl,--delay-all support -- see configure's probe)"
endif
	@$(srcdir)/tools/test-policy.py check --profile runtime=wine $(foreach profile,$(TEST_PROFILE),--profile $(profile))
	@$(srcdir)/tools/run-tests.py --runner "$(WINE)" \
		--profile runtime=wine --profile target_arch=$(ARCH) \
		--profile kernel32=$(KERNEL32) $(TEST_RUN)

# Probe every source-level disposition independently.  Pedantic validates
# that BUG still compiles and fails and that UNIMPL still fails to link;
# strict performs those same probes and additionally rejects BUG and UNIMPL
# fences, while still allowing genuinely inapplicable N/A cases.
check-pedantic: check
	@WINE="$(WINE)" $(srcdir)/tools/test-policy.py pedantic $(foreach profile,$(TEST_PROFILE),--profile $(profile))

check-strict: check
	@WINE="$(WINE)" $(srcdir)/tools/test-policy.py strict $(foreach profile,$(TEST_PROFILE),--profile $(profile))

.PHONY: check check-pedantic check-strict

#
# libc-test: musl's own regression corpus (third_party/libc-test,
# a git submodule pinned at a SHA -- see third_party/README.md),
# adjudicated against test/libc-test-expected.txt.
#
# A separate target from `check`, not extra entries in TEST_SRCS: these
# are not this project's tests.  They are somebody else's, 39% of them
# do not compile here, 27 of the rest fail, and every one of those
# outcomes has to be adjudicated against a ledger rather than reduced to
# a single exit status.  tools/libc-test.sh does that; see its header for
# the rc contract and for why the expected-failure ledger cannot grow
# without saying so.
#
# Depends on $(ALL_LIBS) like linkcheck does: it links 146 PEs against
# lib/libc.a and needs it to exist, and, like `check`, it only ever sees
# the arch config.mak currently names.
#
libc-test: $(ALL_LIBS)
	@WINE="$(WINE)" SPICULE_TEST_MODE=normal SPICULE_TEST_PROFILE="$(TEST_PROFILE)" $(srcdir)/tools/libc-test.sh

libc-test-pedantic: $(ALL_LIBS)
	@WINE="$(WINE)" SPICULE_TEST_MODE=pedantic SPICULE_TEST_PROFILE="$(TEST_PROFILE)" $(srcdir)/tools/libc-test.sh

libc-test-strict: $(ALL_LIBS)
	@WINE="$(WINE)" SPICULE_TEST_MODE=strict SPICULE_TEST_PROFILE="$(TEST_PROFILE)" $(srcdir)/tools/libc-test.sh

.PHONY: libc-test libc-test-pedantic libc-test-strict

#
# posix-optsrun: the Open POSIX Test Suite (third_party/ltp's
# testcases/open_posix_testsuite/, a git submodule pinned at a SHA -- see
# third_party/README.md), adjudicated case by case.
#
# `posix-optsrun-pedantic` checks all 1610 profile dispositions: PASS and
# BUG cases compile and run, UNIMPL cases must fail compilation, NA cases
# stay out, and FLAKY cases remain observable without weakening strict.
#
# This absorbed the separate `posix-gapmap` compile-only census, which
# measured the same 1610 cases and gated four AGGREGATE invariants over
# them -- a census, a partition, floors in both directions, and two
# canaries.  Every one of those is a weaker restatement of what
# test/posix-opts-expected.txt now says per case:
#
#   census + partition   tools/posix-opts.py refuses to run unless the
#                        discovered sources number exactly CENSUS *and*
#                        the discovered set equals the annotated set, so
#                        an unannotated or stale case is a hard error
#                        rather than a count that still adds up.
#   floor (links)        358 PASS + 199 BUG cases must build and run.  A
#                        compiler that stopped finding lib/libc.a fails
#                        557 cases by name, not one threshold.
#   floor (blocked)      1016 UNIMPL cases must FAIL to build.  The
#                        dangerous direction -- an -I that starts
#                        pointing at a host libc, making everything link
#                        and the gap read as closed -- is now caught 1016
#                        times over instead of by a single floor.
#   canaries             two hand-picked cases were a proxy for "the
#                        classifier still discriminates".  The ledger
#                        checks all 1610 in both directions.
#
# The class A/B/C classification the gap map produced did not go away
# either: it is recorded per case in the ledger's reason column ("OPTS
# class A: compile/link blocked by aio.h"), where it names the header
# instead of contributing to a bucket total.
#
# Also deliberately NOT part of `check`, and for the same reason:
# `check` is this library's own suite and its failures are ours.  A
# foreign conformance suite that this library fails a third of is a
# different claim with a different meaning of failure, exactly as
# libc-test is kept separate.
#
# The exact case census and complete profile ledger prevent an empty or
# partial sweep from reporting success. There is no generated report: the
# driver prints every case and its observation to stdout, so the run log
# is the record.
#
# Depends on $(ALL_LIBS) for the same reason libc-test does: without
# lib/libc.a nothing links, nothing runs, and the run reports "no
# failures" about a sweep of zero tests.
#
posix-optsrun: $(ALL_LIBS)
	@WINE="$(WINE)" $(srcdir)/tools/posix-opts.py normal $(foreach profile,$(TEST_PROFILE),--profile $(profile))

posix-optsrun-pedantic: $(ALL_LIBS)
	@WINE="$(WINE)" $(srcdir)/tools/posix-opts.py pedantic $(foreach profile,$(TEST_PROFILE),--profile $(profile))

posix-optsrun-strict: $(ALL_LIBS)
	@WINE="$(WINE)" $(srcdir)/tools/posix-opts.py strict $(foreach profile,$(TEST_PROFILE),--profile $(profile))

.PHONY: posix-optsrun posix-optsrun-pedantic posix-optsrun-strict

#
# check-kernel32: convenience wrapper for a developer who already has a
# normal tree configured (TARGET/CC come from the config.mak that is
# already there) and wants to know, in one command, whether the
# --enable-kernel32 build still passes -- without having to remember the
# `./configure --enable-kernel32 && make clean && make && make check`
# sequence by hand every time. `make clean` in the middle is required,
# not cosmetic: KERNEL32 feeds CFLAGS_ALL above, and object files have no
# dependency on config.mak's *contents* (only a `-include`, which make
# does not treat as a rebuild trigger the way a prerequisite would), so a
# same-tree `./configure --enable-kernel32` followed straight by `make`
# would relink a still-kernel32-disabled lib/libc.a instead of rebuilding
# it -- confirmed locally: nm kept reporting install_ctrl_handler/
# ctrl_handler as present in the archive after a --disable-kernel32
# reconfigure with no intervening `make clean`.
#
# Restores the tree to its original KERNEL32 setting (captured from
# config.mak before this target's own ./configure runs, since $(KERNEL32)
# is resolved at parse time) and rebuilds once more, so the tree is left
# the way a plain `make` would have found it, not switched over to
# --enable-kernel32 permanently.
#
check-kernel32: config.mak
	./configure --host=$(TARGET) CC=$(CC) --enable-kernel32
	$(MAKE) clean
	$(MAKE)
	$(MAKE) check
	./configure --host=$(TARGET) CC=$(CC) --$(if $(filter yes,$(KERNEL32)),enable,disable)-kernel32
	$(MAKE) clean
	$(MAKE)

.PHONY: check-kernel32

#
# install-check: prove that `make install` produces something an outside
# program can actually build and run against, rather than something only
# in-tree gates (which never leave -I./include -I./arch/$(ARCH)
# -Iobj/include -Llib) can see. Configures and builds a second, throwaway
# copy of the tree out-of-tree, installs it into a temporary prefix, and
# builds/runs test programs against *only* that prefix through the
# installed tools/spicule-tcc wrapper -- no source-tree path anywhere on
# the compile line. See tools/install-check.sh for the full rationale and
# what it checks. Requires config.mak (same as `check`): run it once per
# configured arch, the same way `make check` is.
#
install-check: config.mak
	./tools/install-check.sh

.PHONY: install-check

#
# lint: opt-in static checking (gcc/clang strict warnings, the clang static
# analyzer, cppcheck, shellcheck).  Never a prerequisite of anything: the
# library is built with tcc, and tools/lint.sh only reports.  It skips any
# tool that is not installed.  See tools/lint.sh for the flag set and
# .clang-tidy for the check list. Keep this required-stage list explicit so
# `make lint` and the per-stage CI matrix cannot silently disagree about
# which zero-backlog checks are gates.
#
LINT_REQUIRED_STAGES = warn analyze cppcheck shell fallible locks \
	lockset reentrancy variadic signals abizeroinit initproof \
	errno purity ownership undefined unreferenced widthmod

lint:
	./tools/lint.sh $(LINT_REQUIRED_STAGES)

.PHONY: lint

# linkcheck: prove every function a public header declares can actually be
# linked against by a real program, using the real $(CC) and this arch's
# freshly built lib/crt1.o + lib/libc.a + lib/ntdll.def -- the same inputs
# `make check`'s test binaries link against.  This is deliberately NOT a
# stage of `make lint`: lint.sh's tools (gcc/clang/cppcheck/shellcheck)
# never touch $(CC) or produce a real PE link, so they cannot see a macro
# that silently retargets a call to a name tcc cannot resolve -- exactly
# how include/alloca.h's `#define alloca __builtin_alloca` shipped (see
# tools/linkcheck.sh's header for the full story). Catching that needs an
# actual per-arch compile-and-link with the real toolchain, which makes
# this the same shape of gate as `check`/`asan`, not `lint`: a build-and-
# run step keyed to $(CC)/$(ARCH), not a report-only static pass. Like
# `check`, it only ever sees the arch config.mak currently names -- run it
# again after reconfiguring for the other arch (arch/ is not shared,
# include/ is).
linkcheck: $(ALL_LIBS)
	@CC="$(CC)" ARCH="$(ARCH)" CFLAGS_C99FSE="$(CFLAGS_C99FSE)" CFLAGS_AUTO="$(CFLAGS_AUTO)" \
		$(srcdir)/tools/linkcheck.sh

.PHONY: linkcheck
#
# hygiene: every header under include/ (plus the generated obj/include/
# bits/alltypes.h) compiled entirely on its own, twice in one TU (include
# guard), and as C++ where it promises extern "C" -- for both arches,
# under -std=c99 -nostdinc with no feature-test macro set, i.e. exactly
# what a program gets from #include <whatever.h> and nothing else. See
# tools/hdr-hygiene.sh's header comment for the bug class this exists to
# catch (spicule shipping no <pwd.h> at all, unnoticed because nothing
# in-tree ever included a header spicule does not have -- this script is
# the "header exists but isn't independently usable" half of that class).
#
# A separate gate rather than a tools/lint.sh stage: lint.sh is
# explicitly report-only static analysis over src/*.c (warnings, the
# analyzer, cppcheck) and is documented as never a build dependency,
# where this is a pass/fail correctness check over include/*.h with its
# own exit status -- closer in kind to `make asan`/`make check` than to
# a linter, and folding it into lint.sh's stage list would let
# LINT_STRICT=0/report-only framing quietly cover a class of bug that
# should instead just fail the gate.
#
# Deliberately depends on $(GENH), like asan below, so a bare `make
# hygiene` in a fresh tree also has obj/include/bits/alltypes.h.
#
hygiene: $(GENH)
	./tools/hdr-hygiene.sh

.PHONY: hygiene

# minver: the library's minimum supported Windows version, checked rather
# than asserted -- tools/ntdll.def's per-export NTDLL-version annotations
# against the floor README.md declares. Like `ledger`, a grep over two
# checked-in artefacts with no build and no $(CC), so it has no
# prerequisite and runs instantly. Deliberately not a `lint` stage:
# lint.sh is report-only static analysis, and this is pass/fail. See
# tools/lint-minver.sh's header for the bug class (a static import of a
# name the running ntdll does not export makes the loader refuse the
# whole image) and for why neither Wine nor CI's Server 2025 can see it.
minver:
	./tools/lint-minver.sh

.PHONY: minver

# asan/fuzz: a second, native (Linux/ELF) build of the same src/*.c under
# AddressSanitizer, UBSan and libFuzzer.  This is not a substitute for
# `make check` -- it cannot be, since a native build has no ntdll -- but a
# sanitizer sees things Wine cannot, and it needs no cross toolchain.  See
# CONTRIBUTING.md and the comments in tools/asan-build.sh.
#
# Deliberately not part of `all` or `check`: they build the real thing with
# $(CC), and this builds something else with clang.
#
# SPICULE_TEST_PROFILE carries $(TEST_PROFILE) in, the same env name
# tools/libc-test.sh already reads it under.  Exit 77 from the script
# means "unavailable in this environment", not "failed" (see
# tools/asan-available.sh); it is translated into one plain line here
# because a bare `make: *** [asan] Error 77` reads as neither.  The
# status is still 77 and still non-zero: this stage verified nothing,
# and a caller that treats that as success is the failure mode this
# project has closed nine times.
asan: $(GENH)
	@SPICULE_TEST_PROFILE="$(TEST_PROFILE)" $(srcdir)/tools/asan-build.sh; \
	 rc=$$?; \
	 if [ $$rc = 77 ]; then \
	   echo "make: 'asan' is UNAVAILABLE here (exit 77), not failed -- see above."; \
	 fi; \
	 exit $$rc

# Wall-clock seconds per harness, matching tools/fuzz.sh's own `${1:-60}`
# default so the two cannot drift.  It was referenced here and defined
# nowhere, which read as a configured knob and was not one: a `make fuzz`
# passed an empty argument and the real default lived, undocumented, in
# the script.  `?=` so a command-line or environment FUZZ_TIME still
# wins, which is how it was always meant to be used:
#
#   make fuzz FUZZ_TIME=300
#
# Deliberately unquoted below: this is a plain number, and quoting it
# would turn an explicitly empty FUZZ_TIME= into an empty first argument
# (-max_total_time= with nothing after it) instead of no argument at all.
FUZZ_TIME ?= 60

fuzz: $(GENH)
	@$(srcdir)/tools/fuzz.sh $(FUZZ_TIME)

# cfi: the same native ASan+UBSan build as `asan`, plus
# -fsanitize=cfi-icall (Control Flow Integrity's indirect-call check) and
# the -flto it needs.  A separate target rather than folded into `asan`
# by default: LTO measurably slows the link (see tools/asan-build.sh and
# CONTRIBUTING.md for the measured delta), and `asan` is meant to stay the
# fast, always-safe-to-run loop.  Gates on zero cfi-icall traps across
# every applicable test/*.c.
cfi: $(GENH)
	@SPICULE_CFI=1 $(srcdir)/tools/asan-build.sh

# hwasan: a native HWAddressSanitizer build, staged for a future
# arch/aarch64 target -- see tools/hwasan-build.sh.  Its runtime requires
# Linux's arm64 tagged-address ABI, so on every host without it (x86_64
# today, or an arm64 kernel that has not opted in) this reports "not
# applicable" rather than pretending to have tested anything.
hwasan: $(GENH)
	@$(srcdir)/tools/hwasan-build.sh

# tsan: opt-in ThreadSanitizer probe (tools/tsan-probe.sh) driving spicule
# from two host pthreads.  Gated: fails on the known-open aligned_list
# finding or anything unclassified, and treats strtok/localtime-family
# races as suppressed (spec-permitted static storage).  See CONTRIBUTING.md.
tsan: $(GENH)
	@$(srcdir)/tools/tsan-probe.sh

.PHONY: asan fuzz cfi hwasan tsan

clean:
	rm -rf obj lib

distclean: clean
	rm -f config.mak

.PHONY: all clean install install-libs install-headers install-tools check distclean

-include $(ALL_OBJS:.o=.d)
# The same, for the test binaries (see TEST_DEPFLAGS).  Absent on a
# clean tree, which is harmless: the first build creates them.
-include $(TEST_EXES:.exe=.d)

# One place holds the TEST_PROFILE default, and fuzz/Makefile is a
# separate make invocation that needs it (its run/coverage targets ask
# tools/asan-available.sh whether ASan can start).  It asks here rather
# than repeating the default, because two copies of a default are two
# things to forget to change together.
print-test-profile:
	@printf '%s\n' '$(TEST_PROFILE)'

.PHONY: print-test-profile
