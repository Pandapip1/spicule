/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * ls(1p): list directory contents.  Checked against
 * https://pubs.opengroup.org/onlinepubs/9699919799/utilities/ls.html.
 *
 * Not implemented: -h and color (GNU/BSD extensions, not in XCU ls(1p));
 * -g/-o ([XSI] long-format variants -- -l/-n already cover the mandatory
 * ground); -H/-L (this file always lstat()s a link itself, like find.c's
 * default -P). Owner/group names: getpwuid()/getgrgid() (src/misc/pwd.c,
 * src/misc/grp.c) only resolve this process's own uid/gid, so a file
 * owned by a different uid/gid prints numerically instead of by name.
 * -s's block count is ceil(st_size / blocksize), not read from a real
 * "blocks allocated" counter -- du(1p) (src/util/du.c) is this project's
 * real disk-usage auditor. -C/-x column width comes from $COLUMNS (or
 * 80), not a TIOCGWINSZ query -- ls.html leaves this implementation-
 * defined. -q's '?' substitution (build_display_name()) applies to every
 * printed name, not just terminal output as ls.html scopes it -- the
 * safer direction to get wrong.
 *
 * -R does not use this project's ftw()/nftw() (src/ftw/ftw.c, also used
 * by find.c): its walk() recurses into a subdirectory immediately on
 * finding one, before reading that directory's remaining siblings, but
 * ls(1p)'s -R needs one directory's own (sorted) entries printed in full
 * before any subdirectory's -- a shape nftw()'s one-entry callback can't
 * drive without buffering a whole subtree first. So list_dir() below
 * recurses directly on opendir()/readdir()/lstat(), directory by
 * directory instead of file by file.
 *
 * Sort order: byte order by default; -t by mtime (or ctime/atime with
 * -c/-u, whichever was given last), -S by size, both newest/largest
 * first with filename as tiebreaker; -r reverses whatever's in effect;
 * -f forces -a on and sorting off, applied once after option parsing so
 * it wins regardless of argument order.
 *
 * Date column: POSIX's classic "recent vs. old" rule -- within the last
 * six months, "%b %e %H:%M"; otherwise "%b %e  %Y" (fmt_time() below).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include "util.h"

struct ls_opts {
	int a, A, C, F, R, S, c, d, f, i, k, l, m, n, p, q, r, s, t, u, x, one;
};

struct entry {
	char *name;
	struct stat st;
	int stat_ok;
};

static const struct ls_opts *g_sort_opts;
static const struct ls_opts *g_time_opts;

static time_t time_field(const struct entry *e)
{
	if (g_time_opts->c) return e->st.st_ctime;
	if (g_time_opts->u) return e->st.st_atime;
	return e->st.st_mtime;
}

static int cmp_entries(const void *pa, const void *pb)
{
	const struct entry *a = pa, *b = pb;
	int r;

	if (g_sort_opts->S) {
		off_t sa = a->stat_ok ? a->st.st_size : 0, sb = b->stat_ok ? b->st.st_size : 0;
		if (sa < sb) r = 1;
		else if (sa > sb) r = -1;
		else r = strcmp(a->name, b->name);
	} else if (g_sort_opts->t) {
		time_t ta = time_field(a), tb = time_field(b);
		if (ta < tb) r = 1;
		else if (ta > tb) r = -1;
		else r = strcmp(a->name, b->name);
	} else {
		r = strcmp(a->name, b->name);
	}
	return g_sort_opts->r ? -r : r;
}

static int term_width(void)
{
	const char *c = getenv("COLUMNS");
	if (c) {
		char *end;
		long v = strtol(c, &end, 10);
		if (end != c && *end == 0 && v > 0 && v < 10000) return (int)v;
	}
	return 80;
}

/* mode string: 10 bytes ("drwxr-xr-x") plus the NUL fmt_mode() itself
 * appends. */
static void fmt_mode(mode_t m, char *out)
{
	static const char letters[] = "rwxrwxrwx";
	int i;
	if (S_ISDIR(m)) out[0] = 'd';
	else if (S_ISLNK(m)) out[0] = 'l';
	else if (S_ISCHR(m)) out[0] = 'c';
	else if (S_ISBLK(m)) out[0] = 'b';
	else if (S_ISFIFO(m)) out[0] = 'p';
	else if (S_ISSOCK(m)) out[0] = 's';
	else out[0] = '-';
	for (i = 0; i < 9; i++) out[1 + i] = (m & (0400 >> i)) ? letters[i] : '-';
	if (m & S_ISUID) out[3] = (m & S_IXUSR) ? 's' : 'S';
	if (m & S_ISGID) out[6] = (m & S_IXGRP) ? 's' : 'S';
	if (m & S_ISVTX) out[9] = (m & S_IXOTH) ? 't' : 'T';
	out[10] = 0;
}

/* Recent-vs-old date rule -- see this file's header comment. */
static void fmt_time(time_t t, char *out, size_t outlen)
{
	time_t now = time(NULL);
	double age = difftime(now, t);
	struct tm tmv;
	if (!localtime_r(&t, &tmv)) { snprintf(out, outlen, "%*s", 12, ""); return; }
	if (age >= 0 && age < 15778800.0) /* ~6 months, matching classic ls's rule of thumb */
		strftime(out, outlen, "%b %e %H:%M", &tmv);
	else
		strftime(out, outlen, "%b %e  %Y", &tmv);
}

static void owner_name(uid_t uid, char *out, size_t outlen)
{
	struct passwd *pw = getpwuid(uid);
	if (pw) snprintf(out, outlen, "%s", pw->pw_name);
	else snprintf(out, outlen, "%lu", (unsigned long)uid);
}

static void group_name(gid_t gid, char *out, size_t outlen)
{
	struct group *gr = getgrgid(gid);
	if (gr) snprintf(out, outlen, "%s", gr->gr_name);
	else snprintf(out, outlen, "%lu", (unsigned long)gid);
}

/* -F/-p type indicator: '/' and '*' (directory, executable regular file)
 * are what the page documents; '@'/'|'/'=' for symlink/FIFO/socket are
 * common historical extensions. */
static char type_indicator(const struct ls_opts *o, const struct entry *e)
{
	if (!e->stat_ok) return 0;
	if (S_ISDIR(e->st.st_mode)) return (o->F || o->p) ? '/' : 0;
	if (o->p) return 0; /* -p only ever marks directories */
	if (S_ISLNK(e->st.st_mode)) return o->F ? '@' : 0;
	if (S_ISFIFO(e->st.st_mode)) return o->F ? '|' : 0;
	if (S_ISSOCK(e->st.st_mode)) return o->F ? '=' : 0;
	if (o->F && S_ISREG(e->st.st_mode) && (e->st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) return '*';
	return 0;
}

/* -q: substitute '?' for any non-printable byte -- applied
 * unconditionally, see this file's header comment. */
withtok(heap_allocated)
static char *build_display_name(const struct ls_opts *o, const struct entry *e)
{
	char ind = type_indicator(o, e);
	size_t len = strlen(e->name), bytes;
	char *out;
	size_t i;
	if (!__util_size_add(len, 2, &bytes)) return NULL;
	out = malloc(bytes);
	if (!out) return NULL;
	for (i = 0; i < len; i++) {
		unsigned char ch = (unsigned char)e->name[i];
		out[i] = (o->q && (ch < 0x20 || ch == 0x7f)) ? '?' : (char)ch;
	}
	if (ind) out[len++] = ind;
	out[len] = 0;
	return out;
}

static void print_long_one(const struct ls_opts *o, const struct entry *e)
{
	char modebuf[11], tbuf[32], obuf[64], gbuf[64], *disp;
	long blocks;

	if (!e->stat_ok) {
		__util_diagf("ls: %s: cannot access\n", e->name);
		return;
	}
	fmt_mode(e->st.st_mode, modebuf);
	fmt_time(time_field(e), tbuf, sizeof tbuf);
	disp = build_display_name(o, e);
	if (!disp) { __util_diagf("ls: out of memory\n"); return; }

	if (o->s) {
		long bs = o->k ? 1024 : 512;
		blocks = (long)((e->st.st_size + bs - 1) / bs);
		printf("%ld ", blocks);
	}
	if (o->i) printf("%lu ", (unsigned long)e->st.st_ino);

	if (o->n) {
		printf("%s %4lu %5lu %5lu %8lld %s %s\n", modebuf,
			(unsigned long)e->st.st_nlink, (unsigned long)e->st.st_uid,
			(unsigned long)e->st.st_gid, (long long)e->st.st_size, tbuf, disp);
	} else {
		owner_name(e->st.st_uid, obuf, sizeof obuf);
		group_name(e->st.st_gid, gbuf, sizeof gbuf);
		printf("%s %4lu %-8s %-8s %8lld %s %s\n", modebuf,
			(unsigned long)e->st.st_nlink, obuf, gbuf,
			(long long)e->st.st_size, tbuf, disp);
	}
	free(disp);
}

static void print_columns(const struct ls_opts *o, struct entry *ent, size_t n)
{
	char **disp;
	size_t i, maxw = 0, ncols, nrows, row, col, width;
	int tw = term_width();

	if (n == 0) return;
	disp = __util_mallocarray(n, sizeof(char *));
	if (!disp) { __util_diagf("ls: out of memory\n"); return; }
	for (i = 0; i < n; i++) {
		size_t l;
		disp[i] = build_display_name(o, &ent[i]);
		if (!disp[i]) disp[i] = strdup(""); /* keep every slot heap-owned so the cleanup loop below can free() uniformly */
		if (!disp[i]) { __util_diagf("ls: out of memory\n"); n = i; break; }
		l = strlen(disp[i]);
		if (o->i) l += 21; /* room for an inode-number prefix, approximated */
		if (l > maxw) maxw = l;
	}
	width = maxw + 2;
	ncols = (size_t)tw / width;
	if (ncols < 1) ncols = 1;
	nrows = (n + ncols - 1) / ncols;

	for (row = 0; row < nrows; row++) {
		for (col = 0; col < ncols; col++) {
			size_t idx = o->x ? row * ncols + col : col * nrows + row;
			if (idx >= n) continue;
			if (o->i) printf("%*lu ", 9, (unsigned long)ent[idx].st.st_ino);
			if (col + 1 < ncols && (o->x ? row * ncols + col + 1 : col * nrows + row + nrows) < n)
				printf("%-*s", (int)width, disp[idx]);
			else
				printf("%s", disp[idx]);
		}
		putchar('\n');
	}
	for (i = 0; i < n; i++) free(disp[i]);
	free(disp);
}

static void print_comma(const struct ls_opts *o, struct entry *ent, size_t n)
{
	int col = 0, tw = term_width();
	size_t i;
	for (i = 0; i < n; i++) {
		char *disp = build_display_name(o, &ent[i]);
		size_t l;
		if (!disp) continue;
		l = strlen(disp) + (i + 1 < n ? 2 : 0);
		if (col > 0 && col + (int)l > tw) { putchar('\n'); col = 0; }
		col += printf("%s%s", disp, i + 1 < n ? ", " : "");
		free(disp);
	}
	if (n) putchar('\n');
}

static void print_one_per_line(const struct ls_opts *o, struct entry *ent, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		char *disp = build_display_name(o, &ent[i]);
		if (!disp) continue;
		if (o->s) {
			long bs = o->k ? 1024 : 512;
			long blocks = ent[i].stat_ok ? (long)((ent[i].st.st_size + bs - 1) / bs) : 0;
			printf("%ld ", blocks);
		}
		if (o->i) printf("%lu ", (unsigned long)ent[i].st.st_ino);
		printf("%s\n", disp);
		free(disp);
	}
}

static void print_entries(const struct ls_opts *o, struct entry *ent, size_t n)
{
	if (o->l || o->n) {
		size_t i;
		for (i = 0; i < n; i++) print_long_one(o, &ent[i]);
	} else if (o->m) {
		print_comma(o, ent, n);
	} else if (o->one || (!o->C && !o->x && !isatty(1))) {
		print_one_per_line(o, ent, n);
	} else {
		print_columns(o, ent, n);
	}
}

static int grow_entries(struct entry **arr, size_t *n, size_t *cap)
{
	size_t ncap;
	if (!__util_array_capacity(*cap, *n, 1, 32, sizeof(struct entry), &ncap)) return -1;
	if (ncap != *cap) {
		struct entry *g = __util_reallocarray(*arr, ncap, sizeof(struct entry));
		if (!g) return -1;
		*arr = g;
		*cap = ncap;
	}
	return 0;
}

withtok(heap_allocated)
static char *join_path(const char *dir, const char *name)
{
	size_t dl = strlen(dir), nl = strlen(name), bytes;
	int need_slash = dl > 0 && dir[dl - 1] != '/';
	char *p;
	if (!__util_size_add(dl, (size_t)need_slash, &bytes) ||
	    !__util_size_add(bytes, nl, &bytes) ||
	    !__util_size_add(bytes, 1, &bytes)) return NULL;
	p = malloc(bytes);
	if (!p) return NULL;
	snprintf(p, bytes, "%s%s%s", dir, need_slash ? "/" : "", name);
	return p;
}

/* Reads one directory's own entries (never recurses -- list_dir() below
 * drives -R itself). Returns 0 with *outp/*np set on success, -1
 * (diagnostic already written) on failure to open the directory. */
static int read_directory(const struct ls_opts *o, const char *dir, struct entry **outp, size_t *np)
{
	DIR *dp = opendir(dir);
	struct entry *arr = NULL;
	size_t n = 0, cap = 0;
	struct dirent *de;

	if (!dp) {
		__util_diagf("ls: %s: %s\n", dir, strerror(errno));
		return -1;
	}
	while ((de = readdir(dp)) != NULL) {
		size_t namelen = strnlen(de->d_name, sizeof de->d_name);
		int is_dot = namelen == 1 && de->d_name[0] == '.';
		int is_dotdot = namelen == 2 && de->d_name[0] == '.' && de->d_name[1] == '.';
		char *full;

		if (!o->a && !o->A && de->d_name[0] == '.') continue;
		if (o->A && (is_dot || is_dotdot)) continue;

		if (grow_entries(&arr, &n, &cap) < 0) { (void)closedir(dp); goto nomem; }
		{
			size_t namebytes;
			if (!__util_size_add(namelen, 1, &namebytes)) { (void)closedir(dp); goto nomem; }
			arr[n].name = malloc(namebytes);
		}
		if (!arr[n].name) { (void)closedir(dp); goto nomem; }
		memcpy(arr[n].name, de->d_name, namelen);
		arr[n].name[namelen] = 0;

		full = join_path(dir, de->d_name);
		if (!full) { (void)closedir(dp); goto nomem; }
		arr[n].stat_ok = lstat(full, &arr[n].st) == 0;
		free(full);
		n++;
	}
	(void)closedir(dp);
	*outp = arr;
	*np = n;
	return 0;

nomem:
	{
		size_t i;
		for (i = 0; i < n; i++) free(arr[i].name);
	}
	free(arr);
	__util_diagf("ls: out of memory\n");
	return -1;
}

static void free_entries(struct entry *arr, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) free(arr[i].name);
	free(arr);
}

// NOLINTNEXTLINE(misc-no-recursion) -- -R's own recursion mirrors the directory hierarchy and is path-depth bounded
static int list_dir(const struct ls_opts *o, const char *path, int print_header, int *exit_status)
{
	struct entry *ent;
	size_t n, i;

	if (read_directory(o, path, &ent, &n) < 0) { *exit_status = 1; return -1; }
	if (print_header) printf("%s:\n", path);
	if (!o->f) qsort(ent, n, sizeof *ent, cmp_entries);
	print_entries(o, ent, n);

	if (o->R) {
		for (i = 0; i < n; i++) {
			int is_dot = !strcmp(ent[i].name, ".") || !strcmp(ent[i].name, "..");
			if (is_dot || !ent[i].stat_ok || !S_ISDIR(ent[i].st.st_mode)) continue;
			{
				char *sub = join_path(path, ent[i].name);
				if (!sub) { *exit_status = 1; continue; }
				putchar('\n');
				list_dir(o, sub, 1, exit_status);
				free(sub);
			}
		}
	}
	free_entries(ent, n);
	return 0;
}

int __util_ls_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	struct ls_opts o;
	int i, exit_status = 0;
	const char *files[256];
	int nfiles = 0;

	memset(&o, 0, sizeof o);

	for (i = 1; i < argc; i++) {
		char *a = argv[i];
		char *p;
		if (!strcmp(a, "--")) { i++; break; }
		if (a[0] != '-' || a[1] == 0) break;
		for (p = a + 1; *p; p++) {
			switch (*p) {
			case 'a': o.a = 1; break;
			case 'A': o.A = 1; break;
			case 'C': o.C = 1; o.m = o.one = 0; break;
			case 'F': o.F = 1; break;
			case 'R': o.R = 1; break;
			case 'S': o.S = 1; o.t = 0; break;
			case 'c': o.c = 1; o.u = 0; break;
			case 'd': o.d = 1; break;
			case 'f': o.f = 1; break;
			case 'i': o.i = 1; break;
			case 'k': o.k = 1; break;
			case 'l': o.l = 1; o.n = 0; break;
			case 'm': o.m = 1; o.C = o.one = 0; break;
			case 'n': o.n = 1; o.l = 0; break;
			case 'p': o.p = 1; break;
			case 'q': o.q = 1; break;
			case 'r': o.r = 1; break;
			case 's': o.s = 1; break;
			case 't': o.t = 1; o.S = 0; break;
			case 'u': o.u = 1; o.c = 0; break;
			case 'x': o.x = 1; o.C = o.m = o.one = 0; break;
			case '1': o.one = 1; o.C = o.m = 0; break;
			case 'H': case 'L': case 'g': case 'o':
				__util_diagf("ls: -%c: not implemented -- see src/util/ls.c\n", *p);
				return 2;
			default:
				__util_diagf("ls: -%c: invalid option\n", *p);
				return 2;
			}
		}
	}
	if (o.f) { o.a = 1; o.l = 0; o.t = 0; o.S = 0; o.r = 0; }

	for (; i < argc; i++) {
		if (nfiles >= (int)(sizeof files / sizeof files[0])) {
			__util_diagf("ls: too many operands\n");
			return 2;
		}
		files[nfiles++] = argv[i];
	}
	if (nfiles == 0) { files[0] = "."; nfiles = 1; }

	g_sort_opts = &o;
	g_time_opts = &o;

	if (o.d) {
		/* -d: "the name found in each slot", not the directory's own
		 * contents -- so this bypasses list_dir()'s opendir() entirely
		 * and treats every operand (directory or not) as a single entry. */
		struct entry *ent = calloc((size_t)nfiles, sizeof *ent);
		int fi;
		if (!ent) { __util_diagf("ls: out of memory\n"); return 1; }
		for (fi = 0; fi < nfiles; fi++) {
			ent[fi].name = (char *)files[fi];
			ent[fi].stat_ok = lstat(files[fi], &ent[fi].st) == 0;
			if (!ent[fi].stat_ok) { __util_diagf("ls: %s: %s\n", files[fi], strerror(errno)); exit_status = 1; }
		}
		print_entries(&o, ent, (size_t)nfiles);
		free(ent);
		return exit_status;
	}

	{
		/* Plain-file operands print first, as one entry each; directory
		 * operands are then listed in turn, each with a "name:" header
		 * when there's more than one operand total (or -R is recursing) --
		 * a lone directory operand gets no header, per ls.html. */
		struct entry *plain = NULL;
		size_t nplain = 0, cap = 0;
		int fi, multi = nfiles > 1;
		int first_dir_header = 1;

		for (fi = 0; fi < nfiles; fi++) {
			struct stat st;
			if (lstat(files[fi], &st) < 0) {
				__util_diagf("ls: %s: %s\n", files[fi], strerror(errno));
				exit_status = 1;
				continue;
			}
			if (S_ISDIR(st.st_mode)) continue;
			if (grow_entries(&plain, &nplain, &cap) < 0) { __util_diagf("ls: out of memory\n"); exit_status = 1; continue; }
			plain[nplain].name = (char *)files[fi];
			plain[nplain].st = st;
			plain[nplain].stat_ok = 1;
			nplain++;
		}
		if (nplain) { qsort(plain, nplain, sizeof *plain, cmp_entries); print_entries(&o, plain, nplain); }
		free(plain);

		for (fi = 0; fi < nfiles; fi++) {
			struct stat st;
			if (lstat(files[fi], &st) < 0 || !S_ISDIR(st.st_mode)) continue;
			if (!first_dir_header || multi) putchar('\n');
			first_dir_header = 0;
			list_dir(&o, files[fi], multi || o.R, &exit_status);
		}
	}

	return exit_status;
}
