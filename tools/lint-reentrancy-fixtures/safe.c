/* SPDX-FileCopyrightText: (C) 2026 Gavin John */
/* SPDX-License-Identifier: GPL-3.0-or-later */

/* Self-contained stub prototypes, mirroring how
 * tools/lint-lock-discipline-fixtures declares local pthread_mutex_lock-
 * shaped stubs rather than including real headers.  gmtime/strtok are the
 * real spicule family names (see src/time/gmtime.c, src/string/strtok.c);
 * fake_gmtime/fake_localtime are a synthetic pair that shares one static-
 * buffer contract purely to exercise the sibling-invalidation path -- none
 * of spicule's real families have more than one member (see the header
 * comment in tools/clang/ReentrancyChecker.cpp). */
struct tm { int tm_year; };
struct tm *gmtime(const long *);
char *strtok(char *, const char *);
struct tm *fake_gmtime(const long *);
struct tm *fake_localtime(const long *);
int external_sink(struct tm *);

int use_before_second_call(long *t1, long *t2) {
  struct tm *p1 = gmtime(t1);
  int year = p1->tm_year;
  gmtime(t2);
  return year;
}

int different_families_do_not_conflict(long *t1, char *s, const char *sep) {
  struct tm *p1 = gmtime(t1);
  strtok(s, sep);
  return p1->tm_year;
}

int rebind_before_use(long *t1, long *t2) {
  struct tm *p1 = gmtime(t1);
  gmtime(t2);
  p1 = gmtime(t2);
  return p1->tm_year;
}

int deep_copy_survives_invalidation(long *t1, long *t2) {
  struct tm *p1 = gmtime(t1);
  struct tm saved = *p1;
  gmtime(t2);
  return saved.tm_year;
}

int sibling_used_before_invalidation(long *t1, long *t2) {
  struct tm *p1 = fake_gmtime(t1);
  int year = p1->tm_year;
  fake_localtime(t2);
  return year;
}

int copy_used_before_invalidation(long *t1, long *t2) {
  struct tm *p1 = gmtime(t1);
  struct tm *p2 = p1;
  int year = p2->tm_year;
  gmtime(t2);
  return year;
}
