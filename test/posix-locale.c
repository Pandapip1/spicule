/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Clause-by-clause POSIX.1-2017 audit of <locale.h>'s locale-object
 * API -- `newlocale`, `duplocale`, `freelocale`, `uselocale` -- the
 * four functions test/POSIX-GAP-ACCOUNTING.md lists under "Implemented,
 * not clause-audited".  (`setlocale`/`localeconv`, the other two names
 * in <locale.h>, were audited in priority 4 and are not touched here.)
 *
 * Spec pages consulted (https://pubs.opengroup.org/onlinepubs/9699919799/):
 *   functions/newlocale.html   functions/duplocale.html
 *   functions/freelocale.html  functions/uselocale.html
 *   basedefs/locale.h.html
 *
 * ==================== the implementation, in full =====================
 *
 * src/misc/locale.c is 80 lines and its whole locale-object half is:
 *
 *     struct __locale_struct { int dummy; };
 *     static struct __locale_struct __c_locale;
 *
 *     locale_t newlocale(int mask, const char *name, locale_t base)
 *     { (void)mask; (void)base;
 *       if (name && *name && strcmp(name,"C") && strcmp(name,"POSIX"))
 *               { errno = ENOENT; return 0; }
 *       return &__c_locale; }
 *     void     freelocale(locale_t l) { (void)l; }
 *     locale_t duplocale(locale_t l)  { (void)l; return &__c_locale; }
 *     locale_t uselocale(locale_t l)  { (void)l; return &__c_locale; }
 *
 * One immutable, stateless, file-scope object handed out for
 * everything.  spicule is C/POSIX-locale-only -- setlocale() in the same
 * file accepts no other name -- so that is not obviously wrong, and the
 * point of this audit is to separate the parts of it that are genuinely
 * *correct for such a libc* from the parts that would mislead a caller.
 * Those two verdicts come out differently for different functions, so
 * each is argued on its own below rather than the file being labelled
 * "stub" wholesale:
 *
 *   freelocale  N/A -- nothing is ever allocated, so there is no
 *               resource to release.  A no-op is the correct
 *               implementation, not a placeholder for one.
 *   duplocale   N/A -- the object is immutable and carries no
 *               per-object state, so aliasing it is unobservable by
 *               any means POSIX defines, and freelocale() on the
 *               "copy" cannot damage the original because freelocale()
 *               does nothing.
 *   newlocale   covered -- was a BUG (the *shall fail* [EINVAL]
 *               category_mask check was simply absent; nothing about
 *               being C-locale-only excused it, since validating a
 *               bitmask needs no locale data).  Fixed by 5904d9c:
 *               newlocale() rejects a mask bit outside LC_ALL_MASK.
 *   uselocale   covered -- was a BUG, and the interesting one.
 *               uselocale(0) == LC_GLOBAL_LOCALE is THE documented way
 *               to ask whether a thread-local locale is in use, and the
 *               answer was wrong.  Fixed by 9cdd011, with one word of
 *               state; note the fix is NOT "return LC_GLOBAL_LOCALE
 *               unconditionally" -- once uselocale(loc) has been called
 *               a thread-local locale IS in use.  See src/misc/locale.c.
 *
 * No BUGs are fenced in this file.  Every assertion below runs.  Both
 * fences were real when 33a0afd wrote this header; 5904d9c and 9cdd011
 * removed them and left this list behind, which is what this paragraph
 * used to be wrong about.
 */
/* locale_t and newlocale()/LC_*_MASK are feature-test gated in
 * include/locale.h; same define most other tests in test/ already carry for
 * the same reason (see test/posix-glob.c's comment on this exact
 * define). */
#define _GNU_SOURCE
#include <locale.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static int fails;
#define CHECK(cond) do { if (!(cond)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

/* --------------------------------------------------------------------
 * newlocale -- newlocale.html
 *
 * DESCRIPTION: "shall create a new locale object or modify an existing
 * one.  If the base argument is (locale_t)0, a new locale object shall
 * be created."  The three preset locale names "are defined for all
 * settings of category_mask": "POSIX", "C" (equivalent to "POSIX"),
 * and "" (an implementation-defined native environment).
 *
 * RETURN VALUE: "shall return a handle which the caller may use on
 * subsequent calls to duplocale(), freelocale(), and other functions
 * taking a locale_t argument.  Upon failure ... shall return
 * (locale_t)0 and set errno."
 * ------------------------------------------------------------------ */
static void test_newlocale_accepts_the_preset_names(void)
{
	locale_t a, b, c;

	/* "C" / "POSIX" / "" are defined for all settings of
	 * category_mask -- and spicule has no other locale, so all three
	 * name the same one. */
	a = newlocale(LC_ALL_MASK, "C", (locale_t)0);
	b = newlocale(LC_ALL_MASK, "POSIX", (locale_t)0);
	c = newlocale(LC_ALL_MASK, "", (locale_t)0);
	CHECK(a != (locale_t)0);
	CHECK(b != (locale_t)0);
	CHECK(c != (locale_t)0);

	/* a single category mask, not just LC_ALL_MASK */
	CHECK(newlocale(LC_CTYPE_MASK, "C", (locale_t)0) != (locale_t)0);
	CHECK(newlocale(LC_NUMERIC_MASK | LC_TIME_MASK, "C", (locale_t)0) != (locale_t)0);
	CHECK(newlocale(0, "C", (locale_t)0) != (locale_t)0);

	/* "the caller may use [the handle] on subsequent calls to
	 * duplocale(), freelocale()" -- so the handle newlocale() returns
	 * must survive both */
	CHECK(duplocale(a) != (locale_t)0);
	freelocale(b);
}

static void test_newlocale_enoent(void)
{
	/* ERRORS, shall fail: "[ENOENT] For any of the categories in
	 * category_mask, the locale data is not available." */
	errno = 0;
	CHECK(newlocale(LC_ALL_MASK, "de_DE.UTF-8", (locale_t)0) == (locale_t)0);
	CHECK(errno == ENOENT);
	errno = 0;
	CHECK(newlocale(LC_CTYPE_MASK, "en_US", (locale_t)0) == (locale_t)0);
	CHECK(errno == ENOENT);
	/* the name is compared exactly: "c" is not "C" */
	errno = 0;
	CHECK(newlocale(LC_ALL_MASK, "c", (locale_t)0) == (locale_t)0);
	CHECK(errno == ENOENT);
}

static void test_newlocale_base_unchanged_on_failure(void)
{
	/* DESCRIPTION: "If the function call fails and the base argument is
	 * not (locale_t)0, the contents of base shall remain valid and
	 * unchanged."  Vacuously satisfiable here (base is never touched at
	 * all), but the observable half -- base is still a usable handle
	 * after a failed call -- is real and worth asserting. */
	locale_t base = newlocale(LC_ALL_MASK, "C", (locale_t)0);
	CHECK(base != (locale_t)0);
	errno = 0;
	CHECK(newlocale(LC_ALL_MASK, "no_SUCH.locale", base) == (locale_t)0);
	CHECK(errno == ENOENT);
	/* base still valid: still duplicable, still freeable */
	CHECK(duplocale(base) != (locale_t)0);
	freelocale(base);
}

static void test_newlocale_einval_on_invalid_mask(void)
{
	int bad = (int)(~(unsigned)LC_ALL_MASK);   /* bit 31 only */
	errno = 0;
	CHECK(newlocale(bad, "C", (locale_t)0) == (locale_t)0);
	CHECK(errno == EINVAL);
	/* and a mask that mixes valid and invalid bits still fails */
	errno = 0;
	CHECK(newlocale(LC_CTYPE_MASK | bad, "C", (locale_t)0) == (locale_t)0);
	CHECK(errno == EINVAL);
	/* EINVAL is checked before the locale name is looked up: with both
	 * an invalid mask and an unavailable name, EINVAL is the required
	 * answer only if the standard ordered them, which it does not --
	 * so this asserts only that *some* documented failure happens, not
	 * which. */
	errno = 0;
	CHECK(newlocale(bad, "no_SUCH.locale", (locale_t)0) == (locale_t)0);
	CHECK(errno == EINVAL || errno == ENOENT);
}

/* --------------------------------------------------------------------
 * duplocale -- duplocale.html
 *
 * DESCRIPTION: "shall create a duplicate copy of the locale object
 * referenced by the locobj argument.  If the locobj argument is
 * LC_GLOBAL_LOCALE, duplocale() shall create a new locale object
 * containing a copy of the global locale determined by the setlocale()
 * function."  RETURN VALUE: "shall return a handle for a new locale
 * object ... Otherwise ... (locale_t)0 and set errno."  ERRORS, shall
 * fail: "[ENOMEM]".
 *
 * VERDICT: N/A, and the mechanism is the reason, not the convenience.
 * spicule has exactly one locale object; it is a file-scope static with
 * no mutable state (`struct __locale_struct { int dummy; };`), and
 * every category of it is fixed at "C" because setlocale() accepts no
 * other name.  A "duplicate copy" of an immutable, stateless object is
 * indistinguishable from the object itself by every means POSIX
 * defines: there is no field a caller can read, no field a caller can
 * change on one copy and observe on the other, and freeing the copy
 * cannot damage the original because freelocale() releases nothing
 * (see below).  POSIX never promises that two handles compare unequal,
 * so returning the same pointer is not a violation -- it is the same
 * object, correctly.
 *
 * What *is* testable, and asserted below: the returned handle is
 * non-null and is usable everywhere a newlocale() handle is, and the
 * LC_GLOBAL_LOCALE case is handled rather than crashing -- correct
 * here for a second reason, that the global locale is unconditionally
 * "C" so "a copy of the global locale" and "the C locale" are the same
 * object.
 * ------------------------------------------------------------------ */
static void test_duplocale(void)
{
	locale_t base = newlocale(LC_ALL_MASK, "C", (locale_t)0);
	locale_t dup;

	CHECK(base != (locale_t)0);
	dup = duplocale(base);
	/* RETURN VALUE: "shall return a handle for a new locale object" */
	CHECK(dup != (locale_t)0);
	/* "the caller may use [it] on subsequent calls to duplocale(),
	 * freelocale(), and other functions taking a locale_t argument" */
	CHECK(duplocale(dup) != (locale_t)0);
	freelocale(dup);

	/* "If the locobj argument is LC_GLOBAL_LOCALE, duplocale() shall
	 * create a new locale object containing a copy of the global
	 * locale determined by the setlocale() function." */
	CHECK(duplocale(LC_GLOBAL_LOCALE) != (locale_t)0);
	/* and the global locale really is "C", so the copy is the C locale */
	CHECK(!strcmp(setlocale(LC_ALL, (char *)0), "C"));
}

/* --------------------------------------------------------------------
 * freelocale -- freelocale.html
 *
 * DESCRIPTION: "shall cause the resources allocated for a locale object
 * returned by a call to the newlocale() or duplocale() functions to be
 * released."  RETURN VALUE: "None."  ERRORS: "None."  "Any use of a
 * locale object that has been freed results in undefined behavior."
 *
 * VERDICT: N/A, by mechanism.  No resource is ever allocated for a
 * locale object here -- newlocale() and duplocale() both return the
 * address of one file-scope static -- so there is nothing for
 * freelocale() to release and a no-op is the complete, correct
 * implementation of the clause rather than a placeholder for one.  It
 * has no return value and no errors to get wrong, which leaves nothing
 * else on the page to assert.
 *
 * The "any use after freeing is undefined" sentence is deliberately not
 * exercised: it makes the behaviour undefined, so there is nothing to
 * require.  (It is also the sentence that makes duplocale()'s aliasing
 * harmless here rather than dangerous: freeing the "copy" is a no-op,
 * so the original cannot be damaged by it.)
 * ------------------------------------------------------------------ */
static void test_freelocale(void)
{
	locale_t a = newlocale(LC_ALL_MASK, "C", (locale_t)0);
	CHECK(a != (locale_t)0);
	freelocale(a);              /* "RETURN VALUE: None." */
	CHECK(errno == errno);      /* "ERRORS: None." -- nothing to check */
	/* a fresh object after the free is still obtainable and usable */
	CHECK(newlocale(LC_ALL_MASK, "C", (locale_t)0) != (locale_t)0);
	freelocale(duplocale(LC_GLOBAL_LOCALE));
}

/* --------------------------------------------------------------------
 * uselocale -- uselocale.html
 *
 * DESCRIPTION: "shall set or query the current locale for the calling
 * thread ... If the newloc argument is (locale_t)0, the current locale
 * shall not be changed; this value can be used to query the current
 * locale setting.  If the newloc argument is LC_GLOBAL_LOCALE, any
 * thread-local locale for the calling thread shall be uninstalled; the
 * thread shall again use the global locale."
 * ------------------------------------------------------------------ */
static void test_uselocale_query_does_not_change(void)
{
	/* "If the newloc argument is (locale_t)0, the current locale shall
	 * not be changed" -- observable through setlocale(), which reports
	 * the global locale and must still say "C" afterwards. */
	locale_t q1 = uselocale((locale_t)0);
	locale_t q2 = uselocale((locale_t)0);
	CHECK(q1 == q2);
	CHECK(!strcmp(setlocale(LC_ALL, (char *)0), "C"));
}

static void test_uselocale_install_and_uninstall(void)
{
	locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);
	locale_t prev;

	CHECK(loc != (locale_t)0);
	/* "Otherwise, the locale represented by newloc shall be installed
	 * as a thread-local locale to be used as the current locale for
	 * the calling thread." */
	prev = uselocale(loc);
	CHECK(prev != (locale_t)0);   /* a handle, or LC_GLOBAL_LOCALE */
	/* the installed locale is what a query now reports */
	CHECK(uselocale((locale_t)0) == loc);

	/* "If the newloc argument is LC_GLOBAL_LOCALE, any thread-local
	 * locale for the calling thread shall be uninstalled; the thread
	 * shall again use the global locale, and changes to the global
	 * locale shall affect the thread." */
	CHECK(uselocale(LC_GLOBAL_LOCALE) != (locale_t)0);
	CHECK(!strcmp(setlocale(LC_ALL, (char *)0), "C"));
}

static void test_uselocale_reports_lc_global_locale(void)
{
	locale_t loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);

	/* nothing has ever been installed, so the query must say so */
	CHECK(uselocale((locale_t)0) == LC_GLOBAL_LOCALE);
	/* and so must the value handed back by the first install */
	CHECK(uselocale(loc) == LC_GLOBAL_LOCALE);
	/* after uninstalling, the query says global again */
	uselocale(LC_GLOBAL_LOCALE);
	CHECK(uselocale((locale_t)0) == LC_GLOBAL_LOCALE);
}

/* uselocale.html ERRORS: "The uselocale() function *may* fail if:
 * [EINVAL] newloc is not a valid locale object and is not (locale_t)0."
 * *May* fail, not shall -- so not implementing it is conforming, and
 * nothing here asserts it either way.  Recorded so a successor does not
 * mistake its absence for the shall-fail gap in newlocale() above.
 *
 * Likewise newlocale.html's *may fail* "[EINVAL] The locale argument is
 * not a valid string pointer" (spicule accepts a null `name` and treats
 * it as "C") and both pages' shall-fail [ENOMEM], which needs a real
 * allocation failure and has no injection hook here. */

int main(void)
{
	test_newlocale_accepts_the_preset_names();
	test_newlocale_enoent();
	test_newlocale_base_unchanged_on_failure();
	test_newlocale_einval_on_invalid_mask();
	test_duplocale();
	test_freelocale();
	test_uselocale_query_does_not_change();
	/* BEFORE install_and_uninstall(), deliberately.  Its first assertion
	 * is "nothing has ever been installed, so the query must say so",
	 * and that is only a real test of the INITIAL state while no
	 * uselocale() call has yet installed anything.  Run after
	 * install_and_uninstall() it merely re-tests the post-uninstall
	 * state, which the same function's third assertion already covers --
	 * and mutation-testing showed exactly that: seeding the
	 * implementation's state with a locale handle instead of
	 * LC_GLOBAL_LOCALE was NOT caught in the old order, and is caught in
	 * this one.  test_uselocale_query_does_not_change() above is a pure
	 * query and installs nothing, so it is safe ahead of this. */
	test_uselocale_reports_lc_global_locale();
	test_uselocale_install_and_uninstall();

	if (fails) { printf("posix-locale: failures: %d\n", fails); return 1; }
	printf("posix-locale: all ok\n");
	return 0;
}
