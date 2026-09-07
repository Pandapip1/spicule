/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * wctype.html: "shall construct a value ... that describes a class of
 * wide-character codes identified by the string ... in the current
 * locale."  The twelve names below are the ones "defined in all
 * locales" (iswctype.html); spicule has exactly one locale, so that is
 * the whole set.  Encoding is a 1-based index into this same list,
 * consumed by the matching switch in iswctype.c -- kept in sync by
 * living right next to each other, one entry per line, in the same
 * order. */
#include <wctype.h>
#include <string.h>

static const char *const classes[] = {
	"alnum", "alpha", "blank", "cntrl", "digit", "graph",
	"lower", "print", "punct", "space", "upper", "xdigit"
};

wctype_t wctype(const char *name withtok(null_terminated))
{
	size_t i;

	for (i = 0; i < sizeof(classes)/sizeof(classes[0]); i++)
		if (!strcmp(name, classes[i])) return (wctype_t)(i+1);

	/* "If the string ... is not a valid character class name for the
	 * current locale, wctype() shall return a value of zero." */
	return (wctype_t)0;
}

wctype_t wctype_l(const char *name withtok(null_terminated), locale_t loc)
{
	(void)loc;
	return wctype(name);
}
