/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * wctrans.html: "the following character mapping names are defined in
 * all locales: tolower toupper" -- spicule's one locale defines no
 * others.  Encoding (1 = tolower, 2 = toupper) is consumed by the
 * matching switch in towctrans.c. */
#include <wctype.h>
#include <string.h>

wctrans_t wctrans(const char *name withtok(null_terminated))
{
	if (!strcmp(name, "tolower")) return 1;
	if (!strcmp(name, "toupper")) return 2;

	/* "shall return 0 ... if the given character mapping name is not
	 * valid for the current locale." */
	return 0;
}

wctrans_t wctrans_l(const char *name withtok(null_terminated), locale_t loc)
{
	(void)loc;
	return wctrans(name);
}
