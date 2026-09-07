/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * towctrans.html: "shall map the wide-character code wc using the
 * mapping described by desc". POSIX only defines behaviour for a desc
 * obtained from wctrans() (wctrans.html "for use as the argument to
 * the towctrans() function"); a desc of 0 is not such a value.  As
 * with a lone surrogate reaching towlower()/towupper() above, spicule
 * picks a defined answer for that case rather than leaving it
 * undefined: return wc unchanged, the same "not in the domain of this
 * mapping" answer towlower()/towupper() give for any wc outside their
 * cased domain. */
#include <wctype.h>

wint_t towctrans(wint_t wc, wctrans_t desc) // NOLINT(bugprone-easily-swappable-parameters) -- positional C interface; parameter names distinguish semantic roles
{
	switch (desc) {
	case 1: return towlower(wc);
	case 2: return towupper(wc);
	default: return wc;
	}
}

wint_t towctrans_l(wint_t wc, wctrans_t desc, locale_t loc)
{
	(void)loc;
	return towctrans(wc, desc);
}
