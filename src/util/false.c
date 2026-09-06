/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * false(1p): "The false utility shall return with a non-zero exit
 * code, ... ignoring its arguments." */
#include "util.h"

int __util_false_main(
	int argc, char **argv elements_withtok(null_terminated, argc))
{
	(void)argc;
	(void)argv;
	return 1;
}
