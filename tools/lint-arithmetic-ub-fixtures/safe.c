/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later */

int checked_division(int value, int divisor)
{
	if (divisor == 0 || value == (-2147483647 - 1))
		return 0;
	return value / divisor;
}

int checked_signed_division_overflow(int value, int divisor)
{
	if (divisor == 0 ||
	    (value == (-2147483647 - 1) && divisor == -1))
		return 0;
	return value / divisor;
}

int checked_signed_remainder_overflow(int value, int divisor)
{
	if (divisor == 0 ||
	    (value == (-2147483647 - 1) && divisor == -1))
		return 0;
	return value % divisor;
}

int checked_signed_division_assignment(int value, int divisor)
{
	if (divisor == 0 ||
	    (value == (-2147483647 - 1) && divisor == -1))
		return 0;
	value /= divisor;
	return value;
}

int promoted_short_division(short value, short divisor)
{
	if (!divisor)
		return 0;
	return value / divisor;
}

unsigned checked_remainder(unsigned value, unsigned divisor)
{
	if (!divisor)
		return 0;
	value %= divisor;
	return value;
}

unsigned constant_division(unsigned value)
{
	return value / 10;
}

unsigned checked_unsigned_shift(unsigned value, unsigned count)
{
	if (count >= 32)
		return 0;
	return value << count;
}

unsigned checked_signed_count(unsigned value, int count)
{
	if (count < 0 || count >= 32)
		return 0;
	return value >> count;
}

unsigned constant_shift(unsigned value)
{
	value <<= 7;
	return value;
}

int checked_addition(int value)
{
	if (value > 2147483647 - 7)
		return 0;
	return value + 7;
}

int checked_two_operand_addition(int left, int right)
{
	if (right > 0 && left > 2147483647 - right)
		return 0;
	if (right < 0 && left < (-2147483647 - 1) - right)
		return 0;
	return left + right;
}

int checked_positive_multiplication(int left, int right)
{
	if (left < 0 || right <= 0 || left > 2147483647 / right)
		return 0;
	return left * right;
}

int checked_positive_negative_multiplication(int left, int right)
{
	if (left <= 0 || right >= 0)
		return 0;
	if (right == -1)
		return -left;
	if (left > (-2147483647 - 1) / right)
		return 0;
	return left * right;
}

int checked_negative_positive_multiplication(int left, int right)
{
	if (left >= 0 || right <= 0 || left < (-2147483647 - 1) / right)
		return 0;
	return left * right;
}

int checked_negative_multiplication(int left, int right)
{
	if (left >= 0 || right >= 0 || left < 2147483647 / right)
		return 0;
	return left * right;
}

int checked_subtraction(int value)
{
	if (value < (-2147483647 - 1) + 7)
		return 0;
	return value - 7;
}

int checked_negation(int value)
{
	if (value == (-2147483647 - 1))
		return 0;
	return -value;
}

int promoted_signed_char_negation(signed char value)
{
	return -value;
}

int checked_loop_increment(void)
{
	int i;
	for (i = 0; i < 3; i++)
		;
	return i;
}

static int ordered_global_index;

int ordered_global_increment(int limit)
{
	if (ordered_global_index >= limit)
		return 0;
	return ordered_global_index++;
}

int ordered_local_decrement(int value, int limit)
{
	if (value <= limit)
		return 0;
	return value--;
}

int reversed_ordered_increment(int value, int limit)
{
	if (limit > value)
		return value++;
	return 0;
}

int reversed_ordered_decrement(int value, int limit)
{
	if (limit < value)
		return value--;
	return 0;
}

int relational_loop_difference(const unsigned char *bytes, int length)
{
	int cursor = length;
	while (cursor > 0 && bytes[cursor - 1] == 0)
		cursor--;
	return length - cursor;
}

/* Pins symbolInterval()'s BO_Rem decomposition of a value materialized
 * into a local and reread past the point where a source-level walk can
 * see the '%' that narrowed it -- src/stdlib/strtod.c's bn_shl() shape
 * (`int b = k % 32; ...; carry = v >> (32 - b);`), reread three lines
 * later rather than used inline. */
unsigned rem_materialized_then_shift(unsigned v, int k)
{
	int b;
	if (k <= 0)
		return v;
	b = k % 32;
	if (!b)
		return v;
	return v >> (32 - b);
}

/* Pins symbolInterval()'s BO_Add/BO_Sub/BO_Mul decomposition of an affine
 * chain materialized into a local -- src/stdio/printf.c's fmt_a() shape
 * (`int shift = (13 - prec) * 4;`, prec bounded [0,12] by two literal
 * guards immediately above, `shift` reread four times after). 64 bits
 * wide because (13 - prec) * 4 reaches 52, which only a >=53-bit shifted
 * value keeps in range -- the same reason the real code shifts a
 * uint64_t mantissa, not a 32-bit one. */
unsigned long long affine_materialized_then_shift(unsigned long long man,
						   int prec)
{
	int shift;
	if (prec < 0 || prec >= 13)
		return man;
	shift = (13 - prec) * 4;
	return man >> shift;
}

/* Pins the same symbolInterval() BO_Rem decomposition reaching
 * DivisorChecker (not just SignedArithmeticChecker/ShiftCountChecker):
 * `d` is materialized from `k % 100` and reread as a divisor two lines
 * later, plus a `+ 1` (BO_Add) the same decomposition must see through
 * to prove `d` is never zero. */
unsigned rem_materialized_then_divide(unsigned value, unsigned k)
{
	unsigned d;
	d = k % 100 + 1;
	return value % d;
}

int ordered_nonnegative_subtraction(int total, int removed)
{
	if (removed < 0 || removed > total)
		return 0;
	total -= removed;
	return total;
}

static int cleanup_preserved_total;
extern void free(void *);
__attribute__((annotate("spicule_arith_scalar_noop")))
void __free(void *allocation)
{
	free(allocation);
}

int ordered_global_subtraction_across_free(int removed, void *allocation)
{
	if (removed < 0 || removed > cleanup_preserved_total)
		return 0;
	__free(allocation);
	return cleanup_preserved_total - removed;
}

int ordered_nonpositive_subtraction(int total, int removed)
{
	if (removed > 0 || removed < total)
		return 0;
	total -= removed;
	return total;
}

int ordered_subtraction_boundaries(int value)
{
	if (value != (-2147483647 - 1) && value != 2147483647)
		return 0;
	return value - 0;
}

struct member_countdown {
	int count;
	int values[4];
};

void positive_member_countdown(struct member_countdown *state)
{
	while (state->count > 0 && !state->values[state->count - 1])
		state->count--;
}

#define fixture_arith_range(minimum, maximum) \
	__attribute__((annotate("spicule_arith_range:" #minimum ":" #maximum)))
#define fixture_nonzero_field_on_success(argument, field) \
	__attribute__((annotate("spicule_arith_nonzero_field_on_success:" \
		#argument ":" #field)))

static unsigned range_checked_divisor(unsigned value,
	int divisor fixture_arith_range(2, 36))
{
	return value % (unsigned)divisor;
}

unsigned guarded_range_contract_call(unsigned value, int divisor)
{
	if (divisor < 2 || divisor > 36)
		return 0;
	return range_checked_divisor(value, divisor);
}

static int range_checked_digit(unsigned value,
	int radix fixture_arith_range(2, 36))
{
	int digit = (int)(value % (unsigned)radix);
	return digit < 10 ? '0' + digit : 'a' + digit - 10;
}

int guarded_symbolic_remainder_range(unsigned value, int radix)
{
	if (radix < 2 || radix > 36)
		return 0;
	return range_checked_digit(value, radix);
}

static int range_checked_negative_remainder(int value,
	int radix fixture_arith_range(2, 36))
{
	int digit;
	if (value > 0)
		return 0;
	digit = value % radix;
	return digit + 35;
}

int guarded_negative_remainder_range(int value, int radix)
{
	if (radix < 2 || radix > 36)
		return 0;
	return range_checked_negative_remainder(value, radix);
}

struct fixture_bucket_table { unsigned count; };

static int establish_bucket_count(struct fixture_bucket_table *table)
	fixture_nonzero_field_on_success(0, count);

static int establish_bucket_count(struct fixture_bucket_table *table)
{
	if (!table)
		return 0;
	table->count = 16;
	return 1;
}

static int fail_with_zero_bucket_count(struct fixture_bucket_table *table)
	fixture_nonzero_field_on_success(0, count);

static int fail_with_zero_bucket_count(struct fixture_bucket_table *table)
{
	table->count = 0;
	return 0;
}

int failed_summary_may_leave_zero(struct fixture_bucket_table *table)
{
	return fail_with_zero_bucket_count(table);
}

unsigned summarized_nonzero_field(unsigned value,
	struct fixture_bucket_table *table)
{
	if (!establish_bucket_count(table))
		return 0;
	return value % table->count;
}

int signed_mask_bias(int value)
{
	int exponent = value & 0x7ff;
	return exponent - 1023;
}

int reversed_signed_mask_bias(int value)
{
	int exponent = 0x7ff & value;
	return exponent - 1023;
}

int unsigned_shift_mask_bias(unsigned long long bits)
{
	int exponent = (int)((bits >> 52) & 0x7ffu);
	return exponent - 1023;
}

int unsigned_shift_without_mask(unsigned value)
{
	int narrowed = (int)(value >> 1);
	return narrowed - 1;
}

int unsigned_wide_shift_fits_signed(unsigned long long value)
{
	int narrowed = (int)(value >> 33);
	return narrowed - 1;
}

int reassigned_mask_range(unsigned value)
{
	int exponent = (int)(value & 0x7ffu);
	exponent = (int)((value >> 16) & 0xffu);
	return exponent - 255;
}

int value_preserving_signed_char_mask(unsigned value)
{
	signed char narrowed = (signed char)(value & 0x7f);
	return (int)narrowed - 127;
}

int mask_at_int_bounds(unsigned value)
{
	int narrowed = (int)(value & 0x7fffffffU);
	return narrowed + (-2147483647 - 1);
}

#define ARITH_OUTPUT_EXCLUDES_MIN(argument) \
	__attribute__((annotate("spicule_arith_output_excludes_min:" #argument)))

extern double frexp(double, int *) ARITH_OUTPUT_EXCLUDES_MIN(1);
extern float frexpf(float, int *) ARITH_OUTPUT_EXCLUDES_MIN(1);
extern long double frexpl(long double, int *) ARITH_OUTPUT_EXCLUDES_MIN(1);

extern int provide_count(int, int *) ARITH_OUTPUT_EXCLUDES_MIN(1);

int summarized_different_name_output(int value)
{
	int count;
	provide_count(value, &count);
	return count - 1;
}

int summarized_frexp_exponent(double value)
{
	int exponent;
	frexp(value, &exponent);
	return exponent - 1;
}

int summarized_frexpf_exponent(float value)
{
	int exponent;
	frexpf(value, &exponent);
	return exponent - 1;
}

int summarized_frexpl_exponent(long double value)
{
	int exponent;
	frexpl(value, &exponent);
	return exponent - 1;
}

/* Pointer subtraction belongs to provenance/object-bound analysis, not to
 * generic signed integer arithmetic. */
long pointer_difference_is_not_integer_arithmetic(int *left, int *right)
{
	return left - right;
}
