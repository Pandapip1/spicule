/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * A from-scratch RFC 1951 DEFLATE decompressor plus the RFC 1952 gzip
 * container around it -- Tier 4 of src/util/man.c's own troff-engine
 * plan (see .claude/plans/man-troff-engine.md and that file's own
 * header comment): real `/usr/share/man` is almost entirely `.gz`
 * pages, and man.c's own file-opening path (man_read_page()) needs a
 * real decompressor to reach them, not a wrapper around a real one --
 * this project has no zlib/libz anywhere in its tree, by design.
 *
 * ---- DEFLATE (RFC 1951) -------------------------------------------------
 *
 * A DEFLATE stream is a sequence of blocks, each starting with a
 * 1-bit BFINAL flag (this is the last block) and a 2-bit BTYPE (00
 * stored/uncompressed, 01 fixed Huffman, 10 dynamic Huffman, 11
 * reserved/invalid). All bits are packed LSB-first within each byte,
 * least-significant-bit-of-the-stream first -- see bit_get()/
 * bit_getn() below, the one place this file's bit order actually
 * matters; everything above them just calls those two functions and
 * never touches a byte directly except stored blocks and the LEN/
 * NLEN it byte-aligns for.
 *
 * A stored block is the simple case: skip to the next byte boundary,
 * read a 16-bit LEN and its one's-complement NLEN (a self-check with
 * no real error-correcting value, just redundancy -- verified anyway,
 * matching real DEFLATE decoders), then copy LEN literal bytes.
 *
 * A Huffman-coded block (fixed or dynamic) is a stream of symbols in
 * one alphabet of 286 "literal/length" codes (0-255 = a literal byte,
 * 256 = end-of-block, 257-285 = a back-reference LENGTH, each with a
 * base value and a few extra literal bits read straight off the
 * stream -- LEN_BASE/LEN_EXTRA below, RFC 1951 SS3.2.5's own table)
 * paired with a second, independent alphabet of 30 "distance" codes
 * (DIST_BASE/DIST_EXTRA, same shape) that follows every length symbol.
 * A (length, distance) pair means "copy LENGTH bytes from DISTANCE
 * bytes back in the OUTPUT already produced" -- LZ77's own back-
 * reference, and the reason this file keeps the whole decompressed
 * page in one buffer rather than streaming it: the reference window
 * is measured against the output, and the simplest correct thing is
 * to just let it be the real output, unbounded, rather than
 * reimplementing DEFLATE's 32KiB sliding-window as a second data
 * structure a man page never needs (see gz_emit()'s own MAN_GZ_
 * MAX_OUTPUT cap for the actual size bound this file does enforce).
 * A back-reference with LENGTH > DISTANCE (the common "repeat this
 * one byte 200 times" run-length case) still works correctly with a
 * plain byte-at-a-time copy loop -- see the copy loop under BTYPE 1/2
 * below -- because each copied byte becomes readable output before
 * the next one is copied, exactly the self-referential behaviour
 * DEFLATE's own spec describes.
 *
 * "Fixed Huffman" (BTYPE 01) uses one specific, hardcoded pair of code
 * tables RFC 1951 SS3.2.6 spells out literally (fixed_lengths() below);
 * "dynamic Huffman" (BTYPE 10) transmits its own two code tables at
 * the start of the block, themselves Huffman-coded using a THIRD,
 * 19-symbol "code length alphabet" (RFC 1951 SS3.2.7) whose own code
 * lengths are sent as plain 3-bit values in a fixed, deliberately
 * scrambled order (CLEN_ORDER below -- most real files don't use all
 * 19 symbols, so sending the common ones first lets HCLEN truncate the
 * list early) -- decoded with repeat codes 16 ("copy the previous code
 * length 3-6 more times"), 17 and 18 ("N more zero-length codes",
 * i.e. unused symbols) so a mostly-empty table costs only a few bits.
 *
 * Every one of the three alphabets above (code-length, literal/
 * length, distance) is decoded by the exact same canonical-Huffman
 * algorithm, huff_build()/huff_decode() below -- "canonical" meaning
 * codes of the same bit length are assigned consecutively, in symbol
 * order, which is exactly what lets a decoder reconstruct the whole
 * code from nothing but each symbol's LENGTH (never the code itself):
 * huff_build() counts how many symbols share each length, uses that
 * to lay out where each length's symbols start (RFC 1951 SS3.2.2's own
 * two-pass algorithm), and huff_decode() then reads one bit at a time,
 * extending a candidate code and comparing it against the first code
 * of the current length -- if it falls within that length's count of
 * codes, that's the completed symbol; otherwise widen by one bit and
 * try the next length. This needs no lookup table, only the two small
 * per-length arrays, at the cost of being bit-at-a-time rather than
 * table-driven -- entirely fine for decompressing one man page, not a
 * streaming/hot-path use.
 *
 * ---- gzip (RFC 1952) -----------------------------------------------------
 *
 * The container around one DEFLATE stream: a fixed 10-byte header
 * (magic 0x1f 0x8b, compression method -- must be 8, DEFLATE, the
 * only method gzip ever actually shipped -- a flags byte, an mtime
 * this file has no use for, and two more ignored bytes), optional
 * fields gated by that flags byte (FEXTRA/FNAME/FCOMMENT/FHCRC --
 * skipped over, never used for anything, since this file only wants
 * the page's actual troff source), the DEFLATE stream itself, and a
 * trailer of CRC32 + ISIZE (the uncompressed size mod 2^32). Both
 * trailer fields are verified against the real decompressed bytes --
 * cheap, and it is the difference between silently handing man.c's
 * troff parser truncated garbage and a clear "corrupt gzip data"
 * diagnostic.
 *
 * gzip's own CRC32 (man_gz_crc32() below) is NOT src/util/cksum.c's:
 * that file's own header comment explains at length why cksum(1p)'s
 * CRC (MSB-first, unreflected, polynomial 0x04c11db7) and gzip/zlib's
 * CRC (LSB-first table, reflected polynomial 0xedb88320, seeded with
 * all-ones and complemented at the end -- RFC 1952 Appendix 8's own
 * algorithm) are two genuinely different bit-for-bit CRC-32 variants
 * that happen to share a name; reusing cksum.c's table here would
 * silently "verify" every real gzip file as corrupt. This file mirrors
 * cksum.c's own "build the table once, on first use" shape
 * (man_gz_crc32_ready) rather than reusing its actual table.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "man_gz.h"

/* ==== growable output buffer (src/util/man.c's own mbuf_append() idiom,
 * duplicated rather than shared: struct man_buf is man.c-private, and
 * this file has no other reason to depend on man.c's internals). ==== */

struct gzbuf { unsigned char *data; size_t len, cap; };

/* Real man pages, decompressed, are kilobytes; this cap exists purely
 * as a zip-bomb guard (a small crafted DEFLATE stream can legitimately
 * expand far past its own compressed size via long back-references),
 * not a real-world limit -- generous relative to src/util/man.c's own
 * MAN_MAX_PAGE_SIZE (16 MiB) on the COMPRESSED read, since a real
 * page's genuine compression ratio can be several times that without
 * being remotely suspicious. */
#define MAN_GZ_MAX_OUTPUT (64 * 1024 * 1024)

static int gzbuf_append_byte(struct gzbuf *b, unsigned char c)
{
	if (b->len + 1 > b->cap) {
		size_t newcap;
		unsigned char *g;
		if (!__util_array_capacity(b->cap, b->len, 1, 256, 1, &newcap)) return 0;
		g = __util_reallocarray(b->data, newcap, 1);
		if (!g) return 0;
		b->data = g; b->cap = newcap;
	}
	b->data[b->len++] = c;
	return 1;
}

/* ==== bit-level reader over the raw compressed bytes ==================== */

struct bitreader {
	const unsigned char *data;
	size_t len;
	size_t pos;
	unsigned bitbuf;
	int bitcnt;
	/* First error wins: every decode helper below checks/sets this
	 * instead of threading a separate return-status through every
	 * call, since a DEFLATE stream that goes wrong never usefully
	 * recovers -- the whole decompression is one all-or-nothing
	 * operation from man_gunzip()'s own caller's point of view. */
	const char *errmsg;
};

static int bit_get(struct bitreader *br)
{
	int bit;
	if (br->errmsg) return 0;
	if (br->bitcnt == 0) {
		if (br->pos >= br->len) { br->errmsg = "truncated DEFLATE stream"; return 0; }
		br->bitbuf = br->data[br->pos++];
		br->bitcnt = 8;
	}
	bit = br->bitbuf & 1;
	br->bitbuf >>= 1;
	br->bitcnt--;
	return bit;
}

static unsigned bit_getn(struct bitreader *br, int n)
{
	unsigned val = 0;
	int i;
	for (i = 0; i < n; i++) val |= (unsigned)bit_get(br) << i;
	return val;
}

/* Discards any partially-consumed byte -- DEFLATE's own rule for a
 * stored block, which always starts on a byte boundary. */
static void bit_align(struct bitreader *br) { br->bitcnt = 0; br->bitbuf = 0; }

/* Emits one decompressed byte, enforcing MAN_GZ_MAX_OUTPUT and
 * reporting the two ways that can fail (the cap itself, or a real
 * allocation failure) as distinct diagnostics. Every place this file
 * produces output -- literal bytes, stored-block copies, back-
 * reference copies -- goes through this one function. */
static int gz_emit(struct bitreader *br, struct gzbuf *out, unsigned char c)
{
	if (out->len >= MAN_GZ_MAX_OUTPUT) {
		br->errmsg = "decompressed data exceeds this implementation's size limit";
		return 0;
	}
	if (!gzbuf_append_byte(out, c)) {
		br->errmsg = "out of memory";
		return 0;
	}
	return 1;
}

/* ==== canonical Huffman decoding (RFC 1951 SS3.2.2) ====================== */

#define MAXBITS 15
#define MAX_HUFF_SYMBOLS 288 /* the literal/length alphabet's own 288 is the largest of the three */

struct huff {
	int count[MAXBITS + 1]; /* count[len] = how many symbols have that code length */
	int symbol[MAX_HUFF_SYMBOLS]; /* symbols, grouped by length then by symbol value */
};

/* `lengths[0..n)` is symbol -> code length (0 = "this symbol isn't
 * used"). Builds the canonical code purely from those lengths, per
 * RFC 1951 SS3.2.2's own two-pass algorithm: first count how many
 * symbols share each length, then lay out an increasing start offset
 * per length and drop each symbol into its length's next slot, in
 * ascending symbol order -- which is, by definition, the order
 * canonical codes assign within one length. */
static void huff_build(struct huff *h, const unsigned char *lengths, int n)
{
	int offs[MAXBITS + 1];
	int len, sym;

	for (len = 0; len <= MAXBITS; len++) h->count[len] = 0;
	for (sym = 0; sym < n; sym++) h->count[lengths[sym]]++;
	h->count[0] = 0; /* unused symbols never match a real code */

	offs[1] = 0;
	for (len = 1; len < MAXBITS; len++) offs[len + 1] = offs[len] + h->count[len];
	for (sym = 0; sym < n; sym++)
		if (lengths[sym]) h->symbol[offs[lengths[sym]]++] = sym;
}

/* Reads one bit at a time, widening a candidate code and testing it
 * against the range of codes already known to exist at the current
 * length (h->count[len] of them, starting at `first`) -- the standard
 * bit-at-a-time canonical-Huffman decode: no lookup table, just the
 * two small per-length arrays huff_build() filled in. Returns the
 * decoded symbol, or -1 (with br->errmsg set) on EOF or a code that
 * never matches at any length up to MAXBITS -- corrupt input. */
static int huff_decode(struct bitreader *br, const struct huff *h)
{
	int code = 0, first = 0, index = 0, len;

	for (len = 1; len <= MAXBITS; len++) {
		code |= bit_get(br);
		if (br->errmsg) return -1;
		{
			int count = h->count[len];
			if (code - first < count) return h->symbol[index + (code - first)];
			index += count;
			first += count;
			first <<= 1;
			code <<= 1;
		}
	}
	br->errmsg = "invalid Huffman code in DEFLATE stream";
	return -1;
}

/* RFC 1951 SS3.2.6's own literal/length codes 0-143 -> 8 bits, 144-255
 * -> 9 bits, 256-279 -> 7 bits, 280-287 -> 8 bits; all 30 distance
 * codes -> 5 bits. Fixed, hardcoded by the spec itself, not derived. */
static void fixed_lengths(unsigned char *litlen, unsigned char *distlen)
{
	int i = 0;
	for (; i < 144; i++) litlen[i] = 8;
	for (; i < 256; i++) litlen[i] = 9;
	for (; i < 280; i++) litlen[i] = 7;
	for (; i < 288; i++) litlen[i] = 8;
	for (i = 0; i < 30; i++) distlen[i] = 5;
}

/* ==== length/distance code tables (RFC 1951 SS3.2.5) ===================== */

static const unsigned short LEN_BASE[29] = {
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27,
	31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
};
static const unsigned char LEN_EXTRA[29] = {
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
	2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
};
static const unsigned short DIST_BASE[30] = {
	1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129,
	193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
};
static const unsigned char DIST_EXTRA[30] = {
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
	6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
};

/* The order code-length-alphabet lengths are transmitted in for a
 * dynamic block (RFC 1951 SS3.2.7) -- deliberately NOT numeric order,
 * so that HCLEN can truncate the list right after the last symbol a
 * real file actually uses, since the rarer symbols (which real files
 * often skip entirely) are placed last. */
static const unsigned char CLEN_ORDER[19] = {
	16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
};

/* ==== the literal/length + distance symbol stream, shared by fixed and
 * dynamic blocks alike (only their Huffman tables differ) =============== */

static int inflate_decode_block(
	struct bitreader *br, struct gzbuf *out, const struct huff *lit, const struct huff *dist)
{
	for (;;) {
		int sym = huff_decode(br, lit);
		if (sym < 0) return 0;
		if (sym < 256) {
			if (!gz_emit(br, out, (unsigned char)sym)) return 0;
		} else if (sym == 256) {
			return 1; /* end-of-block */
		} else if (sym <= 285) {
			int length, dsym;
			size_t distance, i;

			length = LEN_BASE[sym - 257] + (int)bit_getn(br, LEN_EXTRA[sym - 257]);
			dsym = huff_decode(br, dist);
			if (dsym < 0) return 0;
			if (dsym > 29) { br->errmsg = "invalid distance code in DEFLATE stream"; return 0; }
			distance = DIST_BASE[dsym] + bit_getn(br, DIST_EXTRA[dsym]);
			if (br->errmsg) return 0;
			if (distance > out->len) {
				br->errmsg = "back-reference distance points before start of output";
				return 0;
			}
			/* A byte-at-a-time copy, not memmove(): when distance <
			 * length (a short repeating run, e.g. "aaaa...") each
			 * newly-copied byte must itself become visible to LATER
			 * iterations of this same loop -- exactly what indexing
			 * out->data[out->len - distance] on every iteration
			 * (rather than snapshotting a source pointer once) gives. */
			for (i = 0; i < (size_t)length; i++)
				if (!gz_emit(br, out, out->data[out->len - distance])) return 0;
		} else {
			br->errmsg = "invalid length code in DEFLATE stream";
			return 0;
		}
	}
}

/* Reads a dynamic block's two Huffman tables (SS3.2.7: HLIT/HDIST/
 * HCLEN counts, the code-length alphabet's own lengths in CLEN_ORDER,
 * then the literal/length and distance tables' lengths, decoded
 * through THAT alphabet with the 16/17/18 repeat codes) and decodes
 * the block's symbol stream through them. */
static int inflate_dynamic_block(struct bitreader *br, struct gzbuf *out)
{
	int hlit, hdist, hclen, i, total, n;
	unsigned char clen_lengths[19];
	unsigned char lengths[288 + 32];
	struct huff clen_huff, lit, dist;

	hlit = (int)bit_getn(br, 5) + 257;
	hdist = (int)bit_getn(br, 5) + 1;
	hclen = (int)bit_getn(br, 4) + 4;
	if (br->errmsg) return 0;

	for (i = 0; i < 19; i++) clen_lengths[i] = 0;
	for (i = 0; i < hclen; i++) clen_lengths[CLEN_ORDER[i]] = (unsigned char)bit_getn(br, 3);
	if (br->errmsg) return 0;
	huff_build(&clen_huff, clen_lengths, 19);

	/* hlit/hdist are each an opaque bit_getn() read plus a compile-time
	 * constant (5-bit field + 257, 5-bit field + 1), so `total` is always
	 * >= 258 and the decode loop below always runs at least once, filling
	 * lengths[0..total) before either huff_build() call below reads it.
	 * cppcheck's value-flow does not carry that range through bit_getn()
	 * (an opaque call), so it considers the loop running zero iterations
	 * and reports lengths as unconditionally uninitialised at the first
	 * huff_build() call. Zero it up front, same as clen_lengths just
	 * above, so the array is well-defined even on that unreachable path. */
	for (i = 0; i < (int)(sizeof(lengths) / sizeof(lengths[0])); i++) lengths[i] = 0;

	total = hlit + hdist;
	n = 0;
	while (n < total) {
		int sym = huff_decode(br, &clen_huff);
		if (sym < 0) return 0;
		if (sym < 16) {
			lengths[n++] = (unsigned char)sym;
			continue;
		}
		{
			int repeat;
			unsigned char fill;
			if (sym == 16) {
				if (n == 0) { br->errmsg = "repeat code with no previous code length"; return 0; }
				repeat = (int)bit_getn(br, 2) + 3;
				fill = lengths[n - 1];
			} else if (sym == 17) {
				repeat = (int)bit_getn(br, 3) + 3;
				fill = 0;
			} else if (sym == 18) {
				repeat = (int)bit_getn(br, 7) + 11;
				fill = 0;
			} else {
				br->errmsg = "invalid code-length symbol in DEFLATE stream";
				return 0;
			}
			if (br->errmsg) return 0;
			if (n + repeat > total) { br->errmsg = "code-length repeat overruns its own table"; return 0; }
			while (repeat-- > 0) lengths[n++] = fill;
		}
	}

	huff_build(&lit, lengths, hlit);
	huff_build(&dist, lengths + hlit, hdist);
	return inflate_decode_block(br, out, &lit, &dist);
}

/* ==== the outer block loop (RFC 1951 SS3.2.3) ============================ */

static int inflate_stream(struct bitreader *br, struct gzbuf *out)
{
	int bfinal;

	do {
		int btype;
		bfinal = (int)bit_getn(br, 1);
		btype = (int)bit_getn(br, 2);
		if (br->errmsg) return 0;

		if (btype == 0) {
			size_t blen, nlen;
			bit_align(br);
			if (br->pos + 4 > br->len) { br->errmsg = "truncated stored-block header"; return 0; }
			blen = (size_t)br->data[br->pos] | ((size_t)br->data[br->pos + 1] << 8);
			nlen = (size_t)br->data[br->pos + 2] | ((size_t)br->data[br->pos + 3] << 8);
			br->pos += 4;
			if ((blen ^ 0xFFFFu) != nlen) { br->errmsg = "stored-block LEN/NLEN mismatch"; return 0; }
			if (br->pos + blen > br->len) { br->errmsg = "truncated stored-block data"; return 0; }
			{
				size_t i;
				for (i = 0; i < blen; i++)
					if (!gz_emit(br, out, br->data[br->pos + i])) return 0;
			}
			br->pos += blen;
		} else if (btype == 1) {
			unsigned char litlen[288], distlen[30];
			struct huff lit, dist;
			fixed_lengths(litlen, distlen);
			huff_build(&lit, litlen, 288);
			huff_build(&dist, distlen, 30);
			if (!inflate_decode_block(br, out, &lit, &dist)) return 0;
		} else if (btype == 2) {
			if (!inflate_dynamic_block(br, out)) return 0;
		} else {
			br->errmsg = "invalid DEFLATE block type (reserved value 3)";
			return 0;
		}
	} while (!bfinal);

	return 1;
}

/* ==== gzip's own CRC32 (RFC 1952 Appendix 8) -- see this file's own
 * header comment for why it cannot be src/util/cksum.c's table. ====== */

static uint32_t man_gz_crc32_table[256];
static int man_gz_crc32_ready;

static void man_gz_crc32_build_table(void)
{
	int n, k;
	for (n = 0; n < 256; n++) {
		uint32_t c = (uint32_t)n;
		for (k = 0; k < 8; k++)
			c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
		man_gz_crc32_table[n] = c;
	}
	man_gz_crc32_ready = 1;
}

static uint32_t man_gz_crc32(const unsigned char *data, size_t len)
{
	uint32_t crc;
	size_t i;
	if (!man_gz_crc32_ready) man_gz_crc32_build_table();
	crc = 0xFFFFFFFFUL;
	for (i = 0; i < len; i++)
		crc = man_gz_crc32_table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFFUL;
}

static uint32_t read_u32le(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ==== public entry points (see man_gz.h for the full contract) ========== */

int man_looks_gzipped(const char *data, size_t len)
{
	return len >= 2 && (unsigned char)data[0] == 0x1f && (unsigned char)data[1] == 0x8b;
}

#define GZ_FTEXT    0x01
#define GZ_FHCRC    0x02
#define GZ_FEXTRA   0x04
#define GZ_FNAME    0x08
#define GZ_FCOMMENT 0x10

int man_gunzip(const char *in_, size_t inlen, char **out, size_t *outlen, const char **errmsg)
{
	const unsigned char *in = (const unsigned char *)in_;
	size_t pos;
	unsigned char flg;
	struct bitreader br;
	struct gzbuf ob;
	uint32_t stored_crc, stored_isize, real_crc;

	*errmsg = 0;

	if (inlen < 10 || in[0] != 0x1f || in[1] != 0x8b) {
		*errmsg = "not a gzip file (bad magic number)";
		return 0;
	}
	if (in[2] != 8) {
		*errmsg = "unsupported gzip compression method (only DEFLATE/8 is implemented)";
		return 0;
	}
	flg = in[3];
	pos = 10; /* magic(2) + CM(1) + FLG(1) + MTIME(4) + XFL(1) + OS(1) */

	if (flg & GZ_FEXTRA) {
		size_t xlen;
		if (pos + 2 > inlen) { *errmsg = "truncated gzip header (FEXTRA)"; return 0; }
		xlen = (size_t)in[pos] | ((size_t)in[pos + 1] << 8);
		pos += 2;
		if (pos + xlen > inlen) { *errmsg = "truncated gzip header (FEXTRA)"; return 0; }
		pos += xlen;
	}
	if (flg & GZ_FNAME) {
		while (pos < inlen && in[pos]) pos++;
		if (pos >= inlen) { *errmsg = "truncated gzip header (FNAME)"; return 0; }
		pos++;
	}
	if (flg & GZ_FCOMMENT) {
		while (pos < inlen && in[pos]) pos++;
		if (pos >= inlen) { *errmsg = "truncated gzip header (FCOMMENT)"; return 0; }
		pos++;
	}
	if (flg & GZ_FHCRC) {
		if (pos + 2 > inlen) { *errmsg = "truncated gzip header (FHCRC)"; return 0; }
		pos += 2; /* CRC16 of the header itself -- not verified, same "recognised, not acted on" precedent as elsewhere in this project */
	}

	memset(&br, 0, sizeof br);
	br.data = in; br.len = inlen; br.pos = pos;
	memset(&ob, 0, sizeof ob);

	if (!inflate_stream(&br, &ob)) {
		*errmsg = br.errmsg ? br.errmsg : "corrupt DEFLATE stream";
		free(ob.data);
		return 0;
	}

	bit_align(&br); /* the trailer is always byte-aligned right after the last block */
	if (br.pos + 8 > br.len) {
		*errmsg = "truncated gzip trailer";
		free(ob.data);
		return 0;
	}
	stored_crc = read_u32le(in + br.pos);
	stored_isize = read_u32le(in + br.pos + 4);

	real_crc = man_gz_crc32(ob.data, ob.len);
	if (real_crc != stored_crc) {
		*errmsg = "gzip CRC32 mismatch (corrupt data)";
		free(ob.data);
		return 0;
	}
	if ((uint32_t)ob.len != stored_isize) {
		*errmsg = "gzip ISIZE mismatch (corrupt data)";
		free(ob.data);
		return 0;
	}

	if (!ob.data) { /* empty page, decompressed to nothing -- keep man_read_file()'s "never NULL" contract */
		ob.data = malloc(1);
		if (!ob.data) { *errmsg = "out of memory"; return 0; }
		ob.data[0] = 0;
	}
	*out = (char *)ob.data;
	*outlen = ob.len;
	return 1;
}
