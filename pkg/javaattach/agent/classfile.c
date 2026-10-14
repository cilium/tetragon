// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Tetragon */

/*
 * Class file rewriter.
 *
 * Puts TetragonHook.enter(key) calls at the entry of class methods. It works
 * only with the class file bytes, the caller decides which methods get the
 * call and with what keys, see classfile.h.
 *
 * The class file is big-endian, see the JVM specification chapter 4 for
 * its format.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "classfile.h"

/* Growable output buffer. */
struct buffer {
	unsigned char *p;
	size_t n;
	size_t cap;
};

/* Constant pool entry, bytes and len are set only for CONSTANT_Utf8. */
struct cp_entry {
	uint8_t tag;
	const unsigned char *bytes;
	uint16_t len;
};

/*
 * TetragonHook.enter calls to inject into one method of the class, one for
 * each key. The keys are stored in consecutive CONSTANT_Long constant pool
 * entries, long_index is the index of the first one.
 */
struct method_plan {
	uint64_t *keys;
	size_t count;
	uint16_t long_index;
};

static uint16_t be16(const unsigned char *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t be32(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void put_be16(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)(v >> 8);
	p[1] = (unsigned char)v;
}

static void put_be32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

/* Append n bytes to the buffer, returns -1 when it can not grow. */
static int append(struct buffer *b, const void *p, size_t n)
{
	unsigned char *q;
	size_t cap;

	if (n > SIZE_MAX - b->n)
		return -1;
	if (b->n + n > b->cap) {
		/* Double the capacity until the data fits. */
		cap = b->cap ? b->cap : 256;
		while (cap < b->n + n) {
			if (cap > SIZE_MAX / 2)
				return -1;
			cap *= 2;
		}

		q = realloc(b->p, cap);
		if (!q)
			return -1;
		b->p = q;
		b->cap = cap;
	}

	memcpy(b->p + b->n, p, n);
	b->n += n;
	return 0;
}

static int append_u2(struct buffer *b, uint16_t v)
{
	unsigned char p[2];

	put_be16(p, v);
	return append(b, p, 2);
}

static int append_u4(struct buffer *b, uint32_t v)
{
	unsigned char p[4];

	put_be32(p, v);
	return append(b, p, 4);
}

/* Check that n bytes at offset off fit into total bytes. */
static int bounds(size_t off, size_t n, size_t total)
{
	return off <= total && n <= total - off;
}

/* Returns allocated copy of CONSTANT_Utf8 entry, NULL for other entries. */
static char *cp_string(struct cp_entry *cp, uint16_t idx)
{
	char *s;

	if (!cp[idx].tag || cp[idx].tag != 1)
		return NULL;
	s = calloc(1, (size_t)cp[idx].len + 1);
	if (!s)
		return NULL;
	memcpy(s, cp[idx].bytes, cp[idx].len);
	return s;
}

/*
 * Skip field_info: u2 access_flags, u2 name_index, u2 descriptor_index,
 * u2 attributes_count and the attributes.
 */
static int skip_member(const unsigned char *d, size_t len, size_t *off)
{
	uint16_t attrs, i;
	uint32_t n;

	if (!bounds(*off, 8, len))
		return -1;
	attrs = be16(d + *off + 6);
	*off += 8;
	for (i = 0; i < attrs; i++) {
		if (!bounds(*off, 6, len))
			return -1;
		n = be32(d + *off + 2);
		*off += 6;
		if (!bounds(*off, n, len))
			return -1;
		*off += n;
	}

	return 0;
}

/*
 * Walk the instructions and check they all stay within the code, returns
 * 1 if they do. The code is not changed, only moved by the prefix, so all
 * we need to know is the instruction length.
 */
static int safe_bytecode(const unsigned char *code, uint32_t len)
{
	uint32_t pc = 0, n, pad, base;
	int32_t low, high, pairs;
	uint64_t entries, size;
	uint8_t op;

	while (pc < len) {
		op = code[pc];
		n = 1;

		/*
		 * tableswitch (0xaa) and lookupswitch (0xab) are padded so their
		 * operands start at 4 bytes boundary from the code start.
		 */
		if (op == 0xaa || op == 0xab) {
			pad = (4 - ((pc + 1) & 3)) & 3;
			base = pc + 1 + pad;
			if (!bounds(base, op == 0xaa ? 12 : 8, len))
				return 0;
			if (op == 0xaa) {
				/* u4 default, u4 low, u4 high and high - low + 1 jump offsets */
				low = (int32_t)be32(code + base + 4);
				high = (int32_t)be32(code + base + 8);
				if (high < low)
					return 0;
				entries = (uint64_t)((int64_t)high - low + 1);
				size = 1 + pad + 12 + entries * 4;
				if (size > UINT32_MAX)
					return 0;
				n = (uint32_t)size;
			} else {
				/* u4 default, u4 npairs and npairs pairs of u4 match and offset */
				pairs = (int32_t)be32(code + base + 4);
				if (pairs < 0)
					return 0;
				size = 1 + pad + 8 + (uint64_t)pairs * 8;
				if (size > UINT32_MAX)
					return 0;
				n = (uint32_t)size;
			}
		}

		/*
		 * Instructions with operands, the rest is single byte:
		 *   2 bytes: bipush, ldc, iload..aload, istore..astore, ret,
		 *            newarray
		 *   3 bytes: sipush, ldc_w, ldc2_w, ifeq..jsr, iinc,
		 *            getstatic..invokestatic, new, anewarray, checkcast,
		 *            instanceof, ifnull, ifnonnull
		 *   5 bytes: invokeinterface, invokedynamic, goto_w, jsr_w
		 *   4 bytes: multianewarray
		 *   wide (0xc4): 6 bytes for iinc, 4 bytes otherwise
		 */
		if (op == 0x10 || op == 0x12 || op == 0x15 || op == 0x16 || op == 0x17 ||
		    op == 0x18 || op == 0x19 || op == 0x36 || op == 0x37 || op == 0x38 ||
		    op == 0x39 || op == 0x3a || op == 0xa9 || op == 0xbc) {
			n = 2;
		} else if (op == 0x11 || op == 0x13 || op == 0x14 || (op >= 0x99 && op <= 0xa8) ||
			   op == 0x84 || (op >= 0xb2 && op <= 0xb8) || op == 0xbb || op == 0xbd ||
			   op == 0xc0 || op == 0xc1 || op == 0xc6 || op == 0xc7) {
			n = 3;
		} else if (op == 0xb9 || op == 0xba) {
			n = 5;
		} else if (op == 0xc5) {
			n = 4;
		} else if (op == 0xc8 || op == 0xc9) {
			n = 5;
		} else if (op == 0xc4) {
			if (pc + 1 >= len)
				return 0;
			n = code[pc + 1] == 0x84 ? 6 : 4;
		}

		if (!bounds(pc, n, len))
			return 0;
		pc += n;
	}

	return 1;
}

/*
 * Copy verification_type_info. Object (7) carries constant pool index,
 * Uninitialized (8) carries offset of the new instruction, which moves by
 * the prefix.
 */
static int copy_verification_type(const unsigned char *src, size_t len, size_t *off,
				  uint32_t prefix, struct buffer *out)
{
	uint16_t pc;
	uint8_t tag;

	if (!bounds(*off, 1, len))
		return -1;

	tag = src[(*off)++];
	append(out, &tag, 1);

	if (tag == 7) {
		if (!bounds(*off, 2, len))
			return -1;
		append(out, src + *off, 2);
		*off += 2;
	} else if (tag == 8) {
		if (!bounds(*off, 2, len))
			return -1;
		pc = be16(src + *off);
		if (pc + prefix > 65535)
			return -1;
		append_u2(out, (uint16_t)(pc + prefix));
		*off += 2;
	} else if (tag > 8) {
		return -1;
	}

	return 0;
}

static int copy_element_value(const unsigned char *src, size_t len, size_t *off,
			      struct buffer *out);

/*
 * Copy annotation: u2 type_index, u2 num_element_value_pairs and the
 * pairs of u2 element_name_index and element_value.
 */
static int copy_annotation(const unsigned char *src, size_t len, size_t *off, struct buffer *out)
{
	uint16_t pairs, i;

	if (!bounds(*off, 4, len))
		return -1;
	append(out, src + *off, 4);
	pairs = be16(src + *off + 2);
	*off += 4;
	for (i = 0; i < pairs; i++) {
		if (!bounds(*off, 2, len))
			return -1;
		append(out, src + *off, 2);
		*off += 2;
		if (copy_element_value(src, len, off, out))
			return -1;
	}

	return 0;
}

static int copy_element_value(const unsigned char *src, size_t len, size_t *off, struct buffer *out)
{
	uint16_t n, i;
	uint8_t tag;

	if (!bounds(*off, 1, len))
		return -1;
	tag = src[*off];
	append(out, src + *off, 1);
	(*off)++;

	/* const_value_index for primitive types and String */
	if (strchr("BCDFIJSZs", tag)) {
		if (!bounds(*off, 2, len))
			return -1;
		append(out, src + *off, 2);
		*off += 2;
		return 0;
	}

	/* enum: type_name_index and const_name_index */
	if (tag == 'e') {
		if (!bounds(*off, 4, len))
			return -1;
		append(out, src + *off, 4);
		*off += 4;
		return 0;
	}

	/* class: class_info_index */
	if (tag == 'c') {
		if (!bounds(*off, 2, len))
			return -1;
		append(out, src + *off, 2);
		*off += 2;
		return 0;
	}

	/* nested annotation */
	if (tag == '@')
		return copy_annotation(src, len, off, out);

	/* array: num_values and the values */
	if (tag == '[') {
		if (!bounds(*off, 2, len))
			return -1;
		n = be16(src + *off);
		append(out, src + *off, 2);
		*off += 2;
		for (i = 0; i < n; i++) {
			if (copy_element_value(src, len, off, out))
				return -1;
		}

		return 0;
	}

	return -1;
}

/*
 * Rewrite Runtime(In)VisibleTypeAnnotations of the Code attribute, shift
 * bytecode offsets in the annotation targets by the prefix:
 *   0x40-0x41 localvar_target, table of start_pc, length, index
 *   0x42      catch_target, exception table index (no offset)
 *   0x43-0x46 offset_target
 *   0x47-0x4b type_argument_target, offset and type argument index
 */
static int transform_type_annotations(const unsigned char *src, uint32_t len, uint32_t prefix,
				      struct buffer *out)
{
	uint16_t count, n, pc, i, j;
	uint8_t target, path_len;
	size_t path_bytes;
	size_t off = 2;

	if (len < 2)
		return -1;

	count = be16(src);
	append_u2(out, count);
	for (i = 0; i < count; i++) {
		if (!bounds(off, 1, len))
			return -1;

		target = src[off++];
		append(out, &target, 1);

		if (target == 0x40 || target == 0x41) {
			if (!bounds(off, 2, len))
				return -1;
			n = be16(src + off);
			append_u2(out, n);
			off += 2;
			for (j = 0; j < n; j++) {
				if (!bounds(off, 6, len))
					return -1;
				pc = be16(src + off);
				if (pc + prefix > 65535)
					return -1;
				append_u2(out, (uint16_t)(pc + prefix));
				append(out, src + off + 2, 4);
				off += 6;
			}
		} else if (target == 0x42) {
			if (!bounds(off, 2, len))
				return -1;
			append(out, src + off, 2);
			off += 2;
		} else if (target >= 0x43 && target <= 0x46) {
			if (!bounds(off, 2, len))
				return -1;
			pc = be16(src + off);
			if (pc + prefix > 65535)
				return -1;
			append_u2(out, (uint16_t)(pc + prefix));
			off += 2;
		} else if (target >= 0x47 && target <= 0x4b) {
			if (!bounds(off, 3, len))
				return -1;
			pc = be16(src + off);
			if (pc + prefix > 65535)
				return -1;
			append_u2(out, (uint16_t)(pc + prefix));
			append(out, src + off + 2, 1);
			off += 3;
		} else {
			return -1;
		}

		if (!bounds(off, 1, len))
			return -1;

		/*
		 * type_path, u1 path_length and path_length pairs of u1 kind
		 * and u1 argument index, followed by the annotation itself.
		 */
		path_len = src[off];
		path_bytes = 1 + (size_t)path_len * 2;
		if (!bounds(off, path_bytes, len))
			return -1;
		append(out, src + off, path_bytes);
		off += path_bytes;
		if (copy_annotation(src, len, &off, out))
			return -1;
	}

	return off == len ? 0 : -1;
}

/*
 * Rewrite StackMapTable. Each frame stores offset delta from the previous
 * frame, so only the first frame moves by the prefix. The frame is changed
 * to its extended form when the new delta does not fit into the frame type.
 */
static int transform_stackmap(const unsigned char *src, uint32_t len, uint32_t prefix,
			      struct buffer *out)
{
	uint16_t count, delta, locals, stack, i, j;
	uint32_t shift, d;
	size_t off = 2;
	uint8_t ft, b, k;
	int compact;

	if (len < 2)
		return -1;

	count = be16(src);
	append_u2(out, count);
	for (i = 0; i < count; i++) {
		if (!bounds(off, 1, len))
			return -1;

		ft = src[off++];

		/* Only the first frame has absolute offset. */
		shift = i == 0 ? prefix : 0;

		/* same_frame, changed to same_frame_extended (251) if needed */
		if (ft <= 63) {
			d = (uint32_t)ft + shift;
			if (d > 65535)
				return -1;
			if (d <= 63) {
				b = (uint8_t)d;
				append(out, &b, 1);
			} else {
				b = 251;
				append(out, &b, 1);
				append_u2(out, (uint16_t)d);
			}
			continue;
		}

		/*
		 * same_locals_1_stack_item_frame and its extended form (247),
		 * followed by one verification type
		 */
		if (ft <= 127 || ft == 247) {
			compact = ft <= 127;
			if (compact) {
				delta = (uint16_t)(ft - 64);
			} else {
				if (!bounds(off, 2, len))
					return -1;
				delta = be16(src + off);
				off += 2;
			}

			d = (uint32_t)delta + shift;
			if (d > 65535)
				return -1;

			/* Keep the compact form only if the new delta fits in. */
			if (compact && d <= 63) {
				b = (uint8_t)(64 + d);
				append(out, &b, 1);
			} else {
				b = 247;
				append(out, &b, 1);
				append_u2(out, (uint16_t)d);
			}

			if (copy_verification_type(src, len, &off, prefix, out))
				return -1;
			continue;
		}

		/* chop_frame and same_frame_extended */
		if (ft >= 248 && ft <= 251) {
			if (!bounds(off, 2, len))
				return -1;
			delta = be16(src + off);
			off += 2;
			d = (uint32_t)delta + shift;
			if (d > 65535)
				return -1;
			append(out, &ft, 1);
			append_u2(out, (uint16_t)d);
			continue;
		}

		/* append_frame, followed by ft - 251 verification types */
		if (ft >= 252 && ft <= 254) {
			if (!bounds(off, 2, len))
				return -1;
			delta = be16(src + off);
			off += 2;
			d = (uint32_t)delta + shift;
			if (d > 65535)
				return -1;
			append(out, &ft, 1);
			append_u2(out, (uint16_t)d);
			for (k = 0; k < (uint8_t)(ft - 251); k++) {
				if (copy_verification_type(src, len, &off, prefix, out))
					return -1;
			}
			continue;
		}

		/* full_frame, followed by locals and stack verification types */
		if (ft == 255) {
			if (!bounds(off, 2, len))
				return -1;
			delta = be16(src + off);
			off += 2;
			d = (uint32_t)delta + shift;
			if (d > 65535)
				return -1;
			append(out, &ft, 1);
			append_u2(out, (uint16_t)d);
			if (!bounds(off, 2, len))
				return -1;
			locals = be16(src + off);
			off += 2;
			append_u2(out, locals);
			for (j = 0; j < locals; j++) {
				if (copy_verification_type(src, len, &off, prefix, out))
					return -1;
			}

			if (!bounds(off, 2, len))
				return -1;
			stack = be16(src + off);
			off += 2;
			append_u2(out, stack);
			for (j = 0; j < stack; j++) {
				if (copy_verification_type(src, len, &off, prefix, out))
					return -1;
			}
			continue;
		}

		return -1;
	}

	return off == len ? 0 : -1;
}

/*
 * Rewrite Code attribute, put prefix in front of the bytecode and shift
 * all absolute bytecode offsets by prefix_len. Branch offsets are relative,
 * so the original bytecode is copied unchanged.
 *
 *   u2 max_stack, u2 max_locals, u4 code_length, code,
 *   u2 exception_table_length, exception table,
 *   u2 attributes_count, attributes
 *
 * Returns 1 on success, 0 if the attribute can not be safely rewritten.
 */
static int transform_code(const unsigned char *src, uint32_t src_len, const unsigned char *prefix,
			  uint32_t prefix_len, struct cp_entry *cp, struct buffer *out)
{
	const unsigned char *code, *exception_table;
	uint16_t max_stack, max_locals, exceptions, attrs, i;
	struct buffer nested = {0};
	uint32_t code_len;
	size_t off = 8;

	if (src_len < 12)
		return 0;

	max_stack = be16(src);
	max_locals = be16(src + 2);
	code_len = be32(src + 4);

	/*
	 * The code with the prefix must fit into the 64K method code limit.
	 * The lengths are checked one by one, their sum could overflow for
	 * code_len from broken class file.
	 */
	if (code_len > 65535 || prefix_len > 65535 || code_len + prefix_len > 65535)
		return 0;
	if (!bounds(off, (size_t)code_len + 2, src_len))
		return 0;

	code = src + off;
	if (!safe_bytecode(code, code_len))
		return 0;
	off += code_len;

	exceptions = be16(src + off);
	off += 2;
	if (!bounds(off, (size_t)exceptions * 8 + 2, src_len))
		return 0;

	exception_table = src + off;
	off += (size_t)exceptions * 8;

	/*
	 * Nested attributes with bytecode offsets are rewritten into nested
	 * buffer, unknown attribute fails the transformation.
	 */
	attrs = be16(src + off);
	off += 2;
	for (i = 0; i < attrs; i++) {
		uint16_t name_idx, count, x;
		char *name;
		uint32_t n;

		if (!bounds(off, 6, src_len))
			goto fail;
		name_idx = be16(src + off);
		n = be32(src + off + 2);
		off += 6;
		if (!bounds(off, n, src_len))
			goto fail;
		name = cp_string(cp, name_idx);
		if (!name)
			goto fail;
		if (!strcmp(name, "LineNumberTable")) {
			struct buffer a = {0};

			if (n < 2) {
				free(name);
				goto fail;
			}

			count = be16(src + off);
			/* entries of u2 start_pc, u2 line_number */
			if (n != 2 + (uint32_t)count * 4) {
				free(name);
				goto fail;
			}

			append_u2(&a, count);
			for (x = 0; x < count; x++) {
				uint16_t pc = be16(src + off + 2 + x * 4);

				if (pc + prefix_len > 65535) {
					free(a.p);
					free(name);
					goto fail;
				}

				append_u2(&a, (uint16_t)(pc + prefix_len));
				append(&a, src + off + 4 + x * 4, 2);
			}

			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else if (!strcmp(name, "LocalVariableTable") ||
			   !strcmp(name, "LocalVariableTypeTable")) {
			struct buffer a = {0};

			if (n < 2) {
				free(name);
				goto fail;
			}

			count = be16(src + off);
			/*
			 * entries of u2 start_pc, u2 length, u2 name_index,
			 * u2 descriptor_index (or signature_index), u2 index
			 */
			if (n != 2 + (uint32_t)count * 10) {
				free(name);
				goto fail;
			}

			append_u2(&a, count);
			for (x = 0; x < count; x++) {
				uint16_t pc = be16(src + off + 2 + x * 10);

				if (pc + prefix_len > 65535) {
					free(a.p);
					free(name);
					goto fail;
				}

				append_u2(&a, (uint16_t)(pc + prefix_len));
				append(&a, src + off + 4 + x * 10, 8);
			}

			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else if (!strcmp(name, "StackMapTable")) {
			struct buffer a = {0};

			if (transform_stackmap(src + off, n, prefix_len, &a)) {
				free(a.p);
				free(name);
				goto fail;
			}

			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else if (!strcmp(name, "RuntimeVisibleTypeAnnotations") ||
			   !strcmp(name, "RuntimeInvisibleTypeAnnotations")) {
			struct buffer a = {0};

			if (transform_type_annotations(src + off, n, prefix_len, &a)) {
				free(a.p);
				free(name);
				goto fail;
			}

			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else if (!strcmp(name, "CharacterRangeTable")) {
			struct buffer a = {0};

			if (n < 2) {
				free(name);
				goto fail;
			}

			count = be16(src + off);
			/*
			 * entries of u2 start_pc, u2 end_pc, u4 character_range_start,
			 * u4 character_range_end, u2 flags
			 */
			if (n != 2 + (uint32_t)count * 14) {
				free(name);
				goto fail;
			}

			append_u2(&a, count);
			for (x = 0; x < count; x++) {
				const unsigned char *e = src + off + 2 + x * 14;
				uint16_t start = be16(e), end = be16(e + 2);

				if (start + prefix_len > 65535 || end + prefix_len > 65535) {
					free(a.p);
					free(name);
					goto fail;
				}

				append_u2(&a, (uint16_t)(start + prefix_len));
				append_u2(&a, (uint16_t)(end + prefix_len));
				append(&a, e + 4, 10);
			}

			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else {
			free(name);
			goto fail;
		}

		free(name);
		off += n;
	}

	/* The attribute must be fully consumed. */
	if (off != src_len)
		goto fail;

	/* The long key of the injected call takes two stack slots. */
	append_u2(out, max_stack < 2 ? 2 : max_stack);
	append_u2(out, max_locals);
	append_u4(out, code_len + prefix_len);
	append(out, prefix, prefix_len);
	append(out, code, code_len);
	append_u2(out, exceptions);

	/* u2 start_pc, u2 end_pc, u2 handler_pc, u2 catch_type */
	for (i = 0; i < exceptions; i++) {
		const unsigned char *e = exception_table + i * 8;
		uint16_t start = be16(e), end = be16(e + 2);
		uint16_t handler = be16(e + 4);

		if (start + prefix_len > 65535 || end + prefix_len > 65535 ||
		    handler + prefix_len > 65535)
			goto fail;
		append_u2(out, (uint16_t)(start + prefix_len));
		append_u2(out, (uint16_t)(end + prefix_len));
		append_u2(out, (uint16_t)(handler + prefix_len));
		append(out, e + 6, 2);
	}

	append_u2(out, attrs);
	append(out, nested.p, nested.n);
	free(nested.p);
	return 1;

fail:
	free(nested.p);
	return 0;
}

static void free_plans(struct method_plan *plans, uint16_t count)
{
	uint16_t i;

	for (i = 0; i < count; i++)
		free(plans[i].keys);
	free(plans);
}

/*
 * Rewrite the class so its methods call TetragonHook.enter(key) at entry:
 *   - parse the constant pool and ask keys_fn for the keys of each method
 *   - add constant pool entries for TetragonHook.enter and the method keys
 *   - put the calls in front of the bytecode of each method with keys
 *
 * Returns 1 with the new class in out, 0 if the class stays unchanged.
 *
 * The transformer deliberately declines Code attributes whose verifier or
 * bytecode offsets it cannot safely rewrite; the original class is preserved.
 */
int classfile_instrument(const unsigned char *data, size_t len, classfile_keys_fn keys_fn,
			 void *ctx, unsigned char **out, size_t *out_len)
{
	uint16_t class_utf, class_idx, enter_utf, desc_utf, nt_idx, method_idx;
	uint16_t cp_count, interfaces, fields, method_count, i, a;
	size_t cp_end, method_count_off, methods_end;
	uint32_t new_cp_count, next_cp;
	struct buffer cp_extra = {0};
	struct buffer result = {0};
	struct method_plan *plans;
	struct cp_entry *cp;
	size_t calls = 0;
	size_t off = 10;
	size_t k;

	/* u4 magic, u2 minor_version, u2 major_version, u2 constant_pool_count */
	if (len < 10 || be32(data) != 0xcafebabe)
		return 0;
	cp_count = be16(data + 8);

	/* Full size table, so any u2 index from the class file is safe to use. */
	cp = calloc(65536, sizeof(*cp));
	if (!cp)
		return 0;

	/*
	 * Constant pool, entries are indexed from 1. We only need to skip
	 * them and remember the Utf8 (1) ones:
	 *   3 Integer, 4 Float, 5 Long, 6 Double, 7 Class, 8 String,
	 *   9 Fieldref, 10 Methodref, 11 InterfaceMethodref, 12 NameAndType,
	 *   15 MethodHandle, 16 MethodType, 17 Dynamic, 18 InvokeDynamic,
	 *   19 Module, 20 Package
	 */
	for (i = 1; i < cp_count; i++) {
		size_t n = 0;
		uint8_t tag;

		if (!bounds(off, 1, len))
			goto bad;

		tag = data[off++];
		cp[i].tag = tag;

		switch (tag) {
		case 1:
			if (!bounds(off, 2, len))
				goto bad;
			cp[i].len = be16(data + off);
			off += 2;
			if (!bounds(off, cp[i].len, len))
				goto bad;
			cp[i].bytes = data + off;
			off += cp[i].len;
			continue;
		case 3:
		case 4:
			n = 4;
			break;
		case 5:
		case 6:
			n = 8;
			break;
		case 7:
		case 8:
		case 16:
		case 19:
		case 20:
			n = 2;
			break;
		case 9:
		case 10:
		case 11:
		case 12:
		case 17:
		case 18:
			n = 4;
			break;
		case 15:
			n = 3;
			break;
		default:
			goto bad;
		}

		if (!bounds(off, n, len))
			goto bad;
		off += n;

		/* Long and Double take two constant pool entries. */
		if (tag == 5 || tag == 6)
			i++;
	}

	/* Skip access_flags, this_class, super_class, interfaces and fields. */
	cp_end = off;
	if (!bounds(off, 8, len))
		goto bad;
	off += 6;

	interfaces = be16(data + off);
	off += 2;
	if (!bounds(off, (size_t)interfaces * 2 + 2, len))
		goto bad;
	off += (size_t)interfaces * 2;

	fields = be16(data + off);
	off += 2;
	for (i = 0; i < fields; i++) {
		if (skip_member(data, len, &off))
			goto bad;
	}

	if (!bounds(off, 2, len))
		goto bad;
	method_count_off = off;
	method_count = be16(data + off);
	off += 2;
	plans = calloc(method_count, sizeof(*plans));
	if (!plans)
		goto bad;

	/* Find methods to instrument, the caller provides keys for them. */
	for (i = 0; i < method_count; i++) {
		uint16_t access, name_idx, desc_idx, attrs;
		char *mn, *md;
		uint32_t n;
		int count;

		if (!bounds(off, 8, len))
			goto plan_bad;

		access = be16(data + off);
		name_idx = be16(data + off + 2);
		desc_idx = be16(data + off + 4);
		attrs = be16(data + off + 6);

		mn = cp_string(cp, name_idx);
		md = cp_string(cp, desc_idx);
		if (!mn || !md) {
			free(mn);
			free(md);
			goto plan_bad;
		}

		/* Skip class initializer, native (0x0100) and abstract (0x0400) methods. */
		count = 0;
		if (strcmp(mn, "<clinit>") && !(access & (0x0100 | 0x0400)))
			count = keys_fn(ctx, mn, md, &plans[i].keys);

		free(mn);
		free(md);
		if (count < 0)
			goto plan_bad;
		plans[i].count = (size_t)count;

		off += 8;
		for (a = 0; a < attrs; a++) {
			if (!bounds(off, 6, len))
				goto plan_bad;
			n = be32(data + off + 2);
			off += 6;
			if (!bounds(off, n, len))
				goto plan_bad;
			off += n;
		}
	}

	methods_end = off;
	if (!bounds(off, 2, len))
		goto plan_bad;
	for (i = 0; i < method_count; i++)
		calls += plans[i].count;

	/* Nothing to instrument in this class. */
	if (calls == 0)
		goto plan_bad;

	/*
	 * New constant pool entries are added behind the existing ones, six
	 * for the TetragonHook.enter method and Long (two entries) with the
	 * method key for each call.
	 */
	if (calls > 65535)
		goto plan_bad;
	new_cp_count = (uint32_t)cp_count + 6 + (uint32_t)calls * 2;
	if (new_cp_count > 65535)
		goto plan_bad;

	/*
	 * Utf8 "io/tetragon/TetragonHook", Class, Utf8 "enter", Utf8 "(J)V",
	 * NameAndType (12) and Methodref (10).
	 */
	class_utf = cp_count;
	class_idx = cp_count + 1;
	enter_utf = cp_count + 2;
	desc_utf = cp_count + 3;
	nt_idx = cp_count + 4;
	method_idx = cp_count + 5;
	next_cp = (uint32_t)cp_count + 6;

	append(&cp_extra, "\1", 1);
	append_u2(&cp_extra, 24);
	append(&cp_extra, "io/tetragon/TetragonHook", 24);
	append(&cp_extra, "\7", 1);
	append_u2(&cp_extra, class_utf);
	append(&cp_extra, "\1", 1);
	append_u2(&cp_extra, 5);
	append(&cp_extra, "enter", 5);
	append(&cp_extra, "\1", 1);
	append_u2(&cp_extra, 4);
	append(&cp_extra, "(J)V", 4);
	append(&cp_extra, "\14", 1);
	append_u2(&cp_extra, enter_utf);
	append_u2(&cp_extra, desc_utf);
	append(&cp_extra, "\12", 1);
	append_u2(&cp_extra, class_idx);
	append_u2(&cp_extra, nt_idx);
	for (i = 0; i < method_count; i++) {
		plans[i].long_index = (uint16_t)next_cp;

		for (k = 0; k < plans[i].count; k++) {
			unsigned char entry[9] = { 5 };
			uint64_t v = plans[i].keys[k];
			int b;

			/* CONSTANT_Long (5) with the method key in big-endian. */
			for (b = 0; b < 8; b++)
				entry[8 - b] = (unsigned char)(v >> (8 * b));
			append(&cp_extra, entry, sizeof(entry));
			next_cp += 2;
		}
	}

	/*
	 * Output: header with new constant pool count, constant pool with the
	 * new entries, everything up to methods unchanged and the methods.
	 */
	append(&result, data, 10);
	put_be16(result.p + 8, (uint16_t)new_cp_count);
	append(&result, data + 10, cp_end - 10);
	append(&result, cp_extra.p, cp_extra.n);
	free(cp_extra.p);
	append(&result, data + cp_end, method_count_off + 2 - cp_end);
	off = method_count_off + 2;
	for (i = 0; i < method_count; i++) {
		struct buffer prefix = {0};
		size_t method_start = off;
		uint16_t attrs;

		if (!bounds(off, 8, len))
			goto output_bad;
		attrs = be16(data + off + 6);
		off += 8;
		append(&result, data + method_start, 8);
		for (k = 0; k < plans[i].count; k++) {
			/* ldc2_w <key>; invokestatic TetragonHook.enter */
			unsigned char seq[6] = { 0x14, 0, 0, 0xb8, 0, 0 };

			put_be16(seq + 1, (uint16_t)(plans[i].long_index + k * 2));
			put_be16(seq + 4, method_idx);
			append(&prefix, seq, sizeof(seq));
		}

		/*
		 * Pad the prefix with nops, so the switch instructions in the
		 * original bytecode keep their alignment.
		 */
		while (prefix.n % 4) {
			unsigned char nop = 0;

			append(&prefix, &nop, 1);
		}

		for (a = 0; a < attrs; a++) {
			struct buffer code = {0};
			char *attr_name;
			uint16_t ni;
			uint32_t n;
			size_t hdr;
			int ok;

			if (!bounds(off, 6, len)) {
				free(prefix.p);
				goto output_bad;
			}
			ni = be16(data + off);
			n = be32(data + off + 2);
			hdr = off;
			off += 6;
			if (!bounds(off, n, len)) {
				free(prefix.p);
				goto output_bad;
			}
			attr_name = cp_string(cp, ni);
			if (!attr_name) {
				free(prefix.p);
				goto output_bad;
			}

			/*
			 * Only the Code attribute of instrumented method is
			 * rewritten, everything else is copied.
			 */
			if (prefix.n && !strcmp(attr_name, "Code")) {
				ok = transform_code(data + off, n, prefix.p, (uint32_t)prefix.n, cp,
						    &code);
				if (!ok || code.n > UINT32_MAX) {
					free(attr_name);
					free(code.p);
					free(prefix.p);
					goto output_bad;
				}

				append(&result, data + hdr, 2);
				append_u4(&result, (uint32_t)code.n);
				append(&result, code.p, code.n);
				free(code.p);
			} else {
				append(&result, data + hdr, 6 + n);
			}

			free(attr_name);
			off += n;
		}

		free(prefix.p);
	}

	/* Both passes over the methods must end at the same place. */
	if (off != methods_end || !bounds(off, 2, len))
		goto output_bad;

	/* Class attributes are copied unchanged. */
	append(&result, data + off, len - off);

	free_plans(plans, method_count);
	free(cp);
	*out = result.p;
	*out_len = result.n;
	return 1;

output_bad:
	free(result.p);

plan_bad:
	free_plans(plans, method_count);

bad:
	free(cp);
	return 0;
}
