// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Tetragon */

/*
 * Test driver for the class file rewriter, see classfile_linux_test.go.
 *
 *   classfile-test <in.class> <out.class> [keys [first-key]]
 *
 *     Rewrite the class file, so each of its methods calls TetragonHook.enter
 *     with given number of keys (1 by default). The keys are assigned in
 *     sequence starting with first-key (1 by default) and each of them is
 *     printed together with its method as 'key<TAB>name<TAB>descriptor'.
 *
 *     Returns 0 with the new class in out.class, 2 if the class stays
 *     unchanged and 1 on error.
 *
 *   classfile-test --fuzz <in.class>
 *
 *     Rewrite broken versions of the class file: all its truncations and
 *     the class with each of its bytes changed. The rewriter is expected
 *     to either rewrite the class or keep it unchanged, the driver is built
 *     with sanitizers to catch the rest.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "classfile.h"

static uint64_t next_key = 1;
static int nr_keys = 1;
static int quiet;

/* Give each method nr_keys keys. */
static int test_keys(void *ctx, const char *name, const char *desc, uint64_t **keys)
{
	uint64_t *k;
	int i;

	(void)ctx;

	k = calloc(nr_keys, sizeof(*k));
	if (!k)
		return -1;

	for (i = 0; i < nr_keys; i++) {
		k[i] = next_key++;
		if (!quiet)
			printf("%llu\t%s\t%s\n", (unsigned long long)k[i], name, desc);
	}

	*keys = k;
	return nr_keys;
}

static unsigned char *read_file(const char *path, size_t *len)
{
	unsigned char *data = NULL;
	long size;
	FILE *f;

	f = fopen(path, "rb");
	if (!f)
		return NULL;

	if (fseek(f, 0, SEEK_END) || (size = ftell(f)) < 0 || fseek(f, 0, SEEK_SET))
		goto out;

	data = malloc(size ? size : 1);
	if (data && fread(data, 1, size, f) != (size_t)size) {
		free(data);
		data = NULL;
	}

	*len = (size_t)size;
out:
	fclose(f);
	return data;
}

/*
 * Rewrite the copy of the class file that has exactly len bytes, so the
 * sanitizer sees any access behind them.
 */
static void fuzz_one(const unsigned char *data, size_t len)
{
	unsigned char *copy, *out = NULL;
	size_t out_len = 0;

	copy = malloc(len ? len : 1);
	if (!copy)
		exit(1);
	memcpy(copy, data, len);

	if (classfile_instrument(copy, len, test_keys, NULL, &out, &out_len))
		free(out);
	free(copy);
}

static int fuzz(const unsigned char *data, size_t len)
{
	/* Values that make lengths and counts either zero or too big. */
	static const unsigned char values[] = { 0x00, 0x01, 0x7f, 0x80, 0xff };
	static const unsigned char big[4] = { 0xff, 0xff, 0xff, 0xfe };
	unsigned char *copy;
	size_t i, v;

	quiet = 1;

	for (i = 0; i < len; i++)
		fuzz_one(data, i);

	copy = malloc(len ? len : 1);
	if (!copy)
		return 1;

	for (i = 0; i < len; i++) {
		for (v = 0; v < sizeof(values); v++) {
			memcpy(copy, data, len);
			copy[i] = values[v];
			fuzz_one(copy, len);
		}

		/* u4 length close to the 32-bit limit. */
		if (i + sizeof(big) <= len) {
			memcpy(copy, data, len);
			memcpy(copy + i, big, sizeof(big));
			fuzz_one(copy, len);
		}
	}

	free(copy);
	return 0;
}

int main(int argc, char **argv)
{
	unsigned char *data, *out = NULL;
	size_t len = 0, out_len = 0;
	int rc = 1;
	FILE *f;

	if (argc == 3 && !strcmp(argv[1], "--fuzz")) {
		data = read_file(argv[2], &len);
		if (!data) {
			fprintf(stderr, "failed to read %s\n", argv[2]);
			return 1;
		}

		rc = fuzz(data, len);
		free(data);
		return rc;
	}

	if (argc < 3 || argc > 5) {
		fprintf(stderr, "usage: %s <in.class> <out.class> [keys [first-key]]\n", argv[0]);
		fprintf(stderr, "       %s --fuzz <in.class>\n", argv[0]);
		return 1;
	}

	if (argc > 3)
		nr_keys = atoi(argv[3]);
	if (argc > 4)
		next_key = strtoull(argv[4], NULL, 0);
	if (nr_keys < 1) {
		fprintf(stderr, "invalid number of keys\n");
		return 1;
	}

	data = read_file(argv[1], &len);
	if (!data) {
		fprintf(stderr, "failed to read %s\n", argv[1]);
		return 1;
	}

	if (!classfile_instrument(data, len, test_keys, NULL, &out, &out_len)) {
		free(data);
		return 2;
	}

	f = fopen(argv[2], "wb");
	if (f && fwrite(out, 1, out_len, f) == out_len)
		rc = 0;
	else
		fprintf(stderr, "failed to write %s\n", argv[2]);
	if (f && fclose(f))
		rc = 1;

	free(out);
	free(data);
	return rc;
}
