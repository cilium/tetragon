// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux
// +build linux

package bpf

/*
#cgo CFLAGS:
#cgo LDFLAGS: -L../../lib -lbpf -lelf -lz

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include "btf.h"
#include "libbpf.h"

#ifndef MAX_ERRNO
#define MAX_ERRNO 4095
#endif

static long getError(void *ptr)
{
	if ((unsigned long)ptr >= (unsigned long)-MAX_ERRNO) {
		return -(long)ptr;
	}
	return 0;
}

static void *getBtf(const char *btf)
{
	return btf__parse(btf, NULL);
}

static int addEnumBtf(void *btf, char *name, int value)
{
	return btf__add_enum(btf, name, value);
}

static int addEnumBtfValue(void *btf, char *name, int value)
{
	return btf__add_enum_value(btf, name, value);
}

static void freeBtf(void *btfobj)
{
	btf__free(btfobj);
}

static int32_t BtfFindByName(void *btf, const char *name)
{
	return btf__find_by_name(btf, name);
}

static int32_t BtfFindByNameKind(void *btf, const char *name, __u32 kind)
{
	return btf__find_by_name_kind(btf, name, kind);
}

static const void *BtfTypeByID(void *btf, __u32 type_id)
{
	return btf__type_by_id(btf, type_id);
}

static __u16 BtfTyVlen(void *t)
{
	return btf_vlen(t);
}

static __u32 BtfTySize(void *t)
{
	return ((struct btf_type *)t)->size;
}

static __u32 BtfTy(void *t)
{
	return ((struct btf_type *)t)->type;
}

static __u32 BtfTyNameOff(void *t)
{
	return ((struct btf_type *)t)->name_off;
}

static __u16 BtfTyKind(void *t)
{
	return btf_kind(t);
}

static const void *BtfTyParam(void *t, int idx)
{
	return btf_params(t) + idx;
}

static __u32 BtfParamNameOff(void *p)
{
	return ((struct btf_param *)p)->name_off;
}

static __u32 BtfParamType(void *p)
{
	return ((struct btf_param *)p)->type;
}

static const char *BtfNameByOffset(void *btf, __u32 off)
{
	return btf__name_by_offset(btf, off);
}

struct btf_dump_ctx {
	char *s;
	size_t len;
	size_t off;
	int err;
};

const size_t btf_dump_alloc_grain = 2;

static void doBtfDump(void *ctx_, const char *fmt, va_list args)
{
	struct btf_dump_ctx *ctx = ctx_;

	if (ctx->err)
		return;

	for (;;) {
		va_list va;
		va_copy(va, args);
		size_t avail = ctx->len - ctx->off;
		size_t total = vsnprintf(ctx->s + ctx->off, avail, fmt, va);
		va_end(va);
		if (total < avail) {
			ctx->off += total;
			return;
		}
		ctx->s = realloc(ctx->s, ctx->len + btf_dump_alloc_grain);
		if (ctx->s == NULL) {
			ctx->err = ENOMEM;
			return;
		}
		ctx->len += btf_dump_alloc_grain;
	}
}

static const char *BtfDumpTy(void *btf, __u32 type)
{
	void *ret;
	int err;
	struct btf_dump *d;
	struct btf_dump_ctx ctx = (struct btf_dump_ctx) {
		.s = malloc(btf_dump_alloc_grain),
		.len = btf_dump_alloc_grain,
		.off = 0,
		.err = 0,
	};
	struct btf_dump_opts opts = {
		.ctx = &ctx,
	};

	if (!ctx.s)
		return NULL;
	d = btf_dump__new(btf, NULL, &opts, doBtfDump);
	if ((unsigned long)d >= (unsigned long)-MAX_ERRNO) {
		free(ctx.s);
		return NULL;
	}
	err = btf_dump__emit_type_decl(d, type, NULL);
	if (err || ctx.err) {
		ret = NULL;
		free(ctx.s);
	} else {
		ret = ctx.s;
	}

	btf_dump__free(d);
	return ret;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// BTF is a wrapper for struct btf *
type BTF uintptr

const BTFNil = BTF(0)

// NewBTF creates a new BTF object based on the file in the given path
func NewBTF(path string) (BTF, error) {
	ret := C.getBtf(C.CString(path))
	if err := C.getError(ret); err != 0 {
		return BTF(0), fmt.Errorf("failed to parse BTF %s: %d", path, err)
	}
	return BTF(uintptr(ret)), nil
}

// Close releases the resources of the BTF object
func (btf BTF) Close() {
	ptr := uintptr(btf)
	C.freeBtf(unsafe.Pointer(ptr))
}

func (btf BTF) AddEnum(name string, value int) int {
	ptr := uintptr(btf)
	ret := C.addEnumBtf(unsafe.Pointer(ptr), C.CString(name), C.int(value))
	return int(ret)
}

func (btf BTF) AddEnumValue(name string, value int) int {
	ptr := uintptr(btf)
	ret := C.addEnumBtfValue(unsafe.Pointer(ptr), C.CString(name), C.int(value))
	return int(ret)
}

// part II

// BtfID is a btf id
type BtfID uint32

// BtfType is a wrapper for struct btf_type *
type BtfType uintptr

// BtfParam is a wrapper for struct btf_param *
type BtfParam uintptr

// BtfKind wraps the different kinds of btf types
type BtfKind uint

const (
	BtfKindUnknown   BtfKind = 0  /* Unknown */
	BtfKindInteger   BtfKind = 1  /* Integer */
	BtfKindPtr       BtfKind = 2  /* Pointer */
	BtfKindArray     BtfKind = 3  /* Array */
	BtfKindStruct    BtfKind = 4  /* Struct */
	BtfKindUnion     BtfKind = 5  /* Union */
	BtfKindEnum      BtfKind = 6  /* Enumeration */
	BtfKindForward   BtfKind = 7  /* Forward */
	BtfKindTypdef    BtfKind = 8  /* Typedef */
	BtfKindVolatile  BtfKind = 9  /* Volatile */
	BtfKindConst     BtfKind = 10 /* Const */
	BtfKindRestrict  BtfKind = 11 /* Restrict */
	BtfKindFunc      BtfKind = 12 /* Function */
	BtfKindFuncProto BtfKind = 13 /* Function Proto */
	BtfKindVar       BtfKind = 14 /* Variable */
	BtfKindDatasec   BtfKind = 15 /* Section */
)

// FindByName returns the id of a btf object with the given name
func (btf BTF) FindByName(name string) (BtfID, error) {
	cname := C.CString(name)
	ptr := unsafe.Pointer(btf)
	ret := C.BtfFindByName(ptr, cname)
	if ret < 0 {
		return BtfID(0), fmt.Errorf("failed to find '%s' in BTF (%d)", name, -ret)
	}
	return BtfID(uint32(ret)), nil
}

// FindByName returns the id of a btf object with the given name and the given kind
func (btf BTF) FindByNameKind(name string, kind BtfKind) (BtfID, error) {
	cname := C.CString(name)
	ptr := unsafe.Pointer(btf)
	ret := C.BtfFindByNameKind(ptr, cname, C.uint(kind))
	if ret < 0 {
		return BtfID(0), fmt.Errorf("failed to find '%s' in BTF (%d)", name, -ret)
	}
	return BtfID(uint32(ret)), nil
}

// TypeByID returns a btf type object using the given id
func (btf BTF) TypeByID(id BtfID) (BtfType, error) {
	ptr := unsafe.Pointer(btf)
	ret := C.BtfTypeByID(ptr, C.uint(id))
	var err error
	if uintptr(ret) == 0 {
		err = fmt.Errorf("type with id %d does not exist in BTF", id)
	}
	return BtfType(ret), err
}

// Vlen returns the number of the underlying elements for the given btf type
func (ty BtfType) Vlen() uint16 {
	ptr := unsafe.Pointer(ty)
	return uint16(C.BtfTyVlen(ptr))
}

// Size returns the size of the provided type
func (ty BtfType) Size() uint32 {
	ptr := unsafe.Pointer(ty)
	return uint32(C.BtfTySize(ptr))
}

// Kind returns the kind of the given type
func (ty BtfType) Kind() BtfKind {
	ptr := unsafe.Pointer(ty)
	ret := C.BtfTyKind(ptr)
	return BtfKind(ret)
}

// Param returns the idx parameter of the given type
func (ty BtfType) Param(idx int) BtfParam {
	ptr := unsafe.Pointer(ty)
	ret := C.BtfTyParam(ptr, C.int(idx))
	return BtfParam(ret)
}

// UnderlyingType returns the underlying type id of a type
func (btf BTF) UnderlyingType(ty BtfType) (BtfID, error) {
	switch kind := ty.Kind(); kind {
	case BtfKindPtr,
		BtfKindTypdef,
		BtfKindVolatile,
		BtfKindConst,
		BtfKindRestrict,
		BtfKindFunc,
		BtfKindFuncProto,
		BtfKindVar:
		break

	default:
		return BtfID(0), fmt.Errorf("btf type with kind %d does not have an underlying type", kind)
	}

	return BtfID(C.BtfTy(unsafe.Pointer(ty))), nil
}

// TypeName returns the name of a btf type
func (btf BTF) TypeName(ty BtfType) string {
	nameOff := C.BtfTyNameOff(unsafe.Pointer(ty))
	cStr := C.BtfNameByOffset(unsafe.Pointer(btf), nameOff)
	return C.GoString(cStr)
}

// ParamName returns the name of the idx parameter of a the given type (has to be a function prototype)
func (btf BTF) ParamName(ty BtfType, idx int) (string, error) {
	if kind := ty.Kind(); kind != BtfKindFuncProto {
		return "", fmt.Errorf("btf type with kind %d is not a function prototype", kind)
	}
	if idx >= int(ty.Vlen()) {
		return "", fmt.Errorf("invalid param idx=%d, vlen=%d", idx, ty.Vlen())
	}
	param := ty.Param(idx)
	nameOff := C.BtfParamNameOff(unsafe.Pointer(param))
	cStr := C.BtfNameByOffset(unsafe.Pointer(btf), nameOff)
	return C.GoString(cStr), nil
}

// ParamName returns the type of the idx parameter of a the given type (has to be a function prototype)
func (btf BTF) ParamTypeID(ty BtfType, idx int) (BtfID, error) {
	if kind := ty.Kind(); kind != BtfKindFuncProto {
		return BtfID(0), fmt.Errorf("btf type with kind %d is not a function prototype", kind)
	}
	if idx >= int(ty.Vlen()) {
		return BtfID(0), fmt.Errorf("invalid param idx=%d, vlen=%d", idx, ty.Vlen())
	}
	param := ty.Param(idx)
	tyId := C.BtfParamType(unsafe.Pointer(param))
	return BtfID(tyId), nil
}

// DumpTy dumps a C-compatible representation of a type into a string
func (btf BTF) DumpTy(ty BtfID) (string, error) {
	cStr := C.BtfDumpTy(unsafe.Pointer(btf), C.uint(ty))
	ptr := unsafe.Pointer(cStr)
	if uintptr(ptr) == 0 {
		return "", fmt.Errorf("failed to dump btf id %d", ty)
	}
	str := C.GoString(cStr)
	C.free(ptr)
	return str, nil
}
