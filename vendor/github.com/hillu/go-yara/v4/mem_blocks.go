// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
#include <yara.h>

int scanCallbackFunc(YR_SCAN_CONTEXT*, int, void*, void*);

uint8_t* memoryBlockFetch(YR_MEMORY_BLOCK*);
uint8_t* memoryBlockFetchNull(YR_MEMORY_BLOCK*);

YR_MEMORY_BLOCK* memoryBlockIteratorFirst(YR_MEMORY_BLOCK_ITERATOR*);
YR_MEMORY_BLOCK* memoryBlockIteratorNext(YR_MEMORY_BLOCK_ITERATOR*);
uint64_t memoryBlockIteratorFilesize(YR_MEMORY_BLOCK_ITERATOR*);
*/
import "C"
import (
	"reflect"
	"unsafe"
)

// MemoryBlockIterator is a Go representation of YARA's
// YR_MEMORY_BLOCK_ITERATOR mechanism that is used within
// yr_rules_mem_scan_blobs.
type MemoryBlockIterator interface {
	First() *MemoryBlock
	Next() *MemoryBlock
}

type MemoryBlockIteratorWithFilesize interface {
	MemoryBlockIterator
	Filesize() uint64
}

type memoryBlockIteratorContainer struct {
	MemoryBlockIterator
	// MemoryBlock holds return values of the First and Next methods
	// as it is moved back to libyara.
	*MemoryBlock
	// cblock is passed to memoryBlockFetch. Its data lives in malloc
	// memory.
	cblock *C.YR_MEMORY_BLOCK
	// buf is used by (MemoryBlock).FetchData() to pass data back to
	// YARA. Its backing array lives in malloc memory and will only be
	// resized using the realloc method.
	buf []byte
}

func makeMemoryBlockIteratorContainer(mbi MemoryBlockIterator) (c *memoryBlockIteratorContainer) {
	c = &memoryBlockIteratorContainer{
		MemoryBlockIterator: mbi,
		cblock:              (*C.YR_MEMORY_BLOCK)(C.calloc(1, C.size_t(unsafe.Sizeof(C.YR_MEMORY_BLOCK{})))),
		buf:                 make([]byte, 0, 0),
	}
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&c.buf))
	hdr.Data = 0
	return
}

// The caller is responsible to delete the cgoHandle *cmbi.context and free cmbi.context.
func makeCMemoryBlockIterator(c *memoryBlockIteratorContainer) (cmbi *C.YR_MEMORY_BLOCK_ITERATOR) {
	userData := (*cgoHandle)(C.malloc(C.size_t(unsafe.Sizeof(cgoHandle(0)))))
	*userData = cgoNewHandle(c)
	cmbi = &C.YR_MEMORY_BLOCK_ITERATOR{
		context: unsafe.Pointer(userData),
		first:   C.YR_MEMORY_BLOCK_ITERATOR_FUNC(C.memoryBlockIteratorFirst),
		next:    C.YR_MEMORY_BLOCK_ITERATOR_FUNC(C.memoryBlockIteratorNext),
	}
	if _, implementsFilesize := c.MemoryBlockIterator.(MemoryBlockIteratorWithFilesize); implementsFilesize {
		cmbi.file_size = C.YR_MEMORY_BLOCK_ITERATOR_SIZE_FUNC(C.memoryBlockIteratorFilesize)
	}
	return cmbi
}

func (c *memoryBlockIteratorContainer) realloc(size int) {
	if len(c.buf) < size {
		hdr := (*reflect.SliceHeader)(unsafe.Pointer(&c.buf))
		hdr.Data = uintptr(C.realloc(unsafe.Pointer(hdr.Data), C.size_t(size)))
		hdr.Len = size
		hdr.Cap = hdr.Len
	}
}

func (c *memoryBlockIteratorContainer) free() {
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&c.buf))
	if hdr.Cap > 0 {
		C.free(unsafe.Pointer(hdr.Data))
		c.buf = nil
	}
	C.free(unsafe.Pointer(c.cblock))
}

// MemoryBlock is returned by the MemoryBlockIterator's First and Next methods
type MemoryBlock struct {
	// Base contains the base address of the current block
	Base uint64
	// Size contains the size of the current block
	Size uint64
	// FetchData is used to read size bytes into a byte slice
	FetchData func([]byte)
}

// memoryBlockFetch is used as YR_MEMORY_BLOCK.fetch_data.
// It is called from YARA code.
//
//export memoryBlockFetch
func memoryBlockFetch(cblock *C.YR_MEMORY_BLOCK) *C.uint8_t {
	c := ((*cgoHandle)(cblock.context)).Value().(*memoryBlockIteratorContainer)
	c.realloc(int(cblock.size))
	c.MemoryBlock.FetchData(c.buf)
	return (*C.uint8_t)(unsafe.Pointer(&c.buf[0]))
}

// memoryBlockFetchNull is used as YR_MEMORY_BLOCK.fetch_data for empty blocks.
// It is called from YARA code.
//
//export memoryBlockFetchNull
func memoryBlockFetchNull(*C.YR_MEMORY_BLOCK) *C.uint8_t { return nil }

// memoryBlockIteratorCommon turns a MemoryBlock into a YR_MEMORY_BLOCK
// structure that is used by YARA internally.
func memoryBlockIteratorCommon(cmbi *C.YR_MEMORY_BLOCK_ITERATOR, c *memoryBlockIteratorContainer) (cblock *C.YR_MEMORY_BLOCK) {
	if c.MemoryBlock == nil {
		return
	}
	cblock = c.cblock
	cblock.base = C.uint64_t(c.MemoryBlock.Base)
	cblock.size = C.size_t(c.MemoryBlock.Size)
	cblock.fetch_data = C.YR_MEMORY_BLOCK_FETCH_DATA_FUNC(C.memoryBlockFetchNull)
	if c.MemoryBlock.Size == 0 {
		return
	}
	cblock.context = cmbi.context
	cblock.fetch_data = C.YR_MEMORY_BLOCK_FETCH_DATA_FUNC(C.memoryBlockFetch)
	return
}

// memoryBlockIteratorFirst is used as YR_MEMORY_BLOCK_ITERATOR.first.
// It is called from YARA code.
//
//export memoryBlockIteratorFirst
func memoryBlockIteratorFirst(cmbi *C.YR_MEMORY_BLOCK_ITERATOR) *C.YR_MEMORY_BLOCK {
	c := ((*cgoHandle)(cmbi.context)).Value().(*memoryBlockIteratorContainer)
	c.MemoryBlock = c.MemoryBlockIterator.First()
	return memoryBlockIteratorCommon(cmbi, c)
}

// memoryBlockIteratorNext is used as YR_MEMORY_BLOCK_ITERATOR.next.
// It is called from YARA code.
//
//export memoryBlockIteratorNext
func memoryBlockIteratorNext(cmbi *C.YR_MEMORY_BLOCK_ITERATOR) *C.YR_MEMORY_BLOCK {
	c := ((*cgoHandle)(cmbi.context)).Value().(*memoryBlockIteratorContainer)
	c.MemoryBlock = c.MemoryBlockIterator.Next()
	return memoryBlockIteratorCommon(cmbi, c)
}

//export memoryBlockIteratorFilesize
func memoryBlockIteratorFilesize(cmbi *C.YR_MEMORY_BLOCK_ITERATOR) C.uint64_t {
	c := ((*cgoHandle)(cmbi.context)).Value().(*memoryBlockIteratorContainer)
	return C.uint64_t(c.MemoryBlockIterator.(MemoryBlockIteratorWithFilesize).Filesize())
}
