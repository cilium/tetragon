// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

// Package yara provides bindings to the YARA library.
package yara

/*
#include <yara.h>
*/
import "C"

func init() {
	if err := initialize(); err != nil {
		panic(err)
	}
}

// Prepares the library to be used.
func initialize() error {
	return newError(C.yr_initialize())
}

// Finalize releases all the resources allocated by the YARA library.
// It should be called by the program when it no longer needs YARA,
// e.g. just before the program exits. It is not strictly necessary to
// call Finalize because the allocated memory will be freed on program
// exit; however, explicitly-freed resources will not show up as a
// leak in memory profiling tools.
//
// A good practice is calling Finalize as a deferred function in the
// program's main function:
//     defer yara.Finalize()
func Finalize() error {
	return newError(C.yr_finalize())
}
