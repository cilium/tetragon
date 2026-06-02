// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

func toint64(number interface{}) int64 {
	switch number.(type) {
	case int:
		return int64(number.(int))
	case int8:
		return int64(number.(int8))
	case int16:
		return int64(number.(int16))
	case int32:
		return int64(number.(int32))
	case int64:
		return int64(number.(int64))
	case uint:
		return int64(number.(uint))
	case uint8:
		return int64(number.(uint8))
	case uint16:
		return int64(number.(uint16))
	case uint32:
		return int64(number.(uint32))
	case uint64:
		return int64(number.(uint64))
	}
	panic("wrong number")
}
