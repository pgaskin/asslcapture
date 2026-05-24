// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package kvlines

import (
	"encoding"
	"encoding/hex"
	"hash"
	"reflect"
	"time"
)

type propType int

const (
	_            propType = iota
	propText              // (T).(encoding.TextMarshaler)
	propTextPtr           // (*T).(encoding.TextMarshaler)
	propString            // kind = string
	propInt               // kind = int
	propUint              // kind = uint
	propUnixTime          // UnixTime
	propHash              // Hash
)

func propTypeOf(t reflect.Type) (propType, bool) {
	switch t {
	case reflect.TypeFor[UnixTime]():
		return propUnixTime, true
	case reflect.TypeFor[Hash]():
		return propHash, true
	}
	ptr := reflect.PointerTo(t)
	unmarshalerType := reflect.TypeFor[encoding.TextUnmarshaler]()
	if ptr.Implements(unmarshalerType) {
		if t.Implements(reflect.TypeFor[encoding.TextMarshaler]()) {
			return propText, true
		}
		if ptr.Implements(reflect.TypeFor[encoding.TextMarshaler]()) {
			return propTextPtr, true
		}
	}
	switch t.Kind() {
	case reflect.String:
		return propString, true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return propInt, true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return propUint, true
	}
	return 0, false
}

// Magic is the type for the magic-comment field in a top-level struct. It is
// written and verified as a comment at the top of the file (i.e., prefixed with
// "# ").
//
//	type Things {
//	    Magic kvlines.Magic `kv:"things v1"`
//	    ...
//	}
type Magic struct{}

// UnixTime is a Unix timestamp in seconds.
type UnixTime int64

func MakeUnixTime(t time.Time) UnixTime {
	if t.IsZero() {
		return 0
	}
	return UnixTime(t.Unix())
}

func (t UnixTime) Time() time.Time {
	if t == 0 {
		return time.Time{}
	}
	return time.Unix(int64(t), 0)
}

// Hash contains a digest and algorithm. It is comparable.
type Hash struct {
	alg string
	val string // raw byte, but as a string to be comparable
}

func MakeHash(alg string, h hash.Hash) Hash {
	return Hash{alg: alg, val: string(h.Sum(nil))}
}

func (h Hash) String() string {
	if h.alg == "" {
		return ""
	}
	return h.alg + ":" + hex.EncodeToString([]byte(h.val))
}
