// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package kvlines

import (
	"bytes"
	"encoding"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// Marshal encodes v, which must be the top-level struct (or a pointer to it).
func Marshal(v any) ([]byte, error) {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	fi := fileInfoOf(rv.Type())

	var buf bytes.Buffer

	buf.WriteString(fi.magicString)
	buf.WriteByte('\n')

	for _, me := range fi.maps {
		mapVal := rv.Field(me.fieldIndex)
		for _, key := range slices.SortedFunc(mapVal.Seq(), func(a, b reflect.Value) int {
			return strings.Compare(keyString(a), keyString(b))
		}) {
			line, err := encodeObj(me, mapVal.MapIndex(key).Elem())
			if err != nil {
				return nil, err
			}
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}

	return buf.Bytes(), nil
}

func encodeObj(me fileObj, rv reflect.Value) (string, error) {
	oi := me.objInfo
	var sb strings.Builder
	sb.WriteString(me.objName)

	keyStr, err := encodeVal(oi.keyType, rv.Field(oi.keyIndex))
	if err != nil {
		return "", fmt.Errorf("%s key: %w", me.objName, err)
	}
	sb.WriteByte(' ')
	sb.WriteString(keyStr)

	for _, prop := range oi.props {
		v := rv.Field(prop.index)
		if prop.optional && v.IsZero() {
			continue
		}
		val, err := encodeVal(prop.typ, v)
		if err != nil {
			return "", fmt.Errorf("%s.%s: %w", me.objName, prop.name, err)
		}
		sb.WriteByte(' ')
		sb.WriteString(prop.name)
		sb.WriteByte('=')
		sb.WriteString(val)
	}

	if oi.commentIndex >= 0 {
		if c := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, rv.Field(oi.commentIndex).String()); c != "" {
			sb.WriteString(" # ")
			sb.WriteString(c)
		}
	}

	return sb.String(), nil
}

func keyString(v reflect.Value) string {
	if s, ok := reflect.TypeAssert[fmt.Stringer](v); ok {
		return s.String()
	}
	if v.Kind() == reflect.String {
		return v.String()
	}
	return fmt.Sprint(v.Interface())
}

func encodeVal(pt propType, v reflect.Value) (string, error) {
	switch pt {
	case propText:
		tm, _ := reflect.TypeAssert[encoding.TextMarshaler](v)
		b, err := tm.MarshalText()
		if err != nil {
			return "", err
		}
		return quoteStr(string(b)), nil
	case propTextPtr:
		tm, _ := reflect.TypeAssert[encoding.TextMarshaler](v.Addr())
		b, err := tm.MarshalText()
		if err != nil {
			return "", err
		}
		return quoteStr(string(b)), nil
	case propString:
		return quoteStr(v.String()), nil
	case propInt:
		return strconv.FormatInt(v.Int(), 10), nil
	case propUint:
		return strconv.FormatUint(v.Uint(), 10), nil
	case propUnixTime:
		ut, _ := reflect.TypeAssert[UnixTime](v)
		return strconv.FormatInt(int64(ut), 10), nil
	case propHash:
		h, _ := reflect.TypeAssert[Hash](v)
		return h.String(), nil
	default:
		panic(fmt.Sprintf("invalid propType %d", pt))
	}
}
