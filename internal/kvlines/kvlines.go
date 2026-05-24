// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Package kvlines implements a simple line-based key-value format.
//
// Format:
//
//	# magic string
//	type key prop=value prop=value # comment
//
// The top-level struct must contain only:
//
//   - A [Magic] field (with kv tag giving the magic line) as the first field.
//   - Map fields tagged kv:"typename" where the map value is a pointer to an object struct.
//
// Object structs are of one of the following formats:
//
//   - kv:",key" - object key (type and value must match the map key)
//   - kv:"propname" - required key=value property (zero or more)
//   - kv:"propname,optional" - optional key=value property (omitted if zero, can be absent when parsing) (zero or more)
//   - kv:",comment"   end-of-line comment after # (zero or one)
//
// The properties can be any of the following types:
//
//   - (T).(encoding.TextMarshaler)
//   - (*T).(encoding.TextMarshaler)
//   - kind = string
//   - kind = int
//   - kind = uint
//   - UnixTime
//   - Hash
package kvlines

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Check ensures the types and tags on T are valid.
func Check[T any]() {
	var zero T
	fileInfoOf(reflect.TypeOf(zero))
}

type fileInfo struct {
	magicFieldIndex int
	magicString     string
	maps            []fileObj
	mapByObjName    map[string]int // [objName]idx
}

type fileObj struct {
	fieldIndex int
	objType    reflect.Type
	objInfo    objInfo
	objName    string
}

func fileInfoOf(t reflect.Type) fileInfo {
	fi := fileInfo{magicFieldIndex: -1, mapByObjName: make(map[string]int)}
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("kv")

		if f.Type == reflect.TypeFor[Magic]() {
			if tag == "" {
				panic(fmt.Sprintf("%s.%s (Magic) requires a kv tag", t, f.Name))
			}
			fi.magicFieldIndex = i
			fi.magicString = "# " + tag
			continue
		}

		if f.Type.Kind() != reflect.Map || tag == "" {
			continue
		}

		elem := f.Type.Elem()
		if elem.Kind() != reflect.Pointer || elem.Elem().Kind() != reflect.Struct {
			panic(fmt.Sprintf("%s.%s: map value must be a pointer to a struct", t, f.Name))
		}
		objType := elem.Elem()
		objInfo := objInfoOf(objType)
		if objInfo.keyIndex < 0 {
			panic(fmt.Sprintf("%s: no ,key field (tag kv:\",key\")", objType))
		}
		mapKeyType := f.Type.Key()
		keyFieldType := objType.Field(objInfo.keyIndex).Type
		if mapKeyType != keyFieldType {
			panic(fmt.Sprintf("%s.%s: map key type %s does not match %s key field type %s", t, f.Name, mapKeyType, objType, keyFieldType))
		}

		if _, exists := fi.mapByObjName[tag]; exists {
			panic(fmt.Sprintf("%s.%s: duplicate object name %q", t, f.Name, tag))
		}
		fi.mapByObjName[tag] = len(fi.maps)
		fi.maps = append(fi.maps, fileObj{
			fieldIndex: i,
			objType:    objType,
			objInfo:    objInfo,
			objName:    tag,
		})
	}
	if fi.magicFieldIndex < 0 {
		panic(fmt.Sprintf("%s: missing Magic field", t))
	}
	return fi
}

type objInfo struct {
	keyIndex     int
	keyType      propType
	commentIndex int
	props        []objProp
	propsByName  map[string]int
}

type objProp struct {
	index    int
	name     string
	typ      propType
	optional bool
}

func objInfoOf(t reflect.Type) objInfo {
	oi := objInfo{keyIndex: -1, commentIndex: -1, propsByName: make(map[string]int)}
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("kv")
		if tag == "" || tag == "-" {
			continue
		}
		name, opt, _ := strings.Cut(tag, ",")
		switch opt {
		case "key":
			pt, ok := propTypeOf(f.Type)
			if !ok {
				panic(fmt.Sprintf("%s: unsupported key field type %s", t, f.Type))
			}
			if oi.keyIndex >= 0 {
				panic(fmt.Sprintf("%s: multiple ,key fields", t))
			}
			oi.keyIndex = i
			oi.keyType = pt
		case "comment":
			if f.Type.Kind() != reflect.String {
				panic(fmt.Sprintf("%s: comment field must be string, got %s", t, f.Type))
			}
			oi.commentIndex = i
		default:
			if opt != "" && opt != "optional" {
				panic(fmt.Sprintf("%s.%s: unknown tag option %q", t, f.Name, opt))
			}
			pt, ok := propTypeOf(f.Type)
			if !ok {
				panic(fmt.Sprintf("%s.%s: unsupported prop type %s", t, name, f.Type))
			}
			oi.propsByName[name] = len(oi.props)
			oi.props = append(oi.props, objProp{
				index:    i,
				name:     name,
				typ:      pt,
				optional: opt == "optional",
			})
		}
	}
	return oi
}

func quoteStr(s string) string {
	if s == "" {
		return s
	}
	for _, r := range s {
		if !isBareRune(r) {
			return strconv.Quote(s)
		}
	}
	return s
}

func isBareRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
	case r >= 'A' && r <= 'Z':
	case r >= '0' && r <= '9':
	case r == '-', r == '_', r == '.', r == '/', r == ':', r == '+':
	default:
		return false
	}
	return true
}
