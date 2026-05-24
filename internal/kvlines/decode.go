// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package kvlines

import (
	"bytes"
	"encoding"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// BadMagicError is returned by Unmarshal when the magic header doesn't match.
type BadMagicError struct {
	Got  string
	Want string
}

func (e *BadMagicError) Error() string {
	return fmt.Sprintf("incompatible file (got magic %q, want %q)", e.Got, e.Want)
}

// Unmarshal decodes data into v, which must be a pointer to the top-level struct.
func Unmarshal(data []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer {
		return fmt.Errorf("Unmarshal requires a pointer")
	}
	rv = rv.Elem()
	fi := fileInfoOf(rv.Type())

	for _, me := range fi.maps {
		f := rv.Field(me.fieldIndex)
		f.Set(reflect.MakeMap(f.Type()))
	}

	lineNum := 0
	seenMagic := false
	for rawLine := range bytes.Lines(data) {
		lineNum++
		line := strings.TrimRight(string(rawLine), "\r\n \t")

		if !seenMagic {
			seenMagic = true
			if line != fi.magicString {
				return &BadMagicError{Got: line, Want: fi.magicString}
			}
			continue
		}

		if line == "" || line[0] == '#' {
			continue
		}

		objName, rest := cutBare(line)
		meIdx, ok := fi.mapByObjName[objName]
		if !ok {
			return fmt.Errorf("line %d: unknown object type %q", lineNum, objName)
		}
		me := fi.maps[meIdx]

		objVal, err := decodeObj(me, rest)
		if err != nil {
			return fmt.Errorf("line %d: %s: %w", lineNum, objName, err)
		}

		mapField := rv.Field(me.fieldIndex)
		keyVal := objVal.Field(me.objInfo.keyIndex)
		if mapField.MapIndex(keyVal).IsValid() {
			return fmt.Errorf("line %d: duplicate %s %v", lineNum, objName, keyVal)
		}
		ptr := reflect.New(me.objType)
		ptr.Elem().Set(objVal)
		mapField.SetMapIndex(keyVal, ptr)
	}
	if !seenMagic {
		return &BadMagicError{Got: "", Want: fi.magicString}
	}
	return nil
}

func decodeObj(me fileObj, s string) (reflect.Value, error) {
	oi := me.objInfo
	rv := reflect.New(me.objType).Elem()

	keyStr, s, err := cutValue(s)
	if err != nil {
		return rv, fmt.Errorf("key: %w", err)
	}
	if err := decodeVal(oi.keyType, rv.Field(oi.keyIndex), keyStr); err != nil {
		return rv, fmt.Errorf("key: %w", err)
	}

	seen := make(map[string]bool, len(oi.props))
	for !lineEnd(s) {
		key, val, rest, err := cutProp(s)
		if err != nil {
			return rv, err
		}
		s = rest
		idx, ok := oi.propsByName[key]
		if !ok {
			return rv, fmt.Errorf("unknown prop %q", key)
		}
		if seen[key] {
			return rv, fmt.Errorf("duplicate prop %q", key)
		}
		seen[key] = true
		if err := decodeVal(oi.props[idx].typ, rv.Field(oi.props[idx].index), val); err != nil {
			return rv, fmt.Errorf("%s: %w", key, err)
		}
	}

	for _, prop := range oi.props {
		if !seen[prop.name] && !prop.optional {
			return rv, fmt.Errorf("missing prop %q", prop.name)
		}
	}

	if oi.commentIndex >= 0 {
		rv.Field(oi.commentIndex).SetString(cutComment(s))
	}

	return rv, nil
}

func decodeVal(pt propType, v reflect.Value, s string) error {
	switch pt {
	case propText, propTextPtr:
		tu, _ := reflect.TypeAssert[encoding.TextUnmarshaler](v.Addr())
		return tu.UnmarshalText([]byte(s))
	case propString:
		v.SetString(s)
		return nil
	case propInt:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		v.SetInt(n)
		return nil
	case propUint:
		raw, base := s, 10
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			raw, base = s[2:], 16
		}
		n, err := strconv.ParseUint(raw, base, 64)
		if err != nil {
			return err
		}
		v.SetUint(n)
		return nil
	case propUnixTime:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("unixtime: %w", err)
		}
		v.Set(reflect.ValueOf(UnixTime(n)))
		return nil
	case propHash:
		var h Hash
		if s != "" {
			alg, digest, ok := strings.Cut(s, ":")
			if !ok {
				return fmt.Errorf("hash: expected type:hex, got %q", s)
			}
			b, err := hex.DecodeString(digest)
			if err != nil {
				return fmt.Errorf("hash: invalid hex: %w", err)
			}
			h = Hash{alg: alg, val: string(b)}
		}
		v.Set(reflect.ValueOf(h))
		return nil
	default:
		panic(fmt.Sprintf("invalid propType %d", pt))
	}
}

func cutComment(s string) string {
	s = strings.TrimLeft(s, " \t")
	if s == "" || s[0] != '#' {
		return ""
	}
	return strings.TrimRight(strings.TrimPrefix(s[1:], " "), " \t")
}

func cutBare(s string) (token, rest string) {
	i := strings.IndexAny(s, " \t=#\"")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i:]
}

func cutQuoted(s string) (token, rest string, err error) {
	end := 1
	for end < len(s) {
		switch s[end] {
		case '\\':
			end += 2
		case '"':
			end++
			token, err = strconv.Unquote(s[:end])
			return token, s[end:], err
		default:
			end++
		}
	}
	return "", s, fmt.Errorf("unterminated string")
}

func cutValue(s string) (token, rest string, err error) {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return "", s, fmt.Errorf("unexpected end of line")
	}
	if s[0] == '"' {
		return cutQuoted(s)
	}
	token, rest = cutBare(s)
	if token == "" {
		return "", s, fmt.Errorf("empty value")
	}
	return token, rest, nil
}

func cutProp(s string) (key, val, rest string, err error) {
	s = strings.TrimLeft(s, " \t")
	key, s = cutBare(s)
	if key == "" {
		return "", "", s, fmt.Errorf("expected prop name")
	}
	if s == "" || s[0] != '=' {
		return "", "", s, fmt.Errorf("expected '=' after prop %q", key)
	}
	s = s[1:] // skip '='
	if s == "" || s[0] == ' ' || s[0] == '\t' || s[0] == '#' {
		return key, "", s, nil
	}
	val, rest, err = cutValue(s)
	return
}

func lineEnd(s string) bool {
	s = strings.TrimLeft(s, " \t")
	return s == "" || s[0] == '#'
}
