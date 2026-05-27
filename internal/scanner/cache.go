// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"errors"
	"os"

	"github.com/pgaskin/asslcapture/internal/kvlines"
)

type Cache struct {
	Magic   kvlines.Magic             `kv:"asslcapture cache v1"` // changed whenever we add/remove required fields or make changes requiring re-analysis
	File    map[string]*File          `kv:"file"`                 // cached information about known library names
	Offsets map[kvlines.Hash]*Offsets `kv:"offsets"`              // cached analysis results for elf files
}

type File struct {
	Name    string `kv:",key"`     // library name (i.e., what is passed to dlopen)
	Comment string `kv:",comment"` // free-form human-readable note about how this library was discovered

	Path     string           `kv:"path"`    // file path
	Modified kvlines.UnixTime `kv:"modtime"` // file modification time (used to invalidate the cache)
	Size     int64            `kv:"size"`    // file size (used to invalidate the cache)

	Offset uint64       `kv:"offset"` // elf offset (0 for non-zips)
	Length int64        `kv:"length"` // elf length (same as size for non-zips)
	SHA256 kvlines.Hash `kv:"sha256"` // elf hash (used to cache offsets)
}

type Offsets struct {
	Hash         kvlines.Hash `kv:",key"` // elf hash
	SSLLogSecret uint64       `kv:"fn"`   // ssl_log_secret elf file offset
	S3           int          `kv:"s3"`   // s3 struct field offset
	ClientRandom int          `kv:"cr"`   // client_random struct field offset
}

type BadCacheVersionError struct {
	msg string
}

func (e *BadCacheVersionError) Error() string {
	return e.msg
}

func ReadCache(name string) (*Cache, error) {
	buf, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var cache Cache
	if err := kvlines.Unmarshal(buf, &cache); err != nil {
		if err, ok := errors.AsType[*kvlines.BadMagicError](err); ok {
			return nil, &BadCacheVersionError{err.Error()}
		}
		return nil, err
	}
	return &cache, nil
}

func WriteCache(name string, cache *Cache, perm os.FileMode) error {
	buf, err := kvlines.Marshal(cache)
	if err != nil {
		return err
	}
	if err := os.WriteFile(name, buf, perm); err != nil {
		return err
	}
	return nil
}

func init() {
	kvlines.Check[Cache]()
}
