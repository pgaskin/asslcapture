// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"log/slog"
	"regexp"
)

// apkDirs are the standard Android APK directories.
var apkDirs = [...]string{
	"/system/app",
	"/system/priv-app",
	"/system_ext/app",
	"/system_ext/priv-app",
	"/vendor/app",
	"/vendor/priv-app",
	"/product/app",
	"/product/priv-app",
	"/odm/app",
	"/odm/priv-app",
	"/oem/app",
	"/data/app",
}

// libDirs are the standard Android library directories.
var libDirs = [...]string{
	"/system/lib",
	"/system/lib64",
	"/system_ext/lib",
	"/vendor/lib",
	"/system_ext/lib",
	"/vendor/lib64",
	"/product/lib",
	"/odm/lib",
	"/product/lib",
	"/odm/lib64",
	"/oem/lib",
	"/oem/lib64",
}

// bsslNameRe matches filenames which are likely to be or contain statically
// linked BoringSSL.
var bsslNameRe = regexp.MustCompile(`(libssl|cronet|libchrome|webviewchrom)[^/]+\.so[0-9.]*$`)

// Scanner scans for BoringSSL libraries and analyzes them. It is safe for
// concurrent usage. All scan methods block until complete, but queued tasks may
// execute in any order internally.
type Scanner struct {
}

type Options struct {
	// Logger, if not nil, is where logs are written.
	Logger *slog.Logger

	// Cache is the path to save/load the cache. It does not need to exist, but
	// if it does, it must be of a compatible version, or an error wrapping
	// [BadCacheVersionError] will be returned. If empty, an in-memory cache is
	// used. If an error occurs writing to the cache, [OnError] is called and
	// scanning continues. The cache is saved after each top-level Scan* function complete.
	Cache string

	// Workers is the number of workers to spawn.
	Workers int

	// OnResult, if not nil, is called synchronously when a library has been
	// scanned.
	OnResult func(name string, offsets Offsets)

	// OnError, if not nil, is called synchronously when the scanner encounters
	// an error. It is also called when a cache write fails.
	OnError func(err error)
}

// TODO: decouple from cache load/save logic?

// ScanOptions controls options for a scan.
type ScanOptions struct {
	// All scans all library filenames, not just ones which are probably
	// BoringSSL.
	All bool

	// Force scans libraries, even if they appear to link BoringSSL dynamically.
	Force bool

	// Revalidate ignores cached metadata, re-hashing the file entirely. Offsets
	// are still cached (they're computed deterministically, are somewhat
	// expensive to compute, and if a need to recompute them arises, they should
	// be purged specifically).
	Revalidate bool
}

// ScanInfo contains the result of a scan. All scans will be included, even if
// deduplicated with another concurrently executed scan request.
type ScanInfo struct {
	// File contains stats for filesystem files. Offset contains stats for
	// unique elf files.
	File, Offset struct {
		// Total is the total number of items looked at (Cached + Stale + New).
		// The number of successful items is Total - Error.
		//
		// When scanning a directory or archive, each failure to list an item
		// increments both Total and Error by one.
		Total int
		// Cached is the number of items not re-scanned. For a filesystem file,
		// this is due to metadata matching the cache. For an elf file, this is
		// due to it having a known hash.
		Cached int
		// Stale is the number of items re-scanned due to a detected metadata
		// change. This will normally be zero for an elf file since they are
		// identified by their hash. This includes items which previously
		// existed but were removed since they were deleted or no longer
		// accessible.
		Stale int
		// New is the number of items not previously in the cache.
		New int
		// Error is the number of failed items.
		Error int
	}
}

func (s ScanInfo) Add(x ScanInfo) ScanInfo {
	s.File.Total += x.File.Total
	s.File.Cached += x.File.Cached
	s.File.Stale += x.File.Stale
	s.File.New += x.File.New
	s.File.Error += x.File.Error
	s.Offset.Total += x.Offset.Total
	s.Offset.Cached += x.Offset.Cached
	s.Offset.Stale += x.Offset.Stale
	s.Offset.New += x.Offset.New
	s.Offset.Error += x.Offset.Error
	return s
}

// New creates a new scanner, loads the cache, and starts the workers.
func New(opts *Options) (*Scanner, error) {
	if opts == nil {
		opts = new(Options)
	} else {
		opts = new(*opts)
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	panic("not implemented")
}

// Close stops processing new files, returning after all workers exit.
func (s *Scanner) Close() error {
	panic("not implemented")
}

// PurgeOffsets immediately purges all cached offsets, causing elf files to be
// re-analyzed next time they are scanned. It does not purge the file metadata
// in the cache.
func (s *Scanner) PurgeOffsets() error {
	panic("not implemented")
}

// ScanCached is like calling [ScanFile] on all entries in the cache. The
// revalidate option is the same as [ScanOptions.Revalidate].
func (s *Scanner) ScanCached(revalidate bool) (ScanInfo, errs []error) {
	panic("not implemented")
}

// ScanDir scans a directory for libraries or zip/apk/jar files.
func (s *Scanner) ScanDir(name string, recursive bool, opts *ScanOptions) (ScanInfo, errs []error) {
	if opts == nil {
		opts = new(ScanOptions)
	}
	panic("not implemented")
}

// ScanArchive scans an zip (or an apk/jar) for libraries.
func (s *Scanner) ScanArchive(name string, opts *ScanOptions) (ScanInfo, errs []error) {
	if opts == nil {
		opts = new(ScanOptions)
	}
	panic("not implemented")
}

// Scan scans an elf file, which may contain "!/" to reference files within a
// zip archive. [ScanOptions.All] does not affect this; the specified library is
// always scanned.
func (s *Scanner) Scan(name string, opts *ScanOptions) (ScanInfo, errs error) {
	if opts == nil {
		opts = new(ScanOptions)
	}
	panic("not implemented")
}

// TODO: /proc/.../maps?
