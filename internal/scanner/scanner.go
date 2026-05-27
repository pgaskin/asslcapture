// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package scanner

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pgaskin/asslcapture/internal/analyze"
	"github.com/pgaskin/asslcapture/internal/kvlines"
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
	"/apex",
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
var bsslNameRe = regexp.MustCompile(`(libssl|cronet|libchrome|webviewchrom)[^/]*\.so[0-9.]*$`)

// soRe matches shared-library filenames: a ".so" suffix, optionally followed by
// version digits/dots (though these are uncommon on Android) (e.g.,
// "libfoo.so", "libfoo.so.1", "libfoo.so.1.2.3").
var soRe = regexp.MustCompile(`\.so[0-9.]*$`)

// Scanner scans for BoringSSL libraries and analyzes them. It is safe for
// concurrent usage. All scan methods block until complete, but queued tasks may
// execute in any order internally.
type Scanner struct {
	opts *Options
	log  *slog.Logger

	mu        sync.Mutex
	cond      *sync.Cond
	closed    bool
	ctx       context.Context
	ctxCancel context.CancelFunc
	wg        sync.WaitGroup

	cache *Cache

	queue        []*fileTask
	fileInflight map[fileKey]*fileTask
}

// TODO: more logging

type Options struct {
	// Logger, if not nil, is where logs are written.
	Logger *slog.Logger

	// Cache is the path to save/load the cache. It does not need to exist, but
	// if it does, it must be of a compatible version, or an error wrapping
	// [BadCacheVersionError] will be returned. If empty, an in-memory cache is
	// used. If an error occurs writing to the cache, [OnError] is called and
	// scanning continues. The cache is saved after each top-level Scan*
	// function completes.
	Cache string

	// Workers is the number of workers to spawn.
	Workers int

	// OnResult, if not nil, is called synchronously when a library has been
	// scanned. name is the requested name (which may contain "!/" for zip
	// entries), path is the real filesystem path, and elfOffset is the offset
	// of the elf within that file (0 for non-zips). The absolute file offset of
	// ssl_log_secret is elfOffset + offsets.SSLLogSecret.
	OnResult func(name, path string, elfOffset uint64, offsets Offsets)

	// OnError, if not nil, is called synchronously when the scanner encounters
	// an error.
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

// fileKey is the deduplication key for an in-flight file scan request. Two
// requests with the same key share a single [fileTask].
type fileKey struct {
	name    string
	size    int64
	modtime int64
	opts    ScanOptions
}

// fileTask is a queued or in-progress file scan. The done channel is closed
// when info and errs are final. info and errs are only mutated by the worker
// that owns the task.
type fileTask struct {
	key fileKey

	done chan struct{}
	info ScanInfo
	errs []error
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
	if opts.Workers <= 0 {
		opts.Workers = 1
	}

	var cache *Cache
	if opts.Cache != "" {
		c, err := ReadCache(opts.Cache)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			if err := WriteCache(opts.Cache, &Cache{}, 0644); err != nil {
				opts.Logger.Warn("failed to create new cache, continuing anyways", "path", opts.Cache, "error", err)
				// ignore
			} else {
				opts.Logger.Info("created new cache", "path", opts.Cache)
			}
		} else {
			opts.Logger.Info("read cache", "path", opts.Cache)
			cache = c
		}
	}
	if cache == nil {
		cache = &Cache{}
	}
	if cache.File == nil {
		cache.File = make(map[string]*File)
	}
	if cache.Offsets == nil {
		cache.Offsets = make(map[kvlines.Hash]*Offsets)
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Scanner{
		opts:         opts,
		log:          opts.Logger,
		cache:        cache,
		fileInflight: make(map[fileKey]*fileTask),
		ctx:          ctx,
		ctxCancel:    cancel,
	}
	s.cond = sync.NewCond(&s.mu)

	s.wg.Add(opts.Workers)
	for range opts.Workers {
		go s.worker()
	}
	return s, nil
}

// Close stops processing new files, returning after all workers exit.
func (s *Scanner) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.ctxCancel()
		s.cond.Broadcast()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

// PurgeOffsets immediately purges all cached offsets, causing elf files to be
// re-analyzed next time they are scanned. It does not purge the file metadata
// in the cache.
func (s *Scanner) PurgeOffsets() error {
	s.mu.Lock()
	clear(s.cache.Offsets)
	s.mu.Unlock()
	return s.saveCache()
}

// ScanCached is like calling [Scanner.Scan] on all entries in the cache. The
// revalidate option is the same as [ScanOptions.Revalidate].
func (s *Scanner) ScanCached(revalidate bool) (info ScanInfo, errs []error) {
	info, errs = s.scanCached(revalidate)
	s.saveCache()
	return info, errs
}

// ScanSystem recursively scans the standard Android system library directories.
// Directories which do not exist are silently skipped.
func (s *Scanner) ScanSystem(opts *ScanOptions) (info ScanInfo, errs []error) {
	if opts == nil {
		opts = new(ScanOptions)
	}
	info, errs = s.scanDirs(libDirs[:], *opts)
	s.saveCache()
	return info, errs
}

// ScanApps recursively scans the standard Android app directories for apk/jar
// archives. Directories which do not exist are silently skipped.
func (s *Scanner) ScanApps(opts *ScanOptions) (info ScanInfo, errs []error) {
	if opts == nil {
		opts = new(ScanOptions)
	}
	info, errs = s.scanDirs(apkDirs[:], *opts)
	s.saveCache()
	return info, errs
}

// ScanDir scans a directory for libraries or zip/apk/jar files.
func (s *Scanner) ScanDir(name string, recursive bool, opts *ScanOptions) (info ScanInfo, errs []error) {
	if opts == nil {
		opts = new(ScanOptions)
	}
	info, errs = s.scanDir(name, recursive, *opts)
	s.saveCache()
	return info, errs
}

// ScanArchive scans an zip (or an apk/jar) for libraries.
func (s *Scanner) ScanArchive(name string, opts *ScanOptions) (info ScanInfo, errs []error) {
	if opts == nil {
		opts = new(ScanOptions)
	}
	info, errs = s.scanArchive(name, *opts)
	s.saveCache()
	return info, errs
}

// Scan scans an elf file, which may contain "!/" to reference files within a
// zip archive. [ScanOptions.All] does not affect this; the specified library is
// always scanned.
func (s *Scanner) Scan(name string, opts *ScanOptions) (info ScanInfo, err error) {
	if opts == nil {
		opts = new(ScanOptions)
	}
	i, es := s.scan(name, *opts)
	s.saveCache()
	return i, errors.Join(es...)
}

// TODO: /proc/.../maps?

func (s *Scanner) scanCached(revalidate bool) (ScanInfo, []error) {
	opts := ScanOptions{Revalidate: revalidate}

	s.mu.Lock()
	names := make([]string, 0, len(s.cache.File))
	for name := range s.cache.File {
		names = append(names, name)
	}
	s.mu.Unlock()

	var (
		info  ScanInfo
		errs  []error
		tasks []*fileTask
	)
	for _, name := range names {
		t, err := s.submitTask(name, opts)
		if err != nil {
			info.File.Total++
			info.File.Stale++
			if errors.Is(err, os.ErrNotExist) {
				// drop the deleted file from the cache
				s.mu.Lock()
				delete(s.cache.File, name)
				s.mu.Unlock()
			} else {
				info.File.Error++
				errs = append(errs, err)
				s.callError(err)
			}
			continue
		}
		if t == nil {
			continue
		}
		tasks = append(tasks, t)
	}
	for _, t := range tasks {
		<-t.done
		info = info.Add(t.info)
		errs = append(errs, t.errs...)
	}
	return info, errs
}

// scanDirs walks each of dirs recursively and waits for all tasks to complete.
// Directories which do not exist are silently skipped.
func (s *Scanner) scanDirs(dirs []string, opts ScanOptions) (ScanInfo, []error) {
	var (
		info  ScanInfo
		errs  []error
		tasks []*fileTask
	)
	for _, d := range dirs {
		if _, err := os.Stat(d); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			err = fmt.Errorf("stat %q: %w", d, err)
			info.File.Total++
			info.File.Error++
			errs = append(errs, err)
			s.callError(err)
			continue
		}
		s.walkDir(d, true, opts, &info, &errs, &tasks)
	}
	for _, t := range tasks {
		<-t.done
		info = info.Add(t.info)
		errs = append(errs, t.errs...)
	}
	return info, errs
}

func (s *Scanner) scanDir(name string, recursive bool, opts ScanOptions) (ScanInfo, []error) {
	var (
		info  ScanInfo
		errs  []error
		tasks []*fileTask
	)
	s.walkDir(name, recursive, opts, &info, &errs, &tasks)
	for _, t := range tasks {
		<-t.done
		info = info.Add(t.info)
		errs = append(errs, t.errs...)
	}
	return info, errs
}

func (s *Scanner) walkDir(name string, recursive bool, opts ScanOptions, info *ScanInfo, errs *[]error, tasks *[]*fileTask) {
	entries, err := os.ReadDir(name)
	if err != nil {
		err = fmt.Errorf("list %q: %w", name, err)
		info.File.Total++
		info.File.Error++
		*errs = append(*errs, err)
		s.callError(err)
		return
	}
	for _, e := range entries {
		full := filepath.Join(name, e.Name())
		if e.IsDir() {
			if recursive {
				s.walkDir(full, recursive, opts, info, errs, tasks)
			}
			continue
		}
		n := e.Name()
		switch {
		case soRe.MatchString(n):
			if !opts.All && !bsslNameRe.MatchString(n) {
				continue
			}
			t, err := s.submitTask(full, opts)
			if err != nil {
				info.File.Total++
				info.File.Error++
				*errs = append(*errs, err)
				s.callError(err)
				continue
			}
			if t == nil {
				continue
			}
			*tasks = append(*tasks, t)
		case strings.HasSuffix(n, ".apk"), strings.HasSuffix(n, ".zip"), strings.HasSuffix(n, ".jar"):
			s.queueArchive(full, opts, info, errs, tasks)
		}
	}
}

func (s *Scanner) scanArchive(name string, opts ScanOptions) (ScanInfo, []error) {
	var (
		info  ScanInfo
		errs  []error
		tasks []*fileTask
	)
	s.queueArchive(name, opts, &info, &errs, &tasks)
	for _, t := range tasks {
		<-t.done
		info = info.Add(t.info)
		errs = append(errs, t.errs...)
	}
	return info, errs
}

func (s *Scanner) queueArchive(name string, opts ScanOptions, info *ScanInfo, errs *[]error, tasks *[]*fileTask) {
	zr, err := zip.OpenReader(name)
	if err != nil {
		err = fmt.Errorf("open archive %q: %w", name, err)
		info.File.Total++
		info.File.Error++
		*errs = append(*errs, err)
		s.callError(err)
		return
	}
	defer zr.Close()
	for _, f := range zr.File {
		base := path.Base(f.Name)
		if !soRe.MatchString(base) {
			continue
		}
		if !opts.All && !bsslNameRe.MatchString(base) {
			continue
		}
		// if the entry is compressed and the apk's extracted copy exists
		// alongside it (the Android package manager extracts compressed
		// non-mmapable libs), skip silently since that copy will be scanned (we
		// look for so files in package dirs too).
		if f.Method != zip.Store {
			// TODO: is there a more generic way to handle this (i.e., arm64-v8a -> arm64?
			// TODO: look at the package manager code
			ext := f.Name
			if s, ok := strings.CutPrefix(ext, "lib/arm64-v8a/"); ok {
				ext = "lib/arm64/" + s
			}
			ext = filepath.Join(filepath.Dir(name), ext)
			if _, err := os.Stat(ext); err == nil {
				s.log.Debug("ignoring compressed lib which has already been extracted", "library", name+"!/"+f.Name, "extracted", ext)
				continue
			}
		}
		t, err := s.submitTask(name+"!/"+f.Name, opts)
		if err != nil {
			info.File.Total++
			info.File.Error++
			*errs = append(*errs, err)
			s.callError(err)
			continue
		}
		if t == nil {
			continue
		}
		*tasks = append(*tasks, t)
	}
}

func (s *Scanner) scan(name string, opts ScanOptions) (ScanInfo, []error) {
	t, err := s.submitTask(name, opts)
	if err != nil {
		var info ScanInfo
		info.File.Total++
		info.File.Error++
		s.callError(err)
		return info, []error{err}
	}
	if t == nil {
		return ScanInfo{}, nil
	}
	<-t.done
	return t.info, t.errs
}

// submitTask enqueues a file scan, or returns an existing in-flight task for
// the same dedup key. If the scanner has been closed, it returns (nil, nil).
func (s *Scanner) submitTask(name string, opts ScanOptions) (*fileTask, error) {
	// stat the filesystem file itself without opening the elf (the worker will
	// do that)
	outerPath, _, _ := strings.Cut(name, "!/")
	fi, err := os.Stat(outerPath)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", name, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("stat %q: %s is a directory", name, outerPath)
	}
	key := fileKey{
		name:    name,
		size:    fi.Size(),
		modtime: fi.ModTime().Unix(),
		opts:    opts,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil
	}
	if t, ok := s.fileInflight[key]; ok {
		return t, nil
	}
	t := &fileTask{
		key:  key,
		done: make(chan struct{}),
	}
	s.fileInflight[key] = t
	s.queue = append(s.queue, t)
	s.cond.Signal()
	return t, nil
}

// worker pops tasks from the queue until the scanner is closed and the queue is
// drained. When closed, any remaining queued (not yet started) tasks are
// dropped; tasks already running finish since analyze is not interruptible.
func (s *Scanner) worker() {
	defer s.wg.Done()
	for {
		s.mu.Lock()
		for len(s.queue) == 0 && !s.closed {
			s.cond.Wait()
		}
		if s.closed {
			for _, t := range s.queue {
				delete(s.fileInflight, t.key)
				close(t.done)
			}
			s.queue = nil
			s.mu.Unlock()
			return
		}
		task := s.queue[0]
		s.queue[0] = nil
		s.queue = s.queue[1:]
		s.mu.Unlock()

		s.processTask(task)

		s.mu.Lock()
		delete(s.fileInflight, task.key)
		s.mu.Unlock()
		close(task.done)
	}
}

func (s *Scanner) processTask(task *fileTask) {
	task.info.File.Total++

	// so we can tell if it's new or stale
	s.mu.Lock()
	existing, hasExisting := s.cache.File[task.key.name]
	var existingOffsets *Offsets
	if hasExisting {
		existingOffsets = s.cache.Offsets[existing.SHA256]
	}
	s.mu.Unlock()

	bumpFile := func(success bool) {
		switch {
		case !hasExisting:
			task.info.File.New++
		case existing.Size != task.key.size || int64(existing.Modified) != task.key.modtime:
			task.info.File.Stale++
		default:
			task.info.File.Cached++
		}
		if !success {
			task.info.File.Error++
		}
	}

	ef, err := analyze.Open(task.key.name)
	if err != nil {
		err = fmt.Errorf("open elf %q: %w", task.key.name, err)
		bumpFile(false)
		task.errs = append(task.errs, err)
		s.callError(err)
		return
	}
	defer ef.Close()

	realPath := ef.Path()
	// stat the filesystem file itself without opening the elf (the worker will
	// do that) just in case it changed
	var (
		outerSize    int64 = task.key.size
		outerModTime       = kvlines.MakeUnixTime(time.Unix(task.key.modtime, 0))
	)
	if fi, err := os.Stat(realPath); err == nil {
		outerSize = fi.Size()
		outerModTime = kvlines.MakeUnixTime(fi.ModTime())
	}

	// use the cached offset if the metadata hasn't changed
	if !task.key.opts.Revalidate && hasExisting && existing.Size == task.key.size && int64(existing.Modified) == task.key.modtime && existingOffsets != nil {
		task.info.File.Cached++
		task.info.Offset.Total++
		task.info.Offset.Cached++
		if s.opts.OnResult != nil {
			s.opts.OnResult(task.key.name, existing.Path, existing.Offset, *existingOffsets)
		}
		return
	}

	h := sha256.New()
	if _, err := io.Copy(h, ef.Data()); err != nil {
		err = fmt.Errorf("hash %q: %w", task.key.name, err)
		bumpFile(false)
		task.errs = append(task.errs, err)
		s.callError(err)
		return
	}
	hash := kvlines.MakeHash("sha256", h)

	bumpFileWithHash := func(success bool) {
		switch {
		case !hasExisting:
			task.info.File.New++
		case existing.SHA256 != hash:
			task.info.File.Stale++
		default:
			task.info.File.Cached++
		}
		if !success {
			task.info.File.Error++
		}
	}

	// nothing to analyze if dynamically links BoringSSL (this check is
	// relatively efficient)
	if !task.key.opts.Force && analyze.IsProbablyLinkedBoringSSL(ef.File) {
		bumpFileWithHash(true)
		if hasExisting {
			s.mu.Lock()
			delete(s.cache.File, task.key.name)
			s.mu.Unlock()
		}
		return
	}
	maybe, err := analyze.IsMaybeBoringSSL(ef.File)
	if err != nil {
		err = fmt.Errorf("check boringssl %q: %w", task.key.name, err)
		bumpFileWithHash(false)
		task.errs = append(task.errs, err)
		s.callError(err)
		return
	}
	if !maybe {
		bumpFileWithHash(true)
		if hasExisting {
			s.mu.Lock()
			delete(s.cache.File, task.key.name)
			s.mu.Unlock()
		}
		return
	}

	task.info.Offset.Total++

	// deduplicate analysis by the elf hash (this is best-effort, there may
	// sometimes be concurrent first-time analysis of the same file, but it's
	// deterministic so it's fine)
	//
	// TODO: refactor this to prevent that?
	s.mu.Lock()
	cachedOffsets, hasOffsets := s.cache.Offsets[hash]
	s.mu.Unlock()

	var offsets Offsets
	if hasOffsets {
		offsets = *cachedOffsets
		task.info.Offset.Cached++
	} else {
		fnOff, warn, err := analyze.LogSecret(s.ctx, ef.File)
		for _, w := range warn {
			s.log.Warn("scanner warning", "name", task.key.name, "error", w)
		}
		if err != nil {
			err = fmt.Errorf("find ssl_log_secret %q: %w", task.key.name, err)
			bumpFileWithHash(false)
			task.info.Offset.Error++
			task.errs = append(task.errs, err)
			s.callError(err)
			return
		}
		s3, cr, err := analyze.ClientRandom(ef.File, fnOff)
		if err != nil {
			err = fmt.Errorf("find s3->client_random %q: %w", task.key.name, err)
			bumpFileWithHash(false)
			task.info.Offset.Error++
			task.errs = append(task.errs, err)
			s.callError(err)
			return
		}
		offsets = Offsets{
			Hash:         hash,
			SSLLogSecret: fnOff,
			S3:           s3,
			ClientRandom: cr,
		}
		task.info.Offset.New++
	}

	bumpFileWithHash(true)

	s.mu.Lock()
	s.cache.Offsets[hash] = &offsets
	s.cache.File[task.key.name] = &File{
		Name:     task.key.name,
		Path:     realPath,
		Modified: outerModTime,
		Size:     outerSize,
		Offset:   uint64(ef.Offset()),
		Length:   ef.Size(),
		SHA256:   hash,
	}
	s.mu.Unlock()

	if s.opts.OnResult != nil {
		s.opts.OnResult(task.key.name, realPath, uint64(ef.Offset()), offsets)
	}
}

func (s *Scanner) saveCache() error {
	if s.opts.Cache == "" {
		return nil
	}
	s.mu.Lock()
	buf, err := kvlines.Marshal(s.cache)
	s.mu.Unlock()
	if err != nil {
		err = fmt.Errorf("marshal cache: %w", err)
		s.callError(err)
		return err
	}
	if err := os.WriteFile(s.opts.Cache, buf, 0644); err != nil {
		s.log.Warn("failed to save cache, continuing anyways", "path", s.opts.Cache, "error", err)
		return err
	}
	s.log.Info("saved cache", "path", s.opts.Cache)
	return nil
}

func (s *Scanner) callError(err error) {
	if s.opts.OnError != nil {
		s.opts.OnError(err)
	}
}
