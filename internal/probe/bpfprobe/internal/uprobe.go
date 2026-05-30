//go:build linux

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Package uprobe wraps uprobe functionality via the perf subsystem for non-BTF
// eBPF programs.
package uprobe

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

var SysFS = "/sys"

// TracingDirs lists candidate tracefs mount points checked in order by
// [OpenTracing]. Paths starting with "sys" have that prefix replaced with
// [SysFS].
var TracingDirs = []string{
	"sys/kernel/tracing",
	"sys/kernel/debug/tracing",
}

func PMUType() (uint32, error) {
	b, err := os.ReadFile(filepath.Join(SysFS, "bus/event_source/devices/uprobe/type"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("uprobe pmu not available (%w)", err)
		}
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

type Target struct {
	Path     string // matched by inode
	Offset   uint64 // file offset
	PID      int    // -1 for all
	CPU      int    // -1 for all (but only if pid != -1)
	Retprobe bool
}

type Event struct {
	fd      int
	cleanup func() error
}

func Open(pmuType uint32, target Target) (*Event, error) {
	path, err := unix.BytePtrFromString(target.Path)
	if err != nil {
		return nil, err
	}
	attr := &unix.PerfEventAttr{
		Type:   pmuType,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config: 0,
		Ext1:   uint64(uintptr(unsafe.Pointer(path))),
		Ext2:   target.Offset,
		Bits:   unix.PerfBitDisabled | unix.PerfBitSampleIDAll,
	}
	if target.Retprobe {
		attr.Config = 1
	}
	fd, err := unix.PerfEventOpen(attr, target.PID, target.CPU, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &Event{fd: fd}, nil
}

var tracingSeq atomic.Uint64

// OpenTracing registers a uprobe via the tracefs uprobe_events interface and
// returns the corresponding perf event. The tracing entry is removed when the
// returned Event is closed. This is an alternative to [Open] for kernels where
// the uprobe PMU type is unavailable.
//
// The group is used as the tracepoint group name and must contain only
// alphanumeric characters and underscores.
func OpenTracing(group string, target Target) (*Event, error) {
	tracingDir, err := findTracingDir()
	if err != nil {
		return nil, err
	}

	name := fmt.Sprintf("p_%d_%d", os.Getpid(), tracingSeq.Add(1))

	prefix := "p"
	if target.Retprobe {
		prefix = "r"
	}
	def := fmt.Sprintf("%s:%s/%s %s:0x%x\n", prefix, group, name, target.Path, target.Offset)

	if err := appendFile(filepath.Join(tracingDir, "uprobe_events"), def); err != nil {
		return nil, fmt.Errorf("register tracing uprobe: %w", err)
	}

	idBytes, err := os.ReadFile(filepath.Join(tracingDir, "events", group, name, "id"))
	if err != nil {
		_ = removeTracingUprobe(tracingDir, group, name)
		return nil, fmt.Errorf("read tracing uprobe id: %w", err)
	}
	id, err := strconv.ParseUint(strings.TrimSpace(string(idBytes)), 10, 64)
	if err != nil {
		_ = removeTracingUprobe(tracingDir, group, name)
		return nil, fmt.Errorf("parse tracing uprobe id: %w", err)
	}

	attr := &unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_TRACEPOINT,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config: id,
		Bits:   unix.PerfBitDisabled | unix.PerfBitSampleIDAll,
	}
	fd, err := unix.PerfEventOpen(attr, target.PID, target.CPU, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		_ = removeTracingUprobe(tracingDir, group, name)
		return nil, fmt.Errorf("perf_event_open tracing uprobe: %w", err)
	}

	return &Event{
		fd: fd,
		cleanup: func() error {
			return removeTracingUprobe(tracingDir, group, name)
		},
	}, nil
}

// CleanStaleTracingUprobes removes tracing uprobe entries in the given group
// that were left behind by processes that are no longer running.
func CleanStaleTracingUprobes(group string) error {
	tracingDir, err := findTracingDir()
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(filepath.Join(tracingDir, "events", group))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list stale tracing uprobes: %w", err)
	}

	var errs []error
	for _, entry := range entries {
		name := entry.Name()
		// names are p_<pid>_<seq>; skip anything that doesn't match
		rest, ok := strings.CutPrefix(name, "p_")
		if !ok {
			continue
		}
		pidStr, _, ok := strings.Cut(rest, "_")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid <= 0 {
			continue
		}
		if processAlive(pid) {
			continue
		}
		if err := removeTracingUprobe(tracingDir, group, name); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func processAlive(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || errors.Is(err, unix.EPERM)
}

func findTracingDir() (string, error) {
	for _, dir := range TracingDirs {
		if rest, ok := strings.CutPrefix(dir, "sys"); ok {
			dir = SysFS + rest
		}
		if _, err := os.Stat(filepath.Join(dir, "uprobe_events")); err == nil {
			return dir, nil
		}
	}
	return "", fmt.Errorf("tracefs uprobe_events not found (tried %s)", strings.Join(TracingDirs, ", "))
}

func removeTracingUprobe(tracingDir, group, name string) error {
	return appendFile(filepath.Join(tracingDir, "uprobe_events"), fmt.Sprintf("-:%s/%s\n", group, name))
}

func appendFile(path, data string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	_, err = f.WriteString(data)
	if err2 := f.Close(); err == nil {
		err = err2
	}
	return err
}

func (e *Event) Fd() uintptr {
	return uintptr(e.fd)
}

func (e *Event) Close() error {
	if e.fd == -1 {
		return os.ErrInvalid
	}
	err := unix.Close(e.fd)
	e.fd = -1
	if e.cleanup != nil {
		if err2 := e.cleanup(); err == nil {
			err = err2
		}
	}
	return err
}

func (e *Event) Enable() error {
	return unix.IoctlSetInt(e.fd, unix.PERF_EVENT_IOC_ENABLE, 0)
}

func (e *Event) Disable() error {
	return unix.IoctlSetInt(e.fd, unix.PERF_EVENT_IOC_DISABLE, 0)
}

func (e *Event) SetBPF(progFd int) error {
	return unix.IoctlSetInt(e.fd, unix.PERF_EVENT_IOC_SET_BPF, progFd)
}
