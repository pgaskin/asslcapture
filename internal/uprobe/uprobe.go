//go:build linux

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
	"unsafe"

	"golang.org/x/sys/unix"
)

var SysFS = "/sys"

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
	fd int
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

func (e *Event) Fd() uintptr {
	return uintptr(e.fd)
}

func (e *Event) Close() error {
	if e.fd == -1 {
		return os.ErrInvalid
	}
	err := unix.Close(e.fd)
	e.fd = -1
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
