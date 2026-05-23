//go:build linux

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package uprobe

import (
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// some relevant links:
//	- https://github.com/cilium/ebpf/blob/v0.21.0/perf/ring.go
//	- https://man7.org/linux/man-pages/man2/perf_event_open.2.html (mmap layout)
//	- https://github.com/libbpf/libbpf/blob/dd92bef7f6c7a00bb0312554119b6d9cf38e4f32/src/libbpf.c#L13740-L13786 (perf_event_read_simple)

// Ring is a per-CPU mmap'd perf ring buffer for reading BPF_PERF_EVENT_OUTPUT
// records.
type Ring struct {
	fd   int
	tmp  []byte
	buf  []byte                  // mmap'd metadata, data pages
	meta *unix.PerfEventMmapPage // buf[:...]
	data []byte                  // buf[meta.Data_offset : meta.Data_offset+meta.Data_size]
	size uint64                  // meta.Data_size (always power of two)
}

// OpenRing opens a BPF output ring buffer on the given CPU, allocating the
// specified number of pages (must be a power of 2).
func OpenRing(cpu, pages int) (*Ring, error) {
	if pages < 1 || pages&(pages-1) != 0 {
		return nil, fmt.Errorf("invalid page count %d", pages)
	}
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Size:        uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Wakeup:      1, // wake up after every record
	}
	fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("perf_event_open (cpu %d): %w", cpu, err)
	}
	buf, err := unix.Mmap(fd, 0, (1+pages)*os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("mmap ring (cpu %d): %w", cpu, err)
	}
	meta := (*unix.PerfEventMmapPage)(unsafe.Pointer(&buf[0]))
	return &Ring{
		fd:   fd,
		buf:  buf,
		meta: meta,
		data: buf[meta.Data_offset : meta.Data_offset+meta.Data_size],
		size: meta.Data_size,
	}, nil
}

func (r *Ring) Fd() int {
	return r.fd
}

func (r *Ring) Close() error {
	if r.fd == -1 {
		return os.ErrInvalid
	}
	unix.Munmap(r.buf)
	err := unix.Close(r.fd)
	r.fd = -1
	r.buf = nil
	r.meta = nil
	r.data = nil
	return err
}

// ReadRecord reads one PERF_RECORD_SAMPLE from the ring buffer. If a record is
// available, data is non-nil. It may be nil if an unknown/invalid record was
// skipped. Lost is set to the number of dropped events. If ok is false, the
// ring buffer is empty.
func (r *Ring) ReadRecord() (data []byte, lost uint64, ok bool) {
	head := atomic.LoadUint64(&r.meta.Data_head)
	tail := atomic.LoadUint64(&r.meta.Data_tail)
	if tail >= head {
		return nil, 0, false
	}

	var hdr [8]byte
	r.copyWrap(hdr[:], tail)
	recType := binary.LittleEndian.Uint32(hdr[:4])
	recSize := uint64(binary.LittleEndian.Uint16(hdr[6:]))

	if recSize < 8 {
		atomic.StoreUint64(&r.meta.Data_tail, tail+8)
		return nil, 0, true // skip (bad header)
	}
	if tail+recSize > head {
		return nil, 0, true // skip (data past end)
	}

	r.tmp = slices.Grow(r.tmp[:0], int(recSize))[:recSize]
	r.copyWrap(r.tmp, tail) // includes hdr
	atomic.StoreUint64(&r.meta.Data_tail, tail+recSize)

	switch recType {
	case unix.PERF_RECORD_SAMPLE:
		if len(r.tmp) < 12 {
			return nil, 0, true
		}
		rawSize := binary.LittleEndian.Uint32(r.tmp[8:12])
		if 12+int(rawSize) > len(r.tmp) {
			return nil, 0, true
		}
		return r.tmp[12 : 12+rawSize], 0, true

	case unix.PERF_RECORD_LOST:
		if len(r.tmp) < 24 {
			return nil, 0, true
		}
		return nil, binary.LittleEndian.Uint64(r.tmp[16:24]), true

	default:
		return nil, 0, true
	}
}

func (r *Ring) copyWrap(dst []byte, i uint64) {
	sz := uint64(len(dst))
	off := i & (r.size - 1) // pos % size (size is power of 2)
	end := off + sz
	if end <= r.size {
		copy(dst, r.data[off:end])
		return
	}
	n := r.size - off
	copy(dst[:n], r.data[off:])
	copy(dst[n:], r.data[:sz-n])
}
