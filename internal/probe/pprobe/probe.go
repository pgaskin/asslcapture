//go:build linux

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Package pprobe implements an alternative probe mechanism using ptrace which
// supports per-process tracing on kernels which do not support eBPF.
//
// Unlike the eBPF-based probe, this one doesn't support attaching to processes
// system-wide, nor does it support attaching to libraries not yet loaded when
// attaching. However, compared to the noread eBPF probe variant, this one is
// not racy, making it more reliable on older kernels which don't support the
// full eBPF probe.
//
// Calling Close is important otherwise processes will SIGTRAP on the
// breakpoints after detaching.
package pprobe

import (
	"cmp"
	"context"
	"fmt"
	"iter"
	"sync"
	"sync/atomic"

	"github.com/pgaskin/asslcapture/internal/probe"
	phook "github.com/pgaskin/asslcapture/internal/probe/pprobe/internal"
	"golang.org/x/sys/unix"
)

var _ probe.Probe = (*Probe)(nil)

type Options struct {
	// PIDs is the list of process IDs to attach to.
	PIDs []int

	// BufferSize is the number of events to buffer before dropping.
	BufferSize int
}

type Probe struct {
	mu    sync.Mutex
	specs []attachSpec

	hooks []*phook.Process

	events  chan *probe.Event
	dropped atomic.Int64

	closeOnce sync.Once
	stop      chan struct{}
	wg        sync.WaitGroup

	fatalOnce sync.Once
	fatalCh   chan struct{}
	fatalErr  error
}

type attachSpec struct {
	path   string
	offset uint64
	s3, cr int
}

// New creates a Probe and attaches to the PIDs listed in opts.
func New(opts *Options) (*Probe, error) {
	if opts == nil {
		opts = new(Options)
	}
	p := &Probe{
		events:  make(chan *probe.Event, cmp.Or(opts.BufferSize, probe.DefaultBufferSize)),
		stop:    make(chan struct{}),
		fatalCh: make(chan struct{}),
	}
	for _, pid := range opts.PIDs {
		h, err := phook.Attach(pid)
		if err != nil {
			p.closeHooks()
			return nil, fmt.Errorf("attach to pid %d: %w", pid, err)
		}
		p.hooks = append(p.hooks, h)
	}
	for _, h := range p.hooks {
		p.wg.Add(1)
		go p.run(h)
	}
	return p, nil
}

func (p *Probe) Close() error {
	p.closeOnce.Do(func() {
		close(p.stop)
		p.closeHooks()
		p.wg.Wait()
		close(p.events)
	})
	return nil
}

func (p *Probe) closeHooks() {
	for _, h := range p.hooks {
		h.Close()
	}
}
func (p *Probe) Err() error {
	select {
	case <-p.fatalCh:
		return p.fatalErr
	default:
		return nil
	}
}

func (p *Probe) setFatal(err error) {
	p.fatalOnce.Do(func() {
		p.fatalErr = err
		close(p.fatalCh)
	})
}

func (p *Probe) Attach(path string, offset int64, s3, cr int) error {
	if offset < 0 {
		return fmt.Errorf("negative offset")
	}
	spec := attachSpec{path: path, offset: uint64(offset), s3: s3, cr: cr}
	p.mu.Lock()
	p.specs = append(p.specs, spec)
	p.mu.Unlock()
	for _, h := range p.hooks {
		_ = h.Hook(spec.path, spec.offset)
	}
	return nil
}

func (p *Probe) lookupSpec(path string, offset uint64) (attachSpec, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.specs {
		if s.path == path && s.offset == offset {
			return s, true
		}
	}
	return attachSpec{}, false
}

func (p *Probe) Read() (e *probe.Event, dropped int, ok bool) {
	return p.read(nil)
}

func (p *Probe) Events(ctx context.Context) iter.Seq2[*probe.Event, int] {
	return func(yield func(*probe.Event, int) bool) {
		for {
			e, dropped, ok := p.read(ctx.Done())
			if !ok {
				return
			}
			if ctx.Err() != nil {
				return
			}
			if !yield(e, dropped) {
				return
			}
		}
	}
}

func (p *Probe) read(interrupt <-chan struct{}) (e *probe.Event, dropped int, ok bool) {
	defer func() {
		dropped = int(p.dropped.Load())
		p.dropped.Add(-int64(dropped))
	}()
	select {
	case <-interrupt:
		return nil, 0, true
	case e = <-p.events:
		return e, dropped, true
	case <-p.fatalCh:
	case <-p.stop:
	}
	select {
	case ev := <-p.events:
		return ev, dropped, true
	default:
	}
	if dropped > 0 {
		return nil, dropped, true
	}
	return nil, 0, false
}

func (p *Probe) run(h *phook.Process) {
	defer p.wg.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-p.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	for stop, drops := range h.Events(ctx) {
		if drops > 0 {
			p.dropped.Add(int64(drops))
		}
		if stop == nil {
			continue
		}
		spec, ok := p.lookupSpec(stop.Path, stop.Offset)
		if !ok {
			continue
		}
		event := newEvent(stop, spec.s3, spec.cr)
		select {
		case p.events <- event:
		default:
			p.dropped.Add(1)
		}
	}
	if err := h.Err(); err != nil {
		p.setFatal(fmt.Errorf("phook pid %d: %w", h.PID(), err))
	}
}

func procVMRead(pid int, addr uint64, buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	local := unix.Iovec{Base: &buf[0]}
	local.SetLen(len(buf))
	remote := unix.RemoteIovec{Base: uintptr(addr), Len: len(buf)}
	n, err := unix.ProcessVMReadv(pid, []unix.Iovec{local}, []unix.RemoteIovec{remote}, 0)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("short read: got %d, want %d", n, len(buf))
	}
	return nil
}
