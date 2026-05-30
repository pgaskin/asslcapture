//go:build linux

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Package phook implements a ptrace-based hooking mechanism.
package phook

import (
	"bytes"
	"context"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var ProcFS = "/proc"

// Process manages the ptrace state for a process. All methods are goroutine-safe.
type Process struct {
	pid int

	mu    sync.Mutex
	specs []hookSpec

	threads      map[int]*threadInfo
	pending      map[int]struct{}
	bps          map[uintptr]*bpState
	pendingSpecs []hookSpec

	eventCh chan *Breakpoint
	doneCh  chan struct{}

	cmdCh chan func()

	closeOnce sync.Once
	stop      chan struct{}
	done      chan struct{}

	dropped atomic.Int64

	fatalOnce sync.Once
	fatalCh   chan struct{}
	fatalErr  error
}

// Breakpoint represents a thread stopped at a breakpoint.
type Breakpoint struct {
	PID    int    // tgid of the process
	TID    int    // tid of the thread that hit the breakpoint
	Path   string // path the hook was registered with
	Offset uint64 // offset the hook was registered with
	Regs   *Regs  // architecture-specific registers
}

type hookSpec struct {
	path   string
	offset uint64
}

type threadInfo struct {
	tid      int
	stepping *bpState
	running  bool // between PTRACE_CONT and the next stop
}

type bpState struct {
	va        uintptr
	origInstr [instructionSize]byte
	spec      hookSpec
}

// Attach seizes pid and all of its threads.
func Attach(pid int) (*Process, error) {
	h := &Process{
		pid:     pid,
		threads: make(map[int]*threadInfo),
		pending: make(map[int]struct{}),
		bps:     make(map[uintptr]*bpState),
		eventCh: make(chan *Breakpoint),
		doneCh:  make(chan struct{}),
		cmdCh:   make(chan func(), 128),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		fatalCh: make(chan struct{}),
	}
	attachErr := make(chan error, 1)
	go h.run(attachErr)
	if err := <-attachErr; err != nil {
		<-h.done
		return nil, err
	}
	return h, nil
}

// PID returns the tgid of the attached process.
func (p *Process) PID() int {
	return p.pid
}

// Hook registers a breakpoint at offset within path. The path is matched
// against /proc/.../maps. If the library is not currently mapped in the
// process, the hook will not do anything.
func (p *Process) Hook(path string, offset uint64) error {
	spec := hookSpec{path: path, offset: offset}
	p.mu.Lock()
	p.specs = append(p.specs, spec)
	p.mu.Unlock()
	select {
	case p.cmdCh <- func() { p.install(spec) }:
	case <-p.stop:
	case <-p.fatalCh:
	}
	return nil
}

// TODO: better handling for if the library is not mapped in the process?

// Events iterates over breakpoint hits until ctx is cancelled, the Hook is
// closed, or a fatal error occurs. The traced thread is stopped for the
// duration of the loop body.
//
// The int is the number of breakpoint hits that were dropped because nothing
// was waiting for them.
func (p *Process) Events(ctx context.Context) iter.Seq2[*Breakpoint, int] {
	return func(yield func(*Breakpoint, int) bool) {
		for {
			select {
			case b := <-p.eventCh:
				drops := int(p.dropped.Swap(0))
				cont := yield(b, drops)
				select {
				case p.doneCh <- struct{}{}: // this must be done before returning to avoid indefinitely-stopped threads
				case <-p.done:
					return
				}
				if !cont {
					return
				}
				if ctx.Err() != nil {
					return
				}
			case <-p.done:
				if drops := int(p.dropped.Swap(0)); drops > 0 {
					yield(nil, drops)
				}
				return
			case <-p.fatalCh:
				if drops := int(p.dropped.Swap(0)); drops > 0 {
					yield(nil, drops)
				}
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

func (p *Process) Err() error {
	select {
	case <-p.fatalCh:
		return p.fatalErr
	default:
		return nil
	}
}

// Close detaches from the process, restoring breakpoints and resuming all
// threads.
func (p *Process) Close() error {
	p.closeOnce.Do(func() {
		close(p.stop)
		<-p.done
	})
	return nil
}

func (p *Process) setFatal(err error) {
	p.fatalOnce.Do(func() {
		p.fatalErr = err
		close(p.fatalCh)
	})
}

func (p *Process) emit(b *Breakpoint) {
	select {
	case p.eventCh <- b:
	default:
		// nothing waiting for an event
		p.dropped.Add(1)
		return
	}
	select {
	case <-p.doneCh: // event loop body finished
	case <-p.stop: // shutting down
	}
}

func (p *Process) run(errCh chan<- error) {
	defer close(p.done)

	// ptrace is tied to the specific thread which called PTRACE_SEIZE, signals
	// are delivered to only that thread (via wait4)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := func() (err error) {
		defer func() {
			// errCh is only for attach errors
			errCh <- err
		}()
		tids, err := listThreads(p.pid)
		if err != nil {
			return fmt.Errorf("list threads for pid %d: %w", p.pid, err)
		}
		for _, tid := range tids {
			if err := ptraceSeize(tid, unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_TRACEEXIT); err != nil {
				continue
			}
			p.threads[tid] = &threadInfo{tid: tid, running: true}
		}
		if len(p.threads) == 0 {
			return fmt.Errorf("seize pid %d: no threads attached", p.pid)
		}
		return nil
	}(); err != nil {
		return
	}

	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	for {
	drainCmds:
		for {
			select {
			case fn := <-p.cmdCh:
				fn()
			default:
				break drainCmds
			}
		}

		select {
		case <-p.stop:
			goto cleanup
		default:
		}

		var status unix.WaitStatus
		// without WNOTHREAD, we may get events for a different Process, causing
		// the other one to not see the event, and the tracee to hang forever
		tid, err := unix.Wait4(-1, &status, unix.WNOHANG|unix.WALL|unix.WNOTHREAD, nil)
		if err == unix.EINTR {
			continue
		}
		if err == unix.ECHILD {
			select {
			case <-p.stop:
				goto cleanup
			case fn := <-p.cmdCh:
				fn()
			}
			continue
		}
		if err != nil {
			p.setFatal(fmt.Errorf("wait4: %w", err))
			return
		}
		if tid == 0 {
			select {
			case <-p.stop:
				goto cleanup
			case fn := <-p.cmdCh:
				fn()
			case <-ticker.C:
			}
			continue
		}

		if status.Exited() || status.Signaled() {
			delete(p.threads, tid)
			continue
		}
		if !status.Stopped() {
			continue
		}
		sig := status.StopSignal()
		if _, isPending := p.pending[tid]; isPending {
			delete(p.pending, tid)
			thread := &threadInfo{tid: tid}
			p.threads[tid] = thread
			_ = unix.PtraceSetOptions(tid, unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_TRACEEXIT)
			p.cont(thread, 0)
			continue
		}
		thread, ok := p.threads[tid]
		if !ok {
			// not our thread
			_ = unix.PtraceCont(tid, int(sig)) // TODO: log?
			continue
		}
		thread.running = false
		p.installPending(thread.tid)
		if sig == unix.SIGTRAP && status.TrapCause() != 0 {
			switch status.TrapCause() {
			case unix.PTRACE_EVENT_CLONE, unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK:
				newTidRaw, _ := unix.PtraceGetEventMsg(tid)
				p.pending[int(newTidRaw)] = struct{}{}
			}
			p.cont(thread, 0)
			continue
		}
		if sig == unix.SIGTRAP {
			p.handleBreakpoint(thread)
			continue
		}
		p.cont(thread, sig)
	}

cleanup:
	// TODO: log?

	for _, thread := range p.threads {
		if thread.running {
			_ = unix.PtraceInterrupt(thread.tid) // TODO: log?
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		anyRunning := false
		for _, thread := range p.threads {
			if thread.running {
				anyRunning = true
				break
			}
		}
		if !anyRunning {
			break
		}
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WNOHANG|unix.WALL|unix.WNOTHREAD, nil)
		if err == unix.ECHILD {
			break
		}
		if err != nil || pid == 0 {
			runtime.Gosched()
			continue
		}
		if status.Exited() || status.Signaled() {
			delete(p.threads, pid)
			continue
		}
		if status.Stopped() {
			if t, ok := p.threads[pid]; ok {
				t.running = false
			}
		}
	}

	var stoppedTID int
	for t, th := range p.threads {
		if !th.running {
			stoppedTID = t
			break
		}
	}
	if stoppedTID != 0 {
		for _, bp := range p.bps {
			removeBreakpoint(stoppedTID, bp.va, bp.origInstr)
		}
	}

	for tid := range p.threads {
		_ = unix.PtraceDetach(tid) // TODO: log?
	}
}

func (p *Process) cont(thread *threadInfo, sig syscall.Signal) {
	p.installPending(thread.tid)
	thread.running = true
	_ = unix.PtraceCont(thread.tid, int(sig)) // TODO: log?
}

func (p *Process) install(spec hookSpec) {
	var stoppedTID int
	for t, th := range p.threads {
		if !th.running {
			stoppedTID = t
			break
		}
	}
	if stoppedTID != 0 {
		p.installThread(stoppedTID, spec)
		return
	}
	// no stopped threads, interrupt one to install the breakpoint
	p.pendingSpecs = append(p.pendingSpecs, spec)
	for t := range p.threads {
		_ = unix.PtraceInterrupt(t) // TODO: log?
		break
	}
}

func (p *Process) installPending(tid int) {
	if len(p.pendingSpecs) == 0 {
		return
	}
	for _, spec := range p.pendingSpecs {
		p.installThread(tid, spec)
	}
	p.pendingSpecs = nil
}

func (p *Process) installThread(tid int, spec hookSpec) {
	va, err := resolveAddr(p.pid, spec.path, spec.offset)
	if err != nil {
		return
	}
	if _, ok := p.bps[va]; ok {
		return
	}
	orig, err := installBreakpoint(tid, va)
	if err != nil {
		return
	}
	p.bps[va] = &bpState{va: va, origInstr: orig, spec: spec}
}

func ptraceSeize(pid int, opts int) error {
	// unix.PtraceSeize doesn't support passing options
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(unix.PTRACE_SEIZE), uintptr(pid), 0, uintptr(opts), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func resolveAddr(pid int, path string, fileOffset uint64) (uintptr, error) {
	data, err := os.ReadFile(filepath.Join(ProcFS, strconv.Itoa(pid), "maps"))
	if err != nil {
		return 0, err
	}
	for line := range bytes.SplitSeq(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		parts := bytes.Fields(line)
		if len(parts) < 6 || filepath.Clean(string(parts[len(parts)-1])) != filepath.Clean(path) {
			continue
		}
		addrs := bytes.SplitN(parts[0], []byte{'-'}, 2)
		if len(addrs) != 2 {
			continue
		}
		start, err := strconv.ParseUint(string(addrs[0]), 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(string(addrs[1]), 16, 64)
		if err != nil {
			continue
		}
		offset, err := strconv.ParseUint(string(parts[2]), 16, 64)
		if err != nil {
			continue
		}
		if fileOffset >= offset && fileOffset-offset < end-start {
			return uintptr(start + (fileOffset - offset)), nil
		}
	}
	return 0, fmt.Errorf("no mapping for %q offset %#x in /proc/%d/maps", path, fileOffset, pid)
}

func listThreads(pid int) ([]int, error) {
	entries, err := os.ReadDir(filepath.Join(ProcFS, strconv.Itoa(pid), "task"))
	if err != nil {
		return nil, err
	}
	tids := make([]int, 0, len(entries))
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		tids = append(tids, tid)
	}
	return tids, nil
}
