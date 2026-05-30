//go:build linux

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Package bpfprobe manages the uprobe for reading boringssl secrets.
//
// I'd have used cilium/ebpf for the logic, but:
//
//   - It doesn't support attaching probes to libs in zip files (this is an Android-specific linker feature.)
//   - I want to use the perf_event_open syscall (4.18+, same kconfig) so the probe lifecycle is tied to the fd.
//   - I need to handle CPU hotplug (i.e., cores being turned on and off), which it doesn't do.
//   - I already have file offsets and don't want its calculations (which can't currently be skipped).
//
// Since I don't need most of the features anyways, it's easier to just
// implement it myself, which also gives me explicit control over the behaviour.
//
// Pert of the reason why ecapture is so unreliable on Android is because it
// doesn't take into account any of these things.
package bpfprobe

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/pgaskin/asslcapture/internal/probe"
	uprobe "github.com/pgaskin/asslcapture/internal/probe/bpfprobe/internal"
)

//go:generate go run build.go

// note: if there's a bug in cpu handling, ssl stuff done on that cpu won't be
// handled (test this by enabling tracing, then using taskset on the test ssl
// client)

var _ probe.Probe = (*Probe)(nil)

func newEvent(e *probeEvent) (ev *probe.Event) {
	defer func() {
		if e != nil && ev != nil {
			ev.Delay = monotonicTimeSince(e.Timestamp)
		}
	}()
	if e.DebugLine != -1 {
		return &probe.Event{
			Error: fmt.Errorf("probe error (line=%d ret=%d ptr=%#x)", e.DebugLine, e.DebugRet, e.DebugPtr),
		}
	}
	label := make([]byte, 0, len(e.Label))
	for _, c := range e.Label {
		if c == 0 {
			break
		}
		label = append(label, byte(c))
	}
	return &probe.Event{
		PID:          int(e.PID),
		Label:        string(label),
		ClientRandom: slices.Clone(e.ClientRandom[:]),
		Secret:       slices.Clone(e.Secret[:min(len(e.Secret), int(e.SecretLen))]),
	}
}

func newNoreadEvent(e *probeNoReadEvent, cfg configKey) (ev *probe.Event) {
	defer func() {
		if e != nil && ev != nil {
			ev.Delay = monotonicTimeSince(e.Timestamp)
		}
	}()
	pid := int(e.PID)

	// read the secret first, it's the most time-sensitive
	secretLen := int(e.SecretLen)
	if secretLen < 0 || secretLen > probeSecretMax {
		secretLen = probeSecretMax
	}
	secret := make([]byte, secretLen)
	if secretLen > 0 {
		if err := procVMRead(pid, untag(e.SecretPtr), secret); err != nil {
			return &probe.Event{Delay: monotonicTimeSince(e.Timestamp), Error: fmt.Errorf("read secret (pid=%d ptr=%#x): %w", pid, e.SecretPtr, err)}
		}
	}

	s3PtrBuf := make([]byte, 8)
	if err := procVMRead(pid, untag(e.SSLPtr)+uint64(cfg.s3), s3PtrBuf); err != nil {
		return &probe.Event{Delay: monotonicTimeSince(e.Timestamp), Error: fmt.Errorf("read s3 ptr (pid=%d ssl=%#x off=%d): %w", pid, e.SSLPtr, cfg.s3, err)}
	}
	s3Ptr := binary.LittleEndian.Uint64(s3PtrBuf)

	clientRandom := make([]byte, probeClientRandomSize)
	if err := procVMRead(pid, untag(s3Ptr)+uint64(cfg.cr), clientRandom); err != nil {
		return &probe.Event{Delay: monotonicTimeSince(e.Timestamp), Error: fmt.Errorf("read client_random (pid=%d s3=%#x off=%d): %w", pid, s3Ptr, cfg.cr, err)}
	}

	labelBuf := make([]byte, probeLabelMax)
	if err := procVMRead(pid, e.LabelPtr, labelBuf); err != nil {
		return &probe.Event{Delay: monotonicTimeSince(e.Timestamp), Error: fmt.Errorf("read label (pid=%d ptr=%#x): %w", pid, e.LabelPtr, err)}
	}
	if i := bytes.IndexByte(labelBuf, 0); i >= 0 {
		labelBuf = labelBuf[:i]
	}

	if secretLen > 0 && !slices.ContainsFunc(secret, func(b byte) bool {
		return b != 0
	}) {
		return &probe.Event{Delay: monotonicTimeSince(e.Timestamp), Error: fmt.Errorf("read secret (pid=%d ptr=%#x label=%q client_random=%x): all zeroes (we were probably too slow)", pid, e.SecretPtr, labelBuf, clientRandom)}
	}

	return &probe.Event{
		Label:        string(labelBuf),
		ClientRandom: clientRandom,
		Secret:       secret,
		Delay:        monotonicTimeSince(e.Timestamp),
	}
}

// Options configures a Probe.
type Options struct {
	// BufferSize is the number of events to buffer before dropping them.
	BufferSize int

	// NoRead uses an alternative BPF probe which only captures pointers and the
	// PID, then reads the label, secret, and client_random from the target
	// process in userspace with process_vm_readv. Although this is racy (though
	// this won't usually be an issue since the objects we read from are
	// long-lived, and we're reading near the start of their life), this may
	// work better on old kernels with broken userspace memory reading or overly
	// strict verifiers.
	NoRead bool
}

// Probe manages the uprobes to capture BoringSSL secrets. All methods are
// goroutine-safe.
type Probe struct {
	pmu     uint32
	tracefs bool // use tracefs instead of perf
	cpus    int  // number of possible CPUs
	hotplug *uprobe.CPUHotplug
	noRead  bool

	mu sync.Mutex
	wg sync.WaitGroup // workers

	closeOnce sync.Once
	done      chan struct{} // when close called

	events  chan *probe.Event
	dropped atomic.Int64

	instances map[configKey]*probeInstance // loaded bpf programs for each probe config
	targets   []attachSpec                 // current uprobe targets (for hotplug)
	uprobes   map[attachKey]*uprobe.Event  // per-cpu uprobe perf event buffers

	epollFd      int // for ring buffers
	cancelFd     int // eventfd to wake epoll
	ringFd       map[int]*uprobe.Ring
	ringInstance map[int]*probeInstance // used in noRead mode to look up config key per ring

	fatalOnce sync.Once
	fatalCh   chan struct{} // closed when fatalErr is set
	fatalErr  error
}

type configKey struct {
	s3, cr int
}

type attachSpec struct {
	path   string
	offset uint64
	config configKey
}

type attachKey struct {
	path   string
	offset uint64
}

// probeInstance contains a single instance of the BPF program, plus the buffers
// for all cpus (including offline ones).
type probeInstance struct {
	cfg    configKey
	prog   *ebpf.Program
	config *ebpf.Map // nil in noRead mode
	events *ebpf.Map
	ring   []*uprobe.Ring
}

// New creates a new Probe, starting background goroutines for event reading
// and CPU hotplug handling.
func New(opts *Options) (*Probe, error) {
	if opts == nil {
		opts = new(Options)
	}

	pmu, err := uprobe.PMUType()
	var tracefs bool
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		tracefs = true
		if err := uprobe.CleanStaleTracingUprobes("asslcapture"); err != nil {
			return nil, fmt.Errorf("clean stale tracing uprobes: %w", err)
		}
	}

	cpus, err := uprobe.PossibleCPUs()
	if err != nil {
		return nil, fmt.Errorf("possible cpus: %w", err)
	}

	hotplug, err := uprobe.OpenHotplug()
	if err != nil {
		return nil, fmt.Errorf("open hotplug socket: %w", err)
	}

	epollFd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("epoll_create: %w", err)
	}

	cancelFd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		unix.Close(epollFd)
		return nil, fmt.Errorf("eventfd: %w", err)
	}
	if err := epollAdd(epollFd, cancelFd); err != nil {
		unix.Close(cancelFd)
		unix.Close(epollFd)
		return nil, err
	}

	p := &Probe{
		cpus:         cpus,
		hotplug:      hotplug,
		pmu:          pmu,
		tracefs:      tracefs,
		noRead:       opts.NoRead,
		instances:    make(map[configKey]*probeInstance),
		uprobes:      make(map[attachKey]*uprobe.Event),
		epollFd:      epollFd,
		cancelFd:     cancelFd,
		ringFd:       make(map[int]*uprobe.Ring),
		ringInstance: make(map[int]*probeInstance),
		events:       make(chan *probe.Event, cmp.Or(opts.BufferSize, probe.DefaultBufferSize)),
		done:         make(chan struct{}),
		fatalCh:      make(chan struct{}),
	}
	p.wg.Go(p.handleEvents)
	p.wg.Go(p.handleHotplug)
	return p, nil
}

// Close unloads all probes and stops all background goroutines.
func (p *Probe) Close() error {
	var errs []error
	p.closeOnce.Do(func() {
		close(p.done)

		// close hotplug netlink, wake goroutine
		if err := p.hotplug.Close(); err != nil {
			errs = append(errs, fmt.Errorf("hotplug: %w", err))
		}

		// wake event goroutine
		var one [8]byte
		binary.LittleEndian.PutUint64(one[:], 1)
		if _, err := unix.Write(p.cancelFd, one[:]); err != nil {
			errs = append(errs, fmt.Errorf("notify event goroutine: %w", err))
			// shouldn't happen, but don't wait so it doen't hang if it does
		} else {
			p.wg.Wait()
		}

		// close uprobes
		p.mu.Lock()
		defer p.mu.Unlock()

		for _, evt := range p.uprobes {
			if err := evt.Close(); err != nil {
				errs = append(errs, fmt.Errorf("uprobe: %w", err))
			}
		}
		for _, pi := range p.instances {
			if err := pi.Close(); err != nil {
				errs = append(errs, fmt.Errorf("bpf: %w", err))
			}
		}
		if err := unix.Close(p.cancelFd); err != nil {
			errs = append(errs, fmt.Errorf("cancel fd: %w", err))
		}
		if err := unix.Close(p.epollFd); err != nil {
			errs = append(errs, fmt.Errorf("epoll fd: %w", err))
		}
	})
	return errors.Join(errs...)
}

func (pi *probeInstance) Close() error {
	var errs []error
	if err := pi.prog.Close(); err != nil {
		errs = append(errs, fmt.Errorf("prog: %w", err))
	}
	if pi.config != nil {
		if err := pi.config.Close(); err != nil {
			errs = append(errs, fmt.Errorf("config: %w", err))
		}
	}
	if err := pi.events.Close(); err != nil {
		errs = append(errs, fmt.Errorf("events: %w", err))
	}
	for i, r := range pi.ring {
		if r != nil {
			if err := r.Close(); err != nil {
				errs = append(errs, fmt.Errorf("ring %d: %w", i, err))
			}
		}
	}
	return errors.Join(errs...)
}

// Err returns the fatal error for the probe, if any.
func (p *Probe) Err() error {
	select {
	case <-p.fatalCh:
		return p.fatalErr
	default:
		return nil
	}
}

func (p *Probe) fatal(err error) {
	p.fatalOnce.Do(func() {
		p.fatalErr = err
		close(p.fatalCh)
	})
}

func (p *Probe) Read() (e *probe.Event, dropped int, ok bool) {
	return p.read(nil)
}

func (p *Probe) Events(ctx context.Context) iter.Seq2[*probe.Event, int] {
	return func(yield func(*probe.Event, int) bool) {
		for {
			e, dropped, ok := p.read(ctx.Done())
			if !ok {
				return // fatal error or closed
			}
			if err := ctx.Err(); err != nil {
				return // interrupted
			}
			if !yield(e, dropped) {
				return // break
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
		// fatal error
	case <-p.done:
		// closed
	}
	// drain and notify dropped before returning ok=false
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

// Attach adds a uprobe for the specified file path and offsets if not already
// added.
func (p *Probe) Attach(path string, offset int64, s3, cr int) error {
	if offset < 0 {
		return fmt.Errorf("negative offset")
	}
	spec := attachSpec{
		path:   path,
		offset: uint64(offset),
		config: configKey{s3, cr},
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	pi, err := p.instanceLocked(spec.config)
	if err != nil {
		return err
	}

	if err := p.uprobeLocked(pi, spec); err != nil {
		return err
	}

	p.targets = append(p.targets, spec)
	return nil
}

// instanceLocked creates or returns a probeInstance with the specified config.
func (p *Probe) instanceLocked(cfg configKey) (*probeInstance, error) {
	if pi, ok := p.instances[cfg]; ok {
		return pi, nil // instance with the required config already exists, reuse it
	}

	elf := probeELF
	if p.noRead {
		elf = probeNoReadELF
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err != nil {
		return nil, fmt.Errorf("load bpf: parse elf: %w", err)
	}
	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelBranch,
		},
	})
	if err != nil {
		if ve, ok := errors.AsType[*ebpf.VerifierError](err); ok {
			return nil, fmt.Errorf("load bpf: collection: %w\nverifier log:\n%+v", err, ve)
		}
		return nil, fmt.Errorf("load bpf: collection: %w", err)
	}
	prog, ok := col.Programs["uprobe_ssl_log_secret"]
	if !ok {
		col.Close()
		return nil, fmt.Errorf("load bpf: missing program")
	}
	events, ok := col.Maps["events"]
	if !ok {
		col.Close()
		return nil, fmt.Errorf("load bpf: missing events")
	}

	var configMap *ebpf.Map
	if !p.noRead {
		configMap, ok = col.Maps["config_map"]
		if !ok {
			col.Close()
			return nil, fmt.Errorf("load bpf: missing map")
		}
		if err := configMap.Put(uint32(0), probeConfig{
			S3:           int64(cfg.s3),
			ClientRandom: int64(cfg.cr),
		}); err != nil {
			col.Close()
			return nil, fmt.Errorf("set config: %w", err)
		}
	}

	// detach from collection so Close doesn't close them
	delete(col.Programs, "uprobe_ssl_log_secret")
	delete(col.Maps, "config_map")
	delete(col.Maps, "events")
	col.Close()

	pi := &probeInstance{
		cfg:    cfg,
		prog:   prog,
		config: configMap, // nil in noRead mode
		events: events,
		ring:   make([]*uprobe.Ring, p.cpus),
	}
	p.instances[cfg] = pi

	for cpu := 0; cpu < p.cpus; cpu++ {
		if err := p.ringLocked(pi, cpu); err != nil {
			pi.Close()
			delete(p.instances, cfg)
			return nil, err
		}
	}
	return pi, nil
}

// ringLocked creates a ring buffer for the specified cpu on the specified probe
// instance if it doesn't already exist. If the cpu is offline, nothing is done.
func (p *Probe) ringLocked(pi *probeInstance, cpu int) error {
	if cpu < 0 || cpu >= len(pi.ring) || pi.ring[cpu] != nil {
		return nil
	}

	r, err := uprobe.OpenRing(cpu, 8)
	if errors.Is(err, unix.ENODEV) {
		return nil // cpu is offline (this ring will be created later on hotplug if needed)
	}
	if err != nil {
		return fmt.Errorf("open ring cpu %d: %w", cpu, err)
	}

	ringFD := r.Fd()
	if err := pi.events.Put(uint32(cpu), uint32(ringFD)); err != nil {
		r.Close()
		return fmt.Errorf("register ring cpu %d: %w", cpu, err)
	}
	if err := epollAdd(p.epollFd, ringFD); err != nil {
		r.Close()
		return err
	}
	pi.ring[cpu] = r
	p.ringFd[ringFD] = r
	p.ringInstance[ringFD] = pi

	return nil
}

// uprobeLocked creates a uprobe for the specified target if it doesn't already
// exist. A single event covers all CPUs: uprobe perf events do not enforce CPU
// pinning (they fire on whatever CPU executes the breakpoint), so creating one
// per CPU would invoke the BPF program N times per hit.
func (p *Probe) uprobeLocked(pi *probeInstance, spec attachSpec) error {
	k := attachKey{spec.path, spec.offset}

	if _, exists := p.uprobes[k]; exists {
		return nil // already attached
	}

	target := uprobe.Target{
		Path:   spec.path,
		Offset: spec.offset,
		PID:    -1,
		// pid=-1 requires cpu>=0, but the value doesn't matter since CPU
		// pinning doesn't affect uprobes (we still need the per-cpu buffers
		// though)
		CPU: 0,
	}
	var evt *uprobe.Event
	var err error
	if p.tracefs {
		evt, err = uprobe.OpenTracing("asslcapture", target)
	} else {
		evt, err = uprobe.Open(p.pmu, target)
	}
	if err != nil {
		return fmt.Errorf("open uprobe %s+%#x: %w", spec.path, spec.offset, err)
	}

	progFD := pi.prog.FD()
	if err := evt.SetBPF(progFD); err != nil {
		evt.Close()
		return fmt.Errorf("set bpf %s+%#x: %w", spec.path, spec.offset, err)
	}
	if err := evt.Enable(); err != nil {
		evt.Close()
		return fmt.Errorf("enable uprobe %s+%#x: %w", spec.path, spec.offset, err)
	}

	p.uprobes[k] = evt

	return nil
}

func (p *Probe) handleEvents() {
	events := make([]unix.EpollEvent, 16)
	for {
		n, err := unix.EpollWait(p.epollFd, events, -1)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			select {
			case <-p.done:
				// closing
			default:
				p.fatal(fmt.Errorf("poll perf events: %w", err))
			}
			return
		}
		for i := range n {
			fd := int(events[i].Fd)
			if fd == p.cancelFd {
				return
			}
			p.mu.Lock()
			ring, ok := p.ringFd[fd]
			pi := p.ringInstance[fd]
			p.mu.Unlock()
			if !ok {
				continue
			}
			for {
				data, lost, ok := ring.ReadRecord()
				if !ok {
					break // no more records
				}
				if lost > 0 {
					p.dropped.Add(1)
				}
				if data != nil {
					var out *probe.Event
					if p.noRead {
						var ev probeNoReadEvent
						if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &ev); err != nil {
							continue // TODO: warn?
						}
						var cfg configKey
						if pi != nil {
							cfg = pi.cfg
						}
						out = newNoreadEvent(&ev, cfg)
					} else {
						var ev probeEvent
						if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &ev); err != nil {
							continue // TODO: warn?
						}
						out = newEvent(&ev) // copies the data
					}
					select {
					case p.events <- out:
					default:
						p.dropped.Add(1)
					}
				}
			}
		}
	}
}

func (p *Probe) handleHotplug() {
	for {
		ev, err := p.hotplug.Read()
		if err != nil {
			select {
			case <-p.done:
				// closing
			default:
				p.fatal(fmt.Errorf("read hotplug event: %w", err))
			}
			return
		}
		func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			if ev.Online {
				for _, pi := range p.instances {
					if err := p.ringLocked(pi, ev.CPU); err != nil {
						p.fatal(fmt.Errorf("hotplug: handle %d online: create ring buffer: %w", ev.CPU, err))
						return
					}
				}
			}
		}()
	}
}

func epollAdd(epollFd, fd int) error {
	return unix.EpollCtl(epollFd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(fd),
	})
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

// monotonicTimeSince returns the elapsed time since bpfNs, a CLOCK_MONOTONIC
// timestamp captured by bpf_ktime_get_ns inside the probe.
func monotonicTimeSince(ns uint64) time.Duration {
	if ns == 0 {
		return 0
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	now := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	if now < ns {
		return 0
	}
	return time.Duration(now - ns)
}
