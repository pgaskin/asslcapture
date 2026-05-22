//go:build linux

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Package probe manages the uprobe for reading boringssl secrets.
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
package probe

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/pgaskin/asslcapture/internal/uprobe"
)

//go:generate go run build.go

// note: if there's a bug in cpu handling, ssl stuff done on that cpu won't be
// handled (test this by enabling tracing, then using taskset on the test ssl
// client)

// Event is a decoded keylog event from the BPF program.
type Event struct {
	Error        error
	Label        string
	ClientRandom []byte
	Secret       []byte
}

func newEvent(e *probeEvent) *Event {
	if e.DebugLine != -1 {
		return &Event{
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
	return &Event{
		Label:        string(label),
		ClientRandom: slices.Clone(e.ClientRandom[:]),
		Secret:       slices.Clone(e.Secret[:min(len(e.Secret), int(e.SecretLen))]),
	}
}

// String formats the event as a sslkeylog line.
func (e *Event) String() string {
	var b []byte
	if e.Error != nil {
		b = append(b, "# error: "...)
		if s := e.Error.Error(); strings.Contains(s, "\n") {
			b = strconv.AppendQuote(b, s)
		} else {
			b = append(b, s...)
		}
	} else {
		b = append(b, e.Label...)
		b = append(b, ' ')
		b = hex.AppendEncode(b, e.ClientRandom)
		b = append(b, ' ')
		b = hex.AppendEncode(b, e.Secret)
	}
	return string(b)
}

// Options configures a Probe.
type Options struct {
	// BufferSize is the number of events to buffer before dropping them.
	BufferSize int
}

// Probe manages the uprobes to capture BoringSSL secrets. All methods are
// goroutine-safe.
type Probe struct {
	pmu     uint32
	cpus    int // number of possible CPUs
	hotplug *uprobe.CPUHotplug

	mu sync.Mutex
	wg sync.WaitGroup // workers

	closeOnce sync.Once
	done      chan struct{} // when close called

	events  chan *Event
	dropped atomic.Int64

	instances map[configKey]*probeInstance // loaded bpf programs for each probe config
	targets   []attachSpec                 // current uprobe targets (for hotplug)
	uprobes   map[attachKey]*uprobe.Event  // per-cpu uprobe perf event buffers

	epollFd  int // for ring buffers
	cancelFd int // eventfd to wake epoll
	ringFd   map[int]*uprobe.Ring

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
	prog   *ebpf.Program
	config *ebpf.Map
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
	if err != nil {
		return nil, err
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
		cpus:      cpus,
		hotplug:   hotplug,
		pmu:       pmu,
		instances: make(map[configKey]*probeInstance),
		uprobes:   make(map[attachKey]*uprobe.Event),
		epollFd:   epollFd,
		cancelFd:  cancelFd,
		ringFd:    make(map[int]*uprobe.Ring),
		events:    make(chan *Event, cmp.Or(opts.BufferSize, 64)),
		done:      make(chan struct{}),
		fatalCh:   make(chan struct{}),
	}
	p.wg.Add(2)
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
	if err := pi.config.Close(); err != nil {
		errs = append(errs, fmt.Errorf("config: %w", err))
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

func (p *Probe) fatal(err error) {
	p.fatalOnce.Do(func() {
		p.fatalErr = err
		close(p.fatalCh)
	})
}

// Read returns the next keylog event, blocking until it is available, the probe
// is closed, or a fatal error occurs. The number of dropped events since the
// last call, if any, is returned.
func (p *Probe) Read() (e *Event, dropped int, err error) {
	defer func() {
		dropped = int(p.dropped.Load())
		p.dropped.Add(-int64(dropped))
	}()
	select {
	case <-p.fatalCh:
		return nil, dropped, p.fatalErr
	default:
	}
	select {
	case e = <-p.events:
		return e, dropped, nil
	case <-p.fatalCh:
		return nil, dropped, p.fatalErr
	case <-p.done:
		select {
		case ev := <-p.events: // drain first
			return ev, dropped, nil
		default:
		}
		return nil, dropped, os.ErrClosed
	}
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

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(probeELF))
	if err != nil {
		return nil, fmt.Errorf("load bpf: parse elf: %w", err)
	}
	col, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load bpf: collection: %w", err)
	}
	prog, ok := col.Programs["uprobe_ssl_log_secret"]
	if !ok {
		col.Close()
		return nil, fmt.Errorf("load bpf: missing program")
	}
	config, ok := col.Maps["config_map"]
	if !ok {
		col.Close()
		return nil, fmt.Errorf("load bpf: missing map")
	}
	events, ok := col.Maps["events"]
	if !ok {
		col.Close()
		return nil, fmt.Errorf("load bpf: missing events")
	}
	if err := config.Put(uint32(0), probeConfig{
		S3:           int64(cfg.s3),
		ClientRandom: int64(cfg.cr),
	}); err != nil {
		col.Close()
		return nil, fmt.Errorf("set config: %w", err)
	}

	// detach from collection so Close doesn't close them
	delete(col.Programs, "uprobe_ssl_log_secret")
	delete(col.Maps, "config_map")
	delete(col.Maps, "events")
	col.Close()

	pi := &probeInstance{
		prog:   prog,
		config: config,
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

// instanceLocked creates a ring buffer for the specified cpu on the specified
// probe instance if it doesn't already exist. If the cpu is offline, nothing is
// done.
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

	evt, err := uprobe.Open(p.pmu, uprobe.Target{
		Path:   spec.path,
		Offset: spec.offset,
		PID:    -1,
		// pid=-1 requires cpu>=0, but the value doesn't matter since CPU
		// pinning doesn't affect uprobes (we still need the per-cpu buffers
		// though)
		CPU: 0,
	})
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
					var ev probeEvent
					if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &ev); err != nil {
						continue // TODO: warn?
					}
					out := newEvent(&ev) // copies the data
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
