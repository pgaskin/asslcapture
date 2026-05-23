//go:build linux

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package capture

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/pgaskin/asslcapture/internal/probe"
	"github.com/pgaskin/go-pcapfilter"
	"golang.org/x/net/bpf"
)

// Options configures a PcapNG capture.
type Options struct {
	// Interface name to capture packets from. If empty or "any", packets from
	// all interfaces are captured (this uses ifindex=0 internally, so it
	// continues to work even as interfaces are added or removed).
	Interface string

	// Filter is a tcpdump-syntax capture filter expression. If empty, no filter
	// is applied.
	Filter string

	// Delay is the amount of time to delay writing packets to the pcap to give
	// time for secrets to be written first (since pcapng requires them to be
	// written before they are first used). If zero, a default value is used.
	Delay time.Duration

	// PacketSize is the size of the pre-allocated byte slices for buffered
	// packets. Packets larger than this are allocated on the heap per-packet.
	// If zero, defaults to a value suitable for standard Ethernet MTU.
	PacketSize int

	// Buffer is the maximum number of packets to buffer. To avoid unnecessarily
	// dropping packets during sudden bursts, packets start being flushed after
	// the buffer is half full even if it's before Delay. If zero, a default
	// value is used.
	Buffer int
}

const (
	defaultDelay      = time.Millisecond * 25 // should be more than enough without being too much
	defaultPacketSize = 1518                  // standard ethernet frame size
)

// AutoBufferSize automatically configures buffer parameters for:
//
//   - delaying writing packets by delay
//   - packets which are usually at or a bit under packetSize
//   - being able to handle traffic of full-sized packets at the specified bitrate with the configured delay
//   - being able to handle traffic at the specified pps with the configured delay
//   - while not filling more than half the buffer with the aforementioned conditions (so we aren't forced to flush prematurely)
//
// It returns the amount of memory which will be allocated for packet data in bytes.
func (o *Options) AutoBufferSize(delay time.Duration, packetSize, peakBitsPerSecond, peakPacketsPerSecond int) int {
	o.Delay = max(1, cmp.Or(delay, defaultDelay))
	o.PacketSize = max(1, cmp.Or(packetSize, defaultPacketSize))
	o.Buffer = computeBufferSize(o.Delay, o.PacketSize, peakBitsPerSecond, peakPacketsPerSecond)
	return o.Buffer * (o.PacketSize + 1) // slab size
}

func computeBufferSize(delay time.Duration, packetSize, peakBitsPerSecond, peakPacketsPerSecond int) int {
	ceildiv := func(a, b int64) int64 {
		return (a + b - 1) / b
	}

	// packets arriving during delay at peak bitrate (full-sized packets)
	var fromBitrate int64
	if peakBitsPerSecond > 0 {
		bitsPerPacket := int64(packetSize) * 8
		fromBitrate = ceildiv(int64(peakBitsPerSecond)*int64(delay), bitsPerPacket*int64(time.Second))
	}

	// packets arriving during delay at peak packet rate
	var fromPPS int64
	if peakPacketsPerSecond > 0 {
		fromPPS = ceildiv(int64(peakPacketsPerSecond)*int64(delay), int64(time.Second))
	}

	// double so peak load fits in the first half without causing early flushes,
	// and leaving room for bursts
	return int(max(fromBitrate, fromPPS)) * 2
}

// PcapNG captures packets from the configured interface, writes them to w in
// pcapng format, and interleaves TLS keylog secrets from events. Runs until ctx
// is canceled, events is closed, or a fatal error occurs. On cancellation,
// buffered packets are flushed before returning. Drop warnings are logged via log.
func PcapNG(ctx context.Context, w io.Writer, p *probe.Probe, log *slog.Logger, opt *Options) error {
	if opt == nil {
		opt = new(Options)
	} else {
		opt = new(*opt)
	}
	if opt.Delay <= 0 {
		opt.Delay = defaultDelay
	}
	if opt.PacketSize <= 0 {
		opt.PacketSize = defaultPacketSize
	}
	if opt.Buffer <= 0 {
		opt.Buffer = computeBufferSize(opt.Delay, opt.PacketSize, 2_500_000_000, 5000) // 2.5 gbit/s, 5k pps
	}
	if opt.Interface == "" {
		opt.Interface = "any"
	}

	var topt []any
	if opt.Interface != "any" {
		topt = append(topt, afpacket.OptInterface(opt.Interface))
	}

	// open the capture socket
	handle, err := afpacket.NewTPacket(topt...)
	if err != nil {
		return fmt.Errorf("open afpacket socket: %w", err)
	}

	// apply the capture filter
	if opt.Filter != "" {
		prog, err := pcapfilter.Compile(opt.Filter, nil)
		if err != nil {
			return fmt.Errorf("compile filter: %w", err)
		}
		if err := handle.SetBPF(toBPF(prog.Instructions())); err != nil {
			return fmt.Errorf("set filter: %w", err)
		}
	}

	// open the pcapng writer
	ngw, err := pcapgo.NewNgWriterInterface(w, pcapgo.NgInterface{
		Name:                opt.Interface,
		LinkType:            layers.LinkTypeEthernet,
		TimestampResolution: 9,
		SnapLength:          65535,
	}, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		return fmt.Errorf("write pcapng: %w", err)
	}

	// stop closes the afpacket socket (unblocking read) for an intentional shutdown
	shutdownCtx, shutdown := context.WithCancel(context.Background())
	stop := func() {
		shutdown()
		handle.Close()
	}
	defer stop()
	defer context.AfterFunc(ctx, stop)()

	// read keylog messages
	type keylogMsg struct {
		event   *probe.Event
		dropped int
	}
	var (
		keylogCh = make(chan keylogMsg)
	)
	go func() {
		defer close(keylogCh)
		for event, dropped := range p.Events(ctx) {
			select {
			case keylogCh <- keylogMsg{event, dropped}:
			case <-shutdownCtx.Done():
				return
			}
		}
		if p.Err() != nil {
			stop() // probe error, treat as fatal
		}
	}()

	// pre-allocate packet buffers so put pressure on the gc
	slab := newSlabPool(opt.Buffer, opt.PacketSize)

	// read packets
	type capPkt struct {
		ci   gopacket.CaptureInfo
		data []byte
	}
	var (
		pktCh     = make(chan capPkt, 8)
		capDoneCh = make(chan error, 1)
	)
	go func() (capErr error) {
		defer func() {
			capDoneCh <- capErr
			close(pktCh)
		}()
		for {
			raw, ci, err := handle.ZeroCopyReadPacketData()
			if err != nil {
				if shutdownCtx.Err() != nil {
					return nil
				}
				return err // fatal
			}
			data := slab.alloc(len(raw))
			copy(data, raw)
			select {
			case pktCh <- capPkt{ci: ci, data: data}:
			case <-shutdownCtx.Done():
				slab.release(data)
				return nil
			}
		}
	}()

	// warn about dropped packets
	go func() {
		logDrops := func() {
			if _, s, err := handle.SocketStats(); err == nil && s.Drops() > 0 {
				log.Warn("dropped packets", "n", s.Drops())
			}
		}
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				logDrops()
			case <-shutdownCtx.Done():
				logDrops()
				return
			}
		}
	}()

	// buffer pktCh to delay by opt.Delay (up to half the buffer size of packets)
	type readyPkt struct {
		ci          gopacket.CaptureInfo
		data        []byte
		release     func()
		dropped     int
		lastInBatch bool
	}
	var (
		readyCh = make(chan readyPkt)
	)
	go func() {
		defer close(readyCh)

		type entry struct {
			ci       gopacket.CaptureInfo
			data     []byte
			deadline time.Time
		}
		var (
			entries = make([]entry, opt.Buffer)
			head    int
			count   int
			dropped int
			timer   *time.Timer
			timerCh <-chan time.Time
		)

		scheduleTimer := func() {
			if count == 0 {
				if timer != nil {
					timer.Stop()
					timer = nil
					timerCh = nil
				}
				return
			}
			remaining := max(time.Until(entries[head].deadline), 0)
			if timer == nil {
				timer = time.NewTimer(remaining)
				timerCh = timer.C
			} else {
				timer.Stop()
				timer.Reset(remaining)
			}
		}

		// sendDue flushes due entries (or all if flushAll) to readyCh,
		// returning false if shutdownCtx was cancelled
		sendDue := func(flushAll bool) bool {
			size := len(entries)
			now := time.Now()
			for count > 0 && (flushAll || !now.Before(entries[head].deadline) || count > size/2) {
				e := entries[head]
				entries[head] = entry{}
				head = (head + 1) % size
				count--
				d := dropped
				dropped = 0
				last := count == 0 || (!flushAll && now.Before(entries[head].deadline) && count <= size/2)
				data := e.data
				select {
				case readyCh <- readyPkt{ci: e.ci, data: data, release: func() { slab.release(data) }, dropped: d, lastInBatch: last}:
				case <-shutdownCtx.Done():
					slab.release(data)
					for count > 0 {
						slab.release(entries[head].data)
						entries[head] = entry{}
						head = (head + 1) % size
						count--
					}
					return false
				}
			}
			return true
		}

		for {
			select {
			case pkt, ok := <-pktCh:
				if !ok {
					sendDue(true)
					return
				}
				if count == len(entries) {
					slab.release(entries[head].data)
					entries[head] = entry{}
					head = (head + 1) % len(entries)
					count--
					dropped++
				}
				entries[(head+count)%len(entries)] = entry{
					ci:       pkt.ci,
					data:     pkt.data,
					deadline: time.Now().Add(opt.Delay),
				}
				count++
				if !sendDue(false) {
					return
				}
				scheduleTimer()
			case <-timerCh:
				if !sendDue(false) {
					return
				}
				scheduleTimer()
			case <-shutdownCtx.Done():
				for count > 0 {
					slab.release(entries[head].data)
					entries[head] = entry{}
					head = (head + 1) % len(entries)
					count--
				}
				return
			}
		}
	}()

	// write packets and secrets to the pcap
	for readyCh != nil || keylogCh != nil {
		select {
		case msg, ok := <-keylogCh:
			if !ok {
				keylogCh = nil
			} else {
				if msg.dropped > 0 {
					log.Warn("dropped keylog events", "n", msg.dropped)
				}
				var data []byte
				data = AppendKeylogDroppedEvent(data, msg.dropped)
				data = AppendKeylogEvent(data, msg.event)
				if len(data) > 0 {
					if err := ngw.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, data); err != nil {
						return fmt.Errorf("write pcapng: %w", err)
					}
				}
			}
		case pkt, ok := <-readyCh:
			if !ok {
				readyCh = nil
				continue
			}
			if pkt.dropped > 0 {
				log.Warn("dropped buffered packets", "n", pkt.dropped)
			}
			pkt.ci.InterfaceIndex = 0
			err := ngw.WritePacket(pkt.ci, pkt.data)
			pkt.release()
			if err != nil {
				return fmt.Errorf("write pcapng: %w", err)
			}
			if pkt.lastInBatch {
				if err := ngw.Flush(); err != nil {
					return fmt.Errorf("write pcapng: %w", err)
				}
			}
		}
	}
	// write errors are the most important
	if err := ngw.Flush(); err != nil {
		return fmt.Errorf("write pcapng: %w", err)
	}
	// capture errors are the next most important
	if err := <-capDoneCh; err != nil {
		return err
	}
	// then probe errors
	if err := p.Err(); err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	// if no write/probe/capture errors, return the context error, if any
	return ctx.Err()
}

type slabPool struct {
	pool chan []byte
	size int
	slab []byte
}

func newSlabPool(n, size int) *slabPool {
	size = max(size, 1)
	slab := make([]byte, n*(size+1))
	pool := make(chan []byte, n)
	for i := range n {
		base := i * (size + 1)
		slab[base+size] = 0xFF
		pool <- slab[base : base : base+size+1]
	}
	return &slabPool{pool: pool, size: size, slab: slab}
}

func (s *slabPool) ours(data []byte) bool {
	if cap(data) != s.size+1 {
		return false
	}
	ptr := uintptr(unsafe.Pointer(unsafe.SliceData(data[:cap(data)])))
	start := uintptr(unsafe.Pointer(unsafe.SliceData(s.slab)))
	return ptr >= start && ptr < start+uintptr(len(s.slab))
}

func (s *slabPool) alloc(n int) []byte {
	if n <= s.size {
		select {
		case slot := <-s.pool:
			slot[:s.size+1][s.size] = 0
			return slot[:n]
		default:
		}
	}
	return make([]byte, n)
}

func (s *slabPool) release(data []byte) {
	if !s.ours(data) {
		return
	}
	extra := &data[:s.size+1][s.size]
	if *extra == 0xFF {
		panic("slab double free")
	}
	*extra = 0xFF
	s.pool <- data[: 0 : s.size+1]
}

func toBPF(raw []pcapfilter.RawInstruction) []bpf.RawInstruction {
	return unsafe.Slice((*bpf.RawInstruction)(unsafe.SliceData(raw)), len(raw))
}
