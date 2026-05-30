package probe

import (
	"context"
	"iter"
	"time"
)

const DefaultBufferSize = 64

type Probe interface {
	// Close stops the probe and cleans up any resources.
	Close() error

	// Attach attaches the probe to the specified library and offsets.
	Attach(path string, offset int64, s3, cr int) error

	// Read blocks until an event is available or dropped events are detected,
	// returning false if the probe is closed or a fatal error occurs. It must
	// not be used at the same time as Events.
	Read() (e *Event, dropped int, ok bool)

	// Events yields events and the number dropped events preceding it, until
	// ctx is cancelled, the probe is closed, or a fatal error occurs (after
	// which Err will be non-nil). Only one iterator may be used at a time. The
	// event may be nil if there are dropped events, but no new event.
	Events(ctx context.Context) iter.Seq2[*Event, int]

	// Err returns the fatal error from the probe, if any.
	Err() error
}

// Event is a decoded keylog event from the BPF program.
type Event struct {
	Delay        time.Duration // time from uprobe start to end of processing
	PID          int
	Error        error
	Label        string
	ClientRandom []byte
	Secret       []byte
}
