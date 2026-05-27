//go:build linux

package capture

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/pgaskin/asslcapture/internal/probe"
)

func AppendKeylogEvent(b []byte, event *probe.Event) []byte {
	if event != nil {
		if event.Error != nil {
			b = append(b, "# error: "...)
			if s := event.Error.Error(); strings.Contains(s, "\n") {
				b = strconv.AppendQuote(b, s)
			} else {
				b = append(b, s...)
			}
		} else {
			b = append(b, event.Label...)
			b = append(b, ' ')
			b = hex.AppendEncode(b, event.ClientRandom)
			b = append(b, ' ')
			b = hex.AppendEncode(b, event.Secret)
		}
		b = append(b, '\n')
	}
	return b
}

func AppendKeylogDroppedEvent(b []byte, dropped int) []byte {
	if dropped > 0 {
		b = fmt.Appendf(b, "# dropped %d events\n", dropped)
	}
	return b
}

// Keylog reads keylog messages from events and writes them to w in NSS keylog
// format until ctx is canceled or events is closed.
func Keylog(ctx context.Context, w io.Writer, p *probe.Probe, log *slog.Logger) error {
	bw := bufio.NewWriter(w)
	for event, dropped := range p.Events(ctx) {
		if dropped > 0 {
			log.Warn("dropped keylog events", "n", dropped)
		}
		if dropped > 0 {
			if _, err := bw.Write(AppendKeylogDroppedEvent(bw.AvailableBuffer(), dropped)); err != nil {
				return fmt.Errorf("write keylog: %w", err)
			}
		}
		if event != nil {
			if event.Error != nil {
				if event.Error != nil {
					log.Warn("probe error", "pid", event.PID, "delay", event.Delay, "error", event.Error)
				}
				if event.Delay > time.Millisecond*5 {
					log.Warn("slow probe event", "pid", event.PID, "delay", event.Delay)
				}
			}
			if _, err := bw.Write(AppendKeylogEvent(bw.AvailableBuffer(), event)); err != nil {
				return fmt.Errorf("write keylog: %w", err)
			}
		}
		if err := bw.Flush(); err != nil {
			return fmt.Errorf("write keylog: %w", err)
		}
	}
	// write errors are the most important
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("write keylog: %w", err)
	}
	// probe errors take priority over context errors since they're more useful
	if err := p.Err(); err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	// if no write or probe errors, return the context error, if any
	return ctx.Err()
}
