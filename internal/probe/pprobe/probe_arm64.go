//go:build linux && arm64

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package pprobe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/pgaskin/asslcapture/internal/probe"
	phook "github.com/pgaskin/asslcapture/internal/probe/pprobe/internal"
)

const (
	secretMax        = 256
	labelMax         = 64
	clientRandomSize = 32
)

func newEvent(stop *phook.Breakpoint, s3, cr int) *probe.Event {
	start := time.Now()

	var (
		sslPtr    = stop.Regs.Regs[0]
		labelPtr  = stop.Regs.Regs[1]
		secretPtr = stop.Regs.Regs[2]
		secretLen = int64(stop.Regs.Regs[3])
	)
	if secretLen < 0 || secretLen > secretMax {
		secretLen = secretMax
	}

	secret := make([]byte, secretLen)
	if secretLen > 0 {
		if err := procVMRead(stop.PID, untag(secretPtr), secret); err != nil {
			return &probe.Event{PID: stop.PID, Error: fmt.Errorf("read secret: %w", err), Delay: time.Since(start)}
		}
	}

	s3PtrBuf := make([]byte, 8)
	if err := procVMRead(stop.PID, untag(sslPtr)+uint64(s3), s3PtrBuf); err != nil {
		return &probe.Event{PID: stop.PID, Error: fmt.Errorf("read s3 ptr: %w", err), Delay: time.Since(start)}
	}
	s3Ptr := binary.LittleEndian.Uint64(s3PtrBuf)

	clientRandom := make([]byte, clientRandomSize)
	if err := procVMRead(stop.PID, untag(s3Ptr)+uint64(cr), clientRandom); err != nil {
		return &probe.Event{PID: stop.PID, Error: fmt.Errorf("read client_random: %w", err), Delay: time.Since(start)}
	}

	labelBuf := make([]byte, labelMax)
	if err := procVMRead(stop.PID, labelPtr, labelBuf); err != nil {
		return &probe.Event{PID: stop.PID, Error: fmt.Errorf("read label: %w", err), Delay: time.Since(start)}
	}
	if i := bytes.IndexByte(labelBuf, 0); i >= 0 {
		labelBuf = labelBuf[:i]
	}

	return &probe.Event{
		PID:          stop.PID,
		Label:        string(labelBuf),
		ClientRandom: clientRandom,
		Secret:       secret,
		Delay:        time.Since(start),
	}
}

func untag(p uint64) uint64 {
	return p &^ (uint64(0xFF) << 56)
}
