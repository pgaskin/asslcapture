// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Package probe contains an ARM64 uprobe for capturing the BoringSSL keylog.
//
// TODO: armv7 support
package probe

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pgaskin/asslcapture/internal/analyze"
)

//go:generate go tool bpf2go -tags linux -target arm64 probe probe.c

// cat /proc/*/maps | grep -e libssl -e libconscrypt -e libchrome -e cronet | grep -oE '/.+' | sort -u
// TODO: watch processes and scan for libs

// TODO: refactor this into a proper wrapper
func TODO(lib string) {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	var objs probeObjects
	if err := loadProbeObjects(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()

	ef, err := elf.Open(lib)
	if err != nil {
		panic(err)
	}
	defer ef.Close()

	off, _, err := analyze.LogSecret(ef)
	if err != nil {
		panic(err)
	}

	s3, cr, err := analyze.ClientRandom(ef, off)
	if err != nil {
		panic(err)
	}

	ex, err := link.OpenExecutable(lib)
	if err != nil {
		panic(err)
	}

	up, err := ex.Uprobe("ssl_log_secret", objs.UprobeSslLogSecret, &link.UprobeOptions{
		Address: off, // this is a file offset, not a virtual address
		Offset:  0,
		PID:     -1,
	})
	if err != nil {
		panic(err)
	}
	defer up.Close()

	if err := objs.ConfigMap.Put(uint32(0), probeConfig{
		S3:           int64(s3),
		ClientRandom: int64(cr),
	}); err != nil {
		panic(err)
	}

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			_ = err
		}
	}()

	fmt.Fprintln(os.Stderr, lib, off, s3, cr)

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			panic(err)
		}

		if record.LostSamples != 0 {
			fmt.Printf("dropped %d\n", record.LostSamples)
			continue
		}

		var event probeEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			_ = err
			continue
		}

		label := make([]byte, len(event.Label))
		for i, c := range event.Label {
			if c == 0 {
				label = label[:i]
				break
			}
			label[i] = byte(c)
		}
		//fmt.Printf("%d %d %#x\n", event.DebugLine, event.DebugRet, event.DebugPtr)
		fmt.Printf("%s %x %x\n", label, event.ClientRandom, event.Secret[:event.SecretLen])
	}
}
