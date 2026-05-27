//go:build linux && arm64

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	_ "embed"
	"structs"
)

//go:embed probe_arm64.o
var probeELF []byte

//go:embed probe_noread_arm64.o
var probeNoReadELF []byte

const (
	probeLabelMax         = 64
	probeSecretMax        = 256
	probeClientRandomSize = 32
)

type probeConfig struct {
	_            structs.HostLayout
	S3           int64
	ClientRandom int64
}

type probeEvent struct {
	_         structs.HostLayout
	Timestamp uint64
	PID       uint32
	_         uint32

	DebugLine int64
	DebugRet  int64
	DebugPtr  int64

	Label        [probeLabelMax]int8
	ClientRandom [probeClientRandomSize]uint8
	Secret       [probeSecretMax]uint8
	SecretLen    int64
}

type probeNoReadEvent struct {
	_         structs.HostLayout
	Timestamp uint64
	PID       uint32
	_         uint32

	LabelPtr  uint64
	SecretPtr uint64
	SecretLen int64
	SSLPtr    uint64
}
