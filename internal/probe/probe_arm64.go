//go:build linux && arm64

package probe

import (
	_ "embed"
	"structs"
)

//go:embed probe_arm64.o
var probeELF []byte

type probeConfig struct {
	_            structs.HostLayout
	S3           int64
	ClientRandom int64
}

type probeEvent struct {
	_            structs.HostLayout
	DebugLine    int64
	DebugRet     int64
	DebugPtr     int64
	Label        [64]int8
	ClientRandom [32]uint8
	Secret       [256]uint8
	SecretLen    int64
}
