module github.com/pgaskin/asslcapture

go 1.26.1

tool github.com/cilium/ebpf/cmd/bpf2go

require (
	github.com/cilium/ebpf v0.21.1-0.20260513145500-dd3e0f047da2 // we need at least c0f90bb otherwise attaching to shared libs doesn't work
	github.com/ulikunitz/xz v0.5.15
	golang.org/x/arch v0.27.0
)

require golang.org/x/sys v0.43.0 // indirect
