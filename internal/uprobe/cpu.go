//go:build linux

package uprobe

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// some relevant links:
//	- https://lore.kernel.org/bpf/ef0f23d0-456a-70b0-1ef9-2615a5528278@iogearbox.net/
//	- https://github.com/bpftrace/bpftrace/issues/3125

// PossibleCPUs returns the number of possible CPUs (max index + 1).
func PossibleCPUs() (int, error) {
	data, err := os.ReadFile(filepath.Join(SysFS, "devices/system/cpu/possible"))
	if err != nil {
		return 0, err
	}
	cpus, err := parseCPUs(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	if len(cpus) == 0 {
		return 0, nil
	}
	max := cpus[0]
	for _, c := range cpus[1:] {
		if c > max {
			max = c
		}
	}
	return max + 1, nil
}

// OnlineCPUs returns the indices of all currently online CPUs.
func OnlineCPUs() ([]int, error) {
	data, err := os.ReadFile(filepath.Join(SysFS, "devices/system/cpu/online"))
	if err != nil {
		return nil, err
	}
	return parseCPUs(strings.TrimSpace(string(data)))
}

// CPUHotplugEvent is a CPU online/offline notification from the kernel.
type CPUHotplugEvent struct {
	CPU    int
	Online bool
}

// CPUHotplug reads CPU hotplug events using netlink.
type CPUHotplug struct {
	f   *os.File
	buf []byte
}

// OpenHotplug binds to a NETLINK_KOBJECT_UEVENT netlink socket.
func OpenHotplug() (*CPUHotplug, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_KOBJECT_UEVENT)
	if err != nil {
		return nil, fmt.Errorf("hotplug socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("hotplug bind: %w", err)
	}
	return &CPUHotplug{
		f:   os.NewFile(uintptr(fd), "netlink uevent"),
		buf: make([]byte, 4096),
	}, nil
}

func (h *CPUHotplug) Close() error {
	return h.f.Close()
}

// Read blocks until a CPU hotplug event arrives or the socket is closed.
func (h *CPUHotplug) Read() (CPUHotplugEvent, error) {
	for {
		n, err := h.f.Read(h.buf)
		if err != nil {
			return CPUHotplugEvent{}, err
		}
		if action, cpu, ok := parseCPUEvent(string(h.buf[:n])); ok {
			switch action {
			case "online":
				return CPUHotplugEvent{CPU: cpu, Online: true}, nil
			case "offline":
				return CPUHotplugEvent{CPU: cpu, Online: false}, nil
			}
		}
	}
}

// parseCPUEvent parses a NETLINK_KOBJECT_UEVENT message for a CPU hotplug.
func parseCPUEvent(msg string) (action string, cpu int, ok bool) {
	if strings.HasPrefix(msg, "libudev\x00") {
		return "", 0, false
	}
	tmp, msg, ok := strings.Cut(msg, "\x00")
	if !ok {
		return "", 0, false
	}
	act, devpath, ok := strings.Cut(tmp, "@")
	if !ok {
		return "", 0, false
	}
	var subsystem string
	for kv := range strings.SplitSeq(msg, "\x00") {
		switch k, v, _ := strings.Cut(kv, "="); k {
		case "SUBSYSTEM":
			subsystem = v
		}
	}
	if subsystem != "cpu" {
		return "", 0, false
	}
	base, ok := strings.CutPrefix(devpath[strings.LastIndexByte(devpath, '/')+1:], "cpu")
	if !ok {
		return "", 0, false
	}
	n, err := strconv.Atoi(base)
	if err != nil || n < 0 {
		return "", 0, false
	}
	return act, n, true
}

// parseCPUs parses a list of indexes or ranges.
func parseCPUs(s string) ([]int, error) {
	var cpus []int
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			loN, err1 := strconv.Atoi(lo)
			hiN, err2 := strconv.Atoi(hi)
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			for c := loN; c <= hiN; c++ {
				cpus = append(cpus, c)
			}
		} else {
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid item %q", part)
			}
			cpus = append(cpus, n)
		}
	}
	return cpus, nil
}
