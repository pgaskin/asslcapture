//go:build linux

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
	"github.com/pgaskin/asslcapture/internal/pflagx"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

var config = struct {
	Verbose bool `group:"general" short:"v" long:"verbose" doc:"enable debug output"`
	Help    bool `group:"general" short:"h" long:"help" doc:"show this help text"`

	IgnoreDbgInfo bool `group:"analysis" long:"ignore-dbginfo" doc:"ignore debug info, force full analysis"`

	Cache        string   `group:"scan" short:"c" long:"cache" metavar:"filename" doc:"save and load information about scanned libs to this file"`
	ScanLib      []string `group:"scan" short:"l" long:"scan-lib" metavar:"spec" doc:"scan a single elf file (/path/to/libssl.so), all libs in a zip file (/path/to/app.apk), or a specific lib in a zip file (/path/to/app.apk!/lib/arm64-v8a/libssl.so) (can be specified multiple times)"`
	ScanProcMaps bool     `group:"scan" long:"scan-proc-maps" doc:"scan /proc/*/maps"`
	ScanLibs     string   `group:"scan" long:"scan-libs" metavar:"dir" doc:"scan for libraries in a directory (using heuristics on the name)"`
	ScanLibsSys  bool     `group:"scan" long:"scan-libs-sys" doc:"scan for libraries in standard lib dirs"`
	ScanLibsApp  bool     `group:"scan" long:"scan-libs-app" doc:"scan for libraries in standard app dirs"`

	ProbeBuffer int  `group:"probe" long:"probe-buffer" doc:"number of uprobe events to buffer before dropping"`
	ProbeNoRead bool `group:"probe" long:"probe-noread" doc:"use process_vm_readv to read from userspace instead of bpf_probe_read_user (may work better on old kernels, but slightly racy)"`

	Capture              string        `group:"capture" short:"t" long:"capture" metavar:"mode" doc:"capture mode (if not specified, only scans then exits) (keylog, pcapng)"`
	CaptureOutput        string        `group:"capture" short:"o" long:"capture-output" metavar:"filename" doc:"output filename (default stdout)"`
	CaptureFilter        string        `group:"capture" short:"f" long:"capture-filter" metavar:"str" doc:"tcpdump-style capture filter (does not affect keylog)"`
	CaptureInterface     string        `group:"capture" short:"i" long:"capture-interface" metavar:"str" doc:"interface name to capture packets from (does not affect keylog)"`
	CaptureBufferDelay   time.Duration `group:"capture" long:"capture-buffer-delay" doc:"delay packets by this amount of time to give time for keys to be logged first (does not affect keylog)"`
	CaptureBufferPktSize int           `group:"capture" long:"capture-buffer-pktsize" doc:"size for pre-allocated packet buffers (oversized will be significantly less efficient) (does not affect keylog)"`
	CaptureBufferSize    int           `group:"capture" long:"capture-buffer-size" doc:"number of packets to buffer (will start flushing packets before --capture-buffer-delay when this gets half full) (default: automatic) (does not affect keylog)"`
}{
	CaptureInterface: "any",
}

var flags *pflag.FlagSet

func init() {
	flags = pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.SortFlags = false
	flags.Usage = func() {
		pflagx.PrintHelp(flags)
	}
	pflagx.RegisterFlags(flags, &config)
}

func main() {
	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v (see --help)\n", err)
		os.Exit(2)
	}
	if config.Help || flags.NArg() != 0 {
		flags.Usage()
		if !config.Help {
			os.Exit(2)
		}
		os.Exit(0)
	}

	level := slog.LevelInfo
	if config.Verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(tint.NewHandler(os.Stderr, &tint.Options{
		Level:   level,
		NoColor: !term.IsTerminal(int(os.Stderr.Fd())),
	})))

	// TODO
}
