//go:build linux

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Command asslcapture captures system-wide Conscrypt/BoringSSL TLS traffic on
// Android using eBPF.
//
// This is a non-intrusive alternative to injecting root certs and generally
// works more reliably, but requires root and a modern kernel.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/lmittmann/tint"
	"github.com/pgaskin/asslcapture/internal/capture"
	"github.com/pgaskin/asslcapture/internal/pflagx"
	"github.com/pgaskin/asslcapture/internal/probe"
	"github.com/pgaskin/asslcapture/internal/scanner"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

var config = struct {
	Verbose bool `group:"general" short:"v" long:"verbose" doc:"enable debug output"`
	Help    bool `group:"general" short:"h" long:"help" doc:"show this help text"`
	ExitEOF bool `group:"general" long:"exit-eof" doc:"exit cleanly when eof received on stdin (useful if running directly with shell_v2 since it can send eof, but not signals)"`

	IgnoreDbgInfo bool `group:"analysis" short:"D" long:"ignore-dbginfo" doc:"ignore debug info, force full analysis"`

	Cache   string   `group:"scan" short:"c" long:"cache" metavar:"filename" doc:"save and load information about scanned libs to this file"`
	Scan    bool     `group:"scan" short:"s" long:"scan" doc:"alias for a sensible combination of scan options (currently --scan-libs-sys --scan-libs-app)"`
	ScanLib []string `group:"scan" short:"l" long:"scan-lib" metavar:"spec" doc:"scan a single elf file (/path/to/libssl.so), all libs in a zip file (/path/to/app.apk), or a specific lib in a zip file (/path/to/app.apk!/lib/arm64-v8a/libssl.so) (can be specified multiple times)"` // TODO: glob support?
	// TODO: ScanProcMaps bool `group:"scan" long:"scan-proc-maps" doc:"scan /proc/*/maps"`
	ScanLibs    []string `group:"scan" long:"scan-libs" metavar:"dir" doc:"scan for libraries in a directory (using heuristics on the name) (can be specified multiple times)"`
	ScanLibsSys bool     `group:"scan" long:"scan-libs-sys" doc:"scan for libraries in standard lib dirs"`
	ScanLibsApp bool     `group:"scan" long:"scan-libs-app" doc:"scan for libraries in standard app dirs"`
	ScanWorkers int      `group:"scan" long:"scan-workers" doc:"number of concurrent analyses to run (default: GOMAXPROCS)"`

	ProbeBuffer int  `group:"probe" long:"probe-buffer" doc:"number of uprobe events to buffer before dropping"`
	ProbeNoRead bool `group:"probe" short:"R" long:"probe-noread" doc:"use process_vm_readv to read from userspace instead of bpf_probe_read_user (may work better on old kernels, but slightly racy)"`

	Capture              string        `group:"capture" short:"m" long:"capture" metavar:"mode" doc:"capture mode (if not specified, only scans then exits) (keylog, pcapng)"`
	CaptureOutput        string        `group:"capture" short:"o" long:"capture-output" metavar:"filename" doc:"output filename (default stdout)"`
	CaptureFilter        string        `group:"capture" short:"f" long:"capture-filter" metavar:"str" doc:"tcpdump-style capture filter (does not affect keylog)"`
	CaptureInterface     string        `group:"capture" short:"i" long:"capture-interface" metavar:"str" doc:"interface name to capture packets from (does not affect keylog)"`
	CaptureBufferDelay   time.Duration `group:"capture" long:"capture-buffer-delay" doc:"delay packets by this amount of time to give time for keys to be logged first (does not affect keylog)"`
	CaptureBufferPktSize int           `group:"capture" long:"capture-buffer-pktsize" doc:"size for pre-allocated packet buffers (oversized will be significantly less efficient) (does not affect keylog)"`
	CaptureBufferSize    int           `group:"capture" long:"capture-buffer-size" doc:"number of packets to buffer (will start flushing packets before --capture-buffer-delay when this gets half full) (default: automatic) (does not affect keylog)"`
}{
	ScanWorkers: runtime.GOMAXPROCS(-1),

	ProbeBuffer: probe.DefaultBufferSize,

	CaptureInterface:     "any",
	CaptureBufferDelay:   capture.DefaultDelay,
	CaptureBufferPktSize: capture.DefaultPacketSize,
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

	if config.ScanWorkers < 1 {
		config.ScanWorkers = 1
	}
	if config.ScanWorkers > runtime.GOMAXPROCS(-1) {
		runtime.GOMAXPROCS(config.ScanWorkers)
	}
	if config.Scan {
		config.ScanLibsApp = true
		config.ScanLibsSys = true
	}

	switch config.Capture {
	case "", "keylog", "pcapng":
	default:
		slog.Error("unknown capture mode", "mode", config.Capture)
		os.Exit(2)
	}

	if config.CaptureOutput == "" {
		config.CaptureOutput = "-"
	}

	if config.ProbeNoRead {
		// TODO: can we avoid this by also adding a syscall probe or something like that?
		slog.Warn("using noread probe, secret reading will be racy and may drop or return incorrect secrets")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if config.ExitEOF {
		go func() {
			if _, err := io.Copy(io.Discard, os.Stdin); err == nil {
				slog.Info("stdin closed, stopping")
				stop()
			}
		}()
	}

	context.AfterFunc(ctx, func() {
		slog.Info("stopping gracefully (signal again to force exit)")
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		slog.Error("exiting immediately")
		os.Exit(1)
	})

	var pr *probe.Probe

	sc, err := scanner.New(&scanner.Options{
		Logger:  slog.Default(),
		Cache:   config.Cache,
		Workers: config.ScanWorkers,
		OnError: func(err error) {
			if ctx.Err() != nil {
				return
			}
			slog.Error("scan error", "error", err)
		},
		OnResult: func(name, path string, elfOffset uint64, offsets scanner.Offsets) {
			if pr == nil {
				return
			}
			if ctx.Err() != nil {
				return
			}
			slog.Info("attaching probe", "name", name)
			if err := pr.Attach(path, int64(elfOffset+offsets.SSLLogSecret), offsets.S3, offsets.ClientRandom); err != nil {
				slog.Error("attach probe", "name", name, "error", err)
			}
		},
	})
	if _, ok := errors.AsType[*scanner.BadCacheVersionError](err); ok {
		err = fmt.Errorf("%w (delete the cache file and try again)", err)
	}
	if err != nil {
		slog.Error("initialize scanner", "error", err)
		os.Exit(1)
	}

	if config.Capture != "" {
		p, err := probe.New(&probe.Options{
			BufferSize: config.ProbeBuffer,
			NoRead:     config.ProbeNoRead,
		})
		if err != nil {
			if !config.ProbeNoRead {
				err = fmt.Errorf("%w (try --probe-noread)", err)
			}
			slog.Error("initialize probe", "error", err)
			os.Exit(1)
		}
		pr = p
	}

	var (
		output     io.Writer = os.Stdout
		outputFile *os.File
	)
	if config.Capture != "" && config.CaptureOutput != "-" {
		f, err := os.Create(config.CaptureOutput)
		if err != nil {
			slog.Error("open capture output", "error", err)
			os.Exit(1)
		}
		outputFile = f
		output = f
	}

	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		// errors are logged in the scanner OnError

		slog.Info("revalidating cached libraries")
		info, _ := sc.ScanCached(false) // TODO: make configurable
		slog.Info("scan done", scanInfoAttrs(info)...)

		for _, lib := range config.ScanLib {
			slog.Info("scanning library", "name", lib)
			info, _ := sc.Scan(lib, &scanner.ScanOptions{
				// TODO: make configurable
			})
			slog.Info("scan done", scanInfoAttrs(info)...)
		}

		for _, dir := range config.ScanLibs {
			slog.Info("scanning directory", "dir", dir)
			info, _ := sc.ScanDir(dir, true, &scanner.ScanOptions{
				// TODO: make configurable
			})
			slog.Info("scan done", scanInfoAttrs(info)...)
		}

		if config.ScanLibsSys {
			slog.Info("scanning system library directories")
			info, _ := sc.ScanSystem(&scanner.ScanOptions{
				// TODO: make configurable
			})
			slog.Info("scan done", scanInfoAttrs(info)...)
		}

		if config.ScanLibsApp {
			slog.Info("scanning app directories")
			info, _ := sc.ScanApps(&scanner.ScanOptions{
				// TODO: make configurable
			})
			slog.Info("scan done", scanInfoAttrs(info)...)
		}

		if ctx.Err() != nil {
			return
		}
		slog.Info("all scans complete")
	}()

	if pr != nil {
		outputName := config.CaptureOutput
		if config.CaptureOutput == "-" {
			outputName = "stdout"
		}
		var capErr error
		switch config.Capture {
		case "keylog":
			slog.Info("starting keylog capture", "output", outputName)
			capErr = capture.Keylog(ctx, output, pr, slog.Default())
		case "pcapng":
			slog.Info("starting pcapng capture", "output", outputName, "interface", config.CaptureInterface, "filter", config.CaptureFilter)
			capErr = capture.PcapNG(ctx, output, pr, slog.Default(), &capture.Options{
				Interface:  config.CaptureInterface,
				Filter:     config.CaptureFilter,
				Delay:      config.CaptureBufferDelay,
				PacketSize: config.CaptureBufferPktSize,
				Buffer:     config.CaptureBufferSize,
			})
		}
		slog.Info("capture ended")
		if capErr != nil && !errors.Is(capErr, context.Canceled) {
			slog.Error("capture failed", "error", capErr)
		}
	} else {
		select {
		case <-scanDone:
		case <-ctx.Done():
		}
	}

	slog.Info("shutting down")
	stop()

	if outputFile != nil {
		slog.Info("closing output")
		if err := outputFile.Close(); err != nil {
			slog.Warn("close output", "error", err)
		}
		slog.Info("output closed")
	}

	slog.Info("closing scanner")
	select {
	case <-scanDone:
	default:
		slog.Warn("scan not finished, stopping anyways")
	}
	if err := sc.Close(); err != nil {
		slog.Warn("close scanner", "error", err)
	}
	<-scanDone
	slog.Info("scanner closed")

	if pr != nil {
		slog.Info("closing probe")
		if err := pr.Close(); err != nil {
			slog.Warn("close probe", "error", err)
		}
		slog.Info("probe closed")
	}

	slog.Info("done")
}

func scanInfoAttrs(info scanner.ScanInfo) []any {
	return []any{
		slog.Group("file",
			slog.Group("success",
				"total", info.File.Total-info.File.Error,
				"cached", info.File.Cached,
				"new", info.File.New,
				"stale", info.File.Stale,
			),
			"error", info.File.Error,
		),
		slog.Group("offset",
			slog.Group("success",
				"total", info.Offset.Total-info.Offset.Error,
				"cached", info.Offset.Cached,
				"new", info.Offset.New,
				"stale", info.Offset.Stale,
			),
			"error", info.Offset.Error,
		),
	}
}
