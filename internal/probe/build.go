//go:build ignore

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pgaskin/asslcapture/internal/ndkutil"
)

// NDKVersion is used to consistently select a clang version for reproducible
// builds. If we didn't care about reproducibility, pretty much any clang would
// work.
const NDKVersion = "25.1.8937393"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "build probe: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	pwd, err := os.Getwd()
	if err != nil {
		return err
	}
	ndk, err := ndkutil.Locate(NDKVersion)
	if err != nil {
		return err
	}

	cmd := exec.Command(
		filepath.Join(ndk, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin", "clang"),
		"-c",
		"-g", // need this for relocations to be generated
		"-O2",
		"-mcpu=v1",
		"-target", "bpfel",
		"-D__TARGET_ARCH_arm64",
		"-Wall", "-Wno-compare-distinct-pointer-types",
		"-o", filepath.Join(pwd, "probe_arm64.o"),
		"-fdebug-prefix-map="+pwd+"=.",
		"-fdebug-compilation-dir", ".",
		filepath.Join(pwd, "probe.c"),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	cmd = exec.Command(
		filepath.Join(ndk, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin", "llvm-strip"),
		"-g", // need this for relocations
		filepath.Join(pwd, "probe_arm64.o"),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("strip: %w", err)
	}

	if err := check("probe_arm64.o"); err != nil {
		return fmt.Errorf("check: %w", err)
	}

	return nil
}

func check(bpf string) error {
	ef, err := elf.Open(bpf)
	if err != nil {
		return err
	}
	_ = ef
	return nil
}
