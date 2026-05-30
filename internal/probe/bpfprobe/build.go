//go:build ignore

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	ndk, err := ndkRoot(NDKVersion)
	if err != nil {
		return err
	}

	clang := filepath.Join(ndk, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin", "clang")
	strip := filepath.Join(ndk, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin", "llvm-strip")

	compile := func(output string, cflags ...string) error {
		args := []string{
			"-c",
			"-g", // need this for relocations to be generated
			"-O2",
			"-mcpu=v1",
			"-target", "bpfel",
			"-D__TARGET_ARCH_arm64",
			"-Wall", "-Wno-compare-distinct-pointer-types",
			"-o", filepath.Join(pwd, output),
			"-fdebug-prefix-map=" + pwd + "=.",
			"-fdebug-compilation-dir", ".",
		}
		args = append(args, cflags...)
		args = append(args, filepath.Join(pwd, "probe.c"))
		cmd := exec.Command(clang, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("compile %s: %w", output, err)
		}

		cmd = exec.Command(strip, "-g", filepath.Join(pwd, output)) // -g: keep relocations
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("strip %s: %w", output, err)
		}

		if err := check(output); err != nil {
			return fmt.Errorf("check %s: %w", output, err)
		}
		return nil
	}

	if err := compile("probe_arm64.o"); err != nil {
		return err
	}
	if err := compile("probe_noread_arm64.o", "-DNOREAD"); err != nil {
		return err
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

func ndkVersion(path string) (string, error) {
	buf, err := os.ReadFile(filepath.Join(path, "source.properties"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("missing properties")
		}
		return "", err
	}
	var (
		desc     string
		revision string
	)
	for line := range strings.Lines(string(buf)) {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)

		switch strings.ToLower(k) {
		case "pkg.desc":
			desc = v
		case "pkg.revision":
			revision = v
		}
	}
	if desc == "" || revision == "" {
		return "", fmt.Errorf("source.properties missing pkg.desc or pkg.revision")
	}
	if desc != "Android NDK" {
		return "", fmt.Errorf("source.properties is a %q, not an ndk", desc)
	}
	return revision, nil
}

func ndkRoot(version string) (string, error) {
	type candidate struct {
		source string
		path   string
	}
	var candidates []candidate
	try := func(p ...string) {
		source, matches := expand(p...)
		if len(matches) == 0 {
			candidates = append(candidates, candidate{
				source: source,
			})
		} else {
			for _, path := range matches {
				candidates = append(candidates, candidate{
					source: source,
					path:   path,
				})
			}
		}
	}

	try("${ANDROID_NDK_ROOT}")
	try("${ANDROID_NDK_HOME}") // legacy
	if version != "" {
		try("${ANDROID_NDK_ROOT}", "..", version)
		try("${ANDROID_NDK_HOME}", "..", version)
		try("${ANDROID_HOME}", "ndk", version)
		try("${ANDROID_SDK_ROOT}", "ndk", version) // legacy
	}
	try("${ANDROID_HOME}", "ndk", "*")
	try("${ANDROID_SDK_ROOT}", "ndk", "*")
	try("$(dirname $(which ndk-build))")

	var errs []error
	for _, candidate := range candidates {
		if candidate.path == "" {
			errs = append(errs, fmt.Errorf("try %q: not found", candidate.source))
			continue
		}
		ver, err := ndkVersion(candidate.path)
		if err != nil {
			errs = append(errs, fmt.Errorf("try %q (%s): %w", candidate.source, candidate.path, err))
			continue
		}
		if version != "" && ver != version {
			errs = append(errs, fmt.Errorf("try %q (%s): wrong version %s", candidate.source, candidate.path, ver))
			continue
		}
		return candidate.path, nil

	}
	if len(candidates) == 0 {
		errs = append(errs, fmt.Errorf("no ndk installed"))
	}
	return "", fmt.Errorf("failed to locate ndk %s (please set ANDROID_NDK_ROOT or install it into ANDROID_HOME):\n%w", version, errors.Join(errs...))
}

// expand expands a potential path which may contain globs, "${ENV}", or
// "$(dirname $(which CMD))" components.
func expand(components ...string) (source string, matches []string) {
	source = strings.Join(components, string(filepath.Separator))

	var missing bool
	for i, c := range components {
		if v, ok := strings.CutPrefix(c, "${"); ok {
			if v, ok := strings.CutSuffix(v, "}"); ok {
				if s := os.Getenv(v); s == "" {
					missing = true
				} else {
					components[i] = s
				}
				continue
			}
		}
		if v, ok := strings.CutPrefix(c, "$(dirname $(which "); ok {
			if v, ok := strings.CutSuffix(v, "))"); ok {
				if s, err := exec.LookPath(v); err != nil {
					missing = true
				} else {
					components[i] = filepath.Dir(s)
				}
				continue
			}
		}
		if strings.Contains(c, "$") {
			panic("wtf")
		}
	}
	if !missing {
		path := filepath.Join(components...)
		if m, err := filepath.Glob(path); err == nil {
			for _, x := range m {
				matches = append(matches, x)
			}
		} else {
			matches = append(matches, path)
		}
	}
	return
}
