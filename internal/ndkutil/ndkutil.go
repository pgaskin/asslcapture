// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Package ndkutil does stuff with the Android NDK.
package ndkutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Locate finds the root directory of the NDK with the specified version (or any
// if empty).
func Locate(version string) (string, error) {
	type candidate struct {
		source string
		path   string
	}
	var candidates []candidate
	for _, v := range []string{"ANDROID_NDK_ROOT", "ANDROID_NDK_HOME"} {
		if p := os.Getenv(v); p != "" {
			candidates = append(candidates, candidate{
				source: v + " parent dir",
				path:   filepath.Join(p),
			})
		}
	}
	if version != "" {
		for _, v := range []string{"ANDROID_NDK_ROOT", "ANDROID_NDK_HOME"} {
			if p := os.Getenv(v); p != "" {
				candidates = append(candidates, candidate{
					source: v + " parent dir",
					path:   filepath.Join(p, "..", version),
				})
			}
		}
	}
	for _, v := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		if p := os.Getenv(v); p != "" {
			candidates = append(candidates, candidate{
				source: v,
				path:   filepath.Join(p, "ndk", version),
			})
		}
	}
	for _, v := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		if p := os.Getenv(v); p != "" {
			candidates = append(candidates, candidate{
				source: v,
				path:   filepath.Join(p, "ndk-bundle"),
			})
		}
	}
	if p, err := exec.LookPath("ndk-build"); err == nil {
		candidates = append(candidates, candidate{
			source: "ndk-build in PATH",
			path:   filepath.Join(p, ".."),
		})
	}
	var errs []error
	for _, candidate := range candidates {
		ver, err := Version(candidate.path)
		if err != nil {
			errs = append(errs, fmt.Errorf("try %q (%s): %w", candidate.path, candidate.source, err))
			continue
		}
		if version != "" && ver != version {
			errs = append(errs, fmt.Errorf("try %q (%s): wrong version %s", candidate.path, candidate.source, ver))
			continue
		}
		return candidate.path, nil

	}
	if len(candidates) == 0 {
		errs = append(errs, fmt.Errorf("no ndk installed"))
	}
	return "", fmt.Errorf("failed to locate ndk %s (please set ANDROID_NDK_ROOT or install it into ANDROID_HOME):\n%w", version, errors.Join(errs...))
}

// Version gets the version of the NDK at path.
func Version(path string) (string, error) {
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
