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

// Locate finds the root directory of the NDK with the specified version (or any
// if empty).
func Locate(version string) (string, error) {
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
		ver, err := Version(candidate.path)
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
