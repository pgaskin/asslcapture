//go:build ignore

// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/pgaskin/asslcapture/internal/analyze"
)

func main() {
	if len(os.Args) <= 1 {
		fmt.Printf("usage: %s path[!/zip-entry]...\n", os.Args[0])
		os.Exit(2)
	}
	var failed bool
	for i, name := range os.Args[1:] {
		if i != 0 {
			fmt.Println()
		}
		fmt.Printf("%s\n", name)
		if !func() bool {
			ef, err := analyze.Open(os.Args[1])
			if err != nil {
				fmt.Printf("  error %v\n", err)
				return false
			}
			defer ef.Close()

			fmt.Printf("  elf\n")
			fmt.Printf("    path %q\n", ef.Path())
			fmt.Printf("    offset %#x\n", ef.Offset())
			fmt.Printf("    size %d\n", ef.Size())

			fmt.Printf("  is_maybe_boringssl\n")
			maybe, err := analyze.IsMaybeBoringSSL(ef.File)
			if err != nil {
				fmt.Printf("    error %q\n", err)
			} else {
				fmt.Printf("    %t\n", maybe)
			}

			fmt.Printf("  is_probably_linked_boringssl\n")
			fmt.Printf("    %t\n", analyze.IsProbablyLinkedBoringSSL(ef.File))

			fmt.Printf("  ssl_log_secret\n")
			var off uint64

			fmt.Printf("    minidebug\n")
			moff, err := analyze.LogSecretMiniDebug(ef.File)
			if err != nil {
				fmt.Printf("      error %q\n", err)
			} else {
				fmt.Printf("      offset %#x\n", moff)
				off = moff
			}

			fmt.Printf("    heuristic\n")
			hoff, candidates, err := analyze.LogSecretHeuristic(context.Background(), ef.File)
			if len(candidates) != 0 {
				fmt.Printf("      candidates\n")
				for _, label := range slices.Sorted(maps.Keys(candidates)) {
					fmt.Printf("        %s %#x\n", label, candidates[label])
				}
			}
			if err != nil {
				fmt.Printf("      error %q\n", err)
			} else {
				fmt.Printf("      offset %#x\n", hoff)
				if off == 0 {
					off = hoff
				}
			}

			fmt.Printf("  client_random\n")
			if off == 0 {
				fmt.Printf("    unknown\n")
				return false
			}
			s3, cr, err := analyze.ClientRandom(ef.File, off)
			if err != nil {
				fmt.Printf("    error %q\n", err)
				return false
			}
			fmt.Printf("    s3 %d\n", s3)
			fmt.Printf("    cr %d\n", cr)
			return true
		}() {
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}
