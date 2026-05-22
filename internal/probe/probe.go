// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// Package probe manages the uprobe for reading boringssl secrets.
//
// I'd have used cilium/ebpf for the logic, but:
//
//   - It doesn't support attaching probes to libs in zip files (this is an Android-specific linker feature.)
//   - I want to use the perf_event_open syscall (4.18+, same kconfig) so the probe lifecycle is tied to the fd.
//   - I need to handle CPU hotplug (i.e., cores being turned on and off), which it doesn't do.
//   - I already have file offsets and don't want its calculations (which can't currently be skipped).
//
// Since I don't need most of the features anyways, it's easier to just
// implement it myself, which also gives me explicit control over the behaviour.
//
// Pert of the reason why ecapture is so unreliable on Android is because it
// doesn't take into account any of these things.
package probe

//go:generate go run build.go
