// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

// we don't need much from btf (vmlinux.h) or libbpf (bpf/bpf_helpers.h,
// bpf/bpf_tracing.h), so inlining it here simplifies compilation and also make
// it more obvious what offset we're depending on
#pragma once

// kernel integer types
typedef unsigned char      __u8;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef signed long long   __s64;

// kernel types
struct pt_regs;

// bpf constants
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_F_CURRENT_CPU 0xffffffffULL

// bpf map attributes
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// bpf helpers
static void *(* const bpf_map_lookup_elem)(void *map, const void *key) = (void *(*)(void *, const void *)) 1; // 3.18
static long (* const bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (long (*)(void *, void *, __u64, void *, __u64)) 25; // 4.4

// https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/commit/?id=6ae08ae3dea2cfa03dd3665a3c8475c2d429ef47
// https://github.com/iovisor/bcc/issues/3094
// https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
// https://lkml.org/lkml/2019/2/28/1369
// https://github.com/iovisor/bcc/issues/3783
static long (* const bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (long (*)(void *, __u32, const void *)) 112; // 5.5 (but android kernels have it backported due to an arm64 bug in the non-_user variant)
static long (* const bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (long (*)(void *, __u32, const void *)) 114; // same

// bpf utils
#define SEC(name) __attribute__((section(name), used))

// c null
#ifndef NULL
#define NULL ((void *)0)
#endif

// arm64 uses user_pt_regs instead of the internal pt_regs, and the layout is
// stable
struct user_pt_regs {
	__u64 regs[31]; // x0-x30
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};

#define PT_REGS_PARM1(ctx) (((const struct user_pt_regs *)(ctx))->regs[0])
#define PT_REGS_PARM2(ctx) (((const struct user_pt_regs *)(ctx))->regs[1])
#define PT_REGS_PARM3(ctx) (((const struct user_pt_regs *)(ctx))->regs[2])
#define PT_REGS_PARM4(ctx) (((const struct user_pt_regs *)(ctx))->regs[3])
