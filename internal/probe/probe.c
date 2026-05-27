// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build ignore

#include "bpf.h"

#define LABEL_MAX          64  // larger than we actually need for future-proofing
#define SECRET_MAX         256 // ^
#define CLIENT_RANDOM_SIZE 32  // sizeof(((bssl::SSL3_STATE*) nullptr)->client_random)

// scudo on android tags heap pointers, but bpf_probe_read_user doesn't ignore
// the top bytes, resulting in an EFAULT
#define UNTAG(p) ((void *)((__u64)(p) & ~(0xFFUL << 56)))

#ifndef NOREAD
struct config {
	__s64 s3;            // offsetof(bssl::SSL, s3)
	__s64 client_random; // offsetof(bssl::SSL3_STATE, client_random)
};
#endif

struct event {
	__u64 timestamp;
	__u32 pid;
	__u32 _pad;
#ifdef NOREAD
	__u64 label_ptr;
	__u64 secret_ptr;
	__s64 secret_len;
	__u64 ssl_ptr;
#else
	__s64 debug_line;
	__s64 debug_ret;
	__s64 debug_ptr;
	char  label[LABEL_MAX];
	__u8  client_random[CLIENT_RANDOM_SIZE];
	__u8  secret[SECRET_MAX];
	__s64 secret_len;
#endif
};

// TODO: on 5.15+, we could make the config a hash map on the bpf cookie so we
// can reuse the loaded program for all probes, but that's a bit too new and
// we'd lose too much version support... (and the alternatives would require
// janky stuff like reading proc maps and mapping on process ids)

#ifndef NOREAD
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} config_map SEC(".maps");
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(value, struct event);
} events SEC(".maps");

SEC("uprobe/ssl_log_secret")
int uprobe_ssl_log_secret(struct pt_regs *ctx) {
	__u64       timestamp  = bpf_ktime_get_ns();                // CLOCK_MONOTONIC
	__u32       pid        = bpf_get_current_pid_tgid() >> 32;  // pid
	void       *ssl        = (void *)       PT_REGS_PARM1(ctx); // const SSL *ssl
	const char *label      = (const char *) PT_REGS_PARM2(ctx); // const char *label
	const __u8 *secret     = (const __u8 *) PT_REGS_PARM3(ctx); // const uint8_t* secret / bssl::Span<const uint8_t>->data_
	__s64       secret_len = (__s64)        PT_REGS_PARM4(ctx); // size_t secret_len / bssl::Span<const uint8_t>->size_

	struct event ev = {
		.timestamp = timestamp,
		.pid = pid,
	};

#ifdef NOREAD
	ev.label_ptr  = (__u64) label;
	ev.secret_ptr = (__u64) secret;
	ev.secret_len = secret_len;
	ev.ssl_ptr    = (__u64) ssl;
	goto emit;
#else
	if (!ssl || !label || !secret) {
		ev.debug_line = __LINE__;
		goto emit;
	}

	__u32 key = 0;
	struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg) {
		ev.debug_line = __LINE__;
		goto emit;
	}

	if ((ev.debug_ret = bpf_probe_read_user_str(ev.label, sizeof(ev.label), label)) < 0) { // label is in .rodata, no tagging
		ev.debug_ptr = (__s64) label;
		ev.debug_line = __LINE__;
		goto emit;
	}

	ev.secret_len = secret_len;

	// this may return -EFAULT if it goes out of bounds, but it's unlikely given
	// the memory layout, and the verifier in older kernels can't handle a
	// dynamic range check properly
	if ((ev.debug_ret = bpf_probe_read_user(ev.secret, sizeof(ev.secret), UNTAG(secret))) < 0) {
		ev.debug_ptr = (__s64) secret;
		ev.debug_line = __LINE__;
		goto emit;
	}

	void *s3 = NULL;
	if ((ev.debug_ret = bpf_probe_read_user(&s3, sizeof(s3), (__u8 *)UNTAG(ssl) + cfg->s3)) < 0) {
		ev.debug_ptr = (__s64) (__u8 *)ssl + cfg->s3;
		ev.debug_line = __LINE__;
		goto emit;
	}
	if (s3 == NULL) {
		ev.debug_line = __LINE__;
		goto emit;
	}
	if ((ev.debug_ret = bpf_probe_read_user(ev.client_random, sizeof(ev.client_random), (__u8 *)UNTAG(s3) + cfg->client_random)) < 0) {
		ev.debug_ptr = (__s64) (__u8 *)s3 + cfg->client_random;
		ev.debug_line = __LINE__;
		goto emit;
	}

	ev.debug_ret = 0;
	ev.debug_ptr = 0;
	ev.debug_line = -1; // ok
#endif
emit:
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
