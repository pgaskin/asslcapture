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

struct config {
    __s64 s3;            // offsetof(bssl::SSL, s3)
	__s64 client_random; // offsetof(bssl::SSL3_STATE, client_random)
};

struct event {
    __s64 debug_line;
    __s64 debug_ret;
    __s64 debug_ptr;
	char  label[LABEL_MAX];
	__u8  client_random[CLIENT_RANDOM_SIZE];
	__u8  secret[SECRET_MAX];
	__s64 secret_len;
};

// TODO: on 5.15+, we could make the config a hash map on the bpf cookie so we
// can reuse the loaded program for all probes, but that's a bit too new and
// we'd lose too much version support... (and the alternatives would require
// janky stuff like reading proc maps and mapping on process ids)

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(value, struct event);
} events SEC(".maps");

SEC("uprobe/ssl_log_secret")
int uprobe_ssl_log_secret(struct pt_regs *ctx) {
	__u32 pid = (__u32) bpf_get_current_pid_tgid();
    __u32 cpu = bpf_get_smp_processor_id();

	void       *ssl        = (void *)       PT_REGS_PARM1(ctx); // const SSL *ssl
	const char *label      = (const char *) PT_REGS_PARM2(ctx); // const char *label
	const __u8 *secret     = (const __u8 *) PT_REGS_PARM3(ctx); // const uint8_t* secret / bssl::Span<const uint8_t>->data_
	__s64       secret_len = (__s64)        PT_REGS_PARM4(ctx); // size_t secret_len / bssl::Span<const uint8_t>->size_

	bpf_printk("ssl_log_secret ssl=%p (pid=%u cpu=%u)\n", ssl, pid, cpu);
	bpf_printk("ssl_log_secret label=%p secret=%p secret_len=%d\n", label, secret, secret_len);

	struct event ev = {};
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

	if (secret_len < 0) {
		secret_len = 0;
    }
	if (secret_len > SECRET_MAX) {
		secret_len = SECRET_MAX;
    }
	if (secret_len > 0 && (ev.debug_ret = bpf_probe_read_user(ev.secret, secret_len, UNTAG(secret))) < 0) {
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
    emit:
    {
        long ret = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
        bpf_printk("emit %s %02x (ret=%d)\n", ev.label, ev.client_random[0], ret);
    }
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
