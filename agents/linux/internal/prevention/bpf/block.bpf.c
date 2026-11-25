// SPDX-License-Identifier: GPL-2.0
//
// Prevention: refuse connect() and UDP sendmsg() to listed addresses.
// Attached to the root of the cgroup v2 hierarchy, so it applies to every
// process. A refused call fails with EPERM before any packet is sent. The
// programs are detached when the agent stops (fail open).
//
// Build: sh bpf/build.sh (from internal/prevention)

#include "ow_bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct block_event {
	__u32 pid;
	__u32 family;
	__u32 port;  // destination port, host order
	__u32 proto; // 6 tcp, 17 udp
	__u8 addr[16];
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 200000);
	__type(key, __u32); // IPv4, network order
	__type(value, __u8);
} blocked4 SEC(".maps");

struct ip6key {
	__u32 a[4];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 50000);
	__type(key, struct ip6key);
	__type(value, __u8);
} blocked6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} blocks SEC(".maps");

static __always_inline __u32 ntohs16(__u32 p)
{
	return ((p & 0xff) << 8) | ((p >> 8) & 0xff);
}

static __always_inline void report(struct bpf_sock_addr *ctx, __u32 family, __u32 proto)
{
	struct block_event *e = bpf_ringbuf_reserve(&blocks, sizeof(*e), 0);
	if (!e)
		return;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->family = family;
	e->port = ntohs16(ctx->user_port);
	e->proto = proto;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	__builtin_memset(e->addr, 0, 16);
	if (family == 2) {
		__u32 a = ctx->user_ip4;
		__builtin_memcpy(e->addr, &a, 4);
	} else {
		__u32 a0 = ctx->user_ip6[0], a1 = ctx->user_ip6[1], a2 = ctx->user_ip6[2], a3 = ctx->user_ip6[3];
		__builtin_memcpy(e->addr, &a0, 4);
		__builtin_memcpy(e->addr + 4, &a1, 4);
		__builtin_memcpy(e->addr + 8, &a2, 4);
		__builtin_memcpy(e->addr + 12, &a3, 4);
	}
	bpf_ringbuf_submit(e, 0);
}

static __always_inline int check4(struct bpf_sock_addr *ctx, __u32 proto)
{
	__u32 key = ctx->user_ip4;
	if (bpf_map_lookup_elem(&blocked4, &key)) {
		report(ctx, 2, proto);
		return 0; // refuse
	}
	return 1;
}

static __always_inline int check6(struct bpf_sock_addr *ctx, __u32 proto)
{
	struct ip6key key;
	key.a[0] = ctx->user_ip6[0];
	key.a[1] = ctx->user_ip6[1];
	key.a[2] = ctx->user_ip6[2];
	key.a[3] = ctx->user_ip6[3];
	// IPv4-mapped addresses (::ffff:a.b.c.d) are checked against the IPv4 list.
	if (key.a[0] == 0 && key.a[1] == 0 && key.a[2] == 0xffff0000) {
		__u32 v4 = key.a[3];
		if (bpf_map_lookup_elem(&blocked4, &v4)) {
			report(ctx, 10, proto);
			return 0;
		}
	}
	if (bpf_map_lookup_elem(&blocked6, &key)) {
		report(ctx, 10, proto);
		return 0;
	}
	return 1;
}

SEC("cgroup/connect4")
int ow_connect4(struct bpf_sock_addr *ctx) { return check4(ctx, 6); }

SEC("cgroup/connect6")
int ow_connect6(struct bpf_sock_addr *ctx) { return check6(ctx, 6); }

SEC("cgroup/sendmsg4")
int ow_sendmsg4(struct bpf_sock_addr *ctx) { return check4(ctx, 17); }

SEC("cgroup/sendmsg6")
int ow_sendmsg6(struct bpf_sock_addr *ctx) { return check6(ctx, 17); }
