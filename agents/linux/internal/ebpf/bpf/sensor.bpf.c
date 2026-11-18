// SPDX-License-Identifier: GPL-2.0
//
// Host runtime sensor - kernel programs (spec section 8). NOT COMPILED OR RUN in the environment this
// file was written in (no clang, no libbpf headers): treat it as a reviewed design to be built and
// verified with bpf/README.md before it is relied on.
//
// Everything is filtered IN THE KERNEL by the `watched` map: only tasks that are a service process or
// one of its descendants produce events. Userspace seeds the map with service pids; sched_process_fork
// propagates it to children, so a shell spawned by a web server is watched from its first instruction.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

enum evtype { EV_EXEC = 1, EV_CONNECT = 2, EV_OPEN = 3, EV_PRIV = 4, EV_ESCAPE = 5 };
enum escape { ESC_MOUNT = 1, ESC_SETNS = 2, ESC_UNSHARE = 3 };

struct event {
	__u32 type;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 aux;       // EV_PRIV: new uid; EV_OPEN: open flags; EV_ESCAPE: enum escape
	__u16 sport;
	__u16 dport;
	__u8  family;    // AF_INET (2) / AF_INET6 (10)
	__u8  pad[3];
	__u32 saddr;
	__u32 daddr;     // IPv4 only in this version
	char  fname[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
} watched SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int is_watched(__u32 pid)
{
	return bpf_map_lookup_elem(&watched, &pid) != NULL;
}

static __always_inline struct event *reserve(__u32 type, __u32 pid)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return NULL;
	__builtin_memset(e, 0, sizeof(*e));
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	e->type = type;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	return e;
}

// A child of a watched task is watched.
SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u32 parent = ctx->parent_pid, child = ctx->child_pid;
	__u8 one = 1;
	if (is_watched(parent))
		bpf_map_update_elem(&watched, &child, &one, BPF_ANY);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_delete_elem(&watched, &pid);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!is_watched(pid))
		return 0;
	struct event *e = reserve(EV_EXEC, pid);
	if (e)
		bpf_ringbuf_submit(e, 0);
	return 0;
}

// Outbound TCP: the task that moves a socket to SYN_SENT is the one connecting.
SEC("tracepoint/sock/inet_sock_set_state")
int handle_connect(struct trace_event_raw_inet_sock_set_state *ctx)
{
	if (ctx->newstate != 2 /* TCP_SYN_SENT */ || ctx->family != 2 /* AF_INET */)
		return 0;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!is_watched(pid))
		return 0;
	struct event *e = reserve(EV_CONNECT, pid);
	if (!e)
		return 0;
	e->family = 2;
	e->sport = ctx->sport;
	e->dport = ctx->dport;
	__builtin_memcpy(&e->saddr, ctx->saddr, 4);
	__builtin_memcpy(&e->daddr, ctx->daddr, 4);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!is_watched(pid))
		return 0;
	struct event *e = reserve(EV_OPEN, pid);
	if (!e)
		return 0;
	e->aux = (__u32)ctx->args[2]; // flags
	bpf_probe_read_user_str(e->fname, sizeof(e->fname), (const char *)ctx->args[1]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!is_watched(pid))
		return 0;
	struct event *e = reserve(EV_PRIV, pid);
	if (e) {
		e->aux = (__u32)ctx->args[0];
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int handle_mount(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!is_watched(pid))
		return 0;
	struct event *e = reserve(EV_ESCAPE, pid);
	if (e) {
		e->aux = ESC_MOUNT;
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int handle_setns(struct trace_event_raw_sys_enter *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (!is_watched(pid))
		return 0;
	struct event *e = reserve(EV_ESCAPE, pid);
	if (e) {
		e->aux = ESC_SETNS;
		bpf_ringbuf_submit(e, 0);
	}
	return 0;
}
