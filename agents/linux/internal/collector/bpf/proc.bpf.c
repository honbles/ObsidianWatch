// SPDX-License-Identifier: GPL-2.0
//
// Endpoint process sensor: every successful exec (with argv read in the
// kernel, so short-lived processes are not lost), every process exit and
// every outbound TCP connection attempt with the pid that made it.
//
// Build (from agents/linux/internal/collector):
//   clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c bpf/proc.bpf.c -o bpf/proc_bpfel.o
// The object is architecture-neutral: tracepoint layouts and the fields read
// are the same on amd64 and arm64, and offsets are relocated at load (CO-RE).

#include "ow_bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define EV_EXEC 1
#define EV_EXIT 2
#define EV_CONNECT 3

#define ARGS_MAX 1024
#define PATH_MAX_OW 256

struct exec_event {
	__u32 type;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 gid;
	__u32 args_len;   // bytes of argv copied (NUL separated)
	__u32 args_trunc; // 1 when argv was longer than ARGS_MAX
	__u32 pad;
	__u64 cgroup_id;
	__u64 start_ns;   // task start, boot clock (matches /proc/<pid>/stat starttime)
	__u64 pstart_ns;  // parent start, boot clock
	char comm[16];
	char filename[PATH_MAX_OW];
	char args[ARGS_MAX];
};

struct exit_event {
	__u32 type;
	__u32 pid;
	__u32 ppid;
	__u32 exit_code;
	__u64 start_ns;
};

struct conn_event {
	__u32 type;
	__u32 pid;
	__u32 uid;
	__u16 family;
	__u16 sport;
	__u16 dport;
	__u16 pad;
	__u8 saddr[16];
	__u8 daddr[16];
	__u64 start_ns;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 << 20);
} events SEC(".maps");

// Count of events lost because the ring buffer was full, per type.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline void count_drop(__u32 type)
{
	__u64 *n = bpf_map_lookup_elem(&drops, &type);
	if (n)
		*n += 1;
}

// sched_process_exec: runs in the new program's context after a successful exec.
struct exec_ctx {
	__u64 common;
	__u32 filename_loc; // __data_loc: offset in low 16 bits
	int pid;
	int old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int ow_exec(struct exec_ctx *ctx)
{
	struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(EV_EXEC);
		return 0;
	}
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = NULL;
	struct mm_struct *mm = NULL;
	__u64 ug = bpf_get_current_uid_gid();

	e->type = EV_EXEC;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)ug;
	e->gid = ug >> 32;
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->args_len = 0;
	e->args_trunc = 0;
	e->pad = 0;
	READ_KERN(e->start_ns, t->start_boottime);
	READ_KERN(parent, t->real_parent);
	e->ppid = 0;
	e->pstart_ns = 0;
	if (parent) {
		READ_KERN(e->ppid, parent->tgid);
		READ_KERN(e->pstart_ns, parent->start_boottime);
	}
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
				  (void *)ctx + (ctx->filename_loc & 0xFFFF));

	READ_KERN(mm, t->mm);
	if (mm) {
		unsigned long start = 0, end = 0;
		READ_KERN(start, mm->arg_start);
		READ_KERN(end, mm->arg_end);
		unsigned long len = end - start;
		if (end > start) {
			if (len > ARGS_MAX - 1) {
				len = ARGS_MAX - 1;
				e->args_trunc = 1;
			}
			// The verifier needs a size it can prove is inside args.
			len &= ARGS_MAX - 1;
			if (bpf_probe_read_user(e->args, len, (void *)start) == 0)
				e->args_len = len;
		}
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int ow_exit(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	if ((__u32)id != tgid) // a thread, not the process
		return 0;
	struct exit_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(EV_EXIT);
		return 0;
	}
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = NULL;
	e->type = EV_EXIT;
	e->pid = tgid;
	e->ppid = 0;
	e->exit_code = 0;
	READ_KERN(e->exit_code, t->exit_code);
	READ_KERN(e->start_ns, t->start_boottime);
	READ_KERN(parent, t->real_parent);
	if (parent)
		READ_KERN(e->ppid, parent->tgid);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// sock/inet_sock_set_state: a socket moving to SYN_SENT is an outbound
// connect, and it happens in the connecting task's context.
struct sockstate_ctx {
	__u64 common;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

SEC("tracepoint/sock/inet_sock_set_state")
int ow_connect(struct sockstate_ctx *ctx)
{
	if (ctx->newstate != 2 /* TCP_SYN_SENT */ || ctx->protocol != 6 /* TCP */)
		return 0;
	if (ctx->family != 2 && ctx->family != 10)
		return 0;
	struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(EV_CONNECT);
		return 0;
	}
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	e->type = EV_CONNECT;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->family = ctx->family;
	e->sport = ctx->sport;
	e->dport = ctx->dport;
	e->pad = 0;
	__builtin_memset(e->saddr, 0, 16);
	__builtin_memset(e->daddr, 0, 16);
	if (ctx->family == 2) {
		__builtin_memcpy(e->saddr, ctx->saddr, 4);
		__builtin_memcpy(e->daddr, ctx->daddr, 4);
	} else {
		__builtin_memcpy(e->saddr, ctx->saddr_v6, 16);
		__builtin_memcpy(e->daddr, ctx->daddr_v6, 16);
	}
	e->start_ns = 0;
	READ_KERN(e->start_ns, t->start_boottime);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}
