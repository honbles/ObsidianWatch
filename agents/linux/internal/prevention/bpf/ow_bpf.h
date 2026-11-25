// SPDX-License-Identifier: GPL-2.0
//
// Minimal BPF definitions so the endpoint program builds with plain clang and
// the kernel UAPI headers: no libbpf headers and no generated vmlinux.h.
// Kernel structures are declared locally with only the fields we read and
// marked preserve_access_index, so the loader relocates field offsets against
// the running kernel's BTF (CO-RE).

#ifndef OW_BPF_H
#define OW_BPF_H

#include <linux/types.h>
#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define NULL ((void *)0)

// Helper ids from enum bpf_func_id (include/uapi/linux/bpf.h).
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static __u64 (*bpf_get_current_task)(void) = (void *)35;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *src) = (void *)112;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)113;
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *src) = (void *)115;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

// Read a kernel field with a CO-RE relocation on its offset.
#define READ_KERN(dst, src) \
	bpf_probe_read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(src)))

// Only the fields the program reads; names must match the kernel's.
struct mm_struct {
	unsigned long arg_start;
	unsigned long arg_end;
} __attribute__((preserve_access_index));

struct task_struct {
	int pid;
	int tgid;
	int exit_code;
	__u64 start_boottime;
	struct task_struct *real_parent;
	struct mm_struct *mm;
} __attribute__((preserve_access_index));

#endif
