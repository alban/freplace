#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

#define TASK_COMM_LEN		16
struct event {
	u64 extension;
	u32 pid;
	u8 comm[TASK_COMM_LEN];
};

// we need this to make sure the compiler doesn't remove our struct
const struct event *unusedbindevent __attribute__((unused));

__attribute__((noinline)) int myextension(struct pt_regs *ctx) {
	volatile int ret = 1;
	return ret;
}

SEC("kprobe/sys_execve")
int BPF_KPROBE(kprobe_execve)
{
	struct event event = {};

	event.extension = myextension(ctx);
	event.pid = bpf_get_current_pid_tgid();
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
