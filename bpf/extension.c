#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("freplace/myextension") u64 myextension(struct pt_regs *ctx) {
	return 2;
}

char __license[] SEC("license") = "Dual MIT/GPL";
