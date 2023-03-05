#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// struct pt_regs *ctx
SEC("freplace/myextension") u64 myextension() {
	return 2;
}

char __license[] SEC("license") = "Dual MIT/GPL";
