# eBPF Kernel-Level Hooking Implementation

## Overview

The eBPF implementation provides kernel-level function hooking, making it invisible to user-space tools. This is significantly more stealthy than LD_PRELOAD-based hooking.

## Architecture

### Components

1. **eBPF C Program** (`bpf/protosyte_hook.bpf.c`)
   - Compiles to eBPF bytecode
   - Hooks `write()`, `send()`, `SSL_write()` functions
   - Uses ring buffer to pass data to userspace

2. **Rust eBPF Manager** (`src/ebpf_hooks.rs`)
   - Loads and manages eBPF programs using `aya-rs`
   - Attaches uprobes to target functions
   - Reads from ring buffer and forwards to capture channel

3. **Build Script** (`build.rs`)
   - Compiles eBPF C code to bytecode using `clang`
   - Embeds bytecode in Rust binary

## Requirements

- Linux kernel 5.8+ (for ring buffer support)
- Root privileges (CAP_BPF, CAP_SYS_ADMIN)
- `clang` and LLVM installed
- `libbpf` development headers

### Installation

```bash
# Ubuntu/Debian
sudo apt-get install clang llvm libbpf-dev

# Fedora/RHEL
sudo dnf install clang llvm libbpf-devel
```

## Building

Enable eBPF support with the feature flag:

```bash
cargo build --features ebpf
```

The build script will:
1. Compile eBPF C code to bytecode
2. Embed bytecode in the Rust binary
3. Link with `aya-rs` library

## Usage

```rust
use protosyte_seed::ebpf_hooks::EbpfHookManager;

// Create eBPF hook manager
let mut manager = EbpfHookManager::new()?;

// Attach to write() function in libc
manager.attach_uprobe(
    "/lib/x86_64-linux-gnu/libc.so.6",
    "write",
    0,
)?;

// Start capturing data
let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
tokio::spawn(async move {
    manager.start_capture(tx).await;
});
```

## Advantages Over LD_PRELOAD

1. **Kernel-Level**: Invisible to user-space tools
2. **No Library Injection**: No need to inject into processes
3. **Global Hooking**: Can hook any process without modification
4. **Performance**: Minimal overhead compared to library injection

## Limitations

1. **Root Required**: Needs CAP_BPF and CAP_SYS_ADMIN
2. **Linux Only**: eBPF is Linux-specific
3. **Kernel Version**: Requires kernel 5.8+ for ring buffers
4. **Binary Analysis**: Requires knowing function locations in binaries

## Testing

Run tests with eBPF feature:

```bash
cargo test --features ebpf
```

Note: Tests require root privileges and may need to be run with `sudo`.

## Troubleshooting

### "eBPF bytecode not found"
- Ensure `clang` is installed
- Check that build completed successfully
- Verify `target/bpf/protosyte_hook.bpf.o` exists

### "Failed to load eBPF program"
- Check kernel version (5.8+ required)
- Verify CAP_BPF capability
- Check kernel logs: `dmesg | tail`

### "Permission denied"
- Run with root privileges
- Verify capabilities: `getcap` command
- Check SELinux/AppArmor policies

## Security Considerations

- eBPF programs run in kernel space - bugs can crash the system
- Programs are verified by the kernel before loading
- Ring buffer size is limited to prevent DoS
- Data capture is limited to 512 bytes per event

## Future Enhancements

- [ ] Support for kprobes (kernel function hooking)
- [ ] Tracepoint-based hooking (more stable than uprobes)
- [ ] Multiple binary support (hook multiple libraries)
- [ ] Performance optimization (reduce ring buffer polling)

