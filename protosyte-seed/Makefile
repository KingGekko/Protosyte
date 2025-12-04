# Makefile for Protosyte Seed with eBPF and Obfuscation support

.PHONY: all build build-ebpf build-obfuscated clean test

# Default build
all: build

# Standard build
build:
	cargo build --release

# Build with eBPF support
build-ebpf:
	@echo "Building with eBPF support..."
	@if ! command -v clang >/dev/null 2>&1; then \
		echo "Error: clang not found. Install with:"; \
		echo "  sudo apt-get install clang llvm libbpf-dev"; \
		exit 1; \
	fi
	cargo build --release --features ebpf

# Build with AI filtering
build-ai:
	cargo build --release --features ai-filtering

# Build with post-quantum crypto
build-pqc:
	cargo build --release --features post-quantum

# Build with obfuscation (requires O-LLVM)
build-obfuscated: build
	@echo "Obfuscating binary with O-LLVM..."
	@if ! command -v opt >/dev/null 2>&1 || ! test -f /usr/lib/obfuscator/libObfuscatorPass.so; then \
		echo "Warning: O-LLVM not found. Install with:"; \
		echo "  sudo apt-get install obfuscator-llvm-14"; \
		echo "Or see protosyte-seed/OLLVM_INTEGRATION.md for details"; \
		exit 1; \
	fi
	@echo "Note: O-LLVM obfuscation requires manual integration"
	@echo "See protosyte-seed/OLLVM_INTEGRATION.md for instructions"

# Build all features
build-all:
	cargo build --release --features "ai-filtering,post-quantum,ebpf"

# Clean build artifacts
clean:
	cargo clean
	rm -rf target/bpf

# Run tests
test:
	cargo test

# Check eBPF compilation
check-ebpf:
	@echo "Checking eBPF dependencies..."
	@command -v clang >/dev/null 2>&1 || (echo "clang: NOT FOUND" && exit 1)
	@echo "clang: OK"
	@test -f /usr/include/bpf/bpf_helpers.h || test -f /usr/local/include/bpf/bpf_helpers.h || (echo "libbpf headers: NOT FOUND" && exit 1)
	@echo "libbpf headers: OK"
	@echo "eBPF dependencies: OK"

# Help
help:
	@echo "Protosyte Seed Build System"
	@echo ""
	@echo "Targets:"
	@echo "  build              - Standard release build"
	@echo "  build-ebpf         - Build with eBPF support"
	@echo "  build-ai           - Build with AI filtering"
	@echo "  build-pqc          - Build with post-quantum crypto"
	@echo "  build-all          - Build with all features"
	@echo "  build-obfuscated   - Build with O-LLVM obfuscation"
	@echo "  clean              - Clean build artifacts"
	@echo "  test               - Run tests"
	@echo "  check-ebpf         - Check eBPF dependencies"
	@echo ""
	@echo "Examples:"
	@echo "  make build-ebpf    - Build with kernel-level hooking"
	@echo "  make build-all     - Build with all features enabled"

