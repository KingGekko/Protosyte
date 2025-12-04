.PHONY: all build-seed build-seed-windows build-seed-macos build-broadcast build-rig build-bridge clean

all: build-seed build-broadcast build-rig build-bridge

build-seed:
	@echo "Building Component A: Silent Seed (Linux)..."
	cd protosyte-seed && cargo build --release

build-seed-windows:
	@echo "Building Component A: Silent Seed (Windows)..."
	cd protosyte-seed-windows && cargo build --release --target x86_64-pc-windows-msvc

build-seed-macos:
	@echo "Building Component A: Silent Seed (macOS)..."
	cd protosyte-seed-macos && cargo build --release --target x86_64-apple-darwin

build-broadcast:
	@echo "Building Component B: Broadcast Engine (Go)..."
	cd broadcast-engine && go build -o protosyte-broadcast .

build-rig:
	@echo "Building Component C: Analysis Rig (Go)..."
	cd analysis-rig && go build -o protosyte-rig .

build-bridge:
	@echo "Building Component D: Legal Bridge (Go)..."
	cd legal-bridge && CGO_ENABLED=0 go build -o protosyte-bridge .

clean:
	@echo "Cleaning build artifacts..."
	cd protosyte-seed && cargo clean
	cd protosyte-seed-windows && cargo clean
	cd protosyte-seed-macos && cargo clean
	cd broadcast-engine && rm -f protosyte-broadcast
	cd analysis-rig && rm -f protosyte-rig
	cd legal-bridge && rm -f protosyte-bridge

