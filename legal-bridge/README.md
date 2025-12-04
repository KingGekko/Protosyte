# Component D: The Legal Bridge

Go-based one-time submission terminal for FIP delivery to law enforcement.

## Quick Start

### Using Automation Scripts

```bash
# Build all components (includes legal bridge)
./scripts/build-all.sh

# Manual execution (after FIP generation)
cd legal-bridge
export LE_PORTAL_URL="https://portal.example/submit"
export LE_PORTAL_KEY="your_key"
./protosyte-bridge
```

### Building

```bash
# Static binary (no CGO)
CGO_ENABLED=0 go build -o protosyte-bridge .

# With embedded FIP (requires forensic_intel_packet.json.gz)
go build -o protosyte-bridge .
```

## Usage

1. Generate FIP via CLI
2. Transfer FIP to submission terminal
3. Set environment variables:
   - `LE_PORTAL_URL`: Law enforcement portal endpoint
   - `LE_PORTAL_KEY`: Authorization token
4. Execute binary
5. Binary self-destructs after successful submission

## Workflow

```bash
# 2. Transfer FIP to legal bridge terminal
cp /tmp/rig_out/forensic_intel_packet.json.gz legal-bridge/

# 3. Configure and execute
export LE_PORTAL_URL="https://portal.example/submit"
export LE_PORTAL_KEY="your_key"
cd legal-bridge
./protosyte-bridge
```

## Security

- Binary shreds itself after execution
- Fallback: overwrites with zeros
- Designed for one-time use on disposable hardware
- No persistent state

