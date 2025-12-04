# Protosyte Automation Scripts

This directory contains automation scripts for managing the Protosyte framework.

## Available Scripts

### `setup-env.sh`
**Purpose**: Initial environment setup and dependency checking

**Usage**:
```bash
./scripts/setup-env.sh
```

**What it does**:
- Creates `.env` file from template
- Checks for required dependencies (Rust, Go, Node.js, Tor)
- Installs Next.js dependencies if needed
- Creates necessary directories

### `build-all.sh`
**Purpose**: Build all Protosyte components

**Usage**:
```bash
./scripts/build-all.sh
```

**What it builds**:
- Silent Seed (Linux, Windows, macOS)
- Broadcast Engine
- Analysis Rig
- Legal Bridge
- AdaptixC2 Bridge (if present)

### `start-all.sh`
**Purpose**: Start all Protosyte services

**Usage**:
```bash
./scripts/start-all.sh
```

**What it starts**:
- Broadcast Engine (port 8081)
- Analysis Rig API Server (port 8080) - backend for Next.js
- Next.js Dashboard (port 3000, if installed) - primary interface
- AdaptixC2 Bridge (port 8082, if configured)

**Requirements**:
- Environment variables set (see `.env` file)
- Components built (run `build-all.sh` first)

**Output**:
- Service logs in `/tmp/protosyte-*.log`
- PID files in `/tmp/protosyte-*.pid`

### `stop-all.sh`
**Purpose**: Stop all running Protosyte services

**Usage**:
```bash
./scripts/stop-all.sh
```

**What it stops**:
- All services started by `start-all.sh`
- Cleans up PID files
- Kills any remaining processes

### `test-all.sh`
**Purpose**: Run all test suites

**Usage**:
```bash
./scripts/test-all.sh
```

**What it tests**:
- Silent Seed (Rust tests)
- Broadcast Engine (Go tests)
- Analysis Rig (Go tests)
- Legal Bridge (Go tests)
- AdaptixC2 Bridge (Go tests)
- AI Integration (Go tests)

## Quick Workflow

### First Time Setup
```bash
# 1. Setup environment
./scripts/setup-env.sh

# 2. Edit .env file with your configuration
nano .env

# 3. Build everything
./scripts/build-all.sh

# 4. Run tests
./scripts/test-all.sh
```

### Daily Development
```bash
# Start all services
./scripts/start-all.sh

# ... do your work ...

# Stop all services
./scripts/stop-all.sh
```

## Service URLs

When all services are running:

- **Next.js Dashboard**: http://localhost:3000 (primary interface)
- **API Server**: http://localhost:8080 (backend API for Next.js)
- **Broadcast Engine**: http://localhost:8081 (internal)
- **AdaptixC2 Bridge**: http://localhost:8082 (if configured)

## CLI Commands

**📖 Complete CLI Reference**: See `docs/CLI_COMMANDS.md` for detailed documentation of all commands.

### Analysis Rig CLI

```bash
# View statistics
export PROTOSYTE_PASSPHRASE="your_passphrase"
./analysis-rig/protosyte-rig --mode stats

# List records
./analysis-rig/protosyte-rig --mode records --limit 100

# List unique hosts
./analysis-rig/protosyte-rig --mode hosts

# Generate FIP
./analysis-rig/protosyte-rig --mode fip --format json

# Mission information
./analysis-rig/protosyte-rig --mode mission

# AdaptixC2 status
./analysis-rig/protosyte-rig --mode adaptixc2

# Show help
./analysis-rig/protosyte-rig --help
```

All commands support `--format json` for JSON output.

### VM Management

```bash
# Start VM
./scripts/rig_start.sh

# Enable WAN (for retrieval)
./scripts/vm-manage.sh enable-wan

# Disable WAN (isolate VM)
./scripts/vm-manage.sh disable-wan

# Revert to baseline
./scripts/rig_destroy.sh
```

## Log Files

All service logs are written to `/tmp/`:

- `/tmp/protosyte-broadcast.log` - Broadcast Engine
- `/tmp/protosyte-rig.log` - Analysis Rig
- `/tmp/protosyte-nextjs.log` - Next.js Dashboard
- `/tmp/protosyte-adaptixc2.log` - AdaptixC2 Bridge

## Troubleshooting

### Port Already in Use
If a port is already in use, the script will skip starting that service. Check what's using the port:
```bash
lsof -i :8080  # Check port 8080
```

### Services Not Starting
1. Check environment variables: `cat .env`
2. Check logs: `tail -f /tmp/protosyte-*.log`
3. Verify builds: `./scripts/build-all.sh`

### Permission Denied
Make scripts executable:
```bash
chmod +x scripts/*.sh
```

## Integration with Component READMEs

Each component's README includes references to these scripts:
- `analysis-rig/README.md` - Analysis Rig automation
- `broadcast-engine/README.md` - Broadcast Engine automation
- `legal-bridge/README.md` - Legal Bridge automation
- `protosyte-adaptixc2/README.md` - AdaptixC2 automation

