# Component B: The Broadcast Engine

Go-based Telegram bot that acts as a stateless dead-drop for encrypted payloads.

## Quick Start

### Using Automation Scripts

```bash
# Setup environment (first time)
./scripts/setup-env.sh

# Build
./scripts/build-all.sh

# Start all services (includes broadcast engine)
./scripts/start-all.sh

# Or start individually
cd broadcast-engine
go build -o protosyte-broadcast .
export PROTOSYTE_BOT_TOKEN="your_token"
./protosyte-broadcast
```

### Manual Setup

1. Create a bot via @BotFather
2. Set environment variable: `export PROTOSYTE_BOT_TOKEN=your_token`
3. Build: `go build -o protosyte-broadcast .`
4. Run: `./protosyte-broadcast`

## Deployment

Designed for ephemeral cloud platforms (Fly.io, Render, etc.):

```bash
# Example: Fly.io deployment
fly secrets set PROTOSYTE_BOT_TOKEN=your_token
fly deploy
```

## Local Development

The broadcast engine runs on port 8081 by default (if configured). It automatically:
- Receives encrypted payloads from Silent Seed implants
- Deletes messages after 30 seconds (retrieval window)
- Monitors for unauthorized access
- Logs only message IDs and timestamps (no content)

## Security

- Messages are automatically deleted after 30 seconds
- Bot monitors for unauthorized access
- No content logging
- Stateless operation (no persistent storage)

