# Ollama AI Integration Guide

## Overview

Ollama AI integration provides **automated initial access** capabilities for Protosyte campaigns. It uses local LLM models to analyze targets, research CVEs, generate exploits, and automate exploitation attempts.

---

## Architecture

```
┌─────────────────┐
│  Reconnaissance │  ← Port scans, service detection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Ollama AI      │  ← Target analysis, CVE research
│  (Local LLM)    │     Exploit generation
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Exploitation   │  ← Automated exploit attempts
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Initial Access │  ← Successful exploitation
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Protosyte Seed │  ← Deploy passive collection
└─────────────────┘
```

---

## Integration Points

### 1. **Standalone Component**

Ollama AI is currently a **standalone component** that can be used independently:

```bash
cd protosyte-ai
go run ollama_integration.go
```

**Use Case**: Manual initial access automation before deploying Protosyte.

### 2. **Pre-Campaign Phase**

Ollama runs **before** Protosyte deployment:

1. **Reconnaissance** → Gather target information
2. **Ollama Analysis** → AI analyzes target, finds CVEs, generates exploits
3. **Exploitation** → Automated exploit attempts
4. **Initial Access** → If successful, deploy Protosyte Silent Seed

### 3. **Workflow Integration**

```
Phase 1: Reconnaissance
├── Port scanning (nmap, masscan)
├── Service detection (nmap -sV)
└── Web enumeration (gobuster, dirb)

Phase 2: AI Analysis (Ollama)
├── Target analysis
├── CVE research (NVD, MITRE, Exploit-DB, GitHub)
├── Exploit generation
└── Attack vector prioritization

Phase 3: Automated Exploitation
├── Web application attacks
├── Server-side exploits
└── Social engineering (content generation)

Phase 4: Initial Access
└── Deploy Protosyte Silent Seed

Phase 5: Passive Collection
└── Protosyte collects intelligence
```

---

## How Ollama Works

### 1. **Target Analysis**

```go
client := NewOllamaClient("http://localhost:11434", "llama3.2")

targetInfo := `
IP: 197.243.17.150
Services: Apache 2.4.62, OpenSSL 3.1.7
Applications: Java-based procurement system
`

analysis, err := client.AnalyzeTarget(targetInfo)
```

**What it does**:
- Extracts software versions from target info
- Searches for CVEs related to detected software
- Queries multiple sources (NVD, MITRE, Exploit-DB, GitHub, Web)
- Uses AI to analyze vulnerabilities and suggest attack vectors
- Returns structured analysis with confidence scores

### 2. **CVE Research**

Ollama automatically searches multiple sources:

**NVD (National Vulnerability Database)**:
- Official CVE details
- CVSS scores and severity
- Descriptions

**MITRE CVE Database**:
- CVE descriptions
- References

**Exploit-DB**:
- Exploit code
- Proof-of-concepts

**GitHub**:
- Community POCs
- Exploit repositories
- **Requires approval before download**

**Web Search**:
- General vulnerability research
- Latest exploit information

### 3. **Exploit Generation**

```go
payload, err := client.GenerateExploitPayload(
    "CVE-2024-42516",
    targetInfo,
)
```

**What it does**:
- Researches CVE details
- Searches for exploit code
- Uses AI to generate working payload
- Provides execution steps

### 4. **Automated Exploitation**

```go
results, err := client.AutomateExploitation(analysis)

for _, result := range results {
    if result.Success {
        // Initial access achieved
        deployProtosyte(result.Output)
    }
}
```

**What it does**:
- Attempts exploitation based on AI recommendations
- Tests web application vulnerabilities
- Executes server-side exploits
- Reports success/failure

---

## Configuration

### Environment Variables

```bash
export OLLAMA_HOST="http://localhost:11434"
export OLLAMA_MODEL="llama3.2"
export OLLAMA_TEMPERATURE="0.7"
export OLLAMA_TOP_P="0.9"
```

### Mission.yaml Integration (Future)

Currently, Ollama doesn't read from `mission.yaml`, but it could be integrated:

```yaml
ai:
  enabled: true
  ollama_host: "http://localhost:11434"
  ollama_model: "llama3.2"
  auto_exploit: false  # Require manual approval
  cve_research: true
  github_auto_approve: false  # Always require approval
```

---

## Integration with Other Components

### 1. **AdaptixC2 Integration**

Ollama can feed intelligence to AdaptixC2:

```go
// After Ollama analysis
analysis, _ := client.AnalyzeTarget(targetInfo)

// Feed to AdaptixC2
adaptixBridge.FeedIntelligence(agentID, ProtosyteIntelligence{
    Vulnerabilities: analysis.Vulnerabilities,
    AttackVectors: analysis.AttackVectors,
})
```

### 2. **Protosyte Seed Deployment**

After successful exploitation:

```go
results, _ := client.AutomateExploitation(analysis)

for _, result := range results {
    if result.Success {
        // Deploy Protosyte Silent Seed
        deployProtosyteSeed(result.Output)
    }
}
```

### 3. **Analysis Rig Integration**

Ollama analysis results can be stored in Analysis Rig:

```go
// Store AI analysis in database
intelRecord := &IntelligenceRecord{
    DataType: "AI_ANALYSIS",
    IOCs: json.Marshal(analysis.Vulnerabilities),
}
analyzer.db.Create(intelRecord)
```

---

## Complete Workflow Example

### Step 1: Reconnaissance

```bash
# Port scan
nmap -sV -p- 197.243.17.150 > scan_results.txt

# Web enumeration
gobuster dir -u https://197.243.17.150 -w wordlist.txt >> scan_results.txt
```

### Step 2: AI Analysis

```bash
cd protosyte-ai
go run ollama_integration.go
```

**Output**:
```
Searching for CVEs related to Apache 2.4.62...
Found 8 CVEs: [CVE-2024-42516, CVE-2024-43204, ...]

AI Analysis Complete:
Vulnerabilities Found: 8
Attack Vectors: 5

AI-Generated Exploit for CVE-2024-42516:
[Exploit payload here]
```

### Step 3: Exploitation

```bash
# Execute AI-generated exploit
./exploit.sh CVE-2024-42516
```

### Step 4: Deploy Protosyte

```bash
# After successful exploitation
cd ../protosyte-seed
LD_PRELOAD=./libprotosyte.so /path/to/target_app
```

### Step 5: Passive Collection

Protosyte automatically collects intelligence and exfiltrates.

---

## Key Features

### 1. **Multi-Source CVE Research**

Ollama searches:
- ✅ NVD (official CVE database)
- ✅ MITRE CVE database
- ✅ Exploit-DB (exploit code)
- ✅ GitHub (community POCs)
- ✅ Web search (latest information)

### 2. **GitHub Download Safety**

**By default, all GitHub downloads require explicit approval**:

```
⚠️  GITHUB DOWNLOAD REQUEST ⚠️
Repository: user/exploit-repo
Description: POC for CVE-2024-42516
Stars: 42 | Language: Python
URL: https://github.com/user/exploit-repo

⚠️  WARNING: Downloading code from untrusted sources can be dangerous!
Download this repository? [y/N]:
```

**Auto-approve (DANGEROUS)**:
```go
client.SetAutoApprove(true)  // ⚠️ Only in trusted environments
```

### 3. **AI-Powered Analysis**

- Analyzes target reconnaissance data
- Identifies vulnerabilities automatically
- Prioritizes attack vectors by confidence
- Generates specific exploit payloads
- Provides exploitation steps

### 4. **Automated Exploitation**

- Attempts web application attacks
- Executes server-side exploits
- Tests multiple attack vectors
- Reports success/failure

---

## Model Selection

### For Vulnerability Analysis

**Recommended**: `llama3.2` or `mistral`
- Fast responses
- Good structured output
- Technical analysis

### For Exploit Generation

**Recommended**: `codellama` or `deepseek-coder`
- Code generation
- Exploit development
- Technical accuracy

### For Social Engineering

**Recommended**: `llama3.2` or `mistral`
- Natural language generation
- Context-aware content
- Balanced creativity

---

## Security Considerations

⚠️ **IMPORTANT**:

1. **Authorization Required**: Only use for authorized penetration testing
2. **Review AI Output**: AI may generate incorrect or dangerous commands
3. **Validate Exploits**: Always test exploits in isolated environments first
4. **GitHub Safety**: Never auto-approve GitHub downloads
5. **Model Limitations**: LLMs can hallucinate or provide incorrect information

---

## Limitations

1. **Model Accuracy**: LLMs can provide incorrect information
2. **Context Window**: Limited by model's context size
3. **Speed**: Local inference may be slower than cloud APIs
4. **Resource Usage**: Requires significant RAM/GPU for larger models
5. **No Direct Integration**: Currently standalone, not integrated with mission.yaml

---

## Mission.yaml Integration ✅

### Configuration

```yaml
ai:
  enabled: true
  ollama_host: "http://localhost:11434"  # Or from OLLAMA_HOST env var
  ollama_model: "llama3.2"  # Or from OLLAMA_MODEL env var
  auto_exploit: false  # Require manual approval
  cve_research: true  # Enable automatic CVE lookups
  github_auto_approve: false  # Always require approval
```

### Usage with Mission.yaml

```bash
# Run with mission.yaml
cd protosyte-ai
go run ollama_integration.go --mission ../mission.yaml

# Or use automation script
./scripts/ai-analyze.sh
```

### Environment Variable Override

Environment variables override mission.yaml settings:
- `OLLAMA_HOST` → `ai.ollama_host`
- `OLLAMA_MODEL` → `ai.ollama_model`

## Component Integration ✅

### 1. Analysis Rig Integration

AI analysis results can be stored in the Analysis Rig database:

```go
// Store AI analysis
analyzer.StoreAIAnalysis(
    missionID,
    targetIP,
    targetInfo,
    vulnerabilities,
    attackVectors,
)

// Retrieve AI analysis
records, _ := analyzer.GetAIAnalysis(missionID)
```

**API Endpoints**:
- `GET /api/ai/analysis?mission_id=0xDEADBEEFCAFEBABE` - Get AI analysis
- `POST /api/ai/analysis` - Store AI analysis

### 2. AdaptixC2 Integration

AI analysis can be fed to AdaptixC2 operators:

```go
// Analyze target with AI
analysis, _ := bridge.IntegrateWithOllamaAI(targetInfo)

// Feed to AdaptixC2
bridge.FeedIntelligence(agentID, ProtosyteIntelligence{
    Vulnerabilities: analysis.Vulnerabilities,
    AttackVectors: analysis.AttackVectors,
})
```

**API Endpoint**:
- `POST /api/ai/analyze` - Analyze target with AI

### 3. Dashboard Integration

AI analysis displayed in dashboard:
- View AI analysis results
- See vulnerabilities and attack vectors
- Review exploitation recommendations

### 4. Complete Workflow

```
1. Reconnaissance → Gather target info
2. AI Analysis (Ollama) → Analyze with mission.yaml
3. Store Results → Save to Analysis Rig
4. Feed to AdaptixC2 → Share with operators
5. Exploitation → Use AI recommendations
6. Deploy Protosyte → After initial access
```

---

## Troubleshooting

### Ollama Not Running

```bash
# Start Ollama service
ollama serve

# Or run in background
nohup ollama serve > /dev/null 2>&1 &
```

### Model Not Found

```bash
# List available models
ollama list

# Pull required model
ollama pull llama3.2
```

### Slow Responses

- Use smaller models (`llama3.2` instead of `llama3`)
- Reduce temperature for faster responses
- Use GPU acceleration if available

---

## Example Output

```
Searching for CVEs related to Apache 2.4.62...
Found 8 CVEs for Apache 2.4.62: [CVE-2024-42516, CVE-2024-43204, ...]

Researching CVE: CVE-2024-42516...
CVE Details:
=== CVE-2024-42516 ===
NVD: CVE-2024-42516
Severity: MODERATE (CVSS: 5.3)
Description: HTTP response splitting in Apache HTTP Server...

Exploit-DB: Found 1 exploits:
Exploit ID: 12345 - Apache 2.4.62 HTTP Response Splitting

GitHub POCs found:
- user/exploit-repo (42 stars, Python): POC for CVE-2024-42516
  https://github.com/user/exploit-repo

AI Analysis Complete:
Vulnerabilities Found: 8
Attack Vectors: 5

AI-Generated Exploit for CVE-2024-42516:
Based on CVE research, here's the exploit:
curl -H "Content-Type: text/html\r\n\r\n<script>alert('XSS')</script>" \
  https://197.243.17.150/vulnerable-endpoint

Exploitation Results:
Vector: web_app, Success: false
Vector: server_exploit, Success: true
```

---

## References

- [Ollama Documentation](https://ollama.com/docs)
- [Ollama API](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [Model Library](https://ollama.com/library)
- `protosyte-ai/README.md` - Component-specific documentation

---

**Last Updated**: 2025-12-03  
**Status**: Standalone component, future integration planned

