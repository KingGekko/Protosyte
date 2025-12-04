# Protosyte AI Integration - Ollama for Initial Access

This module integrates Ollama AI (local LLM) to automate initial access phase of penetration testing campaigns.

## Overview

The AI integration uses local LLM models (via Ollama) to:
- Analyze target reconnaissance data
- Identify vulnerabilities and attack vectors
- Generate exploit payloads
- Automate exploitation attempts
- Create social engineering content

## Prerequisites

1. **Install Ollama**:
```bash
# Linux/macOS
curl -fsSL https://ollama.com/install.sh | sh

# Or download from https://ollama.com
```

2. **Pull a Model**:
```bash
# Recommended models for security analysis
ollama pull llama3.2        # Fast, good for structured tasks
ollama pull mistral         # Good for technical analysis
ollama pull codellama       # Best for code generation
ollama pull deepseek-coder  # Excellent for exploit generation
```

3. **Verify Installation**:
```bash
ollama list
ollama run llama3.2 "Hello, test"
```

## Usage

### Basic Target Analysis

```bash
cd protosyte-ai
go run ollama_integration.go
```

### Programmatic Usage

```go
package main

import "protosyte-ai"

func main() {
    // Initialize client
    client := ollama.NewOllamaClient("http://localhost:11434", "llama3.2")
    
    // Analyze target
    targetInfo := `
    IP: 197.243.17.150
    Services: Apache 2.4.62, OpenSSL 3.1.7
    Applications: Java-based procurement system
    `
    
    analysis, err := client.AnalyzeTarget(targetInfo)
    if err != nil {
        log.Fatal(err)
    }
    
    // Use analysis results
    for _, vector := range analysis.AttackVectors {
        fmt.Printf("Vector: %s (confidence: %.2f)\n", 
            vector.Type, vector.Confidence)
    }
}
```

## Features

### 1. CVE Research & Lookup
Automatically searches multiple sources for CVE information:
- **NVD (National Vulnerability Database)**: Official CVE details, CVSS scores
- **MITRE CVE Database**: CVE descriptions and references
- **Exploit-DB**: Exploit code and proof-of-concepts
- **GitHub**: Community POCs and exploit repositories (**requires approval to download**)
- **Web Search**: General vulnerability research

**GitHub Download Safety**:
- Lists available repositories with details
- **Requires explicit user approval** before downloading
- Shows repository info (stars, language, description) for review
- Downloads saved to `./exploits/CVE-ID/` directory

### 2. Target Analysis
Automatically analyzes reconnaissance data and identifies:
- Known vulnerabilities (CVEs) - **with real-time CVE lookups**
- Misconfigurations
- Attack vectors ranked by confidence
- Specific exploitation steps based on CVE research

### 3. Exploit Generation
Generates working exploit payloads for identified vulnerabilities:
- **Uses CVE research** for accurate exploit generation
- Apache CVE exploits (with real CVE details)
- Web application payloads
- Command injection payloads
- SQL injection payloads

### 3. Automated Exploitation
Attempts exploitation based on AI recommendations:
- Web application attacks
- Server-side exploits
- Automated testing

### 4. Social Engineering
Generates social engineering content (for authorized testing):
- Phishing emails
- Spear-phishing content
- Context-aware messaging

## Configuration

### Environment Variables

```bash
export OLLAMA_HOST="http://localhost:11434"
export OLLAMA_MODEL="llama3.2"
export OLLAMA_TEMPERATURE="0.7"  # Creativity (0.0-1.0)
export OLLAMA_TOP_P="0.9"         # Nucleus sampling
```

### Model Selection

**For Vulnerability Analysis**:
- `llama3.2` - Fast, structured responses
- `mistral` - Good technical analysis

**For Exploit Generation**:
- `codellama` - Best for code
- `deepseek-coder` - Excellent for exploits

**For Social Engineering**:
- `llama3.2` - Balanced
- `mistral` - More creative

## Integration with Protosyte Campaign

### Phase 1: AI-Driven Reconnaissance

```go
// After initial port scan
client := ollama.NewOllamaClient("http://localhost:11434", "llama3.2")

targetInfo := formatReconData(scanResults)
analysis, _ := client.AnalyzeTarget(targetInfo)

// Prioritize attack vectors
sort.Slice(analysis.AttackVectors, func(i, j int) bool {
    return analysis.AttackVectors[i].Confidence > 
           analysis.AttackVectors[j].Confidence
})
```

### Phase 2: Automated Exploitation

```go
// Attempt exploitation based on AI recommendations
results, _ := client.AutomateExploitation(analysis)

for _, result := range results {
    if result.Success {
        // Initial access achieved
        deployProtosyte(result.Output)
        break
    }
}
```

### Phase 3: Payload Generation

```go
// Generate specific exploit for CVE
payload, _ := client.GenerateExploitPayload(
    "CVE-2024-42516", 
    targetInfo,
)

// Execute payload
executeExploit(payload)
```

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
- user/exploit-repo (42 stars): POC for CVE-2024-42516
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

## Security Considerations

⚠️ **IMPORTANT**:
- Only use for authorized penetration testing
- Review all AI-generated payloads before execution
- AI may generate incorrect or dangerous commands
- Always validate AI recommendations
- Use in isolated testing environments

### GitHub Download Approval

**By default, all GitHub downloads require explicit user approval**:
- Each repository is displayed with details (name, description, stars, language)
- User must type 'y' or 'yes' to approve each download
- Downloads are saved to `./exploits/CVE-ID/` directory

**Auto-Approve (DANGEROUS)**:
```go
client.SetAutoApprove(true) // ⚠️ Only use in trusted environments
```

**Why Approval is Required**:
- GitHub repositories may contain malicious code
- POCs may be outdated or incorrect
- Always review repository before downloading
- Check repository stars, language, and description

## Limitations

1. **Model Accuracy**: LLMs can hallucinate or provide incorrect information
2. **Context Window**: Limited by model's context size
3. **Speed**: Local inference may be slower than cloud APIs
4. **Resource Usage**: Requires significant RAM/GPU for larger models

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
- Use smaller models (llama3.2 instead of llama3)
- Reduce temperature for faster responses
- Use GPU acceleration if available

## Advanced Usage

### Custom Prompts

```go
prompt := `Analyze this Apache 2.4.62 server and identify:
1. All CVEs affecting this version
2. Exploitation methods
3. Post-exploitation steps

Target: 197.243.17.150`

response, _ := client.Query(prompt)
```

### Streaming Responses

Modify `OllamaRequest` to set `Stream: true` for real-time responses.

### Multi-Model Ensemble

Use multiple models and combine results for better accuracy:

```go
models := []string{"llama3.2", "mistral", "codellama"}
results := make([]*TargetAnalysis, len(models))

for i, model := range models {
    client := NewOllamaClient("http://localhost:11434", model)
    results[i], _ = client.AnalyzeTarget(targetInfo)
}

// Combine results
finalAnalysis := combineAnalyses(results)
```

## References

- [Ollama Documentation](https://ollama.com/docs)
- [Ollama API](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [Model Library](https://ollama.com/library)

---

**Last Updated**: 2025-12-03  
**Purpose**: Research and Educational  
**Authorization**: Hypothetical - Requires Explicit Written Authorization

