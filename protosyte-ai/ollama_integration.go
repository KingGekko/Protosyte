// Ollama AI Integration for Initial Access Automation
// Uses local LLM to analyze targets and generate exploitation strategies
// Includes web search for CVE lookups and exploit research
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type OllamaClient struct {
	BaseURL string
	Model   string
	Client  *http.Client
	Search  *WebSearchClient
	AutoApprove bool // If true, auto-approves downloads (dangerous)
}

type WebSearchClient struct {
	Client *http.Client
	// Can use various search APIs: Google Custom Search, DuckDuckGo, etc.
	SearchAPI string
	APIKey    string
}

type GitHubRepo struct {
	Name        string
	FullName    string
	Description string
	URL         string
	Stars       int
	Language    string
}

type OllamaRequest struct {
	Model    string    `json:"model"`
	Prompt   string    `json:"prompt"`
	Stream   bool      `json:"stream"`
	Options  *Options  `json:"options,omitempty"`
}

type Options struct {
	Temperature float64 `json:"temperature,omitempty"`
	TopP        float64 `json:"top_p,omitempty"`
	TopK        int     `json:"top_k,omitempty"`
}

type OllamaResponse struct {
	Model              string    `json:"model"`
	CreatedAt          time.Time `json:"created_at"`
	Response           string    `json:"response"`
	Done               bool      `json:"done"`
	Context            []int     `json:"context,omitempty"`
	TotalDuration      int64     `json:"total_duration,omitempty"`
	LoadDuration       int64     `json:"load_duration,omitempty"`
	PromptEvalCount    int       `json:"prompt_eval_count,omitempty"`
	PromptEvalDuration int64     `json:"prompt_eval_duration,omitempty"`
	EvalCount          int       `json:"eval_count,omitempty"`
	EvalDuration       int64     `json:"eval_duration,omitempty"`
}

type TargetAnalysis struct {
	IP           string
	Services     []Service
	Vulnerabilities []Vulnerability
	AttackVectors []AttackVector
	Recommendations []string
}

type Service struct {
	Port    int
	Proto   string
	Banner  string
	Version string
}

type Vulnerability struct {
	CVE         string
	Severity    string
	Description string
	Exploitable bool
	ExploitPath string
}

type AttackVector struct {
	Type        string
	Confidence  float64
	Description string
	Payload     string
	Steps       []string
}

func NewOllamaClient(baseURL, model string) *OllamaClient {
	return &OllamaClient{
		BaseURL: baseURL,
		Model:   model,
		Client: &http.Client{
			Timeout: 120 * time.Second,
		},
		Search: NewWebSearchClient(),
		AutoApprove: false, // Default: require approval
	}
}

// SetAutoApprove enables/disables automatic approval of downloads
func (oc *OllamaClient) SetAutoApprove(enabled bool) {
	oc.AutoApprove = enabled
}

func NewWebSearchClient() *WebSearchClient {
	return &WebSearchClient{
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
		SearchAPI: "duckduckgo", // Default to DuckDuckGo (no API key needed)
	}
}

// SearchCVE looks up CVE information from multiple sources
func (wsc *WebSearchClient) SearchCVE(cveID string) (string, error) {
	// Search multiple sources for CVE information
	var results []string
	
	// 1. NVD (National Vulnerability Database)
	nvdInfo, err := wsc.searchNVD(cveID)
	if err == nil && nvdInfo != "" {
		results = append(results, "NVD: "+nvdInfo)
	}
	
	// 2. MITRE CVE database
	mitreInfo, err := wsc.searchMITRE(cveID)
	if err == nil && mitreInfo != "" {
		results = append(results, "MITRE: "+mitreInfo)
	}
	
	// 3. Exploit-DB for exploit code
	exploitInfo, err := wsc.searchExploitDB(cveID)
	if err == nil && exploitInfo != "" {
		results = append(results, "Exploit-DB: "+exploitInfo)
	}
	
	// 4. GitHub for POCs (search only, no download)
	githubRepos, err := wsc.searchGitHub(cveID)
	if err == nil && len(githubRepos) > 0 {
		results = append(results, formatGitHubResults(githubRepos))
	}
	
	// 5. General web search
	webInfo, err := wsc.searchWeb(cveID + " vulnerability exploit")
	if err == nil && webInfo != "" {
		results = append(results, "Web: "+webInfo)
	}
	
	return strings.Join(results, "\n\n"), nil
}

// searchNVD searches the National Vulnerability Database
func (wsc *WebSearchClient) searchNVD(cveID string) (string, error) {
	// NVD API endpoint
	nvdURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)
	
	resp, err := wsc.Client.Get(nvdURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	// Parse NVD JSON response
	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Description struct {
					DescriptionData []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description_data"`
				} `json:"description"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return "", err
	}
	
	if len(nvdResp.Vulnerabilities) == 0 {
		return "", fmt.Errorf("CVE not found in NVD")
	}
	
	vuln := nvdResp.Vulnerabilities[0]
	desc := ""
	if len(vuln.CVE.Description.DescriptionData) > 0 {
		desc = vuln.CVE.Description.DescriptionData[0].Value
	}
	
	severity := "UNKNOWN"
	score := 0.0
	if len(vuln.CVE.Metrics.CvssMetricV31) > 0 {
		score = vuln.CVE.Metrics.CvssMetricV31[0].CvssData.BaseScore
		severity = vuln.CVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
	}
	
	return fmt.Sprintf("CVE: %s\nSeverity: %s (CVSS: %.1f)\nDescription: %s", 
		vuln.CVE.ID, severity, score, desc), nil
}

// searchMITRE searches MITRE CVE database
func (wsc *WebSearchClient) searchMITRE(cveID string) (string, error) {
	mitreURL := fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cveID)
	
	resp, err := wsc.Client.Get(mitreURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	// Extract key information from MITRE page
	bodyStr := string(body)
	
	// Look for description
	descMatch := regexp.MustCompile(`(?s)<div[^>]*class="[^"]*cvedetail[^"]*"[^>]*>(.*?)</div>`).FindStringSubmatch(bodyStr)
	desc := ""
	if len(descMatch) > 1 {
		desc = cleanHTML(descMatch[1])
	}
	
	return fmt.Sprintf("MITRE: %s\nDescription: %s", cveID, desc), nil
}

// searchExploitDB searches Exploit-DB for exploit code
func (wsc *WebSearchClient) searchExploitDB(cveID string) (string, error) {
	// Exploit-DB search
	searchURL := fmt.Sprintf("https://www.exploit-db.com/search?cve=%s", cveID)
	
	resp, err := wsc.Client.Get(searchURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	// Extract exploit information
	bodyStr := string(body)
	
	// Look for exploit links
	exploitMatches := regexp.MustCompile(`href="/exploits/(\d+)"[^>]*>([^<]+)</a>`).FindAllStringSubmatch(bodyStr, -1)
	
	if len(exploitMatches) == 0 {
		return "", fmt.Errorf("No exploits found in Exploit-DB")
	}
	
	var exploits []string
	for _, match := range exploitMatches {
		if len(match) >= 3 {
			exploits = append(exploits, fmt.Sprintf("Exploit ID: %s - %s", match[1], match[2]))
		}
	}
	
	return fmt.Sprintf("Exploit-DB found %d exploits:\n%s", len(exploits), strings.Join(exploits, "\n")), nil
}

// searchGitHub searches GitHub for proof-of-concept code
// Returns repository information without downloading
func (wsc *WebSearchClient) searchGitHub(cveID string) ([]GitHubRepo, error) {
	// GitHub search API (requires token for better rate limits, but works without)
	searchURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s+exploit+poc", url.QueryEscape(cveID))
	
	req, err := http.NewRequest("GET", searchURL, nil)
	if err != nil {
		return nil, err
	}
	
	// GitHub API prefers User-Agent
	req.Header.Set("User-Agent", "Protosyte-AI/1.0")
	
	resp, err := wsc.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	var ghResp struct {
		Items []struct {
			Name        string `json:"name"`
			FullName    string `json:"full_name"`
			Description string `json:"description"`
			HTMLURL     string `json:"html_url"`
			Stars       int    `json:"stargazers_count"`
			Language    string `json:"language"`
		} `json:"items"`
	}
	
	if err := json.Unmarshal(body, &ghResp); err != nil {
		return nil, err
	}
	
	if len(ghResp.Items) == 0 {
		return nil, fmt.Errorf("No GitHub repos found")
	}
	
	var repos []GitHubRepo
	for _, item := range ghResp.Items[:5] { // Top 5 results
		repos = append(repos, GitHubRepo{
			Name:        item.Name,
			FullName:    item.FullName,
			Description: item.Description,
			URL:         item.HTMLURL,
			Stars:       item.Stars,
			Language:    item.Language,
		})
	}
	
	return repos, nil
}

// formatGitHubResults formats GitHub repos as string for display
func formatGitHubResults(repos []GitHubRepo) string {
	if len(repos) == 0 {
		return "No GitHub repos found"
	}
	
	var lines []string
	lines = append(lines, fmt.Sprintf("GitHub POCs found (%d):", len(repos)))
	for _, repo := range repos {
		lines = append(lines, fmt.Sprintf("- %s (%d stars, %s): %s\n  %s", 
			repo.FullName, repo.Stars, repo.Language, repo.Description, repo.URL))
	}
	return strings.Join(lines, "\n")
}

// requestGitHubDownloadApproval prompts user to approve GitHub download
func requestGitHubDownloadApproval(repo GitHubRepo) bool {
	fmt.Printf("\n⚠️  GITHUB DOWNLOAD REQUEST ⚠️\n")
	fmt.Printf("Repository: %s\n", repo.FullName)
	fmt.Printf("Description: %s\n", repo.Description)
	fmt.Printf("Stars: %d | Language: %s\n", repo.Stars, repo.Language)
	fmt.Printf("URL: %s\n", repo.URL)
	fmt.Printf("\n⚠️  WARNING: Downloading code from untrusted sources can be dangerous!\n")
	fmt.Printf("Only approve if you trust this repository and have reviewed it.\n")
	fmt.Printf("\nDownload this repository? [y/N]: ")
	
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// downloadGitHubRepo downloads a GitHub repository (with approval)
func (oc *OllamaClient) downloadGitHubRepo(repo GitHubRepo, targetDir string) error {
	// Check if auto-approve is enabled
	if !oc.AutoApprove {
		approved := requestGitHubDownloadApproval(repo)
		if !approved {
			return fmt.Errorf("download not approved by user")
		}
	} else {
		fmt.Printf("⚠️  Auto-approve enabled: Downloading %s without confirmation\n", repo.FullName)
	}
	
	// Download repository as ZIP
	zipURL := fmt.Sprintf("https://github.com/%s/archive/refs/heads/main.zip", repo.FullName)
	
	fmt.Printf("Downloading %s...\n", repo.FullName)
	
	resp, err := oc.Client.Get(zipURL)
	if err != nil {
		// Try master branch if main doesn't exist
		zipURL = fmt.Sprintf("https://github.com/%s/archive/refs/heads/master.zip", repo.FullName)
		resp, err = oc.Client.Get(zipURL)
		if err != nil {
			return fmt.Errorf("failed to download repository: %v", err)
		}
	}
	defer resp.Body.Close()
	
	// Create target directory
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}
	
	// Save ZIP file
	zipPath := fmt.Sprintf("%s/%s.zip", targetDir, repo.Name)
	file, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()
	
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save file: %v", err)
	}
	
	fmt.Printf("✅ Downloaded to: %s\n", zipPath)
	return nil
}

// DownloadApprovedGitHubRepos downloads only approved GitHub repositories
func (oc *OllamaClient) DownloadApprovedGitHubRepos(cveID string, targetDir string) ([]string, error) {
	repos, err := oc.Search.searchGitHub(cveID)
	if err != nil {
		return nil, err
	}
	
	var downloaded []string
	
	fmt.Printf("\n=== GitHub POC Repositories for %s ===\n", cveID)
	for i, repo := range repos {
		fmt.Printf("\n[%d/%d] %s\n", i+1, len(repos), repo.FullName)
		fmt.Printf("   Description: %s\n", repo.Description)
		fmt.Printf("   Stars: %d | Language: %s\n", repo.Stars, repo.Language)
		fmt.Printf("   URL: %s\n", repo.URL)
		
		err := oc.downloadGitHubRepo(repo, targetDir)
		if err != nil {
			fmt.Printf("   ❌ Download failed or not approved: %v\n", err)
			continue
		}
		
		downloaded = append(downloaded, repo.FullName)
	}
	
	return downloaded, nil
}

// searchWeb performs general web search (DuckDuckGo)
func (wsc *WebSearchClient) searchWeb(query string) (string, error) {
	// DuckDuckGo HTML search (no API key needed)
	searchURL := fmt.Sprintf("https://html.duckduckgo.com/html/?q=%s", url.QueryEscape(query))
	
	resp, err := wsc.Client.Get(searchURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	// Extract search results
	bodyStr := string(body)
	
	// Look for result links
	resultMatches := regexp.MustCompile(`<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>([^<]+)</a>`).FindAllStringSubmatch(bodyStr, -1)
	
	if len(resultMatches) == 0 {
		return "", fmt.Errorf("No web results found")
	}
	
	var results []string
	for i, match := range resultMatches {
		if i >= 5 { // Limit to 5 results
			break
		}
		if len(match) >= 3 {
			results = append(results, fmt.Sprintf("- %s: %s", match[2], match[1]))
		}
	}
	
	return fmt.Sprintf("Web search results:\n%s", strings.Join(results, "\n")), nil
}

// cleanHTML removes HTML tags from text
func cleanHTML(html string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]+>`)
	text := re.ReplaceAllString(html, " ")
	
	// Decode HTML entities (simplified)
	text = strings.ReplaceAll(text, "&nbsp;", " ")
	text = strings.ReplaceAll(text, "&amp;", "&")
	text = strings.ReplaceAll(text, "&lt;", "<")
	text = strings.ReplaceAll(text, "&gt;", ">")
	text = strings.ReplaceAll(text, "&quot;", "\"")
	
	// Clean up whitespace
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")
	return strings.TrimSpace(text)
}

// AnalyzeTarget uses Ollama to analyze target information and suggest attack vectors
// Now includes CVE lookups via web search
func (oc *OllamaClient) AnalyzeTarget(targetInfo string) (*TargetAnalysis, error) {
	// First, extract potential CVEs from target info
	cvePattern := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	cves := cvePattern.FindAllString(targetInfo, -1)
	
	// Also check for version numbers that might have CVEs
	versionPattern := regexp.MustCompile(`Apache[/\s]?(\d+\.\d+\.\d+)`)
	versions := versionPattern.FindAllStringSubmatch(targetInfo, -1)
	
	var cveInfo strings.Builder
	cveInfo.WriteString("CVE Research Results:\n\n")
	
	// Search for each CVE
	for _, cve := range cves {
		info, err := oc.Search.SearchCVE(cve)
		if err == nil {
			cveInfo.WriteString(fmt.Sprintf("=== %s ===\n%s\n\n", cve, info))
		}
	}
	
	// Search for CVEs related to versions
	for _, versionMatch := range versions {
		if len(versionMatch) >= 2 {
			version := versionMatch[1]
			searchQuery := fmt.Sprintf("Apache %s CVE vulnerability", version)
			webInfo, err := oc.Search.searchWeb(searchQuery)
			if err == nil {
				cveInfo.WriteString(fmt.Sprintf("=== Apache %s Vulnerabilities ===\n%s\n\n", version, webInfo))
			}
		}
	}
	
	// Build enhanced prompt with CVE research
	prompt := fmt.Sprintf(`You are an expert penetration tester analyzing a target for authorized security testing.

Target Information:
%s

CVE Research Results:
%s

Analyze this target and provide:
1. Identified vulnerabilities (CVEs, misconfigurations) - use the CVE research above
2. Recommended attack vectors in order of likelihood
3. Specific exploitation steps based on the CVE research
4. Exploit payloads or commands (reference the CVE research for accurate payloads)

Format your response as JSON with this structure:
{
  "vulnerabilities": [
    {
      "cve": "CVE-XXXX-XXXXX",
      "severity": "high|medium|low",
      "description": "...",
      "exploitable": true|false,
      "exploit_path": "...",
      "cve_details": "Summary from CVE research"
    }
  ],
  "attack_vectors": [
    {
      "type": "web_app|server_exploit|social_engineering",
      "confidence": 0.0-1.0,
      "description": "...",
      "payload": "...",
      "steps": ["step1", "step2"],
      "cve_reference": "CVE-XXXX-XXXXX if applicable"
    }
  ],
  "recommendations": ["rec1", "rec2"]
}

Be specific and actionable. Use the CVE research results to provide accurate exploit information. Focus on Apache 2.4.62 vulnerabilities and web application flaws.`, targetInfo, cveInfo.String())

	response, err := oc.Query(prompt)
	if err != nil {
		return nil, err
	}

	// Parse JSON response
	var analysis TargetAnalysis
	if err := json.Unmarshal([]byte(response), &analysis); err != nil {
		// If JSON parsing fails, try to extract JSON from markdown code blocks
		response = extractJSONFromResponse(response)
		if err := json.Unmarshal([]byte(response), &analysis); err != nil {
			return nil, fmt.Errorf("failed to parse AI response: %v", err)
		}
	}

	return &analysis, nil
}

// GenerateExploitPayload creates a specific exploit payload for a vulnerability
// Now includes CVE lookup for accurate exploit generation
func (oc *OllamaClient) GenerateExploitPayload(cve, targetInfo string) (string, error) {
	// First, search for CVE details and exploit code
	cveDetails, err := oc.Search.SearchCVE(cve)
	if err != nil {
		cveDetails = "CVE search failed, proceeding with general knowledge"
	}
	
	// Also search for exploit code specifically
	exploitSearch, err := oc.Search.searchWeb(cve + " exploit code poc")
	exploitInfo := ""
	if err == nil {
		exploitInfo = exploitSearch
	}
	
	prompt := fmt.Sprintf(`Generate a working exploit payload for %s.

Target Information:
%s

CVE Details:
%s

Exploit Research:
%s

Provide:
1. Exact command or payload to exploit this vulnerability (based on the CVE research)
2. Expected behavior
3. How to verify success
4. Any prerequisites or requirements

Be specific and provide executable code/commands. Reference the CVE research for accuracy.`, cve, targetInfo, cveDetails, exploitInfo)

	return oc.Query(prompt)
}

// GenerateSocialEngineeringContent creates phishing content
func (oc *OllamaClient) GenerateSocialEngineeringContent(targetOrg, context string) (string, error) {
	prompt := fmt.Sprintf(`Create a convincing but ethical (for authorized testing) social engineering email for:
Organization: %s
Context: %s

Create:
1. Subject line
2. Email body
3. Call-to-action
4. Explanation of why it's convincing

Remember this is for authorized penetration testing only.`, targetOrg, context)

	return oc.Query(prompt)
}

// AutomateExploitation attempts to exploit based on AI recommendations
func (oc *OllamaClient) AutomateExploitation(target *TargetAnalysis) ([]ExploitResult, error) {
	var results []ExploitResult

	for _, vector := range target.AttackVectors {
		if vector.Confidence < 0.6 {
			continue // Skip low-confidence vectors
		}

		result := ExploitResult{
			Vector:    vector,
			Success:   false,
			Output:    "",
			Timestamp: time.Now(),
		}

		// Execute exploit based on type
		switch vector.Type {
		case "web_app":
			result = oc.exploitWebApp(vector)
		case "server_exploit":
			result = oc.exploitServer(vector)
		case "social_engineering":
			// Generate content but don't auto-send
			content, _ := oc.GenerateSocialEngineeringContent("Rwanda Public Procurement Authority", vector.Description)
			result.Output = content
		}

		results = append(results, result)
	}

	return results, nil
}

type ExploitResult struct {
	Vector    AttackVector
	Success   bool
	Output    string
	Timestamp time.Time
}

func (oc *OllamaClient) exploitWebApp(vector AttackVector) ExploitResult {
	// Execute web application exploit
	// This would integrate with actual HTTP client
	result := ExploitResult{
		Vector:    vector,
		Success:   false,
		Timestamp: time.Now(),
	}

	// Placeholder - would execute actual HTTP requests
	result.Output = "Web app exploit attempted"
	return result
}

func (oc *OllamaClient) exploitServer(vector AttackVector) ExploitResult {
	// Execute server-side exploit
	result := ExploitResult{
		Vector:    vector,
		Success:   false,
		Timestamp: time.Now(),
	}

	// Placeholder - would execute actual exploit
	result.Output = "Server exploit attempted"
	return result
}

// Query sends a prompt to Ollama and returns the response
func (oc *OllamaClient) Query(prompt string) (string, error) {
	reqBody := OllamaRequest{
		Model:  oc.Model,
		Prompt: prompt,
		Stream: false,
		Options: &Options{
			Temperature: 0.7,
			TopP:        0.9,
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/api/generate", oc.BaseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := oc.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var ollamaResp OllamaResponse
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return "", err
	}

	return ollamaResp.Response, nil
}

// extractJSONFromResponse tries to extract JSON from markdown code blocks
func extractJSONFromResponse(response string) string {
	// Look for JSON code blocks
	start := bytes.Index([]byte(response), []byte("```json"))
	if start == -1 {
		start = bytes.Index([]byte(response), []byte("```"))
	}
	if start != -1 {
		start += 3
		end := bytes.Index([]byte(response[start:]), []byte("```"))
		if end != -1 {
			return response[start : start+end]
		}
	}

	// Look for JSON object
	start = bytes.IndexByte([]byte(response), '{')
	if start != -1 {
		end := bytes.LastIndexByte([]byte(response), '}')
		if end != -1 && end > start {
			return response[start : end+1]
		}
	}

	return response
}

// SearchForCVEs searches for CVEs related to software versions
func (oc *OllamaClient) SearchForCVEs(software, version string) ([]string, error) {
	searchQuery := fmt.Sprintf("%s %s CVE vulnerability", software, version)
	results, err := oc.Search.searchWeb(searchQuery)
	if err != nil {
		return nil, err
	}
	
	// Extract CVE IDs from results
	cvePattern := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
	cves := cvePattern.FindAllString(results, -1)
	
	// Remove duplicates
	seen := make(map[string]bool)
	var uniqueCVEs []string
	for _, cve := range cves {
		if !seen[cve] {
			seen[cve] = true
			uniqueCVEs = append(uniqueCVEs, cve)
		}
	}
	
	return uniqueCVEs, nil
}

// Main function for AI-driven initial access
func main() {
	// Parse command line flags
	missionPath := flag.String("mission", "", "Path to mission.yaml (default: ./mission.yaml or ../mission.yaml)")
	flag.Parse()

	// Try to load mission configuration
	var client *OllamaClient
	var missionConfig *mission.MissionConfig

	missionConfig, err := mission.LoadMissionConfig(*missionPath)
	if err == nil && missionConfig != nil && missionConfig.IsAIEnabled() {
		// Use mission configuration
		fmt.Printf("[AI] Loaded mission: %s (ID: %s)\n", missionConfig.Mission.Name, missionConfig.Mission.ID)
		fmt.Printf("[AI] AI integration enabled\n")

		// Get Ollama settings from mission config
		ollamaHost := missionConfig.AI.OllamaHost
		if ollamaHost == "" {
			ollamaHost = os.Getenv("OLLAMA_HOST")
			if ollamaHost == "" {
				ollamaHost = "http://localhost:11434"
			}
		}

		ollamaModel := missionConfig.AI.OllamaModel
		if ollamaModel == "" {
			ollamaModel = os.Getenv("OLLAMA_MODEL")
			if ollamaModel == "" {
				ollamaModel = "llama3.2"
			}
		}

		client = NewOllamaClient(ollamaHost, ollamaModel)

		// Configure based on mission settings
		if missionConfig.AI.GitHubAutoApprove {
			client.SetAutoApprove(true)
			fmt.Printf("[AI] ⚠️  GitHub auto-approve enabled (from mission.yaml)\n")
		}

		if !missionConfig.AI.CVEResearch {
			fmt.Printf("[AI] CVE research disabled in mission.yaml\n")
		}
	} else {
		// Fallback to environment variables
		fmt.Printf("[AI] Mission config not found or AI disabled, using environment variables\n")

		ollamaHost := os.Getenv("OLLAMA_HOST")
		if ollamaHost == "" {
			ollamaHost = "http://localhost:11434"
		}

		ollamaModel := os.Getenv("OLLAMA_MODEL")
		if ollamaModel == "" {
			ollamaModel = "llama3.2"
		}

		client = NewOllamaClient(ollamaHost, ollamaModel)
		missionConfig = nil
	}

	// Target information from reconnaissance
	targetInfo := `
IP: 197.243.17.150
Services:
  - Port 80: HTTP, Apache/2.4.62, redirects to HTTPS
  - Port 443: HTTPS, Apache/2.4.62, OpenSSL/3.1.7
    Application: Rwanda On-Line E-Procurement System
    Cookies: JSESSIONID, SCOUTER, ipmsperf_uuid
  - Port 8084: HTTP, Apache/2.4.62
    Application: e-Document System
    Login page detected
Technology: Java-based (J2EE), Apache 2.4.62, OpenSSL 3.1.7
`

	// Search for CVEs if enabled
	shouldResearchCVEs := true
	if missionConfig != nil {
		shouldResearchCVEs = missionConfig.AI.CVEResearch
	}

	if shouldResearchCVEs {
		fmt.Println("Searching for CVEs related to Apache 2.4.62...")
		apacheCVEs, err := client.SearchForCVEs("Apache", "2.4.62")
		if err == nil {
			fmt.Printf("Found %d CVEs for Apache 2.4.62: %v\n", len(apacheCVEs), apacheCVEs)
			targetInfo += fmt.Sprintf("\nKnown CVEs: %s", strings.Join(apacheCVEs, ", "))
		}

		fmt.Println("Searching for CVEs related to OpenSSL 3.1.7...")
		opensslCVEs, err := client.SearchForCVEs("OpenSSL", "3.1.7")
		if err == nil {
			fmt.Printf("Found %d CVEs for OpenSSL 3.1.7: %v\n", len(opensslCVEs), opensslCVEs)
			targetInfo += fmt.Sprintf("\nOpenSSL CVEs: %s", strings.Join(opensslCVEs, ", "))
		}
	} else {
		fmt.Println("[AI] CVE research disabled (mission.yaml)")
	}

	// Analyze target
	analysis, err := client.AnalyzeTarget(targetInfo)
	if err != nil {
		fmt.Printf("Error analyzing target: %v\n", err)
		return
	}

	fmt.Printf("AI Analysis Complete:\n")
	fmt.Printf("Vulnerabilities Found: %d\n", len(analysis.Vulnerabilities))
	fmt.Printf("Attack Vectors: %d\n", len(analysis.AttackVectors))

	// Generate exploit payloads (with CVE research)
	for _, vuln := range analysis.Vulnerabilities {
		if vuln.Exploitable {
			fmt.Printf("\nResearching CVE: %s...\n", vuln.CVE)
			cveInfo, err := client.Search.SearchCVE(vuln.CVE)
			if err == nil {
				fmt.Printf("CVE Details:\n%s\n\n", cveInfo)
			}
			
			// Check for GitHub POCs (requires approval to download)
			githubRepos, err := client.Search.searchGitHub(vuln.CVE)
			if err == nil && len(githubRepos) > 0 {
				fmt.Printf("\n📦 GitHub POC Repositories Found:\n")
				fmt.Printf("%s\n\n", formatGitHubResults(githubRepos))
				
				// Ask if user wants to download approved repos
				fmt.Printf("Would you like to download approved GitHub POCs? [y/N]: ")
				reader := bufio.NewReader(os.Stdin)
				response, _ := reader.ReadString('\n')
				if strings.TrimSpace(strings.ToLower(response)) == "y" {
					downloaded, err := client.DownloadApprovedGitHubRepos(vuln.CVE, "./exploits/"+vuln.CVE)
					if err == nil {
						fmt.Printf("\n✅ Downloaded %d approved repositories\n", len(downloaded))
					}
				}
			}
			
			payload, err := client.GenerateExploitPayload(vuln.CVE, targetInfo)
			if err == nil {
				fmt.Printf("\nAI-Generated Exploit for %s:\n%s\n", vuln.CVE, payload)
			}
		}
	}

	// Attempt automated exploitation if enabled
	shouldAutoExploit := false
	if missionConfig != nil {
		shouldAutoExploit = missionConfig.AI.AutoExploit
	}

	if shouldAutoExploit {
		fmt.Printf("\n[AI] Auto-exploitation enabled, attempting exploitation...\n")
		results, err := client.AutomateExploitation(analysis)
		if err != nil {
			fmt.Printf("Error in automated exploitation: %v\n", err)
			return
		}

		fmt.Printf("\nExploitation Results:\n")
		for _, result := range results {
			fmt.Printf("Vector: %s, Success: %v\n", result.Vector.Type, result.Success)
			if result.Success {
				fmt.Printf("✅ Initial access achieved via: %s\n", result.Vector.Type)
				if missionConfig != nil {
					fmt.Printf("Mission ID: %s\n", missionConfig.Mission.ID)
					fmt.Printf("Ready to deploy Protosyte Silent Seed\n")
				}
			}
		}
	} else {
		fmt.Printf("\n[AI] Auto-exploitation disabled (mission.yaml: auto_exploit: false)\n")
		fmt.Printf("Review attack vectors above and execute manually if needed\n")
	}
}

