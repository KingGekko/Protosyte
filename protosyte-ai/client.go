// Ollama Client with Mission Configuration Integration
// Provides unified interface for AI-driven initial access

package ollama

import (
	"flag"
	"fmt"
	"os"

	"protosyte.io/mission-config"
)

// Client wraps OllamaClient with mission configuration
type Client struct {
	*OllamaClient
	MissionConfig *mission.MissionConfig
}

// NewClient creates a new Ollama client with mission configuration
func NewClient(missionPath string) (*Client, error) {
	// Load mission configuration
	missionConfig, err := mission.LoadMissionConfig(missionPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load mission config: %w", err)
	}

	// Check if AI is enabled
	if !missionConfig.IsAIEnabled() {
		return nil, fmt.Errorf("AI integration is not enabled in mission.yaml")
	}

	// Get Ollama configuration from mission.yaml or environment
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

	// Create Ollama client
	ollamaClient := NewOllamaClient(ollamaHost, ollamaModel)

	// Configure auto-approve based on mission config
	if missionConfig.AI.GitHubAutoApprove {
		ollamaClient.SetAutoApprove(true)
	}

	return &Client{
		OllamaClient:  ollamaClient,
		MissionConfig: missionConfig,
	}, nil
}

// AnalyzeTargetWithMission analyzes target using mission configuration
func (c *Client) AnalyzeTargetWithMission(targetInfo string) (*TargetAnalysis, error) {
	// Enhance target info with mission details
	enhancedInfo := fmt.Sprintf(`%s

Mission: %s (ID: %s)
Target OS: %s
`, targetInfo, c.MissionConfig.Mission.Name, c.MissionConfig.Mission.ID, c.MissionConfig.Target.OS)

	// Perform analysis
	analysis, err := c.AnalyzeTarget(enhancedInfo)
	if err != nil {
		return nil, err
	}

	return analysis, nil
}

// ShouldAutoExploit returns true if auto-exploitation is enabled
func (c *Client) ShouldAutoExploit() bool {
	return c.MissionConfig.AI.AutoExploit
}

// ShouldResearchCVEs returns true if CVE research is enabled
func (c *Client) ShouldResearchCVEs() bool {
	return c.MissionConfig.AI.CVEResearch
}

