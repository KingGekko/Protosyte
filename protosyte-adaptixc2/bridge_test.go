package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestNewAdaptixC2Bridge(t *testing.T) {
	bridge := NewAdaptixC2Bridge("https://test.example.com", "test-api-key")
	
	if bridge == nil {
		t.Fatal("NewAdaptixC2Bridge returned nil")
	}
	
	if bridge.ServerURL != "https://test.example.com" {
		t.Errorf("Expected ServerURL=https://test.example.com, got %s", bridge.ServerURL)
	}
	
	if bridge.APIKey != "test-api-key" {
		t.Errorf("Expected APIKey=test-api-key, got %s", bridge.APIKey)
	}
	
	if bridge.Client == nil {
		t.Error("Expected HTTP client to be initialized")
	}
	
	if bridge.Agents == nil {
		t.Error("Expected Agents map to be initialized")
	}
}

func TestAdaptixC2BridgeAgents(t *testing.T) {
	bridge := NewAdaptixC2Bridge("https://test.example.com", "test-api-key")
	
	// Test agent map operations
	agent := &Agent{
		ID:       "agent-123",
		Hostname: "test-host",
		IP:       "192.168.1.1",
		OS:       "linux",
		Status:   "active",
		LastSeen: time.Now(),
	}
	
	bridge.Agents["agent-123"] = agent
	
	if bridge.Agents["agent-123"] == nil {
		t.Error("Expected agent to be stored")
	}
	
	if bridge.Agents["agent-123"].ID != "agent-123" {
		t.Errorf("Expected agent ID=agent-123, got %s", bridge.Agents["agent-123"].ID)
	}
}

func TestCommandResult(t *testing.T) {
	result := &CommandResult{
		AgentID:   "agent-123",
		Command:   "ls -la",
		Output:    "test output",
		Error:     "",
		ExitCode:  0,
		Timestamp: time.Now(),
	}
	
	if result.AgentID != "agent-123" {
		t.Errorf("Expected AgentID=agent-123, got %s", result.AgentID)
	}
	
	if result.ExitCode != 0 {
		t.Errorf("Expected ExitCode=0, got %d", result.ExitCode)
	}
}

func TestProtosyteIntelligence(t *testing.T) {
	intel := ProtosyteIntelligence{
		AgentID: "agent-123",
		Credentials: []Credential{
			{
				Type:     "password",
				Username: "testuser",
				Password: "testpass",
				Domain:   "test.com",
				Source:   "captured",
			},
		},
		NetworkFlows: []NetworkFlow{},
		FileMetadata: []FileMetadata{},
		CollectedAt:  time.Now(),
	}
	
	if intel.AgentID != "agent-123" {
		t.Errorf("Expected AgentID=agent-123, got %s", intel.AgentID)
	}
	
	if len(intel.Credentials) != 1 {
		t.Errorf("Expected 1 credential, got %d", len(intel.Credentials))
	}
	
	if intel.Credentials[0].Username != "testuser" {
		t.Errorf("Expected Username=testuser, got %s", intel.Credentials[0].Username)
	}
}

func TestCredentialStructure(t *testing.T) {
	cred := Credential{
		Type:     "password",
		Username: "user",
		Password: "pass",
		Domain:   "domain",
		Source:   "source",
	}
	
	if cred.Type != "password" {
		t.Errorf("Expected Type=password, got %s", cred.Type)
	}
}

func TestNetworkFlowStructure(t *testing.T) {
	flow := NetworkFlow{
		SourceIP:   "192.168.1.1",
		DestIP:     "192.168.1.2",
		SourcePort: 8080,
		DestPort:   443,
		Protocol:   "TCP",
		Timestamp:  time.Now(),
	}
	
	if flow.SourceIP != "192.168.1.1" {
		t.Errorf("Expected SourceIP=192.168.1.1, got %s", flow.SourceIP)
	}
}

func TestFileMetadataStructure(t *testing.T) {
	metadata := FileMetadata{
		Path:     "/path/to/file",
		Size:     1024,
		Modified: time.Now(),
		Hash:     "abc123",
	}
	
	if metadata.Path != "/path/to/file" {
		t.Errorf("Expected Path=/path/to/file, got %s", metadata.Path)
	}
}

func TestSeedDeployer(t *testing.T) {
	deployer := &SeedDeployer{
		SeedBinaryPath: "/path/to/seed",
		BuildPath:      "/path/to/build",
	}
	
	if deployer.SeedBinaryPath != "/path/to/seed" {
		t.Errorf("Expected SeedBinaryPath=/path/to/seed, got %s", deployer.SeedBinaryPath)
	}
}

func TestRigConnector(t *testing.T) {
	connector := &RigConnector{
		RigURL: "http://localhost:8080",
		Client: &http.Client{},
	}
	
	if connector.RigURL != "http://localhost:8080" {
		t.Errorf("Expected RigURL=http://localhost:8080, got %s", connector.RigURL)
	}
}

func TestListActiveAgents(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/agents" {
			t.Errorf("Expected /api/agents, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":"agent-1","os":"linux","status":"active"}]`))
	}))
	defer server.Close()
	
	bridge := NewAdaptixC2Bridge(server.URL, "test-key")
	agents, err := bridge.ListActiveAgents()
	
	if err != nil {
		t.Fatalf("ListActiveAgents failed: %v", err)
	}
	
	if len(agents) != 1 {
		t.Errorf("Expected 1 agent, got %d", len(agents))
	}
	
	if agents[0].ID != "agent-1" {
		t.Errorf("Expected agent ID=agent-1, got %s", agents[0].ID)
	}
}

func TestListActiveAgentsError(t *testing.T) {
	// Create a mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	
	bridge := NewAdaptixC2Bridge(server.URL, "test-key")
	_, err := bridge.ListActiveAgents()
	
	if err == nil {
		t.Error("Expected error from ListActiveAgents")
	}
}

func TestExecuteCommand(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"output":"test output","error":"","exit_code":0}`))
	}))
	defer server.Close()
	
	bridge := NewAdaptixC2Bridge(server.URL, "test-key")
	result, err := bridge.ExecuteCommand("agent-1", "ls -la")
	
	if err != nil {
		t.Fatalf("ExecuteCommand failed: %v", err)
	}
	
	if result.Output != "test output" {
		t.Errorf("Expected output=test output, got %s", result.Output)
	}
}

func TestUploadFile(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("test content")
	tmpFile.Close()
	
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	
	bridge := NewAdaptixC2Bridge(server.URL, "test-key")
	err = bridge.UploadFile("agent-1", tmpFile.Name(), "/tmp/remote.txt")
	
	if err != nil {
		t.Fatalf("UploadFile failed: %v", err)
	}
}

func TestUploadFileError(t *testing.T) {
	bridge := NewAdaptixC2Bridge("https://test.example.com", "test-key")
	
	// Try to upload non-existent file
	err := bridge.UploadFile("agent-1", "/nonexistent/file", "/tmp/remote.txt")
	
	if err == nil {
		t.Error("Expected error when uploading non-existent file")
	}
}

func TestDeployProtosyte(t *testing.T) {
	// This test would require more complex mocking
	// For now, just test the structure
	bridge := NewAdaptixC2Bridge("https://test.example.com", "test-key")
	bridge.Agents["agent-1"] = &Agent{
		ID:   "agent-1",
		OS:   "linux",
		Status: "active",
	}
	
	// DeployProtosyte would need actual seed binary and agent
	// This is a placeholder test
	t.Log("DeployProtosyte test placeholder - requires seed binary")
}

func TestFeedIntelligence(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	
	bridge := NewAdaptixC2Bridge(server.URL, "test-key")
	intel := ProtosyteIntelligence{
		AgentID:     "agent-1",
		Credentials: []Credential{},
		NetworkFlows: []NetworkFlow{},
		FileMetadata: []FileMetadata{},
		CollectedAt:  time.Now(),
	}
	
	err := bridge.FeedIntelligence("agent-1", intel)
	
	if err != nil {
		t.Fatalf("FeedIntelligence failed: %v", err)
	}
}

func TestFeedIntelligenceError(t *testing.T) {
	// Create a mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	
	bridge := NewAdaptixC2Bridge(server.URL, "test-key")
	intel := ProtosyteIntelligence{
		AgentID:     "agent-1",
		Credentials: []Credential{},
		NetworkFlows: []NetworkFlow{},
		FileMetadata: []FileMetadata{},
		CollectedAt:  time.Now(),
	}
	
	err := bridge.FeedIntelligence("agent-1", intel)
	
	if err == nil {
		t.Error("Expected error from FeedIntelligence")
	}
}
