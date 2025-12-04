// AdaptixC2 Bridge Main Entry Point
// Provides HTTP API for AdaptixC2 integration

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"protosyte.io/mission-config"
)

var bridge *AdaptixC2Bridge

func main() {
	missionPath := flag.String("mission", "", "Path to mission.yaml (default: ./mission.yaml or ../mission.yaml)")
	flag.Parse()

	// Load mission configuration
	missionConfig, err := mission.LoadMissionConfig(*missionPath)
	if err != nil {
		log.Printf("[ADAPTIX] Warning: Failed to load mission.yaml: %v (using environment variables)", err)
		missionConfig = nil
	} else if missionConfig != nil {
		log.Printf("[ADAPTIX] Loaded mission: %s (ID: %s)", missionConfig.Mission.Name, missionConfig.Mission.ID)
	}

	// Get AdaptixC2 configuration from mission.yaml or environment
	var serverURL, apiKey string
	
	if missionConfig != nil && missionConfig.IsAdaptixC2Enabled() {
		serverURL = missionConfig.AdaptixC2.Server
		apiKey = missionConfig.AdaptixC2.APIKey
		log.Printf("[ADAPTIX] Using AdaptixC2 configuration from mission.yaml")
	}

	// Fallback to environment variables
	if serverURL == "" {
		serverURL = os.Getenv("ADAPTIXC2_SERVER_URL")
	}
	if apiKey == "" {
		apiKey = os.Getenv("ADAPTIXC2_API_KEY")
	}

	if serverURL == "" {
		log.Fatal("ADAPTIXC2_SERVER_URL not set in mission.yaml or ADAPTIXC2_SERVER_URL environment variable")
	}

	if apiKey == "" {
		log.Fatal("ADAPTIXC2_API_KEY not set in mission.yaml or ADAPTIXC2_API_KEY environment variable")
	}

	bridge = NewAdaptixC2Bridge(serverURL, apiKey)
	
	// Store mission config in bridge for later use
	if missionConfig != nil {
		bridge.MissionConfig = missionConfig
	}

	// Connect to AdaptixC2
	if err := bridge.Connect(); err != nil {
		log.Fatalf("Failed to connect to AdaptixC2: %v", err)
	}

	// Setup routes
	r := mux.NewRouter()
	r.HandleFunc("/api/status", handleStatus).Methods("GET")
	r.HandleFunc("/api/agents", handleGetAgents).Methods("GET")
	r.HandleFunc("/api/deploy/{agentID}", handleDeploy).Methods("POST")
	r.HandleFunc("/api/intelligence/{agentID}", handleGetIntelligence).Methods("GET")
	r.HandleFunc("/api/intelligence/{agentID}", handleFeedIntelligence).Methods("POST")
	r.HandleFunc("/api/campaign/start", handleStartCampaign).Methods("POST")
	r.HandleFunc("/api/ai/analyze", handleAIAnalyze).Methods("POST")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("AdaptixC2 Bridge listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "connected",
		"bridge": "protosyte-adaptixc2",
	})
}

func handleGetAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := bridge.GetAgents()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agents)
}

func handleDeploy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agentID"]

	if err := bridge.DeployProtosyte(agentID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "deployed",
		"agent_id": agentID,
	})
}

func handleGetIntelligence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agentID"]

	// This would retrieve intelligence from Analysis Rig
	// For now, return empty
	intel := ProtosyteIntelligence{
		AgentID:     agentID,
		CollectedAt: bridge.collectProtosyteIntelligence().CollectedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(intel)
}

func handleFeedIntelligence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	agentID := vars["agentID"]

	var intel ProtosyteIntelligence
	if err := json.NewDecoder(r.Body).Decode(&intel); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := bridge.FeedIntelligence(agentID, intel); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "fed",
	})
}

func handleStartCampaign(w http.ResponseWriter, r *http.Request) {
	if err := bridge.ExecuteIntegratedCampaign(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "started",
	})
}

func handleAIAnalyze(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetInfo string `json:"target_info"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Integrate with Ollama AI (placeholder)
	analysis, err := bridge.IntegrateWithOllamaAI(req.TargetInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(analysis)
}

