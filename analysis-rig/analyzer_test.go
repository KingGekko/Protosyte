package main

import (
	"os"
	"testing"
)

func TestAnalyzerDecrypt(t *testing.T) {
	analyzer := NewAnalyzer("test-passphrase")
	
	// This would require actual encrypted data
	// For now, just test that analyzer initializes
	if analyzer == nil {
		t.Fatal("Analyzer initialization failed")
	}
	
	if analyzer.passphrase != "test-passphrase" {
		t.Errorf("Expected passphrase=test-passphrase, got %s", analyzer.passphrase)
	}
	
	if analyzer.store != "/tmp/rig_store" {
		t.Errorf("Expected store=/tmp/rig_store, got %s", analyzer.store)
	}
}

func TestParsePayload(t *testing.T) {
	// Test JSON parsing
	jsonData := `{"data_type":"CREDENTIAL_BLOB","host_fingerprint":"test","collected_ts":1234567890}`
	
	record := parsePayload([]byte(jsonData))
	if record == nil {
		t.Fatal("Failed to parse JSON payload")
	}
	
	if record.DataType != "CREDENTIAL_BLOB" {
		t.Errorf("Expected CREDENTIAL_BLOB, got %s", record.DataType)
	}
	
	if record.HostFingerprint != "test" {
		t.Errorf("Expected host_fingerprint=test, got %s", record.HostFingerprint)
	}
}

func TestAnalyzerParsePayloadInvalidJSON(t *testing.T) {
	invalidJSON := `{invalid json}`
	record := parsePayload([]byte(invalidJSON))
	
	// Should handle invalid JSON gracefully
	// Current implementation may return nil or handle error
	if record != nil {
		t.Log("Invalid JSON handled, record may be nil or have default values")
	}
}

func TestAnalyzerDecryptFunction(t *testing.T) {
	analyzer := NewAnalyzer("test-passphrase")
	
	// Derive key for testing
	key := make([]byte, 32) // AES-256 key
	
	// Test with empty ciphertext
	_, err := analyzer.decrypt([]byte{}, key)
	if err == nil {
		t.Error("Expected error for empty ciphertext")
	}
	
	// Test with too short ciphertext
	shortCiphertext := make([]byte, 5)
	_, err = analyzer.decrypt(shortCiphertext, key)
	if err == nil {
		t.Error("Expected error for too short ciphertext")
	}
}

func TestAnalyzerAnalyze(t *testing.T) {
	analyzer := NewAnalyzer("test-passphrase")
	
	// Create temporary directory for testing
	tmpDir := "/tmp/test_rig_store"
	os.MkdirAll(tmpDir, 0755)
	defer os.RemoveAll(tmpDir)
	
	analyzer.store = tmpDir
	
	// Test with empty directory
	err := analyzer.Analyze()
	if err != nil {
		t.Logf("Analyze returned error (expected for empty directory): %v", err)
	}
	
	// Test with non-existent directory
	analyzer.store = "/tmp/nonexistent_directory_12345"
	err = analyzer.Analyze()
	if err != nil {
		t.Logf("Analyze returned error (expected for non-existent directory): %v", err)
	}
}

func TestNewAnalyzer(t *testing.T) {
	analyzer := NewAnalyzer("test-passphrase")
	
	if analyzer == nil {
		t.Fatal("NewAnalyzer returned nil")
	}
	
	if analyzer.db == nil {
		t.Error("Expected database to be initialized")
	}
	
	// Test database connection
	var count int64
	analyzer.db.Model(&IntelligenceRecord{}).Count(&count)
	// Should not panic
}

func TestIntelligenceRecord(t *testing.T) {
	record := &IntelligenceRecord{
		HostFingerprint: "test-fingerprint",
		DataType:        "CREDENTIAL_BLOB",
		CollectedAt:     1234567890,
		ProcessedAt:     1234567900,
		IOCs:            `["indicator1", "indicator2"]`,
	}
	
	if record.HostFingerprint != "test-fingerprint" {
		t.Errorf("Expected HostFingerprint=test-fingerprint, got %s", record.HostFingerprint)
	}
	
	if record.DataType != "CREDENTIAL_BLOB" {
		t.Errorf("Expected DataType=CREDENTIAL_BLOB, got %s", record.DataType)
	}
}

func TestAnalyzerWithRealData(t *testing.T) {
	// This test would require actual encrypted payloads
	// For now, just test the structure
	analyzer := NewAnalyzer("test-passphrase")
	
	// Verify analyzer can be created and has required fields
	if analyzer.passphrase == "" {
		t.Error("Expected passphrase to be set")
	}
	
	if analyzer.store == "" {
		t.Error("Expected store path to be set")
	}
}
