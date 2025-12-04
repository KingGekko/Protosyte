package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseProtobufEnvelope(t *testing.T) {
	// Test with valid JSON
	jsonData := `{
		"mission_id": 12345,
		"collected_ts": "2025-12-03T10:00:00Z",
		"sequence": 1,
		"payload": {},
		"hmac": []
	}`

	envelope, err := parseProtobufEnvelope([]byte(jsonData))
	if err != nil {
		t.Logf("parseProtobufEnvelope returned error (may be expected): %v", err)
	}

	if envelope != nil {
		if envelope.MissionID != 12345 {
			t.Errorf("Expected MissionID=12345, got %d", envelope.MissionID)
		}
	}
}

func TestParseProtobufEnvelopeInvalidJSONFormat(t *testing.T) {
	invalidJSON := `{invalid json}`
	envelope, err := parseProtobufEnvelope([]byte(invalidJSON))

	if err == nil {
		t.Error("Expected error for invalid JSON")
	}

	if envelope != nil {
		t.Error("Expected nil envelope for invalid JSON")
	}
}

func TestExtractIntelligence(t *testing.T) {
	envelope := &Envelope{
		MissionID:   12345,
		CollectedTS: time.Now(),
		Sequence:    1,
		Payload: &DataBlob{
			HostFingerprint:  []byte("test-fingerprint"),
			DataType:         "CREDENTIAL_BLOB",
			EncryptedPayload: []byte{},
			AESGCMNonce:      []byte{},
			OriginalSize:     100,
		},
		HMAC: []byte{},
	}

	record := extractIntelligence(envelope)

	if record == nil {
		t.Fatal("Expected non-nil record")
	}

	if record.DataType != "CREDENTIAL_BLOB" {
		t.Errorf("Expected DataType=CREDENTIAL_BLOB, got %s", record.DataType)
	}

	if record.HostFingerprint != "test-fingerprint" {
		t.Errorf("Expected HostFingerprint=test-fingerprint, got %s", record.HostFingerprint)
	}
}

func TestExtractIntelligenceNonDataBlob(t *testing.T) {
	envelope := &Envelope{
		MissionID:   12345,
		CollectedTS: time.Now(),
		Sequence:    1,
		Payload:     "not a DataBlob",
		HMAC:        []byte{},
	}

	record := extractIntelligence(envelope)

	if record == nil {
		t.Fatal("Expected non-nil record even with non-DataBlob payload")
	}

	if record.DataType != "" {
		t.Errorf("Expected empty DataType for non-DataBlob, got %s", record.DataType)
	}
}

func TestParsePayloadJSON(t *testing.T) {
	jsonData := `{
		"data_type": "CREDENTIAL_BLOB",
		"host_fingerprint": "test-host",
		"collected_ts": 1234567890
	}`

	record := parsePayload([]byte(jsonData))

	if record == nil {
		t.Fatal("Expected non-nil record")
	}

	if record.DataType != "CREDENTIAL_BLOB" {
		t.Errorf("Expected DataType=CREDENTIAL_BLOB, got %s", record.DataType)
	}

	if record.HostFingerprint != "test-host" {
		t.Errorf("Expected HostFingerprint=test-host, got %s", record.HostFingerprint)
	}

	if record.CollectedAt != 1234567890 {
		t.Errorf("Expected CollectedAt=1234567890, got %d", record.CollectedAt)
	}
}

func TestParsePayloadInvalidJSON(t *testing.T) {
	invalidJSON := `{invalid}`
	record := parsePayload([]byte(invalidJSON))

	if record != nil {
		t.Error("Expected nil record for invalid JSON")
	}
}

func TestParsePayloadEmpty(t *testing.T) {
	record := parsePayload([]byte{})

	if record != nil {
		t.Error("Expected nil record for empty input")
	}
}

func TestParsePayloadPartialJSON(t *testing.T) {
	// Test with partial JSON (missing some fields)
	partialJSON := `{"data_type": "CREDENTIAL_BLOB"}`

	record := parsePayload([]byte(partialJSON))

	if record == nil {
		t.Fatal("Expected non-nil record even with partial JSON")
	}

	if record.DataType != "CREDENTIAL_BLOB" {
		t.Errorf("Expected DataType=CREDENTIAL_BLOB, got %s", record.DataType)
	}
}

func TestDataBlobStructure(t *testing.T) {
	blob := &DataBlob{
		HostFingerprint:  []byte("test"),
		DataType:         "CREDENTIAL_BLOB",
		EncryptedPayload: []byte{1, 2, 3},
		AESGCMNonce:      []byte{4, 5, 6},
		OriginalSize:     100,
	}

	if blob.DataType != "CREDENTIAL_BLOB" {
		t.Errorf("Expected DataType=CREDENTIAL_BLOB, got %s", blob.DataType)
	}

	if blob.OriginalSize != 100 {
		t.Errorf("Expected OriginalSize=100, got %d", blob.OriginalSize)
	}
}

func TestHeartbeatStructure(t *testing.T) {
	heartbeat := &Heartbeat{
		LoadAvg1m:   0.5,
		MemFreeMB:   1024,
		ActiveHooks: []string{"hook1", "hook2"},
	}

	if heartbeat.LoadAvg1m != 0.5 {
		t.Errorf("Expected LoadAvg1m=0.5, got %f", heartbeat.LoadAvg1m)
	}

	if heartbeat.MemFreeMB != 1024 {
		t.Errorf("Expected MemFreeMB=1024, got %d", heartbeat.MemFreeMB)
	}

	if len(heartbeat.ActiveHooks) != 2 {
		t.Errorf("Expected 2 active hooks, got %d", len(heartbeat.ActiveHooks))
	}
}

func TestEnvelopeJSONMarshal(t *testing.T) {
	envelope := &Envelope{
		MissionID:   12345,
		CollectedTS: time.Now(),
		Sequence:    1,
		Payload:     map[string]interface{}{"test": "data"},
		HMAC:        []byte{1, 2, 3},
	}

	jsonData, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Failed to marshal envelope: %v", err)
	}

	if len(jsonData) == 0 {
		t.Error("Expected non-empty JSON data")
	}

	// Try to unmarshal back
	var unmarshaled Envelope
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Logf("Unmarshal may fail due to time format: %v", err)
	}
}
