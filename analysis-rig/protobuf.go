package main

import (
	"encoding/json"
	"time"
)

// Protobuf message structures (simplified - in production, use generated code)
type Envelope struct {
	MissionID   uint64    `json:"mission_id"`
	CollectedTS time.Time `json:"collected_ts"`
	Sequence    uint32    `json:"sequence"`
	Payload     interface{} `json:"payload"`
	HMAC        []byte    `json:"hmac"`
}

type DataBlob struct {
	HostFingerprint []byte `json:"host_fingerprint"`
	DataType        string `json:"data_type"`
	EncryptedPayload []byte `json:"encrypted_payload"`
	AESGCMNonce     []byte `json:"aes_gcm_nonce"`
	OriginalSize    uint32 `json:"original_size"`
}

type Heartbeat struct {
	LoadAvg1m   float32  `json:"load_avg_1m"`
	MemFreeMB   uint32   `json:"mem_free_mb"`
	ActiveHooks []string `json:"active_hooks"`
}

// Parse protobuf envelope (simplified implementation)
func parseProtobufEnvelope(data []byte) (*Envelope, error) {
	// In production, this would use generated protobuf code
	// For now, try JSON unmarshaling as fallback
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		// If not JSON, try binary protobuf
		// This is a simplified version
		return nil, err
	}
	return &envelope, nil
}

// Extract intelligence from envelope
func extractIntelligence(envelope *Envelope) *IntelligenceRecord {
	record := &IntelligenceRecord{
		CollectedAt: envelope.CollectedTS.Unix(),
		ProcessedAt: time.Now().Unix(),
	}
	
	// Store mission ID if available
	if envelope.MissionID != 0 {
		// Mission ID can be stored in a separate field or as part of host fingerprint
		// For now, we'll include it in the record structure if needed
	}
	
	// Extract data based on payload type
	if dataBlob, ok := envelope.Payload.(*DataBlob); ok {
		record.DataType = dataBlob.DataType
		record.HostFingerprint = string(dataBlob.HostFingerprint)
		
		// Extract IOCs (simplified)
		iocs := []string{dataBlob.DataType}
		if iocJSON, err := json.Marshal(iocs); err == nil {
			record.IOCs = string(iocJSON)
		}
	}
	
	return record
}

// ParsePayload is a wrapper that handles both protobuf and JSON formats
func parsePayload(data []byte) *IntelligenceRecord {
	envelope, err := parseProtobufEnvelope(data)
	if err != nil {
		// Fallback to JSON parsing
		var jsonData map[string]interface{}
		if err := json.Unmarshal(data, &jsonData); err != nil {
			return nil
		}
		
		record := &IntelligenceRecord{
			ProcessedAt: time.Now().Unix(),
		}
		
		if dt, ok := jsonData["data_type"].(string); ok {
			record.DataType = dt
		}
		if hf, ok := jsonData["host_fingerprint"].(string); ok {
			record.HostFingerprint = hf
		}
		if ts, ok := jsonData["collected_ts"].(float64); ok {
			record.CollectedAt = int64(ts)
		}
		
		return record
	}
	
	return extractIntelligence(envelope)
}

