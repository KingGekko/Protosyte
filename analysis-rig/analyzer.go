package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Analyzer struct {
	passphrase string
	db         *gorm.DB
	store      string
}

type IntelligenceRecord struct {
	ID            uint   `gorm:"primaryKey"`
	MissionID     uint64 `gorm:"index"` // Mission identifier from mission.yaml
	HostFingerprint string
	DataType      string
	CollectedAt   int64
	ProcessedAt   int64
	IOCs          string // JSON array of indicators
}

func NewAnalyzer(passphrase string) *Analyzer {
	db, err := gorm.Open(sqlite.Open("/tmp/rig_intel.db"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	db.AutoMigrate(&IntelligenceRecord{})
	
	// Migrate AI analysis table
	analyzer := &Analyzer{
		db:        db,
		passphrase: passphrase,
	}
	if err := analyzer.MigrateAIAnalysis(); err != nil {
		log.Printf("[RIG] Warning: Failed to migrate AI analysis table: %v", err)
	}

	return &Analyzer{
		passphrase: passphrase,
		db:         db,
		store:      "/tmp/rig_store",
	}
}

func (a *Analyzer) Analyze() error {
	// Derive decryption key from passphrase
	key := pbkdf2.Key([]byte(a.passphrase), []byte("protosyte-salt"), 4096, 32, sha256.New)

	// Process all encrypted payloads
	return filepath.Walk(a.store, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}

		encrypted, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Decrypt and decompress
		decrypted, err := a.decrypt(encrypted, key)
		if err != nil {
			log.Printf("[ANAL] Decryption failed for %s: %v", path, err)
			return nil
		}

		// Parse protobuf and store in database
		record := parsePayload(decrypted)
		if record != nil {
			a.db.Create(record)
		}

		return nil
	})
}

func (a *Analyzer) decrypt(encrypted []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (a *Analyzer) parsePayload(data []byte) *IntelligenceRecord {
	// First, try to parse as protobuf envelope
	envelope, err := parseProtobufEnvelope(data)
	if err != nil {
		log.Printf("[ANAL] Failed to parse protobuf: %v, trying JSON fallback", err)
		
		// Fallback: try JSON
		var jsonData map[string]interface{}
		if err := json.Unmarshal(data, &jsonData); err != nil {
			log.Printf("[ANAL] Failed to parse as JSON: %v", err)
			return nil
		}
		
		// Create record from JSON
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
	
	// Extract intelligence from envelope
	return extractIntelligence(envelope)
}

