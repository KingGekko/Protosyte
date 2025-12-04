// AI Integration for Analysis Rig
// Stores and displays AI analysis results from Ollama

package main

import (
	"encoding/json"
	"log"
	"time"
)

// AIAnalysisRecord stores AI analysis results
type AIAnalysisRecord struct {
	ID            uint   `gorm:"primaryKey"`
	MissionID     uint64 `gorm:"index"`
	TargetIP      string
	TargetInfo    string `gorm:"type:text"`
	Vulnerabilities string `gorm:"type:text"` // JSON array
	AttackVectors string `gorm:"type:text"`   // JSON array
	AnalysisDate  time.Time
	CreatedAt     time.Time
}

// StoreAIAnalysis stores AI analysis results in the database
func (a *Analyzer) StoreAIAnalysis(missionID uint64, targetIP, targetInfo string, vulnerabilities, attackVectors interface{}) error {
	vulnJSON, err := json.Marshal(vulnerabilities)
	if err != nil {
		return err
	}

	vectorsJSON, err := json.Marshal(attackVectors)
	if err != nil {
		return err
	}

	record := AIAnalysisRecord{
		MissionID:      missionID,
		TargetIP:       targetIP,
		TargetInfo:     targetInfo,
		Vulnerabilities: string(vulnJSON),
		AttackVectors:  string(vectorsJSON),
		AnalysisDate:   time.Now(),
	}

	if err := a.db.Create(&record).Error; err != nil {
		return err
	}

	log.Printf("[RIG] Stored AI analysis for mission %d, target %s", missionID, targetIP)
	return nil
}

// GetAIAnalysis retrieves AI analysis for a mission
func (a *Analyzer) GetAIAnalysis(missionID uint64) ([]AIAnalysisRecord, error) {
	var records []AIAnalysisRecord
	if err := a.db.Where("mission_id = ?", missionID).Find(&records).Error; err != nil {
		return nil, err
	}
	return records, nil
}

// MigrateAIAnalysis creates the AI analysis table
func (a *Analyzer) MigrateAIAnalysis() error {
	return a.db.AutoMigrate(&AIAnalysisRecord{})
}

