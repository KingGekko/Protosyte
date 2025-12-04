package main

import (
	"sync"
	"time"
)

// Metrics tracks operational metrics
type Metrics struct {
	mu                  sync.RWMutex
	PayloadsRetrieved   int64
	PayloadsAnalyzed    int64
	PayloadsFailed      int64
	BytesProcessed      int64
	RecordsStored       int64
	StartTime           time.Time
}

var globalMetrics = &Metrics{
	StartTime: time.Now(),
}

// GetMetrics returns a snapshot of current metrics
func GetMetrics() MetricsSnapshot {
	globalMetrics.mu.RLock()
	defer globalMetrics.mu.RUnlock()

	uptime := time.Since(globalMetrics.StartTime)

	return MetricsSnapshot{
		PayloadsRetrieved: globalMetrics.PayloadsRetrieved,
		PayloadsAnalyzed:  globalMetrics.PayloadsAnalyzed,
		PayloadsFailed:    globalMetrics.PayloadsFailed,
		BytesProcessed:    globalMetrics.BytesProcessed,
		RecordsStored:     globalMetrics.RecordsStored,
		Uptime:            uptime,
	}
}

// IncrementPayloadsRetrieved increments the payloads retrieved counter
func IncrementPayloadsRetrieved() {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()
	globalMetrics.PayloadsRetrieved++
}

// IncrementPayloadsAnalyzed increments the payloads analyzed counter
func IncrementPayloadsAnalyzed() {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()
	globalMetrics.PayloadsAnalyzed++
}

// IncrementPayloadsFailed increments the payloads failed counter
func IncrementPayloadsFailed() {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()
	globalMetrics.PayloadsFailed++
}

// AddBytesProcessed adds bytes to the processed counter
func AddBytesProcessed(bytes int64) {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()
	globalMetrics.BytesProcessed += bytes
}

// IncrementRecordsStored increments the records stored counter
func IncrementRecordsStored() {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()
	globalMetrics.RecordsStored++
}

// MetricsSnapshot represents a snapshot of metrics at a point in time
type MetricsSnapshot struct {
	PayloadsRetrieved int64
	PayloadsAnalyzed  int64
	PayloadsFailed    int64
	BytesProcessed    int64
	RecordsStored     int64
	Uptime            time.Duration
}

// ResetMetrics resets all metrics (useful for testing)
func ResetMetrics() {
	globalMetrics.mu.Lock()
	defer globalMetrics.mu.Unlock()
	globalMetrics.PayloadsRetrieved = 0
	globalMetrics.PayloadsAnalyzed = 0
	globalMetrics.PayloadsFailed = 0
	globalMetrics.BytesProcessed = 0
	globalMetrics.RecordsStored = 0
	globalMetrics.StartTime = time.Now()
}

